package net.pocvpn.client.geodata

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import net.pocvpn.client.vpn.xray.asGeoAssetSource
import java.io.File
import java.io.IOException
import java.util.concurrent.atomic.AtomicBoolean

/** What the manual update is doing right now. */
sealed class GeoOperationState {
    object Idle : GeoOperationState()

    data class Running(val progress: GeoProgress?, val cancelRequested: Boolean = false) : GeoOperationState()

    /** The final outcome of the last manual update ([GeoUpdateResult.Failed] included). */
    data class Finished(val result: GeoUpdateResult) : GeoOperationState()

    /** A plain message, e.g. after "use built-in databases". */
    data class Info(val message: String) : GeoOperationState()
}

data class GeoDataUiState(
    val geoipInput: String = "",
    val geositeInput: String = "",
    val geoipProblem: GeoUrlProblem? = null,
    val geositeProblem: GeoUrlProblem? = null,
    val saved: GeoDataSettings = GeoDataSettings(),
    val saveFailed: Boolean = false,
    val status: GeoDataStatus? = null,
    val operation: GeoOperationState = GeoOperationState.Idle,
) {
    val hasUnsavedChanges: Boolean
        get() = geoipInput.trim() != saved.geoipUrl || geositeInput.trim() != saved.geositeUrl

    val isRunning: Boolean get() = operation is GeoOperationState.Running
}

/**
 * State holder for Settings -> GeoData. All blocking work (hashing the databases, downloading, publishing) runs
 * on [ioDispatcher]; only one update can run at a time ([GeoDataUpdater] also guards against a second one with a
 * lock file, which covers other processes).
 */
class GeoDataViewModel(
    private val settingsStore: GeoDataSettingsStore,
    private val updater: GeoDataUpdater,
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
    private val scopeOverride: CoroutineScope? = null,
) : ViewModel() {

    private val scope: CoroutineScope get() = scopeOverride ?: viewModelScope

    private val _state = MutableStateFlow(initialState())
    val state: StateFlow<GeoDataUiState> = _state.asStateFlow()

    private val cancelRequested = AtomicBoolean(false)

    private fun initialState(): GeoDataUiState {
        val saved = settingsStore.read()
        return GeoDataUiState(geoipInput = saved.geoipUrl, geositeInput = saved.geositeUrl, saved = saved)
    }

    fun onGeoipInputChanged(text: String) {
        _state.update { it.copy(geoipInput = text, geoipProblem = null, saveFailed = false) }
    }

    fun onGeositeInputChanged(text: String) {
        _state.update { it.copy(geositeInput = text, geositeProblem = null, saveFailed = false) }
    }

    /** Reloads the "what is in use" block. Safe to call whenever the screen opens. */
    fun refreshStatus() {
        scope.launch {
            val status = withContext(ioDispatcher) { updater.status() }
            _state.update { it.copy(status = status) }
        }
    }

    /**
     * Validates both inputs and stores them. Blank clears a URL. Returns true when stored; on a validation
     * problem nothing is written and the field shows the reason.
     */
    fun save(): Boolean {
        val current = _state.value
        val geoip = GeoUrlValidator.validate(current.geoipInput)
        val geosite = GeoUrlValidator.validate(current.geositeInput)
        val geoipProblem = (geoip as? GeoUrlValidation.Invalid)?.problem
        val geositeProblem = (geosite as? GeoUrlValidation.Invalid)?.problem
        if (geoipProblem != null || geositeProblem != null) {
            _state.update { it.copy(geoipProblem = geoipProblem, geositeProblem = geositeProblem) }
            return false
        }
        val settings = GeoDataSettings(
            geoipUrl = (geoip as? GeoUrlValidation.Valid)?.url ?: "",
            geositeUrl = (geosite as? GeoUrlValidation.Valid)?.url ?: "",
        )
        return try {
            settingsStore.write(settings)
            _state.update {
                it.copy(
                    saved = settings,
                    geoipInput = settings.geoipUrl,
                    geositeInput = settings.geositeUrl,
                    geoipProblem = null,
                    geositeProblem = null,
                    saveFailed = false,
                )
            }
            true
        } catch (e: IOException) {
            _state.update { it.copy(saveFailed = true) }
            false
        }
    }

    /** Saves the inputs (if they changed) and then downloads and activates. Ignored while an update is running. */
    fun startUpdate() {
        if (_state.value.isRunning) return
        if (_state.value.hasUnsavedChanges && !save()) return
        val settings = _state.value.saved
        if (!settings.hasAnyUrl) {
            _state.update {
                it.copy(operation = GeoOperationState.Finished(GeoUpdateResult.Failed(GeoUpdateFailureKind.NOT_CONFIGURED)))
            }
            return
        }
        cancelRequested.set(false)
        _state.update { it.copy(operation = GeoOperationState.Running(null)) }
        scope.launch {
            val result = withContext(ioDispatcher) {
                try {
                    updater.update(
                        settings,
                        isCancelled = { cancelRequested.get() },
                        onProgress = { progress ->
                            _state.update { s ->
                                val op = s.operation
                                if (op is GeoOperationState.Running) s.copy(operation = op.copy(progress = progress)) else s
                            }
                        },
                    )
                } catch (t: Throwable) {
                    GeoUpdateResult.Failed(GeoUpdateFailureKind.STAGING_FAILED, detail = "The update failed unexpectedly.")
                }
            }
            val status = withContext(ioDispatcher) { updater.status() }
            _state.update { it.copy(operation = GeoOperationState.Finished(result), status = status) }
        }
    }

    /** Asks the running update to stop; it ends at the next received chunk (or when the connection times out). */
    fun cancelUpdate() {
        if (!_state.value.isRunning) return
        cancelRequested.set(true)
        _state.update { s ->
            val op = s.operation
            if (op is GeoOperationState.Running) s.copy(operation = op.copy(cancelRequested = true)) else s
        }
    }

    /** Stops using downloaded databases; the built-in ones are used again. */
    fun useBundled() {
        if (_state.value.isRunning) return
        scope.launch {
            val ok = withContext(ioDispatcher) { updater.resetToBundled() }
            val status = withContext(ioDispatcher) { updater.status() }
            val message = if (ok) {
                "Using the built-in databases again. " + GeoDataPresentation.RESTART_NOTICE
            } else {
                "The built-in databases could not be restored; the current ones are unchanged."
            }
            _state.update { it.copy(operation = GeoOperationState.Info(message), status = status) }
        }
    }

    override fun onCleared() {
        cancelRequested.set(true)
        super.onCleared()
    }

    class Factory(private val context: Context) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            val app = context.applicationContext
            val root = File(app.noBackupFilesDir, "xray-assets")
            val updater = GeoDataUpdater(root, app.assets.asGeoAssetSource(), GeoDatabaseDownloader(HttpsGeoHttp()))
            return GeoDataViewModel(FileGeoDataSettingsStore(app.noBackupFilesDir), updater) as T
        }
    }
}
