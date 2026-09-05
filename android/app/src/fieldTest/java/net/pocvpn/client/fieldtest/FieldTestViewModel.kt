package net.pocvpn.client.fieldtest

import android.app.Application
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import net.pocvpn.client.network.NetworkProfile
import net.pocvpn.client.network.NetworkType
import net.pocvpn.client.smartconnect.RestrictionClass
import net.pocvpn.client.smartconnect.RestrictionClassifier
import net.pocvpn.client.smartconnect.RestrictionEvidence
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.vpn.AmneziaWgTransport
import net.pocvpn.client.vpn.TransportState
import net.pocvpn.client.vpn.VpnTransport
import net.pocvpn.client.vpn.config.ProductionGatewayId
import net.pocvpn.client.vpn.policy.RoutingMode

/**
 * The UI-facing state this build's ONE screen renders (task's required UX:
 * "Nova VPN" / [Connect] / Connecting…/Protected/Connection failed - nothing
 * else). Deliberately a tiny, closed vocabulary - no activation/provisioning
 * state exists in this build at all.
 */
sealed class FieldTestUiState {
    object Idle : FieldTestUiState()
    object Connecting : FieldTestUiState()
    object Protected : FieldTestUiState()
    object Failed : FieldTestUiState()
}

/**
 * Owns the field test's one real action: press Connect -> try Frankfurt,
 * then Stockholm, using the real production AWG transport -> Protected or
 * Connection failed. Also owns the sanitized [FieldTestReport] this run
 * always produces (task requirement: "a failed VPN connection must still
 * produce a complete local diagnostic report" - reporting is NEVER a
 * prerequisite for the VPN attempt itself, see [connect]'s own structure:
 * the connect attempt runs and settles completely before any report/upload
 * logic begins, and a report/upload failure can never roll back or affect
 * [uiState]).
 */
class FieldTestViewModel(
    private val transportFactory: (ProductionGatewayId) -> VpnTransport,
    private val appVersionName: String,
    private val appVersionCode: Long,
    private val reportUploader: FieldTestReportUploader = NoOpFieldTestReportUploader,
    private val networkTypeProvider: () -> NetworkType = { NetworkType.OTHER },
    private val nowProvider: () -> Long = System::currentTimeMillis,
) : ViewModel() {

    private val diagnostics = FieldTestDiagnosticsRecorder(nowProvider)
    private val controller = FieldTestTunnelController(
        transportFactory = transportFactory,
        diagnostics = diagnostics,
        nowProvider = nowProvider,
    )

    private val _uiState = MutableStateFlow<FieldTestUiState>(FieldTestUiState.Idle)
    val uiState: StateFlow<FieldTestUiState> = _uiState.asStateFlow()

    private val _lastReport = MutableStateFlow<FieldTestReport?>(null)
    /** The most recent run's report, or null before any Connect attempt - [FieldTestActivity]'s manual "Share report" action reads this directly (`lastReport.value != null`). */
    val lastReport: StateFlow<FieldTestReport?> = _lastReport.asStateFlow()

    fun connect() {
        if (_uiState.value != FieldTestUiState.Idle && _uiState.value != FieldTestUiState.Failed) return
        _uiState.value = FieldTestUiState.Connecting
        viewModelScope.launch {
            val finalState = controller.connect()
            val networkType = networkTypeProvider()

            when (finalState) {
                is FieldTestState.Protected -> {
                    _uiState.value = FieldTestUiState.Protected
                    val report = buildReport(
                        networkType = networkType,
                        gatewaysAttempted = attemptedFrom(finalState.candidate),
                        finalGateway = finalState.candidate,
                        finalTransportKind = TransportKind.AMNEZIA_WG,
                        outcome = FieldTestOutcome.PROTECTED,
                        failureCategory = FieldTestFailureCategory.NONE,
                    )
                    _lastReport.value = report
                    // Report upload is attempted ONLY now, AFTER the tunnel is
                    // genuinely Protected, and its outcome never feeds back
                    // into uiState - a failed upload leaves the VPN exactly
                    // as connected as it was (task requirement 5).
                    attemptUploadThroughTunnel(report)
                }
                is FieldTestState.Failed -> {
                    _uiState.value = FieldTestUiState.Failed
                    val report = buildReport(
                        networkType = networkType,
                        gatewaysAttempted = finalState.attempted,
                        finalGateway = null,
                        finalTransportKind = null,
                        outcome = FieldTestOutcome.FAILED,
                        failureCategory = FieldTestFailureCategory.ALL_CANDIDATES_EXHAUSTED,
                    )
                    _lastReport.value = report
                }
                is FieldTestState.Idle, is FieldTestState.Connecting -> Unit
            }
        }
    }

    /** Lets the tester retry after a failure - same [connect] entry point, a fresh attempt from Idle. */
    fun retry() {
        if (_uiState.value == FieldTestUiState.Failed) {
            _uiState.value = FieldTestUiState.Idle
            connect()
        }
    }

    private suspend fun attemptUploadThroughTunnel(report: FieldTestReport) {
        diagnostics.recordReportUploadAttempted()
        val uploaded = try {
            reportUploader.uploadThroughTunnel(report)
        } catch (t: Throwable) {
            false
        }
        diagnostics.recordReportUploadResult(uploaded)
        // Refresh the retained report with the upload attempt's own events
        // folded in, so the manual "Share report" fallback (task requirement
        // 4's own "keep the report locally... preserve the existing export/
        // share mechanism") still reflects the full, final timeline even
        // when upload succeeded.
        _lastReport.value = report.copy(events = diagnostics.snapshot())
    }

    private fun attemptedFrom(finalCandidate: ProductionGatewayId): List<ProductionGatewayId> {
        val order = listOf(ProductionGatewayId.GERMANY, ProductionGatewayId.STOCKHOLM)
        val idx = order.indexOf(finalCandidate)
        return if (idx < 0) listOf(finalCandidate) else order.subList(0, idx + 1)
    }

    private fun buildReport(
        networkType: NetworkType,
        gatewaysAttempted: List<ProductionGatewayId>,
        finalGateway: ProductionGatewayId?,
        finalTransportKind: TransportKind?,
        outcome: FieldTestOutcome,
        failureCategory: FieldTestFailureCategory,
    ): FieldTestReport {
        // Reuses the app's REAL restriction-classification logic (task
        // requirement: "restriction/network classification already produced
        // by the app") - RestrictionClassifier.classify is a pure function,
        // no live probe pipeline needs to be wired here (see that object's
        // own docs: missing evidence correctly yields UNKNOWN, never a
        // guess). gatewayHttpsReachable/diverseInternetReachable are not
        // probed by this small flow - null, matching classify()'s own
        // "unknown until observed" contract.
        val evidence = RestrictionEvidence(
            networkProfile = NetworkProfile(
                type = networkType,
                validatedInternet = outcome == FieldTestOutcome.PROTECTED,
                metered = false,
                roaming = null,
                captivePortal = null,
                ipv4Available = true,
                ipv6Available = false,
                vpnActive = outcome == FieldTestOutcome.PROTECTED,
                generation = 0,
            ),
            transportState = if (outcome == FieldTestOutcome.PROTECTED) TransportState.Connected else TransportState.HandshakeFailed,
            awgHandshakeFresh = outcome == FieldTestOutcome.PROTECTED,
            gatewayHttpsReachable = null,
        )
        val restrictionClass: RestrictionClass = RestrictionClassifier.classify(evidence)

        return FieldTestReport(
            buildLabel = FieldTestBuildInfo.BUILD_LABEL,
            appVersionName = appVersionName,
            appVersionCode = appVersionCode,
            generatedAtEpochMillis = nowProvider(),
            networkType = networkType,
            routingMode = RoutingMode.FULL_VPN,
            restrictionClass = restrictionClass,
            gatewaysAttempted = gatewaysAttempted,
            finalGateway = finalGateway,
            finalTransportKind = finalTransportKind,
            outcome = outcome,
            failureCategory = failureCategory,
            events = diagnostics.snapshot(),
        ).sanitizedForExport()
    }

    class Factory(private val application: Application) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            val versionName = try {
                application.packageManager.getPackageInfo(application.packageName, 0).versionName ?: "unknown"
            } catch (t: Throwable) {
                "unknown"
            }
            val versionCode = try {
                application.packageManager.getPackageInfo(application.packageName, 0).let {
                    @Suppress("DEPRECATION")
                    it.versionCode.toLong()
                }
            } catch (t: Throwable) {
                0L
            }
            return FieldTestViewModel(
                transportFactory = { AmneziaWgTransport(application) },
                appVersionName = versionName,
                appVersionCode = versionCode,
            ) as T
        }
    }
}
