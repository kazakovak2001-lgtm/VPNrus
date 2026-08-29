package net.pocvpn.client

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import net.pocvpn.client.diagnostics.DiagnosticsSnapshot
import net.pocvpn.client.diagnostics.DiagnosticsStore
import net.pocvpn.client.identity.ClientKeyRepository
import net.pocvpn.client.identity.ClientKeyRepositoryFactory
import net.pocvpn.client.provisioning.ProvisioningClient
import net.pocvpn.client.provisioning.ProvisioningResult
import net.pocvpn.client.provisioning.ProvisioningUiState
import net.pocvpn.client.vpn.AmneziaWgTransport
import net.pocvpn.client.vpn.AndroidReconnectManager
import net.pocvpn.client.vpn.ControllerEvent
import net.pocvpn.client.vpn.ReconnectManager
import net.pocvpn.client.vpn.TransportState
import net.pocvpn.client.vpn.VpnController
import net.pocvpn.client.vpn.VpnTransport
import net.pocvpn.client.vpn.config.BuildConfigGatewaySource
import net.pocvpn.client.vpn.config.DefaultGatewayConfigurationRepository
import net.pocvpn.client.vpn.config.FileProfileStore
import net.pocvpn.client.vpn.config.GatewayConfiguration
import net.pocvpn.client.vpn.config.GatewayConfigurationRepository
import net.pocvpn.client.vpn.config.MutableGatewayConfigSource
import net.pocvpn.client.vpn.config.PersistedProfile
import net.pocvpn.client.vpn.config.ProfileLoadResult
import net.pocvpn.client.vpn.config.ProfileSource
import net.pocvpn.client.vpn.config.ProfileStore
import net.pocvpn.client.vpn.policy.AndroidInstalledPackageChecker
import net.pocvpn.client.vpn.policy.AppRoutingPolicy
import net.pocvpn.client.vpn.policy.AppRoutingPolicyStore
import net.pocvpn.client.vpn.policy.FileAppRoutingPolicyStore
import net.pocvpn.client.vpn.policy.InstalledPackageChecker

/**
 * Thin state holder above VpnController - MainActivity observes this instead
 * of owning tunnel/connection state itself, so Activity recreation (rotation,
 * process death+restore of the Activity only) doesn't lose or duplicate it.
 * VpnController is built here (not in the Factory) because it needs
 * viewModelScope, which only exists once this ViewModel instance exists.
 */
class MainViewModel(
    private val clientKeyRepository: ClientKeyRepository,
    transport: VpnTransport,
    gatewayConfigurationRepository: GatewayConfigurationRepository,
    reconnectManager: ReconnectManager,
    private val diagnosticsStore: DiagnosticsStore,
    // B8B3B - additive, defaults to null so every existing call site
    // (including MainViewModelTest's) is unaffected. When non-null, this is
    // the SAME GatewayConfigSource instance the Factory below wrapped into
    // gatewayConfigurationRepository above - applying to it is what makes a
    // successful provisioning result visible to the existing Connect flow,
    // with no VpnController change (see MutableGatewayConfigSource's docs).
    private val gatewayConfigOverride: MutableGatewayConfigSource? = null,
    // B8B3C - additive, defaults to null (same reasoning as gatewayConfigOverride
    // above): when non-null, this is where a validated provisioning result is
    // durably saved, and where a prior session's result is restored from at
    // startup (see the init block below).
    private val profileStore: ProfileStore? = null,
    // B8C2A - additive, defaults to the real ProvisioningClient.activate call
    // so every existing (non-test) call site is byte-for-byte unchanged. Exists
    // ONLY so activateDevice()'s public-key sourcing and its Success ->
    // apply()/write() wiring are unit-testable without a live HTTPS call to
    // the real production edge (same reasoning as gatewayConfigOverride/
    // profileStore above - an additive seam, not a network abstraction).
    private val activationClient: (publicKey: String, activationCredential: String) -> ProvisioningResult =
        ProvisioningClient::activate,
    // B8C2A - additive, defaults to Dispatchers.IO (byte-for-byte unchanged
    // production behavior). Lets tests run activateDevice()'s coroutine on
    // the SAME (virtual-time) test dispatcher as the rest of the test instead
    // of a real background thread pool, so runCurrent()/advanceUntilIdle()
    // can deterministically observe its result.
    private val ioDispatcher: kotlinx.coroutines.CoroutineDispatcher = Dispatchers.IO,
    // B8H - additive, defaults to null (same reasoning as gatewayConfigOverride/
    // profileStore above): when non-null, this is the ONE store both
    // VpnController (read-only, at connect time) and this ViewModel (read +
    // write, for the Settings UI) share - see updateAppRoutingPolicy below.
    private val appRoutingPolicyStore: AppRoutingPolicyStore? = null,
    private val installedPackageChecker: InstalledPackageChecker? = null,
) : ViewModel() {

    private val controller = VpnController(
        transport = transport,
        clientKeyRepository = clientKeyRepository,
        gatewayConfigurationRepository = gatewayConfigurationRepository,
        reconnectManager = reconnectManager,
        diagnostics = diagnosticsStore,
        scope = viewModelScope,
        appRoutingPolicyStore = appRoutingPolicyStore ?: AppRoutingPolicyStore.allApps(),
        installedPackageChecker = installedPackageChecker ?: InstalledPackageChecker.alwaysInstalled(),
    )

    val transportState: StateFlow<TransportState> = controller.state
    val diagnostics: StateFlow<DiagnosticsSnapshot> = diagnosticsStore.snapshot
    val events: SharedFlow<ControllerEvent> = controller.events

    // B8H - the saved (not necessarily yet-applied) split-tunneling policy,
    // read once at startup and kept in sync by updateAppRoutingPolicy(). See
    // VpnController.appliedRoutingPolicy for what's actually live right now.
    private val _savedAppRoutingPolicy = MutableStateFlow(appRoutingPolicyStore?.read() ?: AppRoutingPolicy.Default)
    val savedAppRoutingPolicy: StateFlow<AppRoutingPolicy> = _savedAppRoutingPolicy.asStateFlow()
    val appliedAppRoutingPolicy: StateFlow<AppRoutingPolicy?> = controller.appliedRoutingPolicy

    /**
     * B8H - saves ONLY the local policy file; deliberately does NOT touch
     * the transport/tunnel in any way (no connect/disconnect/rebuild) - see
     * VpnController class docs' "Reconnect to apply changes" requirement.
     * The next real connect() (see VpnController.doConnectAttempt) is what
     * actually applies this.
     */
    fun updateAppRoutingPolicy(policy: AppRoutingPolicy) {
        appRoutingPolicyStore?.write(policy)
        _savedAppRoutingPolicy.value = policy
    }

    private val _publicKey = MutableStateFlow<String?>(null)
    val publicKey: StateFlow<String?> = _publicKey.asStateFlow()

    // B8B3A - live production provisioning (POST /v1/peers over the B8B2A
    // HTTPS edge) against the EXISTING device identity above. The bearer
    // token is never stored here or anywhere else in this ViewModel - it
    // only ever exists as the `token` parameter of provisionDevice() for
    // the duration of one call, then falls out of scope. Does not persist
    // across process death (an in-memory StateFlow, like publicKey above);
    // that is intentional for this debug/PoC slice, not an oversight - see
    // gateway/edge and B8B3A's own scope notes.
    private val _provisioningState = MutableStateFlow<ProvisioningUiState>(ProvisioningUiState.Idle)
    val provisioningState: StateFlow<ProvisioningUiState> = _provisioningState.asStateFlow()

    // B8B3C - debug-only visibility into where the effective profile came
    // from this session. DEV_FALLBACK until either a persisted profile is
    // restored below or a fresh provisionDevice() succeeds.
    private val _profileSource = MutableStateFlow(ProfileSource.DEV_FALLBACK)
    val profileSource: StateFlow<ProfileSource> = _profileSource.asStateFlow()

    init {
        viewModelScope.launch {
            _publicKey.value = clientKeyRepository.getPublicKey()
        }
        restorePersistedProfile()
    }

    // B8B3C requirement 6 (fail closed): NotFound and Corrupted are handled
    // identically here - neither ever calls gatewayConfigOverride.apply().
    // A corrupt/partial/tampered file can therefore never reach the AWG
    // config mapper - the effective profile simply stays whatever
    // BuildConfigGatewaySource already provides (DEV_FALLBACK), exactly as
    // if no profile had ever been persisted. This never throws/crashes -
    // ProfileStore.read() itself already converts every I/O/parse failure
    // into Corrupted (see FileProfileStore's own docs).
    private fun restorePersistedProfile() {
        val store = profileStore ?: return
        when (val result = store.read()) {
            is ProfileLoadResult.Found -> {
                val p = result.profile
                gatewayConfigOverride?.apply(
                    endpointHost = p.endpointHost,
                    endpointPort = p.endpointPort,
                    serverPublicKey = p.gatewayPublicKey,
                    clientTunnelIp = p.clientTunnelIp,
                    gatewayTunnelIp = p.gatewayTunnelIp,
                )
                _profileSource.value = ProfileSource.RESTORED_PERSISTED
            }
            is ProfileLoadResult.NotFound -> Unit
            is ProfileLoadResult.Corrupted -> Unit
        }
    }

    /**
     * B8C2 - activation credential -> the EXISTING device public key
     * (never a newly generated one - see ClientKeyRepository's own docs) ->
     * POST /v1/activate. The credential is never stored here or anywhere
     * else in this ViewModel - it only ever exists as this function's
     * `activationCredential` parameter for the duration of one call, then
     * falls out of scope, exactly like provisionDevice's token before it.
     */
    fun activateDevice(activationCredential: String) {
        val trimmedCredential = activationCredential.trim()
        if (trimmedCredential.isEmpty()) {
            _provisioningState.value = ProvisioningUiState.Error("activation credential is empty")
            return
        }
        val key = _publicKey.value
        if (key == null) {
            _provisioningState.value = ProvisioningUiState.Error("device public key not loaded yet")
            return
        }

        _provisioningState.value = ProvisioningUiState.Provisioning
        viewModelScope.launch {
            val result = withContext(ioDispatcher) {
                activationClient(key, trimmedCredential)
            }
            _provisioningState.value = when (result) {
                is ProvisioningResult.Success -> {
                    // B8B3B safety rule: apply() is reached ONLY inside this
                    // branch - i.e. only for a value that has already passed
                    // ProvisioningClient's own structural validation. Never
                    // called against a raw/unvalidated server response. The
                    // device private key is untouched - it is looked up
                    // separately from clientKeyRepository at connect time
                    // (see GatewayConfiguration's own docs) and is not part
                    // of this GatewayConfigSource at all. AWG obfuscation
                    // parameters (Jc/Jmin/Jmax/S1-4/H1-4) come from
                    // PocAwgProfile.value via DefaultGatewayConfigurationRepository's
                    // own `profile` default, untouched here.
                    gatewayConfigOverride?.apply(
                        endpointHost = result.endpointHost,
                        endpointPort = result.endpointPort,
                        serverPublicKey = result.gatewayPublicKey,
                        clientTunnelIp = result.clientTunnelIp,
                        gatewayTunnelIp = result.gatewayTunnelIp,
                    )
                    // B8B3C - durably persist ONLY the five non-secret
                    // gateway fields, exactly what was just applied above.
                    // No token (never in scope here - see provisionDevice's
                    // own token handling), no private key (ProfileStore has
                    // no field for one at all - see its own docs).
                    profileStore?.write(
                        PersistedProfile(
                            endpointHost = result.endpointHost,
                            endpointPort = result.endpointPort,
                            gatewayPublicKey = result.gatewayPublicKey,
                            clientTunnelIp = result.clientTunnelIp,
                            gatewayTunnelIp = result.gatewayTunnelIp,
                        )
                    )
                    _profileSource.value = ProfileSource.PROVISIONED_LIVE
                    ProvisioningUiState.Success(result)
                }
                is ProvisioningResult.Unauthorized -> ProvisioningUiState.Unauthorized
                is ProvisioningResult.Revoked -> ProvisioningUiState.Revoked
                is ProvisioningResult.Expired -> ProvisioningUiState.Expired
                is ProvisioningResult.DeviceLimitReached -> ProvisioningUiState.DeviceLimitReached
                is ProvisioningResult.BadRequest -> ProvisioningUiState.Error("invalid request/device")
                is ProvisioningResult.ServiceUnavailable -> ProvisioningUiState.Error("service temporarily unavailable")
                is ProvisioningResult.MalformedResponse -> ProvisioningUiState.Error("malformed response: ${result.reason}")
                is ProvisioningResult.NetworkError -> ProvisioningUiState.Error(result.message)
            }
        }
    }

    fun gatewayStatus(): GatewayConfiguration = controller.gatewayStatus()

    fun connect() {
        viewModelScope.launch { controller.connect() }
    }

    fun disconnect() {
        viewModelScope.launch { controller.disconnect() }
    }

    fun onVpnPermissionResult(granted: Boolean) {
        viewModelScope.launch { controller.onVpnPermissionResult(granted) }
    }

    fun regenerateIdentity() {
        viewModelScope.launch {
            clientKeyRepository.clearIdentity()
            _publicKey.value = clientKeyRepository.getOrCreateIdentity().publicKeyBase64
        }
    }

    override fun onCleared() {
        controller.shutdown()
    }

    class Factory(private val appContext: Context) : ViewModelProvider.Factory {
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            val context = appContext.applicationContext
            // B8B3B - the SAME instance is wrapped into the repository below
            // AND handed to MainViewModel as gatewayConfigOverride, so a
            // later apply() call is visible to gatewayConfigurationRepository.get()
            // (called fresh by VpnController on every gatewayStatus()/connect() -
            // no caching) without VpnController itself changing at all.
            val gatewayConfigSource = MutableGatewayConfigSource(BuildConfigGatewaySource)
            // B8B3C - same noBackupFilesDir as the identity store
            // (ClientKeyRepositoryFactory), different file: this data is
            // non-secret but still device/session-specific, so Auto Backup
            // restoring it onto a different device would be meaningless.
            val profileStore = FileProfileStore(context.noBackupFilesDir)
            // B8H - same noBackupFilesDir as profileStore above, different
            // file: a device-local UX preference, not something a restore
            // onto a different device should silently reapply either.
            val appRoutingPolicyStore = FileAppRoutingPolicyStore(context.noBackupFilesDir)
            @Suppress("UNCHECKED_CAST")
            return MainViewModel(
                clientKeyRepository = ClientKeyRepositoryFactory.create(context),
                transport = AmneziaWgTransport(context),
                gatewayConfigurationRepository = DefaultGatewayConfigurationRepository(gatewayConfigSource),
                reconnectManager = AndroidReconnectManager(context),
                diagnosticsStore = DiagnosticsStore(),
                gatewayConfigOverride = gatewayConfigSource,
                profileStore = profileStore,
                appRoutingPolicyStore = appRoutingPolicyStore,
                installedPackageChecker = AndroidInstalledPackageChecker(context),
            ) as T
        }
    }
}
