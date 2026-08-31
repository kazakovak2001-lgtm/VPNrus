package net.pocvpn.client.vpn

import android.content.Intent
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlin.coroutines.coroutineContext
import net.pocvpn.client.diagnostics.DiagnosticsStore
import net.pocvpn.client.diagnostics.VpnError
import net.pocvpn.client.identity.ClientKeyRepository
import net.pocvpn.client.identity.XrayProfileRepository
import net.pocvpn.client.identity.XrayProfileRepositoryResolver
import net.pocvpn.client.identity.XrayTlsProfileRepository
import net.pocvpn.client.identity.XrayTlsProfileRepositoryResolver
import net.pocvpn.client.network.NetworkProfile
import net.pocvpn.client.reachability.CoarseNetworkSignals
import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.reachability.NetworkFingerprintKeyProvider
import net.pocvpn.client.reachability.NetworkFingerprinter
import net.pocvpn.client.reachability.PathHistoryStore
import net.pocvpn.client.smartconnect.ConnectionErrorCategory
import net.pocvpn.client.smartconnect.ConnectionOutcome
import net.pocvpn.client.smartconnect.ConnectionOutcomeResult
import net.pocvpn.client.smartconnect.ConnectionOutcomeStore
import net.pocvpn.client.smartconnect.ProductionGateway
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.transport.TransportOrchestrator
import net.pocvpn.client.transport.TransportStats
import net.pocvpn.client.vpn.config.AwgConfig
import net.pocvpn.client.vpn.config.AwgPeer
import net.pocvpn.client.vpn.config.GatewayConfiguration
import net.pocvpn.client.vpn.config.GatewayConfigurationRepository
import net.pocvpn.client.vpn.config.TransportConfig
import net.pocvpn.client.vpn.policy.AppRoutingLists
import net.pocvpn.client.vpn.policy.AppRoutingPolicy
import net.pocvpn.client.vpn.policy.AppRoutingPolicyStore
import net.pocvpn.client.vpn.policy.EffectiveRoutingResult
import net.pocvpn.client.vpn.policy.InstalledPackageChecker
import net.pocvpn.client.vpn.policy.resolveAppRoutingLists
import net.pocvpn.client.vpn.xray.XrayRuntimeResolution
import net.pocvpn.client.vpn.xray.XrayRuntimeResolver
import net.pocvpn.client.vpn.xray.XrayTlsRuntimeResolution

sealed class ControllerEvent {
    data class RequestVpnPermission(val intent: Intent) : ControllerEvent()
}

/**
 * Connection orchestrator sitting between the UI (ViewModel) and VpnTransport.
 * Owns: VPN permission flow, gateway-config precondition checks, connect/
 * disconnect serialization (no overlapping backend operations), and the
 * client-side reconnect state machine. Holds no UI references and survives
 * independently of any Activity.
 *
 * B8G1 - "Break-before-make" and why reconnectLoop() never re-calls connect():
 * decompiling the pinned AmneziaWG AAR's org.amnezia.awg.backend.GoBackend
 * .setState(tunnel, UP, config) shows that whenever a tunnel is ALREADY up,
 * bringing up ANY config (even an unchanged one) first tears the existing
 * one down (setStateInternal(oldTunnel, null, DOWN)) before establishing the
 * new one - a real, brief window where the OS-level VpnService interface
 * and its 0.0.0.0/0+::/0 routes could be gone, before the replacement comes
 * up (GoBackend attempts to roll back to the previous tunnel only if the
 * NEW one throws - it does not avoid the teardown itself). This is internal
 * to that pinned, unmodified dependency - not something this class can
 * avoid by "not calling disconnect" alone.
 *
 * The fix: reconnectLoop() below NEVER calls transport.connect() to retry
 * an unchanged config. Once a tunnel is established, the AmneziaWG/
 * WireGuard protocol itself keeps attempting handshakes on its own - no
 * app-level "nudge" is needed or even available (the pinned AAR's native
 * JNI bridge, org.amnezia.awg.GoBackend, exposes only awgTurnOn / awgTurnOff
 * / awgGetConfig / awgGetSocketV4 / awgGetSocketV6 / awgVersion - no
 * incremental "retry"/"rekey" native call exists to call instead). This is
 * standard, documented
 * WireGuard behavior ("you don't need to worry about asking it to
 * reconnect... everything else is handled for you automatically"),
 * reinforced here by AwgPeer's own default persistentKeepaliveSeconds=25,
 * which keeps the underlying engine periodically retrying even with no
 * real outbound traffic queued. So reconnectLoop() only WAITS (polling the
 * exact same awaitFreshHandshake() the initial connect already uses) for
 * that automatic recovery, leaving the established interface/routes
 * completely untouched throughout - no setState call, no teardown window,
 * for as long as the session is merely recovering rather than being
 * explicitly reconfigured. A real rebuild (a new setState(UP, ...) call)
 * only ever happens for a genuine INITIAL connect() or an explicit
 * reactivation - never as an automatic retry.
 *
 * This closes the automatic-failure leak window Level A (this class) can
 * control. It does NOT make this a strict, OS-enforced kill switch: if the
 * VpnService process itself is killed by the OS (not merely a lost
 * handshake), only Android's own Always-on VPN + "Block connections
 * without VPN" system setting (Level B, entirely outside this app's
 * control - see AlwaysOnVpnState's own docs) can guarantee no leak in that
 * case. Never claim otherwise in the UI.
 */
class VpnController(
    private val transport: VpnTransport,
    private val clientKeyRepository: ClientKeyRepository,
    private val gatewayConfigurationRepository: GatewayConfigurationRepository,
    private val reconnectManager: ReconnectManager,
    private val diagnostics: DiagnosticsStore,
    private val scope: CoroutineScope,
    // B8H - additive, defaults to an in-memory store that always reads
    // AppRoutingPolicy.Default (ALL_APPS) and ignores writes, so every
    // existing call site (real or test, including every B8G/B8G1 test) is
    // byte-for-byte unaffected - same reasoning as MainViewModel's own
    // gatewayConfigOverride/profileStore additive-seam params.
    private val appRoutingPolicyStore: AppRoutingPolicyStore = AppRoutingPolicyStore.allApps(),
    // B8H - additive, defaults to "every package is installed" so the
    // default appRoutingPolicyStore above (always ALL_APPS, empty selection)
    // never spuriously resolves to NoAppsSelected.
    private val installedPackageChecker: InstalledPackageChecker = InstalledPackageChecker.alwaysInstalled(),
    // B8I - additive, defaults to null so every existing call site (real or
    // test) is byte-for-byte unaffected: with no store, recordConnectionOutcome
    // below is simply a no-op. Recording never changes control flow - see
    // that function's own docs for the "real evidence only" invariant.
    private val connectionOutcomeStore: ConnectionOutcomeStore? = null,
    // B8I6 - additive, defaults to null so every existing call site (real or
    // test) is byte-for-byte unaffected: with no repository, TransportKind.
    // XRAY_REALITY simply never enters [supportedKinds] below - the SAME
    // fail-closed refusal a pre-B8I6 caller already saw for any non-AWG
    // kind. When wired (MainViewModel's Factory passes the SAME
    // XrayProfileRepositoryFactory-built instance NovaXrayVpnService/
    // VlessRealityTransport already read from - one authoritative store,
    // never a second one), buildTransportConfig() below reuses it via the
    // EXISTING XrayRuntimeResolver - never fabricates Xray config from AWG
    // GatewayConfiguration fields.
    private val xrayProfileRepository: XrayProfileRepository? = null,
    // B8O2 - additive, defaults to null (same reasoning as
    // xrayProfileRepository above): with no repository, TransportKind.
    // TLS_TCP simply never enters [supportedKinds] below - REALITY's own
    // behavior is completely unaffected by this param's presence.
    private val xrayTlsProfileRepository: XrayTlsProfileRepository? = null,
    // B13 (2026-08-30 audit item 5 fix) - the ONE authoritative
    // endpoint-aware lookup buildTransportConfig() below actually resolves
    // XRAY_REALITY/TLS_TCP repositories through - see that function's own
    // docs. Defaults to a single-entry resolver wrapping [xrayProfileRepository]/
    // [xrayTlsProfileRepository] under the one real production endpoint id,
    // so EVERY pre-existing call site (real or test) that only ever wired
    // the flat repository param - which is every call site before this
    // fix - is byte-for-byte unaffected: `pendingConnectEndpointId` also
    // defaults to the same production endpoint id, so the default resolver
    // always resolves correctly for them. A caller that explicitly wires
    // [xrayProfileRepositoryResolver] (the composition root, going forward)
    // gets genuine per-endpoint selection instead.
    private val xrayProfileRepositoryResolver: XrayProfileRepositoryResolver? = xrayProfileRepository?.let { repo ->
        XrayProfileRepositoryResolver { id -> if (id == EndpointId(ProductionGateway.ID)) repo else null }
    },
    private val xrayTlsProfileRepositoryResolver: XrayTlsProfileRepositoryResolver? = xrayTlsProfileRepository?.let { repo ->
        XrayTlsProfileRepositoryResolver { id -> if (id == EndpointId(ProductionGateway.ID)) repo else null }
    },
    // B13 - additive, defaults to null (same reasoning as connectionOutcomeStore
    // above): with any of the three below missing, recordPathHistory() is a
    // no-op - real live-wiring is opt-in per the SAME "no wiring, no
    // behavior" seam every other optional collaborator in this class already
    // uses. When all three ARE wired (MainViewModel.Factory passes the SAME
    // PathHistoryStore/NetworkFingerprintKeyProvider instances
    // reachabilityDiagnostics() already reads - never a second, independent
    // pair), this becomes the FIRST real writer into PathHistoryStore - see
    // recordPathHistory's own docs for the "authoritative outcome only"
    // discipline it follows.
    private val pathHistoryStore: PathHistoryStore? = null,
    private val fingerprintKeyProvider: NetworkFingerprintKeyProvider? = null,
    // A supplier, not a StateFlow, so this controller never needs its own
    // subscription/collector - it reads whatever the CURRENT network profile
    // is only at the exact moment an authoritative outcome is being recorded
    // (same "read fresh, never cached" discipline gatewayConfigurationRepository.get()
    // already uses elsewhere in this class).
    private val networkProfileProvider: (() -> NetworkProfile)? = null,
) {
    private companion object {
        // B8B3D - "small bounded startup window" per the task's own wording.
        const val HANDSHAKE_TIMEOUT_MS = 8_000L
        const val HANDSHAKE_POLL_INTERVAL_MS = 500L
    }

    // B8I5/B8I6/B8O2 - the kinds this controller instance can actually build
    // a TransportConfig for (see buildTransportConfig's own `when`) -
    // AMNEZIA_WG always; XRAY_REALITY/TLS_TCP only when their own real
    // profile repository was wired (see those params' own docs). A resolved
    // kind outside this set is refused in connect() BEFORE the active
    // transport is ever switched or touched - no permission request, no
    // observer attach.
    private val supportedKinds: Set<TransportKind> = buildSet {
        add(TransportKind.AMNEZIA_WG)
        // B13 - also true whenever a resolver was wired directly (a future
        // composition root that never bothers with the legacy flat field) -
        // "is Xray configured at all for this controller instance" must not
        // go false just because the flat field is absent.
        if (xrayProfileRepository != null || xrayProfileRepositoryResolver != null) add(TransportKind.XRAY_REALITY)
        if (xrayTlsProfileRepository != null || xrayTlsProfileRepositoryResolver != null) add(TransportKind.TLS_TCP)
    }

    // B8O3 - the kind CURRENTLY ACTUALLY RUNNING (see [isRunningTransportState]
    // for the exact states that count as "running") - never a merely
    // attempted/selected/hypothetical one. Set/cleared ONLY by [setState],
    // the ONE place [_state] itself ever changes (see that function's own
    // docs) - so this can never drift out of sync with what [state] reports.
    private val _currentTransportKind = MutableStateFlow<TransportKind?>(null)
    val currentTransportKind: StateFlow<TransportKind?> = _currentTransportKind.asStateFlow()

    private val connectMutex = Mutex()

    private val _state = MutableStateFlow<TransportState>(TransportState.Disconnected)
    val state: StateFlow<TransportState> = _state.asStateFlow()

    /**
     * B8O3 - the ONE place [_state] is ever assigned (every direct
     * `_state.value = ...` call site in this class has been replaced with
     * this function) - centralized specifically so [_currentTransportKind]
     * can never fall out of sync with [state]: whichever path changes the
     * visible state (a real transport event forwarded by
     * [switchActiveTransport]'s own collector, a preflight rejection, a
     * precondition failure inside [doConnectAttempt], a backend/runtime
     * failure, or the reconnect loop) always goes through here. Preserves
     * the "attempted/selected transport" ([pendingConnectKind]) vs
     * "actually running transport" ([currentTransportKind]) distinction the
     * diagnostics UI depends on (see that field's own docs) - a permission
     * denial, a configuration failure, or any other terminal [TransportState.Error]
     * always clears [currentTransportKind] back to null in the SAME
     * assignment that sets the visible error state, never a separate/
     * possibly-missed step.
     */
    private fun setState(newState: TransportState) {
        _state.value = newState
        _currentTransportKind.value = if (isRunningTransportState(newState)) pendingConnectKind else null
    }

    private val _events = MutableSharedFlow<ControllerEvent>(extraBufferCapacity = 1)
    val events: SharedFlow<ControllerEvent> = _events

    // B8H - the AppRoutingPolicy actually baked into the CURRENTLY ACTIVE
    // VpnService interface, i.e. what doConnectAttempt() last successfully
    // handed to transport.connect() - never the merely-saved policy (see
    // appRoutingPolicyStore, which is read fresh but NOT reflected here
    // until the next real connect()). null whenever no session exists.
    // reconnectLoop() NEVER writes this - per B8G1's own "Break-before-make"
    // docs it never rebuilds the tunnel at all, so the policy an automatic
    // recovery cycle preserves is simply whatever this already says.
    private val _appliedRoutingPolicy = MutableStateFlow<AppRoutingPolicy?>(null)
    val appliedRoutingPolicy: StateFlow<AppRoutingPolicy?> = _appliedRoutingPolicy.asStateFlow()

    @Volatile private var userInitiatedDisconnect = true
    private var reconnectJob: Job? = null

    // B8I4 - the kind of the resolution the CURRENT/most recent connect()
    // attempt validated (see connect() below) - defaults to this
    // controller's own constructor-owned transport, so onVpnPermissionResult
    // resumes the SAME attempt after a permission prompt round-trip rather
    // than silently reverting to a hardcoded assumption. Never read/written
    // outside connect()/onVpnPermissionResult, both always called under
    // connectMutex - see doConnectAttempt's own "caller must hold the mutex" note.
    private var pendingConnectKind: TransportKind = transport.kind

    // B13 - the endpoint THIS attempt (or the most recent one) targets - the
    // SAME "which candidate is this attempt for" tracking [pendingConnectKind]
    // already provides, extended to the endpoint axis. Defaults to the one
    // real production endpoint so every pre-B13 caller (including every
    // existing test that never passes a Resolution.Resolved with an explicit
    // endpointId) is byte-for-byte unaffected. Never hardcoded at the
    // recording call sites below - see recordConnectionOutcome/recordPathHistory's
    // own docs for why this field, not a literal, is what they read.
    private var pendingConnectEndpointId: EndpointId = EndpointId(ProductionGateway.ID)

    // B16 - the PINNED GatewayConfigSnapshot for the CURRENT/most recent
    // connect() attempt, when [connect]'s resolved value carried one (an
    // automatic-gateway-selection candidate - see
    // TransportOrchestrator.Resolution.Resolved's own docs). null for every
    // manual-mode attempt (byte-for-byte pre-B16 behavior: doConnectAttempt
    // falls back to reading [gatewayConfigurationRepository] fresh - see
    // [resolveGatewayConfiguration]'s own docs). Read/written only from
    // connect()/disconnect()/doConnectAttempt, all under connectMutex - same
    // discipline as [pendingConnectKind]/[pendingConnectEndpointId].
    private var pendingConnectConfig: net.pocvpn.client.vpn.config.GatewayConfigSnapshot? = null

    // B8I5 - the ONE active transport instance every lifecycle operation
    // (state observation, connect, disconnect, permission resume, stats
    // polling, handshake detection, shutdown) actually targets - never the
    // fixed constructor `transport` directly (that field now exists only to
    // seed this and to build the no-arg connect() default). Starts as
    // `transport`; connect() re-points it via switchActiveTransport() only
    // when a NEW resolved instance differs from the current one. Read/written
    // only from connect() (under connectMutex) and switchActiveTransport()
    // (called only from connect(), same lock) - never concurrently.
    private var activeTransport: VpnTransport = transport

    // B8I5 - the background collector currently observing activeTransport's
    // observeState(). Exactly one is ever running at a time - switching
    // active transports cancels this before starting a new one (see
    // switchActiveTransport) so two collectors can never mutate _state
    // concurrently.
    private var activeObserverJob: Job? = null

    // Guards against a startup race: observeState() is a hot/replaying flow, so
    // whenever our collector coroutine actually gets scheduled to start, its
    // first emission is just a replay of the transport's CURRENT (possibly
    // stale) state - not a new transition. If a permission/gateway-config
    // check set an error state directly (without ever touching the transport)
    // before that replay is collected, we must not let it clobber that error.
    // Once we've actually invoked the (active) transport at least once, every
    // further emission is a genuine transition and is always forwarded. Reset
    // to false whenever switchActiveTransport() attaches a genuinely NEW
    // instance (see that function's own docs) - the exact same "ignore the
    // replay" reasoning applies fresh to that instance's own hot flow.
    @Volatile private var hasTouchedTransport = false

    init {
        switchActiveTransport(transport)
        reconnectManager.start(
            onNetworkLost = { handleNetworkLost() },
            onNetworkAvailable = { /* reconnect loop polls isNetworkAvailable() on its own cadence */ },
        )
    }

    /**
     * B8I5 - the ONE place the active transport instance changes. A no-op
     * when [newTransport] is already the active instance AND its collector
     * is still running (the common/default case: every existing caller that
     * always resolves the SAME constructor-owned transport hits this branch
     * forever after the first call, so this is byte-for-byte the pre-B8I5
     * single-lifetime-collector behavior for that case).
     *
     * Otherwise: cancels the PREVIOUS active transport's collector FIRST,
     * then starts exactly one new collector against [newTransport] - never
     * both running at once. The collector itself ALSO checks
     * `newTransport !== activeTransport` on every emission (not just at
     * attach time) as a second, redundant guard against a genuinely
     * in-flight emission from the old transport's hot flow winning a race
     * against cancellation (cancel() takes effect at the next suspension
     * point, not necessarily synchronously) - see class docs' "stale events
     * must not overwrite current state" requirement.
     */
    private fun switchActiveTransport(newTransport: VpnTransport) {
        if (newTransport === activeTransport && activeObserverJob?.isActive == true) return
        activeObserverJob?.cancel()
        activeTransport = newTransport
        hasTouchedTransport = false
        activeObserverJob = scope.launch {
            newTransport.observeState().collect { transportState ->
                if (!hasTouchedTransport) return@collect
                if (newTransport !== activeTransport) return@collect
                // While a reconnect cycle owns the visible state (Reconnecting/backoff),
                // don't let a transient Disconnected from an internal retry attempt
                // flicker the UI back to plain Disconnected.
                if (reconnectJob?.isActive != true) {
                    setState(transportState)
                }
                diagnostics.updateTransportState(_state.value)
            }
        }
    }

    fun gatewayStatus(): GatewayConfiguration = resolveGatewayConfiguration()

    /**
     * B16 - THE one place a real connect attempt's [GatewayConfiguration] is
     * resolved, for BOTH the actual tunnel-build path (doConnectAttempt) and
     * diagnostics (gatewayStatus()) - guaranteeing they can never disagree.
     * When [pendingConnectConfig] is set (an automatic-gateway-selection
     * candidate's own already-resolved snapshot - see that field's own
     * docs), it is validated via the SAME [net.pocvpn.client.vpn.config.GatewayConfigSnapshotValidator]
     * a manual [gatewayConfigurationRepository] uses internally, but the
     * repository itself - and therefore SelectedGatewayStore/
     * ProductionGatewayCatalog/ClientTunnelIdentityStore - is never
     * consulted again: this is the pinned candidate identity's "exact
     * GatewayConfigSnapshot", not a fresh re-resolution. Manual mode
     * (pendingConnectConfig always null) falls through to
     * [gatewayConfigurationRepository] exactly as every pre-B16 call site did.
     */
    private fun resolveGatewayConfiguration(): GatewayConfiguration =
        pendingConnectConfig?.let { net.pocvpn.client.vpn.config.GatewayConfigSnapshotValidator.validate(it) }
            ?: gatewayConfigurationRepository.get()

    /**
     * B8I2 - Smart Connect preflight (MainViewModel.connect()) rejected
     * BEFORE this controller was ever touched: transport.connect() was never
     * called, transport.preparePermissionIntent() was never called, no VPN
     * permission was requested, no VPN service was started. Reuses the exact
     * same truthful-state-and-diagnostics pattern doConnectAttempt() itself
     * already uses for its own precondition failures (e.g.
     * GatewayConfiguration.Missing) - a fail-closed decision is surfaced
     * exactly like every other precondition failure, never a second/silent
     * failure mode.
     */
    fun rejectPreflight(error: VpnError, message: String) {
        diagnostics.recordError(error)
        setState(TransportState.Error(message))
    }

    /** Call once, early, from the UI layer to know whether a permission prompt will be needed. */
    fun permissionIntentIfNeeded(): Intent? = transport.preparePermissionIntent()

    /**
     * B8I5 - the ONE per-attempt execution boundary: [resolved] is what an
     * upstream caller (MainViewModel, via TransportOrchestrator - the ONE
     * decision authority remains SmartConnectCandidateSelector, never this
     * class) already resolved for THIS attempt. Defaults to this
     * controller's own constructor-owned transport/kind, so every EXISTING
     * caller (including every pre-B8I4 test) is byte-for-byte unaffected.
     *
     * [resolved.kind] must be one of [supportedKinds] (AMNEZIA_WG always;
     * XRAY_REALITY only when a real Xray profile repository was wired - see
     * that param's own docs) - checked BEFORE the active transport is
     * switched or touched at all, so an unsupported kind never requests VPN
     * permission or attaches an observer. When [resolved.kind] IS supported,
     * [resolved.transport]
     * becomes THE active transport for this attempt/session via
     * switchActiveTransport() - a genuinely different instance is adopted
     * (with safe detach/attach, never a silent substitute or a second
     * concurrent collector - see that function's own docs), it is never
     * refused merely for not being the constructor-owned instance.
     */
    suspend fun connect(
        resolved: TransportOrchestrator.Resolution.Resolved = TransportOrchestrator.Resolution.Resolved(transport, transport.kind),
    ) {
        if (!connectMutex.tryLock()) {
            diagnostics.recordError(VpnError.AlreadyInProgress)
            return
        }
        try {
            if (_state.value is TransportState.Connecting || _state.value is TransportState.Connected) {
                return
            }
            if (resolved.kind !in supportedKinds) {
                rejectPreflight(
                    VpnError.UnsupportedTransportSelected(resolved.kind.name),
                    "Resolved transport (${resolved.kind}) is not supported by this VpnController yet",
                )
                return
            }
            switchActiveTransport(resolved.transport)
            // B8O3 fix - pendingConnectKind records which kind THIS attempt
            // is for (needed by onVpnPermissionResult's resume, and by
            // setState() to attribute a later running state to the right
            // kind), but is NOT itself "the current transport" - see
            // currentTransportKind's own docs. It must never be set here:
            // permission has not been requested yet, let alone granted, and
            // no real connect attempt has been made.
            pendingConnectKind = resolved.kind
            pendingConnectEndpointId = resolved.endpointId
            // B16 - resolved exactly once, here, before permission is even
            // requested - never re-derived later in this same attempt (see
            // [resolveGatewayConfiguration]'s own docs). null for manual mode.
            pendingConnectConfig = resolved.gatewayConfigSnapshot
            userInitiatedDisconnect = false
            cancelReconnectLocked()

            val permissionIntent = activeTransport.preparePermissionIntent()
            if (permissionIntent != null) {
                _events.tryEmit(ControllerEvent.RequestVpnPermission(permissionIntent))
                return
            }
            diagnostics.updatePermission(true)
            doConnectAttempt(resolved.kind)
        } finally {
            connectMutex.unlock()
        }
    }

    /**
     * Call from the Activity's permission-result callback. Resumes the SAME
     * attempt connect() deferred: [activeTransport] was already switched (if
     * needed) before the permission request was emitted, and [pendingConnectKind]
     * is the SAME kind validated then - both the resolved instance AND kind
     * are preserved across this round-trip, never re-derived here.
     */
    suspend fun onVpnPermissionResult(granted: Boolean) {
        diagnostics.updatePermission(granted)
        if (!granted) {
            diagnostics.recordError(VpnError.PermissionDenied)
            setState(TransportState.Error("VPN permission denied"))
            // B16 - a denied prompt abandons this attempt; its pinned
            // candidate config must not linger and be reported by
            // gatewayStatus() for a request nothing is acting on any more.
            pendingConnectConfig = null
            return
        }
        connectMutex.withLock { doConnectAttempt(pendingConnectKind) }
    }

    suspend fun disconnect() {
        connectMutex.withLock {
            if (_state.value is TransportState.Disconnected || _state.value is TransportState.Disconnecting) {
                return@withLock
            }
            userInitiatedDisconnect = true
            cancelReconnectLocked()
            hasTouchedTransport = true
            activeTransport.disconnect()
            // B8H - the interface this policy was baked into is gone; the
            // NEXT connect() re-reads appRoutingPolicyStore fresh (see
            // doConnectAttempt), which is what actually applies a changed
            // saved policy - never an automatic mid-session rebuild.
            _appliedRoutingPolicy.value = null
            // B8O3 - nothing is running/attempted any more.
            _currentTransportKind.value = null
            // B16 - a completed/abandoned attempt's pinned candidate config
            // must not linger and be silently reused (or shown by
            // gatewayStatus()) for whatever connect() request comes next -
            // the NEXT connect() always sets this fresh (possibly null,
            // for manual mode) before it is ever read again.
            pendingConnectConfig = null
        }
    }

    /**
     * Caller must already hold connectMutex. Returns true only if
     * transport.connect() completed without throwing. The reconnect loop
     * relies on this return value - NOT on re-reading `_state`, which is
     * only updated asynchronously by the background collector and would
     * race against this same call.
     */
    private suspend fun doConnectAttempt(kind: TransportKind): Boolean {
        // B16 - resolves the SAME pinned candidate config gatewayStatus()
        // reports (see resolveGatewayConfiguration's own docs) - never a
        // second, independent read of gatewayConfigurationRepository once a
        // candidate has been pinned for this attempt.
        when (val config = resolveGatewayConfiguration()) {
            is GatewayConfiguration.Missing -> {
                diagnostics.recordError(VpnError.GatewayConfigurationMissing)
                diagnostics.updateGateway(configured = false, endpointDisplay = "NOT CONFIGURED")
                setState(TransportState.Error("Gateway configuration is not configured. Real VPS required."))
                return false
            }
            is GatewayConfiguration.Invalid -> {
                diagnostics.recordError(VpnError.InvalidGatewayConfiguration(config.reason))
                setState(TransportState.Error("Invalid gateway configuration: ${config.reason}"))
                return false
            }
            is GatewayConfiguration.Configured -> {
                diagnostics.updateGateway(
                    configured = true,
                    endpointDisplay = "${config.endpointHost}:${config.endpointPort}",
                )
                // B8H - read fresh on every real connect() attempt, exactly
                // like gatewayConfigurationRepository.get() above - this is
                // what makes a policy the user saved while disconnected (or
                // while a PRIOR session was up, see class docs' "Reconnect
                // to apply changes" note) take effect on THIS attempt.
                // reconnectLoop() never reaches this function at all, so an
                // automatic recovery cycle can never pick up a newer saved
                // policy mid-session - see appliedRoutingPolicy's own docs.
                val routingPolicy = appRoutingPolicyStore.read()
                val routingResolution = resolveAppRoutingLists(routingPolicy, installedPackageChecker::isInstalled)
                // B8I6 - split tunneling is an AMNEZIA_WG-only concept today
                // (NovaXrayVpnService's own plan is ALL_APPS-only - see its
                // docs); a leftover VPN_ONLY_SELECTED-with-zero-installed-apps
                // policy must not block an XRAY_REALITY attempt that will
                // never even read appRoutingLists.
                if (kind == TransportKind.AMNEZIA_WG && routingResolution is EffectiveRoutingResult.NoAppsSelected) {
                    diagnostics.recordError(VpnError.SplitTunnelingNoAppsSelected)
                    setState(TransportState.Error("VPN-only mode has no apps selected - select at least one app"))
                    return false
                }
                val appRoutingLists = (routingResolution as? EffectiveRoutingResult.Apply)?.lists ?: AppRoutingLists.AllApps
                val transportConfig = try {
                    buildTransportConfig(kind, config, appRoutingLists)
                } catch (e: Exception) {
                    diagnostics.recordError(VpnError.ConfigurationMappingFailure(e.javaClass.simpleName))
                    setState(TransportState.Error("Failed to build tunnel configuration"))
                    return false
                }
                // B8B3D: the attempt's own start time - a handshake is only
                // trusted as proof of THIS attempt's success if it is at or
                // after this timestamp, never a stale one from a prior
                // session (see class docs' session-semantics note). B8I:
                // declared outside the try below (not inside it) so it is
                // also visible to the catch branch's own outcome recording.
                val attemptStartEpochMillis = System.currentTimeMillis()
                return try {
                    hasTouchedTransport = true
                    activeTransport.connect(transportConfig)
                    // B8H - the VpnService interface now reflects
                    // routingPolicy (whether or not a handshake follows) -
                    // only a thrown connect() (caught below) means no
                    // interface was actually built, so this is set here and
                    // ONLY here, never in the catch branch.
                    _appliedRoutingPolicy.value = routingPolicy
                    if (kind == TransportKind.AMNEZIA_WG) {
                        // Interface-up/TX>0 alone is deliberately NOT treated as
                        // success here - see awaitFreshHandshake's own docs. Set
                        // directly (not left to the background collector) for the
                        // same reason the prior direct-set comment explained: we
                        // know unambiguously, right here, whether THIS attempt
                        // produced a real handshake.
                        if (awaitFreshHandshake(attemptStartEpochMillis)) {
                            recordCurrentStats()
                            setState(TransportState.Connected)
                            recordConnectionOutcome(ConnectionOutcomeResult.SUCCESS, ConnectionErrorCategory.NONE, attemptStartEpochMillis)
                            recordPathHistory(success = true, kind = kind, endpointId = pendingConnectEndpointId, nowEpochMillis = System.currentTimeMillis())
                            true
                        } else {
                            diagnostics.recordError(VpnError.HandshakeTimeout)
                            // Deliberately does NOT call transport.disconnect() -
                            // failover/kill-switch policy is out of scope for this
                            // slice (see class docs). The interface may still be
                            // up; only the user-visible state reflects the truth.
                            setState(TransportState.HandshakeFailed)
                            recordConnectionOutcome(ConnectionOutcomeResult.FAILURE, ConnectionErrorCategory.HANDSHAKE_TIMEOUT, attemptStartEpochMillis)
                            recordPathHistory(success = false, kind = kind, endpointId = pendingConnectEndpointId, nowEpochMillis = System.currentTimeMillis())
                            false
                        }
                    } else {
                        // B8I6 - XRAY_REALITY (the only other kind reaching
                        // here) has no proven handshake-evidence channel yet -
                        // VlessRealityTransport's own observeState() never
                        // reports Connected without one (see its own docs).
                        // Never fabricate a stronger success signal than the
                        // transport itself provides: no awaitFreshHandshake
                        // wait, no forced Connected here - the ALREADY-
                        // attached active-transport collector (switchActiveTransport,
                        // called earlier in connect()) is what surfaces
                        // whatever _state genuinely becomes. No
                        // ConnectionOutcome recording either - that model is
                        // AWG-handshake-specific (see recordConnectionOutcome's
                        // own docs) and does not yet have an Xray equivalent -
                        // see handleNetworkLost's own docs for why this also
                        // means no automatic reconnect for this kind.
                        true
                    }
                } catch (e: Exception) {
                    diagnostics.recordError(VpnError.BackendStartFailure(e.javaClass.simpleName))
                    setState(TransportState.Error("Backend failed to start"))
                    recordConnectionOutcome(ConnectionOutcomeResult.FAILURE, ConnectionErrorCategory.BACKEND_START_FAILURE, attemptStartEpochMillis)
                    recordPathHistory(success = false, kind = kind, endpointId = pendingConnectEndpointId, nowEpochMillis = System.currentTimeMillis())
                    false
                }
            }
        }
    }

    /**
     * B8I4/B8I6 - the generic per-attempt execution seam: which TransportConfig
     * SHAPE to build is dispatched on [kind]. AMNEZIA_WG builds from the AWG
     * [config]/[appRoutingLists] exactly as before (unchanged). XRAY_REALITY
     * builds from the REAL persisted/provisioned Xray profile via the
     * EXISTING [XrayRuntimeResolver] against the repository resolved for
     * [pendingConnectEndpointId] - the SAME endpointId this exact attempt
     * carried all the way from `GatewayCandidate.id` (see that field's own
     * docs) - never [xrayProfileRepository] read unconditionally. It never
     * reads [config]/[appRoutingLists] (those are AWG-shaped
     * GatewayConfiguration fields; fabricating an Xray config from them
     * would be exactly the "fake config" this slice must not do). A missing/
     * corrupt/invalid profile, OR an endpoint the resolver has no repository
     * for at all (B13 - never silently substituted with a different
     * endpoint's repository, never defaulted to `ProductionGateway.ID`),
     * throws [XrayProfileNotReadyException] (message is the SAME non-secret
     * reason XrayRuntimeResolver already produces, plus - for the
     * unknown-endpoint case - the endpoint id itself, which is already
     * non-secret per EndpointId's own docs; never a uuid/key/short_id),
     * which doConnectAttempt's existing try/catch around this call already
     * turns into the SAME ConfigurationMappingFailure fail-closed path every
     * other malformed-config case uses (no new failure mode, no fallback to
     * AWG). Any other kind still throws [UnsupportedOperationException] -
     * structurally unreachable via the public API since connect() already
     * refuses a kind outside [supportedKinds] before ever reaching here.
     */
    private suspend fun buildTransportConfig(kind: TransportKind, config: GatewayConfiguration.Configured, appRoutingLists: AppRoutingLists): TransportConfig =
        when (kind) {
            TransportKind.AMNEZIA_WG -> {
                val privateKey = clientKeyRepository.getPrivateKeyForTunnel()
                val awgConfig = AwgConfig(
                    privateKeyBase64 = privateKey,
                    localAddresses = listOf("${config.clientTunnelIp}/32"),
                    dnsServers = config.dnsServers,
                    profile = config.profile,
                    includedApplications = appRoutingLists.includedApplications,
                    excludedApplications = appRoutingLists.excludedApplications,
                    peer = AwgPeer(
                        publicKeyBase64 = config.serverPublicKeyBase64,
                        endpointHost = config.endpointHost,
                        endpointPort = config.endpointPort,
                        allowedIps = config.allowedIps,
                        persistentKeepaliveSeconds = config.persistentKeepaliveSeconds,
                    ),
                )
                TransportConfig.Awg(awgConfig)
            }
            TransportKind.XRAY_REALITY -> {
                // B13 (audit item 5 fix) - resolved by the CURRENT attempt's
                // real endpointId, never the flat field directly. Unreachable
                // unless xrayProfileRepositoryResolver != null (that's the
                // only way XRAY_REALITY ever enters supportedKinds) - the
                // null-check here is defensive, not a real code path. A
                // resolver returning null for THIS endpoint fails closed with
                // the endpoint id named explicitly, never a silent fallback
                // to whatever the production endpoint's repository happens
                // to be.
                val resolver = xrayProfileRepositoryResolver
                    ?: throw XrayProfileNotReadyException("Xray profile repository not wired")
                val repository = resolver.resolve(pendingConnectEndpointId)
                    ?: throw XrayProfileNotReadyException("no Xray profile repository configured for endpoint ${pendingConnectEndpointId.value}")
                when (val resolution = XrayRuntimeResolver.resolve(repository)) {
                    is XrayRuntimeResolution.Rejected -> throw XrayProfileNotReadyException(resolution.reason)
                    is XrayRuntimeResolution.Ready -> TransportConfig.Xray(resolution.config, endpointId = pendingConnectEndpointId)
                }
            }
            TransportKind.TLS_TCP -> {
                // B8O2/B13 - same reasoning as XRAY_REALITY above, against the
                // TLS profile repository resolver instead. Unreachable
                // unless xrayTlsProfileRepositoryResolver != null.
                val resolver = xrayTlsProfileRepositoryResolver
                    ?: throw XrayProfileNotReadyException("Xray TLS profile repository not wired")
                val repository = resolver.resolve(pendingConnectEndpointId)
                    ?: throw XrayProfileNotReadyException("no Xray TLS profile repository configured for endpoint ${pendingConnectEndpointId.value}")
                when (val resolution = XrayRuntimeResolver.resolveTls(repository)) {
                    is XrayTlsRuntimeResolution.Rejected -> throw XrayProfileNotReadyException(resolution.reason)
                    is XrayTlsRuntimeResolution.Ready -> TransportConfig.XrayTls(resolution.config, endpointId = pendingConnectEndpointId)
                }
            }
            else -> throw UnsupportedOperationException("no TransportConfig builder for $kind yet")
        }

    /**
     * B8B3D - the authoritative startup-success signal: a REAL AWG handshake
     * for THIS connection attempt, observed via the existing
     * VpnTransport.stats() boundary (AmneziaWgTransport.stats(), backed by
     * Backend.getLastHandshake/getStatistics - no second polling system, no
     * new state-machine framework). Polls at a fixed virtual-time interval,
     * bounded by HANDSHAKE_TIMEOUT_MS total - purely delay()-driven (no
     * wall-clock deadline check), so it is exactly as fast-forwardable under
     * kotlinx-coroutines-test's virtual time as the existing reconnect
     * backoff loop already is.
     *
     * A handshake only counts if its timestamp is >= attemptStartEpochMillis -
     * a stale handshake left over from a previous session can never satisfy
     * a NEW attempt. This is also exactly why an established CONNECTED
     * session is never re-evaluated later: this function runs ONCE per
     * connect() attempt and is never invoked again while already connected -
     * ordinary handshake-age growth during an idle period never reaches this
     * check at all.
     *
     * A transport that cannot report stats at all (Unsupported/NotImplemented -
     * i.e. there is nothing to observe) is trusted on its own connect()
     * success, exactly like pre-B8B3D behavior - this check can only make a
     * transport's reported success LESS trusted when it has real evidence to
     * evaluate, never penalize a transport that offers none.
     */
    private suspend fun awaitFreshHandshake(attemptStartEpochMillis: Long): Boolean {
        val maxPolls = (HANDSHAKE_TIMEOUT_MS / HANDSHAKE_POLL_INTERVAL_MS).toInt()
        for (pollIndex in 0..maxPolls) {
            when (val stats = activeTransport.stats()) {
                is TransportStats.Counters -> {
                    if (isFreshHandshake(stats.lastHandshakeEpochMillis, attemptStartEpochMillis)) {
                        return true
                    }
                }
                TransportStats.Unsupported, TransportStats.NotImplemented -> return true
                TransportStats.Unavailable -> Unit
            }
            if (pollIndex < maxPolls) delay(HANDSHAKE_POLL_INTERVAL_MS)
        }
        return false
    }

    private suspend fun recordCurrentStats() {
        val stats = activeTransport.stats()
        if (stats is TransportStats.Counters) {
            diagnostics.updateStats(stats.lastHandshakeEpochMillis, stats.bytesReceived, stats.bytesSent)
        }
    }

    /**
     * B8I - no-op unless connectionOutcomeStore was actually wired (see its
     * own additive-default docs). [attemptStartEpochMillis] is always the
     * REAL start of the connection/recovery attempt this outcome reports on
     * - never a fabricated/backfilled value - so [handshakeDurationMs] is a
     * genuine measured duration, exactly the same real-time-vs-virtual-time
     * split awaitFreshHandshake's own docs already establish elsewhere in
     * this class. Called ONLY from real evidence (a completed connect()
     * attempt or an exhausted reconnect cycle) - never speculatively.
     */
    private fun recordConnectionOutcome(
        result: ConnectionOutcomeResult,
        errorCategory: ConnectionErrorCategory,
        attemptStartEpochMillis: Long,
    ) {
        val store = connectionOutcomeStore ?: return
        val nowEpochMillis = System.currentTimeMillis()
        store.record(
            ConnectionOutcome(
                transport = activeTransport.kind,
                // B13 - the REAL endpoint this attempt targeted (see
                // pendingConnectEndpointId's own docs), never a hardcoded
                // literal - it merely defaults to the same production
                // endpoint ID this constant always named before this slice,
                // so single-gateway production behavior is unchanged.
                gatewayId = pendingConnectEndpointId.value,
                result = result,
                handshakeDurationMs = nowEpochMillis - attemptStartEpochMillis,
                errorCategory = errorCategory,
                timestampEpochMillis = nowEpochMillis,
            ),
        )
    }

    /**
     * B13 - the FIRST real writer into PathHistoryStore (previously
     * write-side-unused since B11 - see docs/B12_ENDPOINT_IDENTITY_AUDIT.md's
     * own note on why this was deliberately deferred). No-op unless all
     * three of [pathHistoryStore]/[fingerprintKeyProvider]/[networkProfileProvider]
     * are wired (same additive seam as every other optional collaborator in
     * this class). Called ONLY from the exact same authoritative-outcome
     * call sites [recordConnectionOutcome] already uses - never from a
     * ControllerEvent, never for a merely-attempted/Connecting state, never
     * twice for the same real attempt (see each call site's own docs for why
     * that discipline already holds for ConnectionOutcome, reused verbatim
     * here rather than inventing a second recording model). [kind]/[endpointId]
     * are threaded from the caller rather than read from mutable controller
     * state, so a reconnect-exhaustion record (recorded against the ORIGINAL
     * attempt's kind/endpoint, per reconnectLoop()'s own "one record for the
     * whole cycle" model) can never accidentally pick up a DIFFERENT pending
     * attempt's kind/endpoint if one raced in in the meantime.
     */
    private fun recordPathHistory(success: Boolean, kind: TransportKind, endpointId: EndpointId, nowEpochMillis: Long) {
        val store = pathHistoryStore ?: return
        val keyProvider = fingerprintKeyProvider ?: return
        val profileProvider = networkProfileProvider ?: return
        val profile = profileProvider()
        val fingerprint = NetworkFingerprinter.fingerprint(
            CoarseNetworkSignals(profile.type, profile.dnsServerAddresses),
            keyProvider.keyBytes(),
        )
        store.record(fingerprint, endpointId, kind, success, nowEpochMillis)
    }

    /**
     * B8I5/B8I6 - reconnect (this whole automatic-recovery polling
     * mechanism) stays AWG-only, explicitly: it only ever triggers when
     * `_state.value is Connected`, which today is set ONLY by
     * doConnectAttempt()'s AMNEZIA_WG branch (see its own docs) -
     * XRAY_REALITY's branch there deliberately never forces Connected
     * (VlessRealityTransport has no proven handshake-evidence channel yet),
     * so this can structurally never engage for it. No generic "retry" is
     * invented here for a kind that doesn't support it - a future Xray
     * transport that DOES earn a real Connected signal would need its own
     * deliberate decision about whether polling-for-a-fresh-handshake even
     * makes sense for that protocol, never assumed automatically by reusing
     * this loop as-is.
     */
    private fun handleNetworkLost() {
        if (userInitiatedDisconnect) return
        if (_state.value !is TransportState.Connected) return
        diagnostics.updateNetworkType("unavailable")
        reconnectJob = scope.launch { reconnectLoop() }
    }

    /**
     * B8G1 - kill-switch fix: this loop NEVER calls transport.connect() (=
     * backend.setState(UP, config)) to "retry" - see the class doc's own
     * "Break-before-make" section for exactly why that would be
     * counterproductive. It only WAITS for the SAME already-established
     * tunnel to recover a fresh handshake on its own, polling via the exact
     * same awaitFreshHandshake() helper doConnectAttempt() uses for the
     * initial connect - reused verbatim, not reimplemented.
     *
     * reconnectionThresholdEpochMillis is captured ONCE, at the moment this
     * reconnect session begins - not recomputed per attempt - because the
     * underlying AmneziaWG tunnel keeps retrying handshakes entirely on its
     * own timeline (protocol-level retry backed by PersistentKeepalive, see
     * class docs), asynchronously to this loop's own polling cadence. A
     * per-attempt "now" threshold could miss a handshake that already
     * landed moments before this loop happened to check.
     */
    private suspend fun reconnectLoop() {
        var attempt = 0
        val reconnectionThresholdEpochMillis = System.currentTimeMillis()
        while (coroutineContext.isActive && !userInitiatedDisconnect) {
            attempt++
            diagnostics.updateReconnectAttempts(attempt)
            setState(TransportState.Reconnecting(attempt))

            if (attempt > ReconnectBackoff.MAX_ATTEMPTS) {
                diagnostics.recordError(VpnError.ReconnectExhausted)
                setState(TransportState.Error("Reconnect attempts exhausted"))
                // B8I - ONE outcome for the whole exhausted recovery cycle,
                // not one per backoff attempt - keeps the bounded history
                // meaningful instead of filling up with per-attempt noise.
                recordConnectionOutcome(ConnectionOutcomeResult.FAILURE, ConnectionErrorCategory.RECONNECT_EXHAUSTED, reconnectionThresholdEpochMillis)
                recordPathHistory(success = false, kind = pendingConnectKind, endpointId = pendingConnectEndpointId, nowEpochMillis = System.currentTimeMillis())
                return
            }

            delay(ReconnectBackoff.delayForAttempt(attempt))
            if (!coroutineContext.isActive || userInitiatedDisconnect) return

            if (!reconnectManager.isNetworkAvailable()) {
                continue // keep backing off until a network reappears
            }

            val recovered = connectMutex.withLock { awaitFreshHandshake(reconnectionThresholdEpochMillis) }
            if (recovered) {
                recordCurrentStats()
                setState(TransportState.Connected)
                diagnostics.updateReconnectAttempts(0)
                // B8I1 - OUTCOME OWNERSHIP: deliberately does NOT call
                // recordConnectionOutcome() here. The chosen model is: one
                // record per doConnectAttempt() (the initial SUCCESS/FAILURE)
                // plus one record if a recovery cycle exhausts (see the
                // RECONNECT_EXHAUSTED branch above) - a recovery that
                // succeeds before exhausting is not a second/duplicate
                // "connection" in this model, just the SAME session's
                // handshake coming back, so it produces no new outcome
                // record. This is the ONLY place in the codebase that
                // records outcomes for THIS controller/session - a future
                // TransportOrchestrator executing a decision must never add
                // a second, competing record for the same real attempt.
                return
            }
        }
    }

    /** Caller must already hold connectMutex. */
    private fun cancelReconnectLocked() {
        reconnectJob?.cancel()
        reconnectJob = null
    }

    /**
     * B8I5 - final teardown: stops network-loss observation AND cleans up
     * the active transport's observer/reconnect job explicitly, rather than
     * relying solely on `scope` being cancelled by the caller afterwards -
     * makes cleanup deterministic and independently testable. Not called
     * under connectMutex (this is a one-time terminal call, not a lifecycle
     * transition to serialize against another connect()/disconnect()).
     */
    fun shutdown() {
        reconnectManager.stop()
        reconnectJob?.cancel()
        activeObserverJob?.cancel()
    }
}

/**
 * B8I6 - the stored/provisioned Xray profile was absent, corrupted, or
 * failed structural validation (see XrayRuntimeResolver.Rejected's own
 * reason strings, which this message is always exactly one of) - never
 * carries a uuid/reality-public-key/short_id, only the same non-secret
 * reason XrayRuntimeResolver itself already produces.
 */
private class XrayProfileNotReadyException(reason: String) : Exception(reason)

/**
 * B8B3D - pure, file-scope (not a VpnController member) specifically so it
 * is directly unit-testable with concrete millisecond values, independent
 * of FakeVpnTransport/any transport double - the exact thing the seconds-
 * vs-milliseconds unit bug needed proving against (a value that is only
 * "fresh" if compared as milliseconds, not seconds).
 *
 * `handshakeEpochMillis` must already be real epoch MILLISECONDS - see
 * AmneziaWgTransport.stats()'s own docs for why it sources this from
 * Statistics.PeerStats.latestHandshakeEpochMillis(), never from the
 * seconds-valued Backend.getLastHandshake(). A null input (no handshake
 * observed, including a normalized 0/sentinel) is never fresh.
 */
internal fun isFreshHandshake(handshakeEpochMillis: Long?, attemptStartEpochMillis: Long): Boolean =
    handshakeEpochMillis != null && handshakeEpochMillis >= attemptStartEpochMillis

/**
 * B8O3 - pure, file-scope predicate (same reasoning as [isFreshHandshake]
 * above): which [TransportState]s count as "a transport is genuinely
 * running" for [VpnController.currentTransportKind] purposes. Deliberately
 * narrow - [TransportState.Connected] (a real, confirmed session) and
 * [TransportState.Reconnecting] (a previously-Connected session recovering
 * on its own, per this class's own "Break-before-make" docs - the interface
 * is still up throughout) - and nothing else. In particular
 * [TransportState.HandshakeFailed] is NOT running: the class's own docs
 * note the interface MAY still be up, but no confirmed working tunnel was
 * ever established for this attempt, so it must not be reported as the
 * current transport any more than [TransportState.Error] is.
 */
internal fun isRunningTransportState(state: TransportState): Boolean =
    state is TransportState.Connected || state is TransportState.Reconnecting
