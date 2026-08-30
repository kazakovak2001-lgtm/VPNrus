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
) {
    private companion object {
        // B8B3D - "small bounded startup window" per the task's own wording.
        const val HANDSHAKE_TIMEOUT_MS = 8_000L
        const val HANDSHAKE_POLL_INTERVAL_MS = 500L
    }

    private val connectMutex = Mutex()

    private val _state = MutableStateFlow<TransportState>(TransportState.Disconnected)
    val state: StateFlow<TransportState> = _state.asStateFlow()

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

    // Guards against a startup race: observeState() is a hot/replaying flow, so
    // whenever our collector coroutine actually gets scheduled to start, its
    // first emission is just a replay of the transport's CURRENT (possibly
    // stale) state - not a new transition. If a permission/gateway-config
    // check set an error state directly (without ever touching the transport)
    // before that replay is collected, we must not let it clobber that error.
    // Once we've actually invoked the transport at least once, every further
    // emission is a genuine transition and is always forwarded.
    @Volatile private var hasTouchedTransport = false

    init {
        scope.launch {
            transport.observeState().collect { transportState ->
                if (!hasTouchedTransport) return@collect
                // While a reconnect cycle owns the visible state (Reconnecting/backoff),
                // don't let a transient Disconnected from an internal retry attempt
                // flicker the UI back to plain Disconnected.
                if (reconnectJob?.isActive != true) {
                    _state.value = transportState
                }
                diagnostics.updateTransportState(_state.value)
            }
        }
        reconnectManager.start(
            onNetworkLost = { handleNetworkLost() },
            onNetworkAvailable = { /* reconnect loop polls isNetworkAvailable() on its own cadence */ },
        )
    }

    fun gatewayStatus(): GatewayConfiguration = gatewayConfigurationRepository.get()

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
        _state.value = TransportState.Error(message)
    }

    /** Call once, early, from the UI layer to know whether a permission prompt will be needed. */
    fun permissionIntentIfNeeded(): Intent? = transport.preparePermissionIntent()

    /**
     * B8I4 - the ONE per-attempt execution boundary: [resolved] is what an
     * upstream caller (MainViewModel, via TransportOrchestrator - the ONE
     * decision authority remains SmartConnectCandidateSelector, never this
     * class) already resolved for THIS attempt. Defaults to this
     * controller's own constructor-owned transport/kind, so every EXISTING
     * caller (including every pre-B8I4 test) is byte-for-byte unaffected.
     *
     * This no longer blindly assumes the constructor-owned transport is
     * what should run: [resolved] is validated against it first. A
     * DIFFERENT transport instance is refused, not silently substituted -
     * this controller's background observeState() collector (see init
     * block), disconnect(), and stats() polling are all wired to exactly
     * ONE transport instance for its whole lifetime; safely driving a
     * second, independent instance through the SAME lifecycle/state
     * machine would need a real redesign (multiple collectors, per-attempt
     * disconnect/stats routing) that is explicitly out of scope here - see
     * class docs' "avoid parallel state machines" and B8I5's own scope note.
     * [resolved.kind] then selects which TransportConfig shape
     * buildTransportConfig() below builds - today only AMNEZIA_WG has one;
     * any other kind fails closed via the EXISTING
     * ConfigurationMappingFailure path, never a new/parallel failure mode.
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
            // B8I4 - the ONE place this controller's actual execution
            // capability is checked: [resolved.transport] must be the exact
            // instance this controller owns (never a silent substitute -
            // see class docs on why a different instance can't be safely
            // driven yet), AND [resolved.kind] must be AMNEZIA_WG - the only
            // kind buildTransportConfig() below can actually build a config
            // for today. A resolved instance whose OWN .kind happens to
            // equal AMNEZIA_WG too would trivially satisfy an
            // instance-vs-its-own-kind check, so AMNEZIA_WG is compared
            // explicitly here, not merely resolved.kind == transport.kind.
            if (resolved.transport !== transport || resolved.kind != TransportKind.AMNEZIA_WG) {
                rejectPreflight(
                    VpnError.UnsupportedTransportSelected(resolved.kind.name),
                    "Resolved transport (${resolved.kind}) cannot be executed by this VpnController instance yet",
                )
                return
            }
            pendingConnectKind = resolved.kind
            userInitiatedDisconnect = false
            cancelReconnectLocked()

            val permissionIntent = transport.preparePermissionIntent()
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

    /** Call from the Activity's permission-result callback. */
    suspend fun onVpnPermissionResult(granted: Boolean) {
        diagnostics.updatePermission(granted)
        if (!granted) {
            diagnostics.recordError(VpnError.PermissionDenied)
            _state.value = TransportState.Error("VPN permission denied")
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
            transport.disconnect()
            // B8H - the interface this policy was baked into is gone; the
            // NEXT connect() re-reads appRoutingPolicyStore fresh (see
            // doConnectAttempt), which is what actually applies a changed
            // saved policy - never an automatic mid-session rebuild.
            _appliedRoutingPolicy.value = null
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
        when (val config = gatewayConfigurationRepository.get()) {
            is GatewayConfiguration.Missing -> {
                diagnostics.recordError(VpnError.GatewayConfigurationMissing)
                diagnostics.updateGateway(configured = false, endpointDisplay = "NOT CONFIGURED")
                _state.value = TransportState.Error("Gateway configuration is not configured. Real VPS required.")
                return false
            }
            is GatewayConfiguration.Invalid -> {
                diagnostics.recordError(VpnError.InvalidGatewayConfiguration(config.reason))
                _state.value = TransportState.Error("Invalid gateway configuration: ${config.reason}")
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
                if (routingResolution is EffectiveRoutingResult.NoAppsSelected) {
                    diagnostics.recordError(VpnError.SplitTunnelingNoAppsSelected)
                    _state.value = TransportState.Error("VPN-only mode has no apps selected - select at least one app")
                    return false
                }
                val appRoutingLists = (routingResolution as EffectiveRoutingResult.Apply).lists
                val transportConfig = try {
                    buildTransportConfig(kind, config, appRoutingLists)
                } catch (e: Exception) {
                    diagnostics.recordError(VpnError.ConfigurationMappingFailure(e.javaClass.simpleName))
                    _state.value = TransportState.Error("Failed to build tunnel configuration")
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
                    transport.connect(transportConfig)
                    // B8H - the VpnService interface now reflects
                    // routingPolicy (whether or not a handshake follows) -
                    // only a thrown connect() (caught below) means no
                    // interface was actually built, so this is set here and
                    // ONLY here, never in the catch branch.
                    _appliedRoutingPolicy.value = routingPolicy
                    // Interface-up/TX>0 alone is deliberately NOT treated as
                    // success here - see awaitFreshHandshake's own docs. Set
                    // directly (not left to the background collector) for the
                    // same reason the prior direct-set comment explained: we
                    // know unambiguously, right here, whether THIS attempt
                    // produced a real handshake.
                    if (awaitFreshHandshake(attemptStartEpochMillis)) {
                        recordCurrentStats()
                        _state.value = TransportState.Connected
                        recordConnectionOutcome(ConnectionOutcomeResult.SUCCESS, ConnectionErrorCategory.NONE, attemptStartEpochMillis)
                        true
                    } else {
                        diagnostics.recordError(VpnError.HandshakeTimeout)
                        // Deliberately does NOT call transport.disconnect() -
                        // failover/kill-switch policy is out of scope for this
                        // slice (see class docs). The interface may still be
                        // up; only the user-visible state reflects the truth.
                        _state.value = TransportState.HandshakeFailed
                        recordConnectionOutcome(ConnectionOutcomeResult.FAILURE, ConnectionErrorCategory.HANDSHAKE_TIMEOUT, attemptStartEpochMillis)
                        false
                    }
                } catch (e: Exception) {
                    diagnostics.recordError(VpnError.BackendStartFailure(e.javaClass.simpleName))
                    _state.value = TransportState.Error("Backend failed to start")
                    recordConnectionOutcome(ConnectionOutcomeResult.FAILURE, ConnectionErrorCategory.BACKEND_START_FAILURE, attemptStartEpochMillis)
                    false
                }
            }
        }
    }

    /**
     * B8I4 - the generic per-attempt execution seam: which TransportConfig
     * SHAPE to build is now dispatched on [kind] rather than always
     * assuming AMNEZIA_WG. Only AMNEZIA_WG has a real builder today - any
     * other kind throws, which doConnectAttempt's existing try/catch around
     * this call already turns into the SAME ConfigurationMappingFailure
     * fail-closed path every other malformed-config case uses (no new
     * failure mode). Wiring a real non-AWG builder here is B8I5's job, not
     * this slice's - see class docs.
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
            when (val stats = transport.stats()) {
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
        val stats = transport.stats()
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
                transport = transport.kind,
                gatewayId = ProductionGateway.ID,
                result = result,
                handshakeDurationMs = nowEpochMillis - attemptStartEpochMillis,
                errorCategory = errorCategory,
                timestampEpochMillis = nowEpochMillis,
            ),
        )
    }

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
            _state.value = TransportState.Reconnecting(attempt)

            if (attempt > ReconnectBackoff.MAX_ATTEMPTS) {
                diagnostics.recordError(VpnError.ReconnectExhausted)
                _state.value = TransportState.Error("Reconnect attempts exhausted")
                // B8I - ONE outcome for the whole exhausted recovery cycle,
                // not one per backoff attempt - keeps the bounded history
                // meaningful instead of filling up with per-attempt noise.
                recordConnectionOutcome(ConnectionOutcomeResult.FAILURE, ConnectionErrorCategory.RECONNECT_EXHAUSTED, reconnectionThresholdEpochMillis)
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
                _state.value = TransportState.Connected
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

    fun shutdown() {
        reconnectManager.stop()
    }
}

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
