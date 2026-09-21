package net.pocvpn.client.vpn

import android.content.Intent
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
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
import net.pocvpn.client.reachability.CdnClientRuntimeCapabilities
import net.pocvpn.client.reachability.CoarseNetworkSignals
import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.reachability.signedTransportProfile
import net.pocvpn.client.reachability.NetworkFingerprintKeyProvider
import net.pocvpn.client.reachability.NetworkFingerprinter
import net.pocvpn.client.reachability.PathHistoryStore
import net.pocvpn.client.relay.RelayReadinessStage
import net.pocvpn.client.relay.VpnAttemptContext
import net.pocvpn.client.smartconnect.ConnectionErrorCategory
import net.pocvpn.client.smartconnect.ConnectionOutcome
import net.pocvpn.client.smartconnect.ConnectionOutcomeResult
import net.pocvpn.client.smartconnect.ConnectionOutcomeStore
import net.pocvpn.client.smartconnect.ProductionGateway
import net.pocvpn.client.smartconnect.RestrictionClass
import net.pocvpn.client.smartconnect.RoutingDecisionEngine
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
import net.pocvpn.client.vpn.policy.RoutingMode
import net.pocvpn.client.vpn.policy.RoutingModeStore
import net.pocvpn.client.vpn.policy.resolveAppRoutingLists
import net.pocvpn.client.vpn.xray.XrayRuntimeResolution
import net.pocvpn.client.vpn.xray.XrayRuntimeResolver
import net.pocvpn.client.vpn.xray.XrayTlsRuntimeResolution

sealed class ControllerEvent {
    data class RequestVpnPermission(val intent: Intent) : ControllerEvent()
}

sealed interface ReconnectIncidentEvent {
    val generation: Long

    data class Started(
        override val generation: Long,
        val endpointId: EndpointId,
        val transportKind: TransportKind,
        val attemptContext: VpnAttemptContext,
        val restartsTransport: Boolean,
    ) : ReconnectIncidentEvent

    data class Succeeded(override val generation: Long) : ReconnectIncidentEvent
    data class Failed(override val generation: Long) : ReconnectIncidentEvent
    data class Disconnected(override val generation: Long) : ReconnectIncidentEvent
}

/**
 * Connection orchestrator sitting between the UI (ViewModel) and VpnTransport.
 * Owns: VPN permission flow, gateway-config precondition checks, connect/
 * disconnect serialization (no overlapping backend operations), and the
 * client-side reconnect state machine. Holds no UI references and survives
 * independently of any Activity.
 *
 * B8G1/R4 - reconnect behavior follows the transport's declared network-change contract.
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
 * For AmneziaWG, reconnectLoop() never calls transport.connect(). Once a tunnel is established, the AmneziaWG/
 * WireGuard protocol itself keeps attempting handshakes on its own - no
 * app-level "nudge" is needed or even available (the pinned AAR's native
 * JNI bridge, org.amnezia.awg.GoBackend, exposes only awgTurnOn / awgTurnOff
 * / awgGetConfig / awgGetSocketV4 / awgGetSocketV6 / awgVersion - no
 * incremental "retry"/"rekey" native call exists to call instead). This is
 * standard, documented
 * WireGuard behavior ("you don't need to worry about asking it to
 * reconnect... everything else is handled for you automatically"),
 * reinforced here by AwgPeer's own default persistentKeepaliveSeconds=25.
 * Its reconnect path only waits (polling the
 * exact same awaitFreshHandshake() the initial connect already uses) for
 * that automatic recovery, leaving the established interface/routes
 * completely untouched throughout - no setState call, no teardown window,
 * for as long as the session is merely recovering rather than being
 * explicitly reconfigured. Xray transports declare RESTART_SESSION because
 * their process/outbound sockets do not migrate reliably between Android
 * Network identities. Their recovery stops the old session completely and
 * starts one replacement from the already-pinned TransportConfig.
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
    // B18 - additive, defaults to an in-memory store that always reads
    // RoutingMode.FULL_VPN and ignores writes, so every pre-B18 call site is
    // byte-for-byte unaffected (FULL_VPN's route-prefix behavior is exactly
    // the pre-B18 default). Same "read fresh at connect time, apply for the
    // whole session, no live rebuild" discipline as appRoutingPolicyStore -
    // see doConnectAttempt's own docs.
    private val routingModeStore: RoutingModeStore = RoutingModeStore.fullVpn(),
    // B18 - additive, defaults to null so every pre-B18 call site is
    // byte-for-byte unaffected. A supplier (same pattern as
    // networkProfileProvider below), not a StateFlow - read fresh, once, at
    // the exact moment a real connect() attempt builds its route set. A null
    // provider (or a null result) is treated as RestrictionClass.UNKNOWN,
    // which RoutingDecisionEngine.decideAdaptiveRoute never lets broaden
    // DIRECT beyond routingMode - so an unwired caller behaves identically
    // to one deliberately supplying UNKNOWN.
    private val restrictionClassProvider: (() -> RestrictionClass)? = null,
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
    // B25 (task A/F) - a SEPARATE, additive resolver consulted ONLY when
    // [pendingAttemptContext] is [VpnAttemptContext.Relayed] (see
    // buildTransportConfig's own docs) - never consulted for a Direct
    // attempt, so [xrayProfileRepositoryResolver]/[xrayTlsProfileRepositoryResolver]'s
    // existing germany/stockholm-only behavior is completely unaffected by
    // this param's presence. Defaults to null (every pre-B25 caller, and
    // every caller that never wires real ingress provisioning, is
    // byte-for-byte unaffected - a relayed attempt simply fails closed with
    // [net.pocvpn.client.diagnostics.VpnError.ConfigurationMappingFailure],
    // same as an unresolvable Direct endpoint already does). When wired
    // (MainViewModel's Factory), this resolves ANY endpoint id via the SAME
    // [net.pocvpn.client.identity.XrayProfileRepositoryFactory] convention
    // [net.pocvpn.client.vpn.VlessRealityTransport]'s own default already
    // uses - the exact per-endpoint file
    // [net.pocvpn.client.relay.RelayIngressResolverImpl] already wrote the
    // matched ingress profile into for THIS SAME attempt, never a second/
    // independent lookup.
    private val relayXrayProfileRepositoryResolver: XrayProfileRepositoryResolver? = null,
    private val relayXrayTlsProfileRepositoryResolver: XrayTlsProfileRepositoryResolver? = null,
    // B35 Android execution - one authoritative local runtime capability
    // snapshot shared with candidate eligibility. Conservative default keeps
    // every legacy/test caller fail-closed for CDN-fronted XHTTP.
    private val cdnRuntimeCapabilities: CdnClientRuntimeCapabilities =
        CdnClientRuntimeCapabilities.unsupported(),
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
    // R2: optional, diagnostic-only observation of the exact pinned endpoint's
    // transport call. Invoked after permission/config validation, immediately
    // before connect(); failure in an observer cannot alter execution.
    private val onTransportAttemptStarting: ((EndpointId, TransportKind) -> Unit)? = null,
    private val onReconnectIncident: ((ReconnectIncidentEvent) -> Unit)? = null,
    // B45B-4 - additive, defaults to null (same "no wiring, no behavior" seam
    // every other optional collaborator in this class already uses). The SAME
    // real ShadowsocksTransport instance the Smart Connect registry
    // (MainViewModel.buildTransportRegistry) also registers - never a second,
    // independently-constructed one (see that class's own "one instance"
    // discipline). Its own credential/ABI/binary eligibility is unaffected by
    // this wiring - only WHETHER this controller can build a TransportConfig
    // for SHADOWSOCKS_2022 at all (see supportedKinds/buildTransportConfig's
    // own docs); registry-level AVAILABLE/NOT_IMPLEMENTED is the real gate on
    // whether Smart Connect ever resolves this kind in the first place.
    private val shadowsocksTransport: VpnTransport? = null,
    // B46-4A - additive, defaults to null (same "no wiring, no behavior"
    // seam every other optional collaborator in this class already uses).
    // The SAME real Hysteria2Transport instance the Smart Connect registry
    // (MainViewModel.buildTransportRegistry) also registers - never a
    // second, independently-constructed one (mirrors shadowsocksTransport's
    // own docs). Registry-level AVAILABLE/NOT_IMPLEMENTED is the real gate
    // on whether Smart Connect ever resolves this kind in the first place;
    // this wiring only decides whether THIS controller can build a
    // TransportConfig for HYSTERIA2 at all.
    private val hysteria2Transport: VpnTransport? = null,
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
        // B25 (task A/F) - also true whenever ONLY the relay-specific
        // resolver was wired (a relay-only composition root that never
        // wires the Direct-mode germany/stockholm map at all) - a resolved
        // relayed XRAY_REALITY/TLS_TCP candidate must not be refused here
        // before buildTransportConfig ever gets a chance to consult
        // [relayXrayProfileRepositoryResolver]/[relayXrayTlsProfileRepositoryResolver].
        if (xrayProfileRepository != null || xrayProfileRepositoryResolver != null || relayXrayProfileRepositoryResolver != null) add(TransportKind.XRAY_REALITY)
        if (xrayTlsProfileRepository != null || xrayTlsProfileRepositoryResolver != null || relayXrayTlsProfileRepositoryResolver != null) add(TransportKind.TLS_TCP)
        if (cdnRuntimeCapabilities.isPinnedXhttpExecutable()) add(TransportKind.XRAY_XHTTP)
        // B45B-4 - same shape as the others: this controller can only ever
        // build a TransportConfig.Shadowsocks (see buildTransportConfig's own
        // `when`) when a real ShadowsocksTransport was actually wired.
        if (shadowsocksTransport != null) add(TransportKind.SHADOWSOCKS_2022)
        // B46-4A - same shape as the others: this controller can only ever
        // build a TransportConfig.Hysteria2 (see buildTransportConfig's own
        // `when`) when a real Hysteria2Transport was actually wired.
        if (hysteria2Transport != null) add(TransportKind.HYSTERIA2)
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

    // B25 (task A) - the real, typed session identity THIS attempt (or the
    // most recent one) carries - see [VpnAttemptContext]'s own docs. Same
    // "pinned once at connect(), reset on disconnect()" lifecycle as
    // [pendingConnectEndpointId]/[pendingConnectKind]. @Volatile because
    // [sessionHealth]'s recomputation (triggered from [setState]/
    // [reportRelayStage]) may run on the SAME thread that just wrote this
    // under [connectMutex] in the common case, but must never observe a
    // torn/stale value if it doesn't.
    @Volatile private var pendingAttemptContext: VpnAttemptContext = VpnAttemptContext.Direct

    // B25 (task B/C) - the highest real [RelayReadinessStage] confirmed for
    // the CURRENT relayed attempt, reported ONLY by the caller that owns
    // relay-specific policy (MainViewModel.armFailoverWatch - see that
    // function's own docs) via [reportRelayStage]. null for every Direct
    // attempt and before any relay evidence exists - [computeSessionHealth]
    // treats null the same as [RelayReadinessStage.INGRESS_HANDSHAKE_OK]
    // once [TransportState.Connected] is real (see that function's own
    // docs), so a relayed session can never read as Protected merely
    // because this hasn't been reported yet.
    private val _relayStage = MutableStateFlow<RelayReadinessStage?>(null)

    // B25 (task B) - the ONE authoritative Protected-gating signal UI code
    // must read instead of deriving "Protected" directly from [state] (see
    // this type's own docs). Recomputed, from [state]/[pendingAttemptContext]/
    // [_relayStage] together, every time any of those three can change -
    // never partially stale.
    private val _sessionHealth = MutableStateFlow<VpnSessionHealth>(VpnSessionHealth.Idle)
    val sessionHealth: StateFlow<VpnSessionHealth> = _sessionHealth.asStateFlow()

    private fun recomputeSessionHealth() {
        _sessionHealth.value = computeSessionHealth(_state.value, pendingAttemptContext, _relayStage.value)
    }

    /**
     * B25 (task B/C) - the ONE place [_relayStage] is ever written, called
     * ONLY by the real relay-policy owner (MainViewModel.armFailoverWatch)
     * from real evidence (a genuine [TransportState.Connected] observation
     * for the ingress hop, or a real [net.pocvpn.client.relay.RelayEndToEndProbe]
     * result) - never speculatively, never to represent a merely-attempted
     * stage. A no-op call with the SAME stage the current attempt already
     * reported is harmless (StateFlow itself dedupes equal values).
     */
    fun reportRelayStage(stage: RelayReadinessStage?) {
        _relayStage.value = stage
        recomputeSessionHealth()
    }

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
        recomputeSessionHealth()
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

    // B18 - the RoutingMode actually baked into the CURRENTLY ACTIVE session,
    // same "applied, not merely saved" discipline as _appliedRoutingPolicy
    // above (and the same non-reasons: reconnectLoop() never writes this).
    private val _appliedRoutingMode = MutableStateFlow<RoutingMode?>(null)
    val appliedRoutingMode: StateFlow<RoutingMode?> = _appliedRoutingMode.asStateFlow()

    @Volatile private var userInitiatedDisconnect = true
    private var reconnectJob: Job? = null
    private val reconnectOwnershipLock = Any()
    private var reconnectGeneration = 0L

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

    // B45B-4P (correction) - the PINNED, trusted EndpointTransportBinding for
    // the CURRENT/most recent connect() attempt, when [connect]'s resolved
    // value carried one (see TransportOrchestrator.Resolution.Resolved
    // .endpointTransportBinding's own docs). Same "resolved exactly once, at
    // connect() time, never re-derived later in this same attempt" discipline
    // as [pendingConnectConfig] - a manifest refresh mid-attempt must never
    // change what THIS attempt already pinned. null for every kind that does
    // not consume it (AMNEZIA_WG/XRAY_REALITY/TLS_TCP/XRAY_XHTTP keep reading
    // their own existing address authorities, byte-for-byte unaffected).
    private var pendingConnectTransportBinding: net.pocvpn.client.reachability.EndpointTransportBinding? = null

    /** Test-only observation seam - no production code path reads this; buildTransportConfig reads [pendingConnectTransportBinding] directly. Exists only so lifecycle tests can prove the field is cleared on every terminal teardown path without making the field itself public. */
    internal val pendingConnectTransportBindingForTest: net.pocvpn.client.reachability.EndpointTransportBinding?
        get() = pendingConnectTransportBinding

    private var activeTransportConfig: TransportConfig? = null

    // B22 - the private-gateway keypair repository for the CURRENT/most
    // recent connect() attempt, when resolved carried one (see
    // TransportOrchestrator.Resolution.Resolved.privateKeyRepository's own
    // docs). null for every AUTO/MANUAL_MANAGED attempt - buildTransportConfig
    // falls back to the constructor-owned [clientKeyRepository] exactly as
    // before this field existed. Same lifecycle/locking discipline as
    // [pendingConnectConfig] - reset alongside it on every path that clears it.
    private var pendingConnectPrivateKeyRepository: net.pocvpn.client.identity.ClientKeyRepository? = null

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
            onUnderlyingNetworkChanged = { handleUnderlyingNetworkChanged() },
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
                // B33 - an Xray-kind transport's OWN async observeState()
                // (never doConnectAttempt itself - that branch deliberately
                // does not fabricate a stronger signal than the transport
                // provides, see its own docs) is the only place a REAL
                // post-startLoop() remote-confirmation failure
                // (NovaXrayVpnService's XrayRuntimeEvent.Failed, published
                // only after XrayCoreController.requestStart's own bounded
                // confirmation - see that function's own docs) ever surfaces
                // for a Direct/Manual attempt. Recorded here, BEFORE
                // setState below, so a concurrently-attached armFailoverWatch
                // observing the SAME state transition always sees the
                // correct typed error already in place - never a stale/null
                // one. Reuses the SAME eligible-for-Auto-advance category
                // AWG's own handshake timeout already uses (task's own
                // "reuse the correct existing place", never a second
                // failure taxonomy) - AWG's own HandshakeTimeout recording
                // (VpnController.doConnectAttempt) is completely unaffected,
                // this only ever fires for an XRAY_REALITY/TLS_TCP transport.
                if (transportState is TransportState.Error &&
                    (
                        newTransport.kind == TransportKind.XRAY_REALITY || newTransport.kind == TransportKind.TLS_TCP ||
                            newTransport.kind == TransportKind.XRAY_XHTTP ||
                            // B45B-4 - same reasoning: ShadowsocksTransport's own
                            // observeState() only reports Error after
                            // ShadowsocksVpnService's own real fail-closed checks
                            // (credential/binary/tun) - see that service's own
                            // docs - so this is a genuine terminal failure, never
                            // fabricated, and must be recorded under the SAME
                            // typed category for Auto-gateway advancement to work.
                            newTransport.kind == TransportKind.SHADOWSOCKS_2022 ||
                            // B46-4A - same reasoning: Hysteria2Transport's own
                            // observeState() only reports Error after
                            // Hysteria2VpnService's own real fail-closed checks
                            // (credential/ABI-binary/child-process/tun) - a
                            // genuine terminal failure, never fabricated.
                            newTransport.kind == TransportKind.HYSTERIA2
                        )
                ) {
                    diagnostics.recordError(VpnError.HandshakeTimeout)
                }
                val failureIncidentGeneration = if (
                    transportState is TransportState.Error &&
                    _state.value is TransportState.Connected &&
                    reconnectJob?.isActive != true
                ) {
                    publishReconnectIncidentStarted(restartsTransport = false)
                } else {
                    null
                }
                // While a reconnect cycle owns the visible state (Reconnecting/backoff),
                // don't let a transient Disconnected from an internal retry attempt
                // flicker the UI back to plain Disconnected.
                if (reconnectJob?.isActive != true) {
                    setState(transportState)
                }
                diagnostics.updateTransportState(_state.value)
                failureIncidentGeneration?.let {
                    runCatching { onReconnectIncident?.invoke(ReconnectIncidentEvent.Failed(it)) }
                }
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
        val supersededRecovery = cancelReconnectForExplicitConnect()
        if (supersededRecovery) {
            connectMutex.lock()
        } else if (!connectMutex.tryLock()) {
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
            pendingConnectTransportBinding = resolved.endpointTransportBinding
            pendingConnectPrivateKeyRepository = resolved.privateKeyRepository
            // B25 (task A/B) - pinned exactly once, here, before permission
            // is even requested - never re-derived later in this same
            // attempt (same discipline as pendingConnectConfig above).
            // _relayStage is reset so a PRIOR relayed attempt's stage can
            // never leak into this one's sessionHealth computation.
            pendingAttemptContext = resolved.attemptContext
            _relayStage.value = null
            recomputeSessionHealth()
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
            pendingConnectPrivateKeyRepository = null
            // B45B-4P (correction, lifecycle hygiene) - same "abandoned
            // attempt, must not linger" reasoning as pendingConnectConfig
            // immediately above: this pinned attempt is over, and the NEXT
            // connect() always sets this fresh before it is ever read again.
            pendingConnectTransportBinding = null
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
            _appliedRoutingMode.value = null
            activeTransportConfig = null
            // B8O3 - nothing is running/attempted any more.
            _currentTransportKind.value = null
            // B16 - a completed/abandoned attempt's pinned candidate config
            // must not linger and be silently reused (or shown by
            // gatewayStatus()) for whatever connect() request comes next -
            // the NEXT connect() always sets this fresh (possibly null,
            // for manual mode) before it is ever read again.
            pendingConnectConfig = null
            pendingConnectPrivateKeyRepository = null
            // B45B-4P (correction, lifecycle hygiene) - same reasoning as
            // pendingConnectConfig immediately above, applied to the newer
            // pinned Shadowsocks transport-binding authority: a user-
            // initiated disconnect ends this attempt, so the pinned binding
            // must not linger for a later, unrelated connect() to observe.
            pendingConnectTransportBinding = null
            // B25 - the session that owned this context/stage is gone; the
            // NEXT connect() always pins these fresh (see connect()'s own
            // docs) - never left to linger and be read by sessionHealth for
            // a request nothing is acting on any more.
            pendingAttemptContext = VpnAttemptContext.Direct
            _relayStage.value = null
            recomputeSessionHealth()
        }
    }

    /**
     * B25 review fix (PR #39) - the ONE way a caller abandons a FAILED
     * attempt whose transport already reached a real [TransportState.Connected]
     * (a genuine handshake) but that the caller has independently determined
     * is NOT actually healthy - today, exclusively
     * [net.pocvpn.client.MainViewModel.armFailoverWatch]'s relay branch,
     * when a resolved relay's ingress-handshake `Connected` is followed by a
     * REAL [net.pocvpn.client.relay.RelayEndToEndProbe] failure (see that
     * function's own docs - a relayed session must never be left claiming
     * Connected once its end-to-end proof has genuinely failed).
     *
     * This closes a real bug: [connect] immediately returns whenever
     * `_state.value` is already [TransportState.Connecting] or
     * [TransportState.Connected] (see its own early-return guard) - so
     * without an explicit teardown here, the NEXT globally-ranked combined
     * candidate's own `controller.connect(...)` call would silently be
     * swallowed by that guard, never actually dialing anything, while the
     * UI kept observing the stale (already-failed) relay session.
     *
     * Deliberately NOT the same thing as a user pressing disconnect: never
     * sets [userInitiatedDisconnect]. That flag exists only to gate
     * [handleNetworkLost]'s automatic reconnect loop, and this function
     * already makes that loop structurally unreachable for the abandoned
     * session by moving `_state` away from [TransportState.Connected] BEFORE
     * returning - [handleNetworkLost]'s own `state !is Connected` guard means
     * a later network-loss callback for this (now torn-down) session can
     * never start [reconnectLoop] for it, with no need to also repurpose a
     * flag whose name and only other reader ([reconnectLoop] itself) both
     * mean "the USER asked to stop". [disconnect]'s own manual-disconnect
     * semantics (including that flag) are completely untouched by this
     * function existing.
     *
     * Runs under the SAME [connectMutex] every other lifecycle operation
     * uses (never manipulates [activeTransport]/VpnService state from
     * outside this class - task's own "do not manipulate VpnService/
     * transport directly from MainViewModel"), reuses the exact teardown
     * steps [disconnect] already performs (cancel any in-flight reconnect,
     * tear down the active transport, clear applied routing/pending-config/
     * attempt-context state), and additionally clears [_relayStage] so no
     * stale [net.pocvpn.client.vpn.VpnSessionHealth.RelayHandshake]/
     * [net.pocvpn.client.vpn.VpnSessionHealth.RelayProtected] can survive
     * into whatever the caller does next. Ends at a genuine
     * [TransportState.Disconnected] - the NEXT real [connect] call (for a
     * different candidate) is therefore genuinely accepted, never silently
     * swallowed by the guard this function exists to unblock.
     */
    suspend fun abandonAttemptForFailover() {
        connectMutex.withLock {
            teardownActiveAttemptLocked()
            setState(TransportState.Disconnected)
        }
    }

    /**
     * B34 - the shared teardown [disconnect]/[abandonAttemptForFailover]/
     * [abandonAttemptWithTerminalError] all need: tear down whatever
     * transport/VpnService/tun the CURRENT attempt owns and clear every
     * piece of per-attempt pinned state, WITHOUT deciding what
     * [TransportState] the caller ends up in - that decision is the ONE
     * thing that genuinely differs between "the user asked to stop"
     * (Disconnected), "Auto is moving to the next candidate" (Disconnected,
     * transient - [abandonAttemptForFailover]), and "Auto has genuinely
     * exhausted every candidate" (a terminal [TransportState.Error] the
     * caller sets AFTER this returns - [abandonAttemptWithTerminalError] -
     * so teardown itself can never silently overwrite that terminal reason
     * back to a plain Disconnected the UI/diagnostics cannot tell apart from
     * an ordinary user-initiated stop). Caller must already hold
     * [connectMutex]. Never duplicated - every real transport/tun teardown
     * on this class goes through this ONE function.
     */
    private suspend fun teardownActiveAttemptLocked() {
        cancelReconnectLocked()
        hasTouchedTransport = true
        // B34 - cancelled BEFORE disconnect() (never after): activeTransport
        // .disconnect() itself flips the transport's OWN observeState() to
        // Disconnected, which the STILL-ATTACHED switchActiveTransport
        // collector would otherwise asynchronously forward into `_state` -
        // a real race that clobbered abandonAttemptWithTerminalError's own
        // explicit terminal Error back to Disconnected the instant the
        // caller's next `runCurrent()`/dispatch let that queued collector
        // emission run (caught by this file's own tests). Harmless for
        // [abandonAttemptForFailover] (which explicitly sets Disconnected
        // itself immediately after anyway) and for [disconnect] (which
        // already relied on this SAME collector to arrive at Disconnected -
        // still true, since `switchActiveTransport`'s own guard
        // (`activeObserverJob?.isActive == true`) already treats a
        // cancelled job as "must attach a fresh one", so the very next real
        // connect() genuinely reattaches a live collector for this exact
        // instance, never left permanently deaf).
        activeObserverJob?.cancel()
        activeTransport.disconnect()
        _appliedRoutingPolicy.value = null
        _appliedRoutingMode.value = null
        activeTransportConfig = null
        pendingConnectConfig = null
        pendingConnectPrivateKeyRepository = null
        // B45B-4P (correction, lifecycle hygiene) - shared by
        // abandonAttemptForFailover/abandonAttemptWithTerminalError, same
        // "attempt is over" reasoning as pendingConnectConfig above.
        pendingConnectTransportBinding = null
        pendingAttemptContext = VpnAttemptContext.Direct
        _relayStage.value = null
    }

    /**
     * B34 - the terminal-exhaustion counterpart of [abandonAttemptForFailover]:
     * physically reproduced as a real bug (PR #53's CHAIN_DIRECT physical
     * validation) - once the combined Auto sequence genuinely exhausts every
     * admitted candidate, [MainViewModel.attemptCombined] previously called
     * [rejectPreflight] to report the terminal error, but that function was
     * built for the OTHER case ("reject before this controller was ever
     * touched" - see its own docs) and never tears down a transport/tun a
     * REAL prior attempt in this same sequence already brought up - the
     * device was left with a stale, non-functional VPN interface and NO
     * working Internet at all (worse than the "Connection failed" UI
     * communicated) until the app process was force-stopped.
     *
     * Reuses the EXACT SAME teardown [abandonAttemptForFailover] already
     * uses (never a second/duplicated disconnect path), but ends at a real
     * [TransportState.Error] carrying [message] (after recording [error]
     * into diagnostics, the same [diagnostics] instance every other error
     * path already writes into) instead of [TransportState.Disconnected] -
     * so the terminal reason is preserved for the UI/diagnostics, never
     * silently replaced. The ONE production caller today is
     * [MainViewModel.attemptCombined]'s own genuine-exhaustion branch.
     */
    suspend fun abandonAttemptWithTerminalError(error: VpnError, message: String) {
        connectMutex.withLock {
            teardownActiveAttemptLocked()
            diagnostics.recordError(error)
            setState(TransportState.Error(message))
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
                // B18 - read fresh on every real connect() attempt, same
                // discipline as routingPolicy above - see routingModeStore's
                // own docs for why this is what makes a mode change the user
                // saved while disconnected take effect on THIS attempt only.
                val routingMode = routingModeStore.read()
                val transportConfig = try {
                    buildTransportConfig(kind, config, appRoutingLists, routingMode)
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
                    runCatching { onTransportAttemptStarting?.invoke(pendingConnectEndpointId, kind) }
                    activeTransport.connect(transportConfig)
                    activeTransportConfig = transportConfig
                    // B8H - the VpnService interface now reflects
                    // routingPolicy (whether or not a handshake follows) -
                    // only a thrown connect() (caught below) means no
                    // interface was actually built, so this is set here and
                    // ONLY here, never in the catch branch.
                    _appliedRoutingPolicy.value = routingPolicy
                    _appliedRoutingMode.value = routingMode
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
                            // B25 (task D fix) - see the catch block's own
                            // docs below for why a relayed attempt's outcome
                            // is recorded EXCLUSIVELY by
                            // MainViewModel.recordRelayOutcome, never here.
                            // AMNEZIA_WG is not a real client<->ingress
                            // transport in production (see PROJECT_ARCHITECTURE.md's
                            // B24 relay matrix) - this guard exists for
                            // defense in depth/test-double correctness, not
                            // because a real relay attempt reaches this
                            // branch today.
                            if (pendingAttemptContext !is VpnAttemptContext.Relayed) {
                                recordConnectionOutcome(ConnectionOutcomeResult.SUCCESS, ConnectionErrorCategory.NONE, attemptStartEpochMillis)
                                recordPathHistory(success = true, kind = kind, endpointId = pendingConnectEndpointId, nowEpochMillis = System.currentTimeMillis())
                            }
                            true
                        } else {
                            diagnostics.recordError(VpnError.HandshakeTimeout)
                            // Deliberately does NOT call transport.disconnect() -
                            // failover/kill-switch policy is out of scope for this
                            // slice (see class docs). The interface may still be
                            // up; only the user-visible state reflects the truth.
                            setState(TransportState.HandshakeFailed)
                            if (pendingAttemptContext !is VpnAttemptContext.Relayed) {
                                recordConnectionOutcome(ConnectionOutcomeResult.FAILURE, ConnectionErrorCategory.HANDSHAKE_TIMEOUT, attemptStartEpochMillis)
                                recordPathHistory(success = false, kind = kind, endpointId = pendingConnectEndpointId, nowEpochMillis = System.currentTimeMillis())
                            }
                            false
                        }
                    } else {
                        // B8I6/B33/B45B-4/B46-4A - XRAY_REALITY/TLS_TCP/XRAY_XHTTP/
                        // SHADOWSOCKS_2022/HYSTERIA2 (the only other kinds
                        // reaching here): never fabricate a stronger
                        // success signal than the transport itself provides -
                        // no forced Connected here, ever. As of B33,
                        // VlessRealityTransport/VlessTlsTransport's own
                        // observeState() only reports Connected AFTER
                        // XrayCoreController.requestStart's own bounded
                        // remote/data-plane confirmation genuinely succeeded
                        // (a real measureDelay round trip through the
                        // just-started core's own outbound - see that
                        // function's own docs) - a real failure to confirm
                        // surfaces as Error via the SAME channel. The
                        // ALREADY-attached active-transport collector
                        // (switchActiveTransport, called earlier in
                        // connect()) is what surfaces whatever _state
                        // genuinely becomes, and (B33) now also records the
                        // typed VpnError.HandshakeTimeout the instant that
                        // Error state arrives - see that collector's own
                        // docs for why recording it there (not here) is what
                        // lets a concurrently-attached armFailoverWatch
                        // correctly advance the combined Auto sequence past
                        // a genuinely failed Xray Direct attempt. No
                        // ConnectionOutcome/PathHistory recording here either
                        // - that model is AWG-handshake-specific (see
                        // recordConnectionOutcome's own docs) and does not
                        // yet have an Xray equivalent - see
                        // handleNetworkLost's own docs for why this also
                        // means no automatic RECONNECT (distinct from Auto
                        // gateway advancement, which B33 does now support)
                        // for this kind.
                        true
                    }
                } catch (e: Exception) {
                    if (e is CancellationException) throw e
                    diagnostics.recordError(VpnError.BackendStartFailure(e.javaClass.simpleName))
                    setState(TransportState.Error("Backend failed to start"))
                    // B25 (task D fix) - a relayed attempt's outcome is
                    // recorded EXCLUSIVELY by MainViewModel.recordRelayOutcome
                    // under the FULL historyPathId (see that function's own
                    // docs) - this generic per-kind/per-endpoint recording
                    // must never ALSO fire for one, which would otherwise
                    // write a separate, single-hop record keyed by the bare
                    // ingress endpoint id (the exact B24-documented gap this
                    // fixes - see PROJECT_ARCHITECTURE.md's B24 section).
                    // Unaffected for every Direct/manual/private-gateway
                    // attempt (pendingAttemptContext is always Direct there).
                    if (pendingAttemptContext !is VpnAttemptContext.Relayed) {
                        recordConnectionOutcome(ConnectionOutcomeResult.FAILURE, ConnectionErrorCategory.BACKEND_START_FAILURE, attemptStartEpochMillis)
                        recordPathHistory(success = false, kind = kind, endpointId = pendingConnectEndpointId, nowEpochMillis = System.currentTimeMillis())
                    }
                    false
                }
            }
        }
    }

    /**
     * B18/B18-2 - the ONE place RoutingDecisionEngine's destination-route
     * decision becomes an actual AmneziaWG AllowedIPs list (which is BOTH
     * the Android VpnService route table AND WireGuard's own cryptokey-
     * routing ingress filter for this peer - see AwgConfigMapper's own
     * docs). Delegates the actual IPv4 route-set decision to
     * [RoutingDecisionEngine.resolveIpv4Routes] - the SAME shared resolver
     * [net.pocvpn.client.vpn.xray.buildXrayVpnPlan] uses for XRAY_REALITY/
     * TLS_TCP (see that function's own docs) - never a second, parallel copy
     * of this decision. Only the IPv4 entries of [gatewayAllowedIps] are
     * ever touched; every IPv6 entry (normally "::/0") is kept verbatim in
     * every mode - Full VPN/IPv6-fail-closed stay exactly as before. A
     * manifest-provided narrower [gatewayAllowedIps] IPv4 override is
     * intentionally superseded by the standard exclusion set in ADAPTIVE
     * mode, never combined with it.
     */
    private fun resolveAdaptiveAllowedIps(gatewayAllowedIps: List<String>, routingMode: RoutingMode): List<String> {
        val ipv4Entries = gatewayAllowedIps.filterNot { it.contains(":") }
        val ipv6Entries = gatewayAllowedIps.filter { it.contains(":") }
        val restrictionClass = restrictionClassProvider?.invoke() ?: RestrictionClass.UNKNOWN
        val resolvedIpv4 = RoutingDecisionEngine.resolveIpv4Routes(ipv4Entries, routingMode, restrictionClass)
        return resolvedIpv4 + ipv6Entries
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
     * B18-2 - [routingMode] is now ALSO threaded into the XRAY_REALITY/
     * TLS_TCP branches (`TransportConfig.Xray/XrayTls.routingMode`) so
     * NovaXrayVpnService's own route plan uses the SAME
     * RoutingDecisionEngine.resolveIpv4Routes authority AWG's
     * [resolveAdaptiveAllowedIps] already uses - see that shared function's
     * own docs for why this is not a second routing engine.
     */
    private suspend fun buildTransportConfig(
        kind: TransportKind,
        config: GatewayConfiguration.Configured,
        appRoutingLists: AppRoutingLists,
        routingMode: RoutingMode,
    ): TransportConfig =
        when (kind) {
            TransportKind.AMNEZIA_WG -> {
                // B22 - a PRIVATE gateway attempt supplies its own
                // ClientKeyRepository (a genuinely distinct keypair, never
                // the managed-network identity - see
                // PrivateGatewayKeyRepositoryFactory's own docs); every
                // AUTO/MANUAL_MANAGED attempt has this null and is
                // byte-for-byte unaffected.
                val privateKey = (pendingConnectPrivateKeyRepository ?: clientKeyRepository).getPrivateKeyForTunnel()
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
                        allowedIps = resolveAdaptiveAllowedIps(config.allowedIps, routingMode),
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
                // B25 (task A/F) - a relayed attempt resolves through the
                // SEPARATE [relayXrayProfileRepositoryResolver] (never the
                // Direct-only germany/stockholm map) - see that field's own
                // docs.
                val resolver = (if (pendingAttemptContext is VpnAttemptContext.Relayed) relayXrayProfileRepositoryResolver else xrayProfileRepositoryResolver)
                    ?: throw XrayProfileNotReadyException("Xray profile repository not wired")
                val repository = resolver.resolve(pendingConnectEndpointId)
                    ?: throw XrayProfileNotReadyException("no Xray profile repository configured for endpoint ${pendingConnectEndpointId.value}")
                when (val resolution = XrayRuntimeResolver.resolve(repository)) {
                    is XrayRuntimeResolution.Rejected -> throw XrayProfileNotReadyException(resolution.reason)
                    is XrayRuntimeResolution.Ready -> TransportConfig.Xray(
                        resolution.config,
                        endpointId = pendingConnectEndpointId,
                        routingMode = routingMode,
                        // B33 relay follow-up - see TransportConfig.Xray.isRelayed's own docs.
                        isRelayed = pendingAttemptContext is VpnAttemptContext.Relayed,
                        // B33 relay follow-up (round 2) - see TransportConfig.Xray.relayExitProbeHost's own docs.
                        relayExitProbeHost = (pendingAttemptContext as? VpnAttemptContext.Relayed)?.plan?.exitBinding?.host,
                    )
                }
            }
            TransportKind.TLS_TCP -> {
                // B8O2/B13 - same reasoning as XRAY_REALITY above, against the
                // TLS profile repository resolver instead. Unreachable
                // unless xrayTlsProfileRepositoryResolver != null.
                val resolver = (if (pendingAttemptContext is VpnAttemptContext.Relayed) relayXrayTlsProfileRepositoryResolver else xrayTlsProfileRepositoryResolver)
                    ?: throw XrayProfileNotReadyException("Xray TLS profile repository not wired")
                val repository = resolver.resolve(pendingConnectEndpointId)
                    ?: throw XrayProfileNotReadyException("no Xray TLS profile repository configured for endpoint ${pendingConnectEndpointId.value}")
                when (val resolution = XrayRuntimeResolver.resolveTls(repository)) {
                    is XrayTlsRuntimeResolution.Rejected -> throw XrayProfileNotReadyException(resolution.reason)
                    is XrayTlsRuntimeResolution.Ready -> TransportConfig.XrayTls(
                        resolution.config,
                        endpointId = pendingConnectEndpointId,
                        routingMode = routingMode,
                        // B33 relay follow-up - see TransportConfig.Xray.isRelayed's own docs.
                        isRelayed = pendingAttemptContext is VpnAttemptContext.Relayed,
                        // B33 relay follow-up (round 2) - see TransportConfig.Xray.relayExitProbeHost's own docs.
                        relayExitProbeHost = (pendingAttemptContext as? VpnAttemptContext.Relayed)?.plan?.exitBinding?.host,
                    )
                }
            }
            TransportKind.XRAY_XHTTP -> {
                val context = pendingAttemptContext as? VpnAttemptContext.Relayed
                    ?: throw XrayProfileNotReadyException(
                        "XHTTP requires a relayed attempt context",
                    )

                when (
                    val resolution =
                        net.pocvpn.client.vpn.xray.CdnXhttpRuntimeConfigResolver.resolve(
                            ingressProfile = context.profile,
                            exitEndpointId = context.plan.exitEndpointId,
                            runtime = cdnRuntimeCapabilities,
                        )
                ) {
                    is net.pocvpn.client.vpn.xray.CdnXhttpRuntimeResolution.Rejected ->
                        throw XrayProfileNotReadyException(
                            "XHTTP runtime rejected: ${resolution.reason}",
                        )

                    is net.pocvpn.client.vpn.xray.CdnXhttpRuntimeResolution.Ready ->
                        TransportConfig.XrayXhttp(
                            config = resolution.config,
                            endpointId = pendingConnectEndpointId,
                            routingMode = routingMode,
                            isRelayed = true,
                            relayExitProbeHost = context.plan.exitBinding.host,
                        )
                }
            }

            TransportKind.SHADOWSOCKS_2022 -> {
                // B45B-4P (correction) - PROVEN ROOT CAUSE of the original
                // physical data-plane failure: config.endpointHost/
                // endpointPort (GatewayConfigSnapshot) are AWG-only (see
                // AutoGatewaySelector.snapshotFor's own docs) - using them
                // here silently dialed the AWG peer port instead of the real
                // Shadowsocks listener. host/port/method now come EXCLUSIVELY
                // from [pendingConnectTransportBinding] - the pinned, trusted
                // manifest binding for THIS attempt (manual:
                // MainViewModel.trustedTransportBindingFor; auto:
                // GatewayAttemptCandidate.transportBinding) - never from
                // GatewayConfiguration/the AWG snapshot, never re-resolved
                // from a catalog. Deliberately still carries no key material
                // (mirrors TransportConfig.Shadowsocks's own docs): the
                // AEAD-2022 secret is resolved from
                // Shadowsocks2022CredentialRepository inside
                // ShadowsocksVpnService at connect() time, scoped to
                // endpointId. Fails closed (never silently falls back to the
                // AWG snapshot) for: no pinned binding, wrong endpoint/kind,
                // or an invalid/legacy/missing signed profile - a debug
                // "Force SHADOWSOCKS_2022" preference never bypasses this.
                val binding = pendingConnectTransportBinding
                    ?: throw ShadowsocksProfileNotReadyException("no pinned Shadowsocks transport binding for this attempt")
                require(binding.kind == TransportKind.SHADOWSOCKS_2022) {
                    "pinned transport binding is ${binding.kind}, not SHADOWSOCKS_2022"
                }
                val profile = when (
                    val result = binding.signedTransportProfile(pendingConnectEndpointId)
                ) {
                    is net.pocvpn.client.reachability.SignedTransportProfileReadResult.Parsed -> {
                        (result.profile as? net.pocvpn.client.reachability.SignedTransportProfile.Shadowsocks2022)
                            ?: throw ShadowsocksProfileNotReadyException(
                                "no typed Shadowsocks2022 signed profile for endpoint ${pendingConnectEndpointId.value} (legacy/wrong-kind binding)",
                            )
                    }
                    net.pocvpn.client.reachability.SignedTransportProfileReadResult.Missing ->
                        throw ShadowsocksProfileNotReadyException("signed Shadowsocks profile missing for endpoint ${pendingConnectEndpointId.value}")
                    net.pocvpn.client.reachability.SignedTransportProfileReadResult.Unsupported ->
                        throw ShadowsocksProfileNotReadyException("signed Shadowsocks profile version unsupported for endpoint ${pendingConnectEndpointId.value}")
                    net.pocvpn.client.reachability.SignedTransportProfileReadResult.Invalid ->
                        throw ShadowsocksProfileNotReadyException("signed Shadowsocks profile invalid for endpoint ${pendingConnectEndpointId.value}")
                }
                TransportConfig.Shadowsocks(
                    endpointId = pendingConnectEndpointId,
                    host = binding.host,
                    port = binding.port,
                    method = profile.profile.method,
                    routingMode = routingMode,
                )
            }

            TransportKind.HYSTERIA2 -> {
                // B46-4A - mirrors SHADOWSOCKS_2022's own B45B-4P correction
                // exactly: host/port/sni/obfuscationMode come EXCLUSIVELY
                // from [pendingConnectTransportBinding] - the pinned,
                // trusted manifest binding for THIS attempt - never a
                // hardcoded Stockholm host/port, never re-resolved from a
                // catalog. Carries no auth/obfuscation secret: those are
                // resolved from Hysteria2CredentialRepository inside
                // Hysteria2VpnService at connect() time, scoped to
                // endpointId. Fails closed for: no pinned binding, wrong
                // endpoint/kind, or an invalid/legacy/missing signed
                // profile - a debug "Force HYSTERIA2" preference never
                // bypasses this.
                val binding = pendingConnectTransportBinding
                    ?: throw Hysteria2ProfileNotReadyException("no pinned Hysteria2 transport binding for this attempt")
                require(binding.kind == TransportKind.HYSTERIA2) {
                    "pinned transport binding is ${binding.kind}, not HYSTERIA2"
                }
                val profile = when (
                    val result = binding.signedTransportProfile(pendingConnectEndpointId)
                ) {
                    is net.pocvpn.client.reachability.SignedTransportProfileReadResult.Parsed -> {
                        (result.profile as? net.pocvpn.client.reachability.SignedTransportProfile.Hysteria2)
                            ?: throw Hysteria2ProfileNotReadyException(
                                "no typed Hysteria2 signed profile for endpoint ${pendingConnectEndpointId.value} (legacy/wrong-kind binding)",
                            )
                    }
                    net.pocvpn.client.reachability.SignedTransportProfileReadResult.Missing ->
                        throw Hysteria2ProfileNotReadyException("signed Hysteria2 profile missing for endpoint ${pendingConnectEndpointId.value}")
                    net.pocvpn.client.reachability.SignedTransportProfileReadResult.Unsupported ->
                        throw Hysteria2ProfileNotReadyException("signed Hysteria2 profile version unsupported for endpoint ${pendingConnectEndpointId.value}")
                    net.pocvpn.client.reachability.SignedTransportProfileReadResult.Invalid ->
                        throw Hysteria2ProfileNotReadyException("signed Hysteria2 profile invalid for endpoint ${pendingConnectEndpointId.value}")
                }
                if (routingMode != RoutingMode.FULL_VPN) {
                    throw Hysteria2ProfileNotReadyException("HYSTERIA2 supports FULL_VPN only this slice, requested $routingMode")
                }
                TransportConfig.Hysteria2(
                    endpointId = pendingConnectEndpointId,
                    host = binding.host,
                    port = binding.port,
                    sni = profile.profile.sni,
                    obfuscationMode = profile.profile.obfuscationMode,
                    routingMode = routingMode,
                )
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
        store.record(fingerprint, endpointId.value, kind, success, nowEpochMillis)
    }

    /**
     * B8I5/B8I6 - triggers whenever `_state.value is Connected` when the
     * real underlying network is lost - NOT AWG-specific: `_state` reaches
     * Connected for TLS_TCP/XRAY_REALITY too, via [switchActiveTransport]'s
     * own collector forwarding whatever [VlessTlsTransport]/
     * [VlessRealityTransport].observeState() reports (see those classes' own
     * docs) - so this loop engages for any kind once it is genuinely
     * Connected, not only AMNEZIA_WG (B30B correction: an earlier version of
     * this doc claimed otherwise, which was already imprecise and became a
     * real bug once combined with [AndroidReconnectManager]'s pre-B30B
     * network-scope defect - see that class's own docs for the full root
     * cause). [awaitFreshHandshake] below still degrades gracefully per
     * kind: AWG gets a real fresh-handshake check; a kind with no evidence
     * channel (`TransportStats.Unsupported`/`NotImplemented` - Xray/TLS_TCP,
     * XRAY_REALITY today) is trusted once the real network is confirmed back
     * (same "trust the transport's own signal when it offers no counter-
     * evidence" discipline [awaitFreshHandshake]'s own docs already
     * establish for the initial connect) - never a second, kind-specific
     * retry mechanism invented here.
     */
    private fun handleNetworkLost() {
        if (userInitiatedDisconnect) return
        if (_state.value !is TransportState.Connected) return
        diagnostics.updateNetworkType("unavailable")
        startReconnect(restartImmediately = false)
    }

    /**
     * R4: the existing reconnect authority also owns changes between two
     * simultaneously available NOT_VPN Android Network identities. Xray
     * transports require a fresh process/socket session on that boundary;
     * AWG keeps its existing in-place native migration behavior.
     */
    private fun handleUnderlyingNetworkChanged() {
        if (userInitiatedDisconnect) return
        if (_state.value !is TransportState.Connected) return
        if (activeTransport.underlyingNetworkRecovery != UnderlyingNetworkRecovery.RESTART_SESSION) return
        startReconnect(restartImmediately = true)
    }

    private fun startReconnect(restartImmediately: Boolean) {
        synchronized(reconnectOwnershipLock) {
            reconnectJob?.cancel()
            val generation = ++reconnectGeneration
            reconnectJob = scope.launch { reconnectLoop(generation, restartImmediately) }
        }
    }

    private fun publishReconnectIncidentStarted(restartsTransport: Boolean): Long {
        val generation = synchronized(reconnectOwnershipLock) { ++reconnectGeneration }
        runCatching {
            onReconnectIncident?.invoke(
                ReconnectIncidentEvent.Started(
                    generation,
                    pendingConnectEndpointId,
                    pendingConnectKind,
                    pendingAttemptContext,
                    restartsTransport,
                ),
            )
        }
        return generation
    }

    /**
     * AWG waits for its established tunnel's fresh handshake. A transport
     * declaring RESTART_SESSION is stopped to a terminal Disconnected state
     * and restarted from activeTransportConfig. Every state publication is
     * fenced by [generation], and no saved routing/endpoint input is reread.
     *
     * reconnectionThresholdEpochMillis is captured ONCE, at the moment this
     * reconnect session begins - not recomputed per attempt - because the
     * underlying AmneziaWG tunnel keeps retrying handshakes entirely on its
     * own timeline (protocol-level retry backed by PersistentKeepalive, see
     * class docs), asynchronously to this loop's own polling cadence. A
     * per-attempt "now" threshold could miss a handshake that already
     * landed moments before this loop happened to check.
     */
    private suspend fun reconnectLoop(generation: Long, restartImmediately: Boolean) {
        var attempt = 0
        val reconnectionThresholdEpochMillis = System.currentTimeMillis()
        runCatching {
            onReconnectIncident?.invoke(
                ReconnectIncidentEvent.Started(
                    generation,
                    pendingConnectEndpointId,
                    pendingConnectKind,
                    pendingAttemptContext,
                    activeTransport.underlyingNetworkRecovery == UnderlyingNetworkRecovery.RESTART_SESSION,
                ),
            )
        }
        while (coroutineContext.isActive && !userInitiatedDisconnect) {
            attempt++
            if (!isCurrentReconnect(generation)) return
            diagnostics.updateReconnectAttempts(attempt)
            if (!setReconnectState(generation, TransportState.Reconnecting(attempt))) return

            if (attempt > ReconnectBackoff.MAX_ATTEMPTS) {
                if (!setReconnectState(generation, TransportState.Error("Reconnect attempts exhausted"))) return
                diagnostics.recordError(VpnError.ReconnectExhausted)
                // B8I - ONE outcome for the whole exhausted recovery cycle,
                // not one per backoff attempt - keeps the bounded history
                // meaningful instead of filling up with per-attempt noise.
                // B25 (task D fix) - same relayed-context guard as
                // doConnectAttempt's own AMNEZIA_WG branch (see that
                // function's own docs) - defense in depth, since a real
                // relayed attempt never actually reaches this AWG-only
                // reconnect loop today (see handleNetworkLost's own docs).
                if (pendingAttemptContext !is VpnAttemptContext.Relayed) {
                    recordConnectionOutcome(ConnectionOutcomeResult.FAILURE, ConnectionErrorCategory.RECONNECT_EXHAUSTED, reconnectionThresholdEpochMillis)
                    recordPathHistory(success = false, kind = pendingConnectKind, endpointId = pendingConnectEndpointId, nowEpochMillis = System.currentTimeMillis())
                }
                runCatching { onReconnectIncident?.invoke(ReconnectIncidentEvent.Failed(generation)) }
                return
            }

            if (!(restartImmediately && attempt == 1)) {
                delay(ReconnectBackoff.delayForAttempt(attempt))
            }
            if (!coroutineContext.isActive || userInitiatedDisconnect) return
            if (!isCurrentReconnect(generation)) return

            if (!reconnectManager.isNetworkAvailable()) {
                continue // keep backing off until a network reappears
            }

            val recovered = if (activeTransport.underlyingNetworkRecovery == UnderlyingNetworkRecovery.RESTART_SESSION) {
                restartActiveTransportForNetworkChange(generation)
            } else {
                connectMutex.withLock {
                    if (!isCurrentReconnect(generation)) return@withLock false
                    awaitFreshHandshake(reconnectionThresholdEpochMillis)
                }
            }
            if (!isCurrentReconnect(generation)) return
            if (recovered) {
                recordCurrentStats()
                if (!setReconnectState(generation, TransportState.Connected)) return
                diagnostics.updateReconnectAttempts(0)
                runCatching { onReconnectIncident?.invoke(ReconnectIncidentEvent.Succeeded(generation)) }
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

    private suspend fun restartActiveTransportForNetworkChange(generation: Long): Boolean = connectMutex.withLock {
        if (!isCurrentReconnect(generation) || userInitiatedDisconnect) return@withLock false
        hasTouchedTransport = true
        activeTransport.disconnect()
        val stoppedState = activeTransport.observeState().first {
            it is TransportState.Disconnected || it is TransportState.Error
        }
        if (!isCurrentReconnect(generation) || userInitiatedDisconnect) return@withLock false
        if (stoppedState is TransportState.Error) {
            setReconnectState(generation, stoppedState)
            return@withLock false
        }
        val config = activeTransportConfig ?: return@withLock false
        runCatching { onTransportAttemptStarting?.invoke(pendingConnectEndpointId, pendingConnectKind) }
        try {
            activeTransport.connect(config)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            if (!isCurrentReconnect(generation)) return@withLock false
            diagnostics.recordError(VpnError.BackendStartFailure(e.javaClass.simpleName))
            setReconnectState(generation, TransportState.Error("Backend failed to restart"))
            return@withLock false
        }
        val terminalState = activeTransport.observeState().first {
            it is TransportState.Connected || it is TransportState.Error
        }
        if (!isCurrentReconnect(generation) || userInitiatedDisconnect) return@withLock false
        when (terminalState) {
            is TransportState.Connected -> true
            is TransportState.Error -> {
                setReconnectState(generation, terminalState)
                false
            }
            else -> false
        }
    }

    private fun isCurrentReconnect(generation: Long): Boolean =
        synchronized(reconnectOwnershipLock) { generation == reconnectGeneration }

    private fun setReconnectState(generation: Long, state: TransportState): Boolean =
        synchronized(reconnectOwnershipLock) {
            if (generation != reconnectGeneration) return@synchronized false
            setState(state)
            true
        }

    private fun cancelReconnectForExplicitConnect(): Boolean {
        val cancelledGeneration = synchronized(reconnectOwnershipLock) {
            if (reconnectJob?.isActive != true) return@synchronized null
            val oldGeneration = reconnectGeneration
            reconnectGeneration++
            reconnectJob?.cancel()
            reconnectJob = null
            oldGeneration
        }
        if (cancelledGeneration != null) {
            runCatching { onReconnectIncident?.invoke(ReconnectIncidentEvent.Disconnected(cancelledGeneration)) }
        }
        return cancelledGeneration != null
    }

    /** Caller must already hold connectMutex. */
    private fun cancelReconnectLocked() {
        val cancelledGeneration = synchronized(reconnectOwnershipLock) {
            val oldGeneration = reconnectGeneration
            reconnectGeneration++
            reconnectJob?.cancel()
            reconnectJob = null
            oldGeneration
        }
        runCatching { onReconnectIncident?.invoke(ReconnectIncidentEvent.Disconnected(cancelledGeneration)) }
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

/** B45B-4P (correction) - thrown by buildTransportConfig's SHADOWSOCKS_2022 branch; caught the SAME way XrayProfileNotReadyException already is (VpnError.ConfigurationMappingFailure), never a silent fallback to the AWG snapshot. */
private class ShadowsocksProfileNotReadyException(reason: String) : Exception(reason)

/** B46-4A - thrown by buildTransportConfig's HYSTERIA2 branch; caught the SAME way ShadowsocksProfileNotReadyException already is (VpnError.ConfigurationMappingFailure), never a silent fallback to the AWG snapshot or a hardcoded host/port. */
private class Hysteria2ProfileNotReadyException(reason: String) : Exception(reason)

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
