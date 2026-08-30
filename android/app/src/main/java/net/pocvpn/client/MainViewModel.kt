package net.pocvpn.client

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import net.pocvpn.client.diagnostics.DiagnosticsSnapshot
import net.pocvpn.client.diagnostics.DiagnosticsStore
import net.pocvpn.client.diagnostics.VpnError
import net.pocvpn.client.identity.ClientKeyRepository
import net.pocvpn.client.identity.ClientKeyRepositoryFactory
import net.pocvpn.client.identity.XrayProfileRepository
import net.pocvpn.client.identity.XrayProfileRepositoryFactory
import net.pocvpn.client.identity.XrayTlsProfileRepository
import net.pocvpn.client.identity.XrayTlsProfileRepositoryFactory
import net.pocvpn.client.network.NetworkProfile
import net.pocvpn.client.network.NetworkProfiler
import net.pocvpn.client.provisioning.ProvisioningClient
import net.pocvpn.client.provisioning.ProvisioningResult
import net.pocvpn.client.provisioning.ProvisioningUiState
import net.pocvpn.client.provisioning.XrayProfileProvisioner
import net.pocvpn.client.provisioning.XrayProfileProvisioningOutcome
import net.pocvpn.client.provisioning.XrayTlsProfileProvisioner
import net.pocvpn.client.smartconnect.AwgXrayFailoverPolicy
import net.pocvpn.client.smartconnect.ConnectionOutcome
import net.pocvpn.client.smartconnect.ConnectionOutcomeResult
import net.pocvpn.client.smartconnect.ConnectionOutcomeStore
import net.pocvpn.client.smartconnect.FileConnectionOutcomeStore
import net.pocvpn.client.smartconnect.GatewayReachabilityProbe
import net.pocvpn.client.smartconnect.HttpsGatewayReachabilityProbe
import net.pocvpn.client.smartconnect.RestrictionClass
import net.pocvpn.client.smartconnect.RestrictionClassifier
import net.pocvpn.client.smartconnect.RestrictionEvidence
import net.pocvpn.client.smartconnect.RestrictionMonitor
import net.pocvpn.client.smartconnect.SmartConnectCandidateSelector
import net.pocvpn.client.smartconnect.SmartConnectDecision
import net.pocvpn.client.smartconnect.TransportHealthCalculator
import net.pocvpn.client.smartconnect.TransportScorer
import net.pocvpn.client.smartconnect.TransportSelectionDecision
import net.pocvpn.client.transport.TransportCapabilities
import net.pocvpn.client.transport.TransportDescriptor
import net.pocvpn.client.transport.TransportHealth
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.transport.TransportOrchestrator
import net.pocvpn.client.transport.TransportRegistry
import net.pocvpn.client.transport.TransportStatus
import net.pocvpn.client.transport.UserTransportPreference
import net.pocvpn.client.vpn.AmneziaWgTransport
import net.pocvpn.client.vpn.AndroidReconnectManager
import net.pocvpn.client.vpn.ControllerEvent
import net.pocvpn.client.vpn.ReconnectManager
import net.pocvpn.client.vpn.TransportState
import net.pocvpn.client.vpn.VlessRealityTransport
import net.pocvpn.client.vpn.VlessTlsTransport
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
import net.pocvpn.client.vpn.xray.XrayRuntimeResolver
import net.pocvpn.client.vpn.xray.XrayTlsRuntimeResolution
import net.pocvpn.client.vpn.policy.AndroidInstalledPackageChecker
import net.pocvpn.client.vpn.policy.AppRoutingPolicy
import net.pocvpn.client.vpn.policy.AppRoutingPolicyStore
import net.pocvpn.client.vpn.policy.FileAppRoutingPolicyStore
import net.pocvpn.client.vpn.policy.InstalledPackageChecker

/**
 * B8I8A - everything needed to evaluate [AwgXrayFailoverPolicy] for ONE
 * connect() request, captured at resolution time and carried unchanged
 * across an async VPN-permission prompt so the LATER evaluation (in
 * [MainViewModel.onVpnPermissionResult]) uses the EXACT same context the
 * SYNCHRONOUS path would have used - never re-derived after the gap (Xray
 * availability, in particular, must reflect what was true FOR THIS REQUEST,
 * not whatever happens to be true whenever the user eventually responds to
 * the system permission dialog).
 */
private class PendingFailoverAttempt(
    val initialKind: TransportKind,
    val preference: UserTransportPreference,
    val registry: TransportRegistry,
    val orchestrator: TransportOrchestrator,
)

/**
 * Thin state holder above VpnController - MainActivity observes this instead
 * of owning tunnel/connection state itself, so Activity recreation (rotation,
 * process death+restore of the Activity only) doesn't lose or duplicate it.
 * VpnController is built here (not in the Factory) because it needs
 * viewModelScope, which only exists once this ViewModel instance exists.
 */
class MainViewModel(
    private val clientKeyRepository: ClientKeyRepository,
    // B8I1 - retained (not just a constructor-only param) so
    // smartConnectDecision() below can build a TransportRegistry from the
    // SAME real transport instance VpnController uses - never a second,
    // independently-constructed one.
    private val transport: VpnTransport,
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
    // B8I - additive, defaults to null (same reasoning as gatewayConfigOverride/
    // profileStore above). When non-null, started in init/stopped in
    // onCleared - see this class's own lifecycle block. NetworkProfiler
    // itself never touches VpnController/the tunnel (see its own docs) -
    // purely an observation layer.
    private val networkProfiler: NetworkProfiler? = null,
    // B8I - additive, defaults to null; the SAME instance VpnController
    // records real connection outcomes into (see controller construction
    // below) and this ViewModel reads back for diagnostics.
    private val connectionOutcomeStore: ConnectionOutcomeStore? = null,
    // B8I1 - additive test seam, defaults to null (production behavior
    // unchanged: still NetworkProfile.unavailable(0) until a real
    // NetworkProfiler is wired). NetworkProfiler is a concrete Android class
    // (real ConnectivityManager underneath) with no fake substitute
    // possible in a plain JVM test - this lets smartConnectDecision() be
    // proven end-to-end against a genuinely USABLE network fact without
    // constructing one.
    initialNetworkProfile: NetworkProfile? = null,
    // B8J - additive, defaults to null (same reasoning as networkProfiler/
    // connectionOutcomeStore above). When non-null, a RestrictionMonitor is
    // built from it (see below) and started in init/stopped in onCleared -
    // it never itself touches VpnController/VpnTransport (see its own docs).
    restrictionProbe: GatewayReachabilityProbe? = null,
    // B8M - additive, defaults to empty (same reasoning as restrictionProbe
    // above) - see RestrictionMonitor's own docs for why an empty list is a
    // safe, fully backward-compatible no-op (diverseInternetReachable stays
    // null forever, RestrictionClassifier's existing behavior is untouched).
    diverseReachabilityProbes: List<GatewayReachabilityProbe> = emptyList(),
    // B8K4B - additive, defaults to null (same reasoning as gatewayConfigOverride/
    // profileStore above): when non-null, activateDevice() below fetches and
    // persists an Xray VLESS+REALITY profile immediately after a successful
    // AWG activation, using the SAME activation credential and SAME existing
    // device public key - no second identity, no new credential. Does not
    // wire TransportRegistry/Smart Connect/VlessRealityTransport/
    // NovaXrayVpnService - see XrayProfileProvisioner's own docs.
    private val xrayProfileProvisioner: XrayProfileProvisioner? = null,
    // B8I7 - additive, defaults to null (same reasoning as gatewayConfigOverride/
    // profileStore above): when non-null, this is the SAME real
    // VlessRealityTransport instance registered in BOTH the Smart Connect
    // registry (buildTransportRegistry below) AND handed to VpnController as
    // its resolvable XRAY_REALITY executor - never a second, independently-
    // constructed instance. Still requires xrayAvailable (see below) before
    // its descriptor is ever AVAILABLE - constructing it is not the same as
    // it being usable.
    private val xrayTransport: VpnTransport? = null,
    // B8I7 - additive, defaults to null: the SAME XrayProfileRepository
    // instance xrayProfileProvisioner/VpnController/xrayTransport already
    // read from (see Factory) - used ONLY to check, at startup and again
    // the instant a fresh provisioning succeeds, whether a real persisted
    // Xray profile actually exists, so xrayTransport's registry-descriptor
    // availability reflects reality rather than a hardcoded true.
    private val xrayProfileRepository: XrayProfileRepository? = null,
    // B8O2 - additive, defaults to null (same reasoning as
    // xrayProfileProvisioner/xrayTransport/xrayProfileRepository above): the
    // TLS/TCP counterparts of each. Wiring these does NOT change automatic
    // Smart Connect selection/failover (see AwgXrayFailoverPolicy,
    // deliberately untouched) - see docs/ROADMAP.md's TLS/TCP fallback row.
    private val xrayTlsProfileProvisioner: XrayTlsProfileProvisioner? = null,
    private val xrayTlsTransport: VpnTransport? = null,
    private val xrayTlsProfileRepository: XrayTlsProfileRepository? = null,
    // B8I8 - additive, defaults to Auto (byte-for-byte unchanged production
    // behavior - no product UI sets anything else yet). Threaded into every
    // smartConnectDecision() call AND consulted by the AWG -> Xray failover
    // check below - a user who pins Manual(AMNEZIA_WG)/Manual(XRAY_REALITY)
    // gets exactly that transport, success or failure, never a silent
    // automatic substitute (see AwgXrayFailoverPolicy's own docs).
    private val userTransportPreference: UserTransportPreference = UserTransportPreference.Auto,
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
        connectionOutcomeStore = connectionOutcomeStore,
        xrayProfileRepository = xrayProfileRepository,
        xrayTlsProfileRepository = xrayTlsProfileRepository,
    )

    // B8I - CURRENT network facts only (see NetworkProfile's own docs for
    // why this is deliberately separate from connectionOutcomeStore's
    // HISTORICAL outcomes). Falls back to a static "no profiler wired"
    // unavailable value so this StateFlow is never null.
    val networkProfile: StateFlow<NetworkProfile> =
        networkProfiler?.profile ?: MutableStateFlow(initialNetworkProfile ?: NetworkProfile.unavailable(0)).asStateFlow()

    // B8I7 - flips true the moment a real Xray profile is CONFIRMED to
    // exist: checked once at startup (init block below, for a profile
    // persisted by a PRIOR session) and again the instant activateDevice()
    // saves a fresh one (XrayProfileProvisioningOutcome.Saved, below) -
    // never polled, never inferred from elapsed time. buildTransportRegistry()
    // reads this synchronously (a plain StateFlow.value read) so the
    // registry it builds always reflects the CURRENT truth.
    private val xrayAvailable = MutableStateFlow(false)

    // B8O2 - the TLS/TCP counterpart of [xrayAvailable] above: flips true
    // once a real TLS profile is CONFIRMED to exist (startup check + fresh
    // activateDevice() success), same "never polled" discipline.
    private val xrayTlsAvailable = MutableStateFlow(false)

    // B8O2-ops - debug-only override of [userTransportPreference], null by
    // default so production behavior (the constructor-supplied preference,
    // always Auto today - see Factory below) is completely unaffected. This
    // is the ONLY way to reach UserTransportPreference.Manual(TLS_TCP)
    // today (no product UI exposes transport selection yet) - it exercises
    // the EXISTING, already-safe SmartConnectDecisionEngine.decideManual
    // code path (the same one a future real "choose transport" screen would
    // use), never a bespoke bypass of connect()'s own resolution/support
    // checks. Does NOT change Auto's own PREFERRED_ORDER or
    // AwgXrayFailoverPolicy - no new automatic TLS failover is introduced by
    // this override existing.
    private val _debugTransportPreferenceOverride = MutableStateFlow<UserTransportPreference?>(null)
    val debugTransportPreferenceOverride: StateFlow<UserTransportPreference?> = _debugTransportPreferenceOverride.asStateFlow()
    private val effectiveTransportPreference: UserTransportPreference
        get() = _debugTransportPreferenceOverride.value ?: userTransportPreference

    /** Debug-only - see [_debugTransportPreferenceOverride]'s own docs. */
    fun debugSetTransportPreference(preference: UserTransportPreference?) {
        _debugTransportPreferenceOverride.value = preference
    }

    /**
     * B8O3 - the kind of the transport actually running/last attempted
     * (VpnController.currentTransportKind - set only when a resolved,
     * supported kind is actually handed to switchActiveTransport(), cleared
     * on disconnect()) - NEVER a fresh hypothetical smartConnectDecision()
     * pick. Diagnostics UI must read this, not recompute a new decision, to
     * avoid showing a transport that was never actually selected/running
     * for this session (see docs/ROADMAP.md's own diagnostics-gap note).
     */
    val currentTransportKind: StateFlow<TransportKind?> = controller.currentTransportKind

    // B8I8A/B8K6A - the CURRENT connect() request's retained failover
    // context, non-null from the moment a resolved AWG attempt starts until
    // its failover has been decided (once, ever) or the request is
    // superseded. Written ONLY by connect() (a fresh request always
    // supersedes/invalidates whatever was here), consumed (and ALWAYS
    // cleared first) ONLY by armFailoverWatch's own collector - see that
    // function's own docs for why clearing first is what makes a stale/
    // duplicate signal a safe no-op rather than a second fallback attempt.
    // disconnect() also clears this (a user-initiated cancellation abandons
    // any pending attempt). @Volatile: connect()/onVpnPermissionResult()/
    // disconnect() are independent viewModelScope.launch bodies - a plain
    // field write in one must be visible to a read in another.
    @Volatile private var pendingFailoverAttempt: PendingFailoverAttempt? = null

    // B8K6A - the single live collector (if any) currently watching
    // controller.state on behalf of [pendingFailoverAttempt]. Tracked so
    // every place that invalidates the attempt (a NEW connect() request,
    // disconnect(), permission denial, or the watch's own successful/stale
    // completion) can also stop the collector deterministically instead of
    // leaving it running for the rest of this ViewModel's lifetime.
    @Volatile private var failoverObserverJob: Job? = null

    // B8K6A - the ONE place both halves of the retained failover context
    // (the attempt object AND its observer coroutine) are torn down
    // together, so neither can ever exist without the other.
    private fun clearFailoverWatch() {
        pendingFailoverAttempt = null
        failoverObserverJob?.cancel()
        failoverObserverJob = null
    }

    /**
     * B8I1/B8I7 - built FRESH on every call (never cached as a field) so
     * XRAY_REALITY's AVAILABLE/NOT_IMPLEMENTED status always reflects the
     * CURRENT [xrayAvailable] signal, same "no caching" discipline
     * [smartConnectDecision] itself already documents. The factory closures
     * always return the SAME already-constructed `transport`/[xrayTransport]
     * instances - rebuilding this registry object never constructs a new
     * transport instance, so selection (smartConnectDecision) and execution
     * (connect()'s own orchestrator, built from THIS SAME function) can
     * never end up looking at two different Xray instances.
     *
     * `internal` (not private) so tests can inspect the exact descriptors
     * this produces directly, without needing a real Android Context to
     * drive smartConnectDecision()/connect() end to end.
     */
    internal fun buildTransportRegistry(): TransportRegistry {
        val descriptors = mutableListOf(
            TransportDescriptor(kind = transport.kind, status = TransportStatus.AVAILABLE, capabilities = transport.capabilities, factory = { transport }),
        )
        val xray = xrayTransport
        if (xray != null) {
            val available = xrayAvailable.value
            descriptors += TransportDescriptor(
                kind = xray.kind,
                status = if (available) TransportStatus.AVAILABLE else TransportStatus.NOT_IMPLEMENTED,
                capabilities = if (available) xray.capabilities else TransportCapabilities.notImplemented(),
                factory = if (available) ({ xray }) else null,
            )
        }
        // B8O2 - same shape as XRAY_REALITY above. Registering this as
        // AVAILABLE does NOT make it an automatic Smart Connect pick today:
        // SmartConnectDecisionEngine's Auto path always prefers AMNEZIA_WG
        // (always AVAILABLE, first in PREFERRED_ORDER) and AwgXrayFailoverPolicy
        // never names TLS_TCP - it only becomes selectable via an explicit
        // UserTransportPreference.Manual(TLS_TCP) or a future, deliberate
        // failover decision - see docs/ROADMAP.md's own safety-boundary note.
        val xrayTls = xrayTlsTransport
        if (xrayTls != null) {
            val available = xrayTlsAvailable.value
            descriptors += TransportDescriptor(
                kind = xrayTls.kind,
                status = if (available) TransportStatus.AVAILABLE else TransportStatus.NOT_IMPLEMENTED,
                capabilities = if (available) xrayTls.capabilities else TransportCapabilities.notImplemented(),
                factory = if (available) ({ xrayTls }) else null,
            )
        }
        return TransportRegistry.build(descriptors)
    }

    /**
     * B8I1 - THE single call site for THE ONE Smart Connect decision
     * authority (SmartConnectCandidateSelector, which itself reuses
     * SmartConnectDecisionEngine for the transport sub-decision - see both
     * classes' own docs). Recomputed fresh from CURRENT network/gateway
     * facts on every read (same no-caching pattern as gatewayStatus()
     * below) - never a stale cached decision. restrictionClass() below is
     * carried through TRUTHFULLY (see ConnectionScore's own docs) but never
     * changes WHICH candidate is selected - no restriction-driven switching.
     */
    fun smartConnectDecision(): SmartConnectDecision = SmartConnectCandidateSelector.decide(
        networkProfile = networkProfile.value,
        gatewayCandidates = SmartConnectCandidateSelector.productionGatewayCandidates(gatewayStatus()),
        registry = buildTransportRegistry(),
        preference = effectiveTransportPreference,
        health = transportHealth(),
        connectionHistory = recentConnectionOutcomes(),
        restrictionClass = restrictionClass(),
    )

    /** B8I - DEBUG diagnostics only; bounded by connectionOutcomeStore's own maxRecords. */
    fun recentConnectionOutcomes(): List<ConnectionOutcome> = connectionOutcomeStore?.recent().orEmpty()

    /**
     * B8L - THE ONLY place a TransportHealth is computed for this
     * ViewModel (see TransportHealthCalculator's own docs) - real,
     * evidence-based per-kind health from the SAME connectionOutcomeStore
     * history recentConnectionOutcomes()/restrictionClass() already read,
     * never a second store. Recomputed fresh on every read, same
     * no-caching pattern as smartConnectDecision()/restrictionClass().
     * Carried into smartConnectDecision()'s `health` parameter, which
     * SmartConnectDecisionEngine.decide() does not yet act on for
     * selection - same "truthfully surfaced, not yet decision-driving"
     * boundary restrictionClass() already established.
     */
    fun transportHealth(): Map<TransportKind, TransportHealth> {
        val outcomes = recentConnectionOutcomes()
        return TransportKind.entries.associateWith { kind -> TransportHealthCalculator.fromOutcomes(outcomes, kind) }
    }

    /**
     * B8N - real TransportScorer.score() over each registered kind's
     * ACTUAL TransportCapabilities (buildTransportRegistry() - never a
     * fabricated capability set) and REAL TransportHealth (transportHealth()
     * above, same store). Recomputed fresh on every read, same no-caching
     * pattern as transportHealth()/smartConnectDecision(). Deliberately
     * NOT passed into smartConnectDecision() - see TransportScorer's own
     * "not yet decision-driving" docs.
     */
    fun transportScores(): Map<TransportKind, Int> {
        val health = transportHealth()
        return buildTransportRegistry().all().associate { descriptor ->
            descriptor.kind to TransportScorer.score(descriptor.kind, descriptor.capabilities, health.getValue(descriptor.kind))
        }
    }

    // B8J - built ONLY when a probe was actually wired (production: always,
    // via the Factory below) - null means "no probing at all", same
    // additive-seam shape as networkProfiler/connectionOutcomeStore.
    private val restrictionMonitor = restrictionProbe?.let { RestrictionMonitor(it, viewModelScope, diverseReachabilityProbes) }

    /**
     * B8J - THE ONLY place a RestrictionClass is computed for this
     * ViewModel, assembled purely from evidence already available
     * elsewhere (see RestrictionEvidence's own field list: NetworkProfiler's
     * current facts, VpnController's current state, the MOST RECENT real
     * ConnectionOutcome, and the MOST RECENT bounded probe result - never a
     * fresh probe run synchronously here). Recomputed fresh on every read,
     * same no-caching pattern as gatewayStatus()/smartConnectDecision().
     */
    fun restrictionClass(): RestrictionClass = RestrictionClassifier.classify(
        RestrictionEvidence(
            networkProfile = networkProfile.value,
            transportState = transportState.value,
            awgHandshakeFresh = recentConnectionOutcomes().lastOrNull()?.let { it.result == ConnectionOutcomeResult.SUCCESS },
            gatewayHttpsReachable = restrictionMonitor?.lastProbeResult?.value,
            diverseInternetReachable = restrictionMonitor?.lastDiverseReachabilityResult?.value,
        ),
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

    // B8K4B - null until the first activateDevice() call that reaches Xray
    // provisioning (i.e. only after a successful AWG activation, and only
    // when xrayProfileProvisioner is wired). See XrayProfileProvisioningOutcome
    // for what each state means.
    private val _xrayProfileProvisioningState = MutableStateFlow<XrayProfileProvisioningOutcome?>(null)
    val xrayProfileProvisioningState: StateFlow<XrayProfileProvisioningOutcome?> = _xrayProfileProvisioningState.asStateFlow()

    // B8O2-ops - the outcome of the LAST standalone provisionTlsProfile()
    // call (see that function's own docs). Separate from
    // xrayProfileProvisioningState above since this can be triggered
    // independently of a fresh AWG activation (a device already activated
    // in an earlier session has no reachable ActivationScreen - see
    // screenFor's own gate - so this is the only way such a device can
    // (re)fetch its TLS profile without a destructive reset).
    private val _tlsProfileProvisioningState = MutableStateFlow<XrayProfileProvisioningOutcome?>(null)
    val tlsProfileProvisioningState: StateFlow<XrayProfileProvisioningOutcome?> = _tlsProfileProvisioningState.asStateFlow()

    init {
        viewModelScope.launch {
            _publicKey.value = clientKeyRepository.getPublicKey()
        }
        restorePersistedProfile()
        // B8I7 - one-time startup check: does a real Xray profile already
        // exist from a PRIOR session? Never polled again after this - the
        // only other place xrayAvailable changes is the real
        // XrayProfileProvisioningOutcome.Saved event in activateDevice()
        // below.
        xrayProfileRepository?.let { repository ->
            viewModelScope.launch {
                xrayAvailable.value = try {
                    repository.getProfileOrNull() != null
                } catch (t: Throwable) {
                    false
                }
            }
        }
        // B8O2 fix - a decryptable-but-invalid stored profile must NOT
        // register TLS_TCP as AVAILABLE: this uses the SAME authoritative
        // validation XrayCoreController/VlessTlsTransport actually run at
        // connect time (XrayRuntimeResolver.resolveTls) - never a
        // duplicated/looser "profile exists" check that could disagree with
        // what connect() itself will accept.
        xrayTlsProfileRepository?.let { repository ->
            viewModelScope.launch {
                xrayTlsAvailable.value = XrayRuntimeResolver.resolveTls(repository) is XrayTlsRuntimeResolution.Ready
            }
        }
        // B8I - mirrors reconnectManager's own start()-in-init/stop()-in-
        // onCleared lifecycle (see VpnController's own reconnectManager.start
        // call and this class's onCleared below) - registered exactly once
        // per ViewModel instance, unregistered exactly once.
        networkProfiler?.start()
        // B8J - same lifecycle pattern. Probes only on real transportState/
        // networkProfile transitions (see RestrictionMonitor's own docs) -
        // never a timer, never continuous polling.
        restrictionMonitor?.start(transportState, networkProfile)
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
                    // B8K4B - runs only after the AWG activation above has
                    // already fully succeeded (applied + persisted). Reuses
                    // the SAME `key`/`trimmedCredential` this activation call
                    // used - no second identity, no new credential. Any
                    // outcome other than Saved (network error/401/403/503/
                    // malformed) leaves this AWG success and any previously
                    // stored Xray profile completely untouched - see
                    // XrayProfileProvisioner's own docs.
                    xrayProfileProvisioner?.let { provisioner ->
                        val outcome = withContext(ioDispatcher) {
                            provisioner.provision(key, trimmedCredential)
                        }
                        _xrayProfileProvisioningState.value = outcome
                        if (outcome == XrayProfileProvisioningOutcome.Saved) {
                            // B8I7 - the real, event-driven moment Xray
                            // becomes selectable - never polled, never
                            // inferred from elapsed time (see xrayAvailable's
                            // own docs).
                            xrayAvailable.value = true
                        }
                    }
                    // B8O2 - same reasoning as xrayProfileProvisioner above:
                    // runs only after the AWG activation has already fully
                    // succeeded, reusing the SAME key/credential, and never
                    // touches AWG's own success/state either way.
                    xrayTlsProfileProvisioner?.let { provisioner ->
                        val tlsOutcome = withContext(ioDispatcher) {
                            provisioner.provision(key, trimmedCredential)
                        }
                        // B8O2 fix - re-derive from the SAME authoritative
                        // resolveTls() check the startup path uses (see its
                        // own docs), rather than assuming a structurally-
                        // valid-at-the-wire Saved outcome is automatically
                        // connect()-ready - one validation authority, never
                        // two rules that could silently disagree.
                        if (tlsOutcome == XrayProfileProvisioningOutcome.Saved) {
                            val repository = xrayTlsProfileRepository
                            if (repository != null) {
                                xrayTlsAvailable.value = XrayRuntimeResolver.resolveTls(repository) is XrayTlsRuntimeResolution.Ready
                            }
                        }
                    }
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

    /**
     * B8O2-ops - debug-only standalone TLS profile (re)fetch for a device
     * that is ALREADY activated (see DiagnosticsDialog's own gate - this is
     * only ever reachable from the debug diagnostics surface, never the
     * normal onboarding flow). Reuses the EXISTING device identity/public
     * key and the EXISTING [xrayTlsProfileProvisioner] - creates no new
     * activation, no new identity, and never touches AWG/REALITY state.
     * Exists specifically because a device activated in an earlier session
     * has no reachable [net.pocvpn.client.ui.screens.ActivationScreen] (see
     * `screenFor`'s own profileSource gate) to re-run [activateDevice]
     * through, yet the SAME activation credential is exactly what
     * POST /v1/xray-profile?transport=tls still requires - this is the
     * narrowest addition that lets an already-activated device obtain a TLS
     * profile without a destructive identity reset.
     */
    fun provisionTlsProfile(activationCredential: String) {
        val trimmedCredential = activationCredential.trim()
        val provisioner = xrayTlsProfileProvisioner
        val key = _publicKey.value
        if (trimmedCredential.isEmpty() || provisioner == null || key == null) {
            _tlsProfileProvisioningState.value = XrayProfileProvisioningOutcome.Malformed("credential/public key/provisioner not ready")
            return
        }
        viewModelScope.launch {
            val outcome = withContext(ioDispatcher) { provisioner.provision(key, trimmedCredential) }
            _tlsProfileProvisioningState.value = outcome
            if (outcome == XrayProfileProvisioningOutcome.Saved) {
                val repository = xrayTlsProfileRepository
                if (repository != null) {
                    // B8O2 fix - same single validation authority as the
                    // startup/activateDevice paths (see their own docs).
                    xrayTlsAvailable.value = XrayRuntimeResolver.resolveTls(repository) is XrayTlsRuntimeResolution.Ready
                }
            }
        }
    }

    fun gatewayStatus(): GatewayConfiguration = controller.gatewayStatus()

    /**
     * B8I4/B8I7/B8I8 - Smart Connect preflight: a fresh smartConnectDecision()
     * (THE single decision authority - see that function's own docs) is
     * obtained immediately before every connect attempt. The ALREADY-
     * selected kind is then handed to a TransportOrchestrator built from a
     * SECOND buildTransportRegistry() call - two separate registry OBJECTS,
     * but built back-to-back with no suspension in between and from the
     * exact same underlying state (xrayAvailable.value, the transport
     * instances themselves), so they are guaranteed to describe the SAME
     * availability/instances - selection and execution can never disagree
     * within one connect() attempt. A resolved candidate is handed STRAIGHT to
     * controller.connect(resolution) - VpnController itself is the one
     * place that validates whether IT can safely execute that exact
     * resolution (per-attempt execution boundary - see its own docs) and
     * fails closed via rejectPreflight() if not. Every other outcome
     * (NoCandidateAvailable, or an unresolvable kind) still fails closed
     * here via VpnController.rejectPreflight() before controller.connect()
     * is ever reached - no VPN permission is requested, no VPN service is
     * started.
     *
     * B8I8/B8I8A/B8K6A - after controller.connect(resolution) SETTLES
     * SYNCHRONOUSLY (no VPN permission was needed), armFailoverWatch() below
     * starts watching controller.state for THIS attempt immediately. If a
     * permission prompt is needed instead, watching is deferred: the exact
     * context (kind/preference/registry/orchestrator) is already retained in
     * [pendingFailoverAttempt] by then, and onVpnPermissionResult() is what
     * starts the watch once the user actually responds - see that function's
     * own docs. Either way, [AwgXrayFailoverPolicy] is consulted against
     * every state controller.state reaches for this attempt (its immediate
     * synchronous outcome AND any later asynchronous one - e.g. a real AWG
     * session that briefly reports Connected before an eligible terminal
     * failure arrives - see armFailoverWatch's own docs) but ACTS on it
     * EXACTLY ONCE per connect() request.
     */
    fun connect() {
        viewModelScope.launch {
            // B8I8A - a NEW connect() request always supersedes/invalidates
            // any still-pending permission/failover context (and stops
            // watching for it) from an EARLIER, unresolved request - a later
            // permission result or async state change for that OLD request
            // must never reuse it.
            clearFailoverWatch()
            when (val decision = smartConnectDecision()) {
                is SmartConnectDecision.Selected -> {
                    val kind = decision.score.candidate.transport.kind
                    val registry = buildTransportRegistry()
                    val orchestrator = TransportOrchestrator(registry)
                    when (val resolution = orchestrator.resolve(TransportSelectionDecision.SelectTransport(kind))) {
                        is TransportOrchestrator.Resolution.Resolved -> {
                            // B8I8A - checked BEFORE connect() (same
                            // side-effect-free query VpnController.connect()
                            // itself performs immediately after, on the SAME
                            // instance, with no suspension in between - see
                            // VpnTransport.preparePermissionIntent's own
                            // contract) so this ViewModel knows, without
                            // guessing, whether THIS attempt will settle
                            // synchronously or pause for the user.
                            val permissionPending = resolution.transport.preparePermissionIntent() != null
                            val attempt = PendingFailoverAttempt(
                                initialKind = kind,
                                preference = effectiveTransportPreference,
                                registry = registry,
                                orchestrator = orchestrator,
                            )
                            pendingFailoverAttempt = attempt
                            controller.connect(resolution)
                            if (!permissionPending) {
                                // Already fully settled synchronously (or
                                // will settle/transition asynchronously from
                                // here on) - start watching now, exactly like
                                // every pre-B8K6A connect() attempt started
                                // its ONE synchronous check now.
                                armFailoverWatch(attempt)
                            }
                            // else: RequestVpnPermission was just emitted -
                            // wait for onVpnPermissionResult() to resume this
                            // SAME attempt and start watching then.
                        }
                        is TransportOrchestrator.Resolution.NotSelectable -> {
                            controller.rejectPreflight(
                                VpnError.UnsupportedTransportSelected(kind.name),
                                "Selected transport ($kind) could not be resolved",
                            )
                        }
                    }
                }
                SmartConnectDecision.NoCandidateAvailable -> {
                    controller.rejectPreflight(VpnError.NoCandidateAvailable, "No connection candidate available")
                }
            }
        }
    }

    /**
     * B8I8 - the ONE call site for the controlled AWG -> Xray failover logic:
     * consults [AwgXrayFailoverPolicy] (the ONE eligibility authority - this
     * function never re-implements or second-guesses that rule) using the
     * CURRENT controller.state/diagnostics snapshot, which truthfully reflect
     * THIS attempt's own outcome (see that policy's own docs on why both are
     * required together) and the RETAINED [preference]/[registry]/[orchestrator]
     * for the request being evaluated - never freshly recomputed, so a
     * permission-prompt-delayed evaluation still judges the SAME request it
     * started with. On a genuine eligible failure: the failed AWG attempt is
     * cleanly detached first (controller.disconnect() - reusing the EXISTING
     * active-transport teardown, never a bespoke one) so AWG and Xray can
     * never be active concurrently, THEN the SAME production XRAY_REALITY
     * instance is resolved from [registry]/[orchestrator] (never re-built,
     * never a second/independent instance) and executed via the SAME
     * per-attempt execution boundary (controller.connect(resolution)) every
     * other attempt uses - no bespoke Xray-only code path. Called from
     * exactly one place per connect() request (armFailoverWatch()'s own
     * collector, which acts at most once per attempt - see its own docs) -
     * a failed Xray fallback surfaces its own truthful terminal state and
     * nothing more (no retry, no bounce back to AWG).
     */
    private suspend fun maybeFailoverToXray(
        initialKind: TransportKind,
        preference: UserTransportPreference,
        registry: TransportRegistry,
        orchestrator: TransportOrchestrator,
    ) {
        val eligible = AwgXrayFailoverPolicy.isEligibleForXrayFallback(
            initialKind = initialKind,
            preference = preference,
            awgState = controller.state.value,
            awgError = diagnosticsStore.snapshot.value.lastError,
            xrayAvailable = registry.descriptorFor(TransportKind.XRAY_REALITY)?.status == TransportStatus.AVAILABLE,
        )
        if (!eligible) return

        when (val xrayResolution = orchestrator.resolve(TransportSelectionDecision.SelectTransport(TransportKind.XRAY_REALITY))) {
            is TransportOrchestrator.Resolution.Resolved -> {
                controller.disconnect()
                controller.connect(xrayResolution)
            }
            // Defensive only: xrayAvailable already guarantees the registry
            // has a real, resolvable XRAY_REALITY descriptor at this point.
            is TransportOrchestrator.Resolution.NotSelectable -> Unit
        }
    }

    /**
     * B8K6A - the ONE place [pendingFailoverAttempt] is watched and (at most
     * once) consumed, from BOTH connect() (when no permission prompt was
     * needed) and onVpnPermissionResult() (when one was) - a single shared
     * path, never a duplicated copy of the failover-triggering logic.
     *
     * Fixes the confirmed physical-device gap: a real AWG session can report
     * Connected (interface/handshake momentarily up) and only LATER settle
     * into an eligible terminal failure asynchronously, via a controller.state
     * emission that arrives after this function's caller has already
     * returned - a single immediate check right after connect() returns (the
     * pre-B8K6A behavior) can miss that later transition entirely. Instead,
     * this collects controller.state - the SAME hot StateFlow every other
     * consumer already observes, no second/competing observation mechanism -
     * for as long as [attempt] remains THE current pending one. StateFlow
     * replays its current value immediately on subscription, so the FIRST
     * collected value is always this attempt's synchronous outcome (byte-
     * for-byte the same fast path as before); every value after that is a
     * genuine later transition, checked against the exact SAME policy and
     * the exact SAME retained [attempt] context (never re-derived).
     *
     * Guarded against duplicate/stale activity two ways: (1) a no-op if a
     * watch for this exact attempt is already running (a stale/duplicate
     * onVpnPermissionResult() call for an attempt still being watched never
     * starts a second collector); (2) every collected emission first checks
     * `pendingFailoverAttempt === attempt` - once a NEWER connect() request,
     * disconnect(), or permission denial has cleared/replaced the context
     * (see clearFailoverWatch()), this collector sees the mismatch and stops
     * itself, so a stale emission from an OLD/superseded request can never
     * act. On a genuine eligible emission, the attempt is cleared (so
     * nothing else can also act on it) BEFORE [maybeFailoverToXray] runs,
     * and the collector stops itself only AFTER that call returns - it is
     * never cancelled out from under its own in-flight fallback attempt.
     */
    private fun armFailoverWatch(attempt: PendingFailoverAttempt) {
        if (failoverObserverJob?.isActive == true) return
        failoverObserverJob = viewModelScope.launch {
            controller.state.collect { state ->
                if (pendingFailoverAttempt !== attempt) {
                    failoverObserverJob?.cancel()
                    failoverObserverJob = null
                    return@collect
                }
                val eligible = AwgXrayFailoverPolicy.isEligibleForXrayFallback(
                    initialKind = attempt.initialKind,
                    preference = attempt.preference,
                    awgState = state,
                    awgError = diagnosticsStore.snapshot.value.lastError,
                    xrayAvailable = attempt.registry.descriptorFor(TransportKind.XRAY_REALITY)?.status == TransportStatus.AVAILABLE,
                )
                if (!eligible) return@collect
                pendingFailoverAttempt = null
                maybeFailoverToXray(
                    initialKind = attempt.initialKind,
                    preference = attempt.preference,
                    registry = attempt.registry,
                    orchestrator = attempt.orchestrator,
                )
                failoverObserverJob?.cancel()
                failoverObserverJob = null
            }
        }
    }

    fun disconnect() {
        // B8I8A - a user-initiated disconnect/cancellation abandons any
        // pending attempt this ViewModel was tracking - never resume a
        // stale context, and never keep watching, for a request the user no
        // longer wants acted on.
        clearFailoverWatch()
        viewModelScope.launch { controller.disconnect() }
    }

    /**
     * B8I8A/B8K6A - resumes the SAME connect() request armFailoverWatch's
     * synchronous path already handles when no permission prompt was needed:
     * granted -> let controller.onVpnPermissionResult(true) finish the
     * pending initial attempt (exactly as before B8I8A), THEN start
     * watching the retained failover context via armFailoverWatch() - the
     * SAME shared function connect() itself uses, never a duplicated copy of
     * the failover logic. Denied -> permission denial must never trigger
     * fallback (per policy/product semantics) - only discards any retained
     * context/watch, evaluation never runs.
     */
    fun onVpnPermissionResult(granted: Boolean) {
        viewModelScope.launch {
            controller.onVpnPermissionResult(granted)
            if (granted) {
                pendingFailoverAttempt?.let { armFailoverWatch(it) }
            } else {
                clearFailoverWatch()
            }
        }
    }

    fun regenerateIdentity() {
        viewModelScope.launch {
            clientKeyRepository.clearIdentity()
            _publicKey.value = clientKeyRepository.getOrCreateIdentity().publicKeyBase64
        }
    }

    override fun onCleared() {
        controller.shutdown()
        // B8I - no leak: unregisters the SAME ConnectivityManager callback
        // start() registered above (see NetworkProfiler.stop's own docs).
        networkProfiler?.stop()
        // B8J - cancels the observe loop AND any in-flight probe.
        restrictionMonitor?.stop()
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
            // B8I - same noBackupFilesDir as the stores above, different
            // file: bounded technical connection-metadata history (see
            // ConnectionOutcomeStore's own privacy docs), still device-
            // specific rather than something a cross-device restore should
            // silently reapply.
            val connectionOutcomeStore = FileConnectionOutcomeStore(context.noBackupFilesDir)
            // B8I7 - the ONE authoritative Xray profile repository instance -
            // shared by the provisioner, VpnController's config builder, and
            // xrayTransport's own pre-flight check (see each class's own
            // docs) - never a second, independently-constructed store.
            val xrayProfileRepository = XrayProfileRepositoryFactory.create(context)
            // B8O2 - the TLS/TCP counterpart of xrayProfileRepository above -
            // its own independent store/AndroidKeyStore alias (see
            // XrayTlsProfileRepositoryFactory's own docs), shared by its own
            // provisioner and xrayTlsTransport's own pre-flight check.
            val xrayTlsProfileRepository = XrayTlsProfileRepositoryFactory.create(context)
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
                networkProfiler = NetworkProfiler(context),
                connectionOutcomeStore = connectionOutcomeStore,
                // B8J - the one pinned gateway's HTTPS probe (see its own
                // docs) - default timeout/URL, no credentials/keys involved.
                restrictionProbe = HttpsGatewayReachabilityProbe(),
                // B8M - three diverse, unrelated, well-known real HTTPS
                // destinations (different vendors/infra), reusing the SAME
                // plain HEAD-request probe mechanism as restrictionProbe
                // above - no credentials, no pocvpn data, never the same
                // host as the gateway probe. Each is itself a standard
                // OS/browser connectivity-check endpoint (Google/Apple/
                // Mozilla each already probe their own for exactly this
                // purpose) - an honest reachability check, never an
                // impersonation of any of them (architecture principle 4).
                diverseReachabilityProbes = listOf(
                    HttpsGatewayReachabilityProbe(urlString = "https://connectivitycheck.gstatic.com/generate_204"),
                    HttpsGatewayReachabilityProbe(urlString = "https://captive.apple.com/hotspot-detect.html"),
                    HttpsGatewayReachabilityProbe(urlString = "https://detectportal.firefox.com/success.txt"),
                ),
                xrayProfileProvisioner = XrayProfileProvisioner(xrayProfileRepository),
                // B8I7 - the SAME real VlessRealityTransport instance is
                // registered for BOTH Smart Connect selection
                // (buildTransportRegistry) and execution
                // (VpnController.connect(resolved)/TransportOrchestrator) -
                // never a second, independently-constructed one.
                xrayTransport = VlessRealityTransport(context, xrayProfileRepository),
                xrayProfileRepository = xrayProfileRepository,
                // B8O2 - same reasoning as xrayTransport/xrayProfileRepository
                // above, for TLS/TCP: the SAME real VlessTlsTransport instance
                // is registered for BOTH Smart Connect selection and execution.
                xrayTlsProfileProvisioner = XrayTlsProfileProvisioner(xrayTlsProfileRepository),
                xrayTlsTransport = VlessTlsTransport(context, xrayTlsProfileRepository),
                xrayTlsProfileRepository = xrayTlsProfileRepository,
            ) as T
        }
    }
}
