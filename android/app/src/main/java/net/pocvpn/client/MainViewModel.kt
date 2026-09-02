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
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
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
import net.pocvpn.client.vpn.blocksGatewaySelection
import net.pocvpn.client.vpn.VlessRealityTransport
import net.pocvpn.client.vpn.VlessTlsTransport
import net.pocvpn.client.vpn.VpnController
import net.pocvpn.client.vpn.VpnTransport
import net.pocvpn.client.vpn.config.BuildConfigGatewaySource
import net.pocvpn.client.vpn.config.DefaultGatewayConfigurationRepository
import net.pocvpn.client.vpn.config.FileProfileStore
import net.pocvpn.client.vpn.config.GatewayConfiguration
import net.pocvpn.client.vpn.config.GatewayConfigurationRepository
import net.pocvpn.client.vpn.config.toGatewayConfigSnapshot
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
import net.pocvpn.client.vpn.policy.FileRoutingModeStore
import net.pocvpn.client.vpn.policy.InstalledPackageChecker
import net.pocvpn.client.vpn.policy.RoutingMode
import net.pocvpn.client.vpn.policy.RoutingModeStore

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
    // B13 - the SAME endpoint the initial (pre-failover) attempt targeted -
    // a Xray fallback for a real second gateway must stay ON that gateway,
    // never silently jump back to a different endpoint's default.
    val endpointId: net.pocvpn.client.reachability.EndpointId,
    // B16 - non-null exactly when this attempt is part of an automatic
    // gateway-selection sequence - see [PendingAutoGatewayContext]'s own
    // docs. null (the default) means "manual gateway, existing intra-gateway
    // AWG->Xray failover only" - byte-for-byte the pre-B16 shape.
    val autoContext: PendingAutoGatewayContext? = null,
    // B24 review fix (PR #38, round 3) - non-null exactly when this attempt
    // is a RELAYED combined-Auto candidate (see RelayIngressResolver's own
    // docs). Lets armFailoverWatch's SAME real controller.state observation
    // record the terminal outcome under the correct FULL relayed
    // historyPathId (never a single-hop endpoint id) and route a failure
    // back into the combined coordinator - a relay attempt has no AWG<->Xray
    // intra-gateway concept, so this also skips that branch entirely. null
    // (the default) is byte-for-byte the pre-B24 Direct/Manual shape.
    val relayPlan: net.pocvpn.client.relay.RelayedExecutionPlan? = null,
    // B25 (task C) - the SAME already-matched IngressClientProfile
    // [RelayIngressResolution.Resolved] carried for this attempt (see that
    // type's own docs) - pinned here so armFailoverWatch's real end-to-end
    // probe never has to re-resolve the ingress profile store mid-attempt.
    // Always non-null exactly when [relayPlan] is non-null.
    val relayProfile: net.pocvpn.client.relay.IngressClientProfile? = null,
)

/**
 * B16/B24 - the retained context an automatic-gateway connect() sequence
 * needs to advance past a failed candidate: the FULL COMBINED (Direct +
 * Relayed) ranked attempt list (built once, at the start of the sequence -
 * never rebuilt mid-sequence, so a later candidate is never silently
 * re-scored against evidence that changed because of the very failure being
 * handled) and which [net.pocvpn.client.smartconnect.AutoGatewaySelector
 * .AutoConnectAttempt.attemptKey]s have already been attempted this
 * request.
 *
 * B24 review fix (PR #38) - this used to carry a DIRECT-ONLY candidate list/
 * attempted-set, which made [attemptAutoCandidate] "own" the rest of the
 * Direct sequence on its own terminal failure (`NotSelectable`, or a real
 * async failure observed by [armFailoverWatch]) - silently skipping any
 * higher-ranked Relayed candidate in between and defeating the shared
 * [net.pocvpn.client.smartconnect.AutoGatewaySelector.MAX_ATTEMPTS] budget
 * this class's own docs already claimed. Now carries the SAME combined
 * `(attempts, attemptedKeys)` shape [attemptCombined] itself operates on, so
 * EVERY terminal-failure path (this class's synchronous `NotSelectable`
 * branch and [armFailoverWatch]'s asynchronous one) reports back into
 * [attemptCombined] - the ONE bounded progression authority for the whole
 * request, regardless of candidate shape.
 */
private class PendingAutoGatewayContext(
    val combinedAttempts: List<net.pocvpn.client.smartconnect.AutoGatewaySelector.AutoConnectAttempt>,
    val combinedAttemptedKeys: Set<String>,
)

/**
 * B16 - compact, truthful diagnostics for the automatic gateway decision
 * (task requirement 10): the ranked candidate list, which one is currently
 * targeted, the full attempt history for this request, the most recent
 * failure's category, and whether the bounded candidate set has been
 * exhausted. Never carries a secret/credential field - every field here is
 * already one this codebase's own diagnostics surfaces expose elsewhere
 * (GatewayAttemptCandidate/VpnError's own types structurally carry none).
 */
data class AutoGatewayDiagnostics(
    val rankedCandidates: List<net.pocvpn.client.smartconnect.GatewayAttemptCandidate>,
    val attempted: List<net.pocvpn.client.smartconnect.GatewayAttemptCandidate>,
    val current: net.pocvpn.client.smartconnect.GatewayAttemptCandidate?,
    val lastFailureReason: String?,
    val exhausted: Boolean,
)

/**
 * B28 (requirement 10) - one ranked entry from [MainViewModel
 * .combinedAutoRankingDiagnostics]. [kind] is one of "DIRECT", "CHAIN_DIRECT",
 * "CHAIN_CDN" - never an endpoint id/host. [reasons] is filtered to the
 * stable [net.pocvpn.client.reachability.PathScorer.Reason] token names only
 * (the free-text entries [PathScorer] also appends, e.g. "reachability=...",
 * are deliberately dropped here even though they carry no secret either -
 * this surface stays token-only so it never needs re-auditing if a future
 * free-text entry starts embedding something sensitive).
 */
data class CombinedAttemptDiagnostic(
    val kind: String,
    val score: Long,
    val reasons: List<String>,
)

/**
 * B28 (requirement 10) - the restriction evidence in effect for this read,
 * plus the ranked attempt list it influenced - see
 * [MainViewModel.combinedAutoRankingDiagnostics]'s own docs for the
 * no-secrets contract.
 */
data class CombinedAutoRankingDiagnostics(
    val restrictionClass: net.pocvpn.client.smartconnect.RestrictionClass,
    val ranked: List<CombinedAttemptDiagnostic>,
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
    // B14 - Stockholm's OWN activation client. Real by default (mirrors
    // [activationClient] immediately above, never a null "not wired" seam)
    // so production/every non-test call site genuinely attempts a request
    // to Stockholm's own edge without needing explicit Factory wiring - see
    // MainViewModel's own docs for why this is a SEPARATE function value
    // rather than [activationClient] itself parameterized by a target host:
    // [activationClient] stays exactly 2-arg so every pre-B14 test/call
    // site (including `ProvisioningClient::activate` used as a bare
    // function reference) stays byte-for-byte unchanged. Stockholm has no
    // deployed control-plane today, so this genuinely fails closed with a
    // real [ProvisioningResult.NetworkError] (connection refused/TLS
    // failure/timeout) until an operator deploys one (see
    // gateway/DEPLOYMENT.md's own second-gateway section) - never a
    // fabricated success.
    private val stockholmActivationClient: (publicKey: String, activationCredential: String) -> ProvisioningResult =
        { publicKey, activationCredential ->
            ProvisioningClient.activate(publicKey, activationCredential, net.pocvpn.client.vpn.config.ProductionGatewayCatalog.STOCKHOLM.awg.endpointHost)
        },
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
    // B18 - additive, defaults to null (same reasoning as appRoutingPolicyStore
    // above): when non-null, this is the ONE store both VpnController
    // (read-only, at connect time) and this ViewModel (read + write, for the
    // Settings UI) share - see updateRoutingMode below.
    private val routingModeStore: RoutingModeStore? = null,
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
    // B13 consolidated review fix - additive, defaults to null (same "no
    // wiring, no behavior" seam as every other optional dependency above).
    // [xrayProfileRepository]/[xrayTlsProfileRepository] above are ALWAYS
    // the production/Germany endpoint's own repository (see Factory) - a
    // real bug had Stockholm's XRAY_REALITY/TLS_TCP availability silently
    // inherit Germany's flag instead of ever consulting Stockholm's OWN
    // repository. These two are Stockholm's own, separately-scoped
    // repository instances (same on-disk file the debug-only
    // XrayDiagnosticsActivity manual-save path already writes to when an
    // operator has provisioned Stockholm credentials - never a second/
    // fabricated store) - see xrayAvailableEndpoints/xrayTlsAvailableEndpoints
    // and buildTransportRegistry(endpointId) below for how these make
    // availability genuinely per-endpoint.
    private val stockholmXrayProfileRepository: XrayProfileRepository? = null,
    private val stockholmXrayTlsProfileRepository: XrayTlsProfileRepository? = null,
    // B14 - Stockholm's OWN Xray REALITY/TLS provisioners, additive/
    // defaults to null (same "no wiring, no behavior" seam as
    // [xrayProfileProvisioner]/[xrayTlsProfileProvisioner] themselves -
    // Factory is the one production call site that constructs these, each
    // wired to [stockholmXrayProfileRepository]/[stockholmXrayTlsProfileRepository]
    // above and a fetch function targeting Stockholm's own edge - never
    // Germany's repository or Germany's edge). A successful Stockholm
    // activation (see activateDevice() below) runs these instead of the
    // Germany-fixed ones, so Stockholm's REALITY/TLS profiles land in
    // Stockholm's own endpoint-scoped storage through the REAL app
    // provisioning flow - never XrayDiagnosticsActivity (debug-only,
    // absent from release - see that class's own docs).
    private val stockholmXrayProfileProvisioner: XrayProfileProvisioner? = null,
    private val stockholmXrayTlsProfileProvisioner: XrayTlsProfileProvisioner? = null,
    // B8I8 - additive, defaults to Auto (byte-for-byte unchanged production
    // behavior - no product UI sets anything else yet). Threaded into every
    // smartConnectDecision() call AND consulted by the AWG -> Xray failover
    // check below - a user who pins Manual(AMNEZIA_WG)/Manual(XRAY_REALITY)
    // gets exactly that transport, success or failure, never a silent
    // automatic substitute (see AwgXrayFailoverPolicy's own docs).
    private var userTransportPreference: UserTransportPreference = UserTransportPreference.Auto,
    // B11 - additive, defaults to null (same "no wiring, no behavior" seam
    // as every other optional dependency above). Powers
    // reachabilityDiagnostics() below - a read-only snapshot - AND, as of
    // B17, is the authoritative source of WHICH endpoints are eligible for
    // automatic gateway selection (buildAutoGatewayCandidates()) - null here
    // means Auto discovery sees zero manifest endpoints and fails closed
    // (task requirement 9.D), never a fallback to the raw catalog. Still
    // never consulted by smartConnectDecision()/buildTransportRegistry()
    // (transport SELECTION within one already-chosen gateway stays
    // unaffected - see ReachabilityDiagnosticsSnapshot's own "observational
    // only" docs for that boundary, unchanged by B17).
    private val manifestRepository: net.pocvpn.client.reachability.EndpointManifestRepository? = null,
    private val pathHistoryStore: net.pocvpn.client.reachability.PathHistoryStore? = null,
    private val fingerprintKeyProvider: net.pocvpn.client.reachability.NetworkFingerprintKeyProvider? = null,
    // B24 review fix (PR #38, round 3) - the real client<->ingress
    // PREPARATION boundary a relayed Auto winner is handed to (see
    // RelayIngressResolver's own docs). A Resolved result is fed into the
    // SAME TransportOrchestrator/VpnController path Direct uses - this
    // object never owns tunnel state itself. Defaults to
    // NotProvisionedRelayIngressResolver - the ONLY implementation wired
    // into production today - which reports NotProvisioned for every plan
    // (no real ingress is deployed/activated against this slice). Additive
    // seam, same pattern as every optional collaborator above.
    private val relayIngressResolver: net.pocvpn.client.relay.RelayIngressResolver = net.pocvpn.client.relay.NotProvisionedRelayIngressResolver,
    // B25 (task C) - the real end-to-end data-plane proof channel a
    // resolved relayed attempt's ingress-handshake success is checked
    // against (see armFailoverWatch's own docs). Defaults to
    // NotConfiguredRelayEndToEndProbe - fails closed with
    // EXECUTION_NOT_IMPLEMENTED for every attempt, same additive-seam
    // discipline as [relayIngressResolver] above - no real ingress is
    // deployed for this device to probe yet.
    private val relayEndToEndProbe: net.pocvpn.client.relay.RelayEndToEndProbe = net.pocvpn.client.relay.NotConfiguredRelayEndToEndProbe,
    // B25 (task A/F) - threaded straight into VpnController's own
    // same-named additive params (see that class's own docs) - null here
    // (the default) means a resolved relayed attempt fails closed at
    // buildTransportConfig with ConfigurationMappingFailure, exactly like
    // any other unresolvable endpoint, until a real composition root wires
    // real per-endpoint Xray profile resolution for ingress endpoints.
    private val relayXrayProfileRepositoryResolver: net.pocvpn.client.identity.XrayProfileRepositoryResolver? = null,
    private val relayXrayTlsProfileRepositoryResolver: net.pocvpn.client.identity.XrayTlsProfileRepositoryResolver? = null,
    // B26 (task D) - the real ingress activation control-plane path
    // (POST /v1/ingress-profile -> validate -> IngressClientProfile ->
    // FileIngressProfileStore), consulted by [activateIngress] below.
    // Defaults to null (same "no wiring, no behavior" seam as every other
    // optional dependency above): with no provisioner wired,
    // activateIngress() below is a no-op that reports
    // IngressActivationOutcome.Unavailable, never a fabricated success.
    private val ingressProfileProvisioner: net.pocvpn.client.relay.IngressProfileProvisioner? = null,
    // B12/B20 - additive, defaults to null (same seam as every optional
    // dependency above): with no client, refreshManifest() below is a
    // no-op that returns null, and manifestRepository's trusted state is
    // whatever the embedded bootstrap/previously-adopted LKG already say -
    // this constructor param existing does not, by itself, cause any
    // network access. B20 - now a MultiOriginManifestDistributionClient
    // (was a single-origin ManifestDistributionClient) - the ONE production
    // trigger this class calls is unchanged, only the number of HTTPS
    // origins one logical refresh actually tries.
    private val manifestDistributionClient: net.pocvpn.client.reachability.MultiOriginManifestDistributionClient? = null,
    // B13 - additive, defaults to a store that always reads GERMANY and
    // ignores writes (see SelectedGatewayStore.germanyOnly()'s own docs) -
    // every pre-B13 call site/test is byte-for-byte unaffected: the manual
    // gateway picker simply has nothing to persist to, and
    // gatewayConfigurationRepository is unaffected by this param entirely
    // (it is wired to read the SAME store at the composition root - see
    // Factory - so this field only drives the UI-facing
    // selectedGateway/selectGateway() below, never a second, competing
    // source of truth for the actual connect-time config).
    private val selectedGatewayStore: net.pocvpn.client.vpn.config.SelectedGatewayStore = net.pocvpn.client.vpn.config.SelectedGatewayStore.germanyOnly(),
    // B16 - additive, defaults to a store that always reads Manual (false)
    // and ignores writes (byte-for-byte pre-B16 behavior for every existing
    // call site/test: automatic gateway selection did not exist before this
    // slice, so its absence here changes nothing).
    private val gatewayAutoModeStore: net.pocvpn.client.vpn.config.GatewayAutoModeStore = net.pocvpn.client.vpn.config.GatewayAutoModeStore.manualOnly(),
    // B13 review fix - additive, defaults to null (same "no wiring, no
    // behavior" seam as every other optional dependency above). When
    // non-null, this is the SAME per-device ClientTunnelIdentityStore
    // instance the Factory's real SelectedProductionGatewaySource already
    // resolves clientTunnelIp() from (see that class's own docs) - never a
    // second, independently-constructed store that could disagree with
    // what connect() actually resolves. Drives isGatewayProvisioned()/
    // provisionedGatewayIds below AND the startup reconciliation the
    // _selectedGateway initializer runs. With no store wired, every
    // gateway is treated as provisioned - byte-for-byte unchanged
    // behavior for every pre-existing call site/test.
    private val clientTunnelIdentityStore: net.pocvpn.client.vpn.config.ClientTunnelIdentityStore? = null,
    // B22 - additive, defaults to a store that always reads MANUAL_MANAGED
    // and ignores writes (byte-for-byte pre-B22 behavior for every existing
    // call site/test: Private Gateway Mode did not exist before this slice).
    private val gatewaySelectionModeStore: net.pocvpn.client.vpn.config.GatewaySelectionModeStore =
        net.pocvpn.client.vpn.config.GatewaySelectionModeStore.managedOnly(),
    // B22 - additive, defaults to null (no wiring, no behavior - same seam
    // shape as clientTunnelIdentityStore above). With no store wired,
    // PRIVATE mode's connectPrivate() fails closed (GatewayConfigurationMissing).
    private val privateGatewayStore: net.pocvpn.client.vpn.config.PrivateGatewayStore? = null,
    // B22 - a GENUINELY DISTINCT ClientKeyRepository instance from the
    // constructor-level [clientKeyRepository] above (see
    // PrivateGatewayKeyRepositoryFactory's own docs for why) - additive,
    // defaults to null. With no repository wired, PRIVATE mode's
    // connectPrivate() fails closed rather than falling back to the
    // managed-network identity (that fallback would silently register this
    // device's managed-network public key as a peer on the user's own VPS,
    // an identity-linkage bug, not a convenience).
    private val privateGatewayKeyRepository: ClientKeyRepository? = null,
) : ViewModel() {

    /**
     * B13 review fix - whether THIS DEVICE has a client tunnel identity
     * provisioned for [id] (see ClientTunnelIdentityStore's own docs) -
     * i.e. whether [id] is actually connectable, not merely a catalog
     * entry. With no store wired ([clientTunnelIdentityStore] null), every
     * gateway is considered provisioned.
     */
    fun isGatewayProvisioned(id: net.pocvpn.client.vpn.config.ProductionGatewayId): Boolean {
        val store = clientTunnelIdentityStore ?: return true
        return store.read(id) != null
    }

    /**
     * The subset of [net.pocvpn.client.vpn.config.ProductionGatewayCatalog.all]
     * this device can actually connect to right now - GatewayPickerDialog
     * uses this to decide which rows to disable. The catalog itself stays
     * fully visible regardless (see that dialog's own docs) - this is
     * readiness, never a second, competing gateway list.
     */
    val provisionedGatewayIds: Set<net.pocvpn.client.vpn.config.ProductionGatewayId>
        get() = net.pocvpn.client.vpn.config.ProductionGatewayCatalog.all
            .map { it.id }
            .filter(::isGatewayProvisioned)
            .toSet()

    // B13 - the CURRENT manual gateway selection, for the UI (LocationCard/
    // the gateway picker) to render and react to. Read once at construction
    // (matches appRoutingPolicyStore's own savedAppRoutingPolicy pattern)
    // and updated in-place by selectGateway() - the actual connect-time
    // GatewayConfigurationRepository reads selectedGatewayStore fresh on
    // every get() regardless of this StateFlow's value (see
    // SelectedProductionGatewaySource's own docs), so this is purely a UI
    // convenience, never a second authoritative copy.
    //
    // B13 review fix - reconciled through reconcileSelectedGateway() below
    // rather than the raw store read: a PERSISTED selection this device
    // turns out not to be provisioned for (e.g. Stockholm was selected
    // before this device's Stockholm identity was ever set, or the
    // evidence-based migration left it unprovisioned) is deterministically
    // switched to another provisioned gateway - and that switch is
    // PERSISTED too, so it survives a restart rather than re-drifting back
    // every launch. If NO gateway is provisioned, the persisted selection
    // is left exactly as read: no identity is invented, no gateway is
    // substituted as a guess, and the existing fail-closed connect-time
    // validation (DefaultGatewayConfigurationRepository - blank
    // clientTunnelIp() -> Invalid, never a silent default) is preserved
    // untouched.
    private val _selectedGateway = MutableStateFlow(reconcileSelectedGateway(selectedGatewayStore.read()))
    val selectedGateway: StateFlow<net.pocvpn.client.vpn.config.ProductionGatewayId> = _selectedGateway.asStateFlow()

    private fun reconcileSelectedGateway(
        persisted: net.pocvpn.client.vpn.config.ProductionGatewayId,
    ): net.pocvpn.client.vpn.config.ProductionGatewayId {
        if (isGatewayProvisioned(persisted)) return persisted
        val fallback = net.pocvpn.client.vpn.config.ProductionGatewayCatalog.all
            .map { it.id }
            .firstOrNull(::isGatewayProvisioned)
            ?: return persisted
        selectedGatewayStore.write(fallback)
        return fallback
    }

    /**
     * B13 consolidated review fix (finding 2) - re-runs the SAME
     * reconciliation [reconcileSelectedGateway] performs at construction,
     * but callable AFTER construction, any time this device's provisioning
     * readiness might just have changed (today: exactly once, right after
     * activateDevice() writes a fresh ClientTunnelIdentityStore entry - see
     * that function's own docs). Startup reconciliation alone is
     * insufficient: a gateway that was unprovisioned when this ViewModel
     * was constructed (so its stale persisted selection was deliberately
     * LEFT AS-IS - see reconcileSelectedGateway's own "no gateway
     * provisioned" branch) can become provisioned later in the SAME
     * session, with no app restart, and [selectedGateway] must reflect that
     * immediately rather than silently staying stuck on an unusable
     * gateway until the next launch. No-op (and no store write) when the
     * current selection is already provisioned, or when nothing at all is
     * provisioned yet - same "never invent/guess a fallback" contract as
     * the constructor-time call.
     */
    private fun reconcileSelectedGatewayIfNeeded() {
        _selectedGateway.value = reconcileSelectedGateway(_selectedGateway.value)
    }

    /**
     * B13 - THE one place a manual gateway selection is made. Deterministic:
     * always resolves to exactly the requested [id], persisted immediately
     * so it survives an app restart (FileSelectedGatewayStore, atomic
     * write - see its own docs), and reflected in [selectedGateway]
     * immediately so the UI updates without waiting for a re-read. Does NOT
     * itself reconnect/touch the tunnel - same "select now, apply on the
     * next real connect()" contract as a saved AppRoutingPolicy change (see
     * updateAppRoutingPolicy's own docs) - a currently active session keeps
     * running on whichever gateway it already connected to until the user
     * disconnects/reconnects.
     *
     * B13 review fix - a no-op for an [id] this device has no client tunnel
     * identity for (see [isGatewayProvisioned]): GatewayPickerDialog itself
     * already disables that row's tap target/RadioButton (see its own
     * docs), and this is the same guard enforced again at the one real
     * selection boundary, never relying on the UI alone.
     *
     * B13 consolidated review fix (finding 5) - ALSO a no-op while a VPN
     * session actually exists (transportState is Connecting/Connected/
     * Reconnecting/Disconnecting - see [blocksGatewaySelection]): changing
     * [selectedGateway] while traffic may still be exiting the PREVIOUS
     * gateway would make Home render a location the active tunnel is not
     * actually using - false "you're in Sweden now" UI while packets still
     * exit Germany. AppRoot's own gateway picker already refuses to open at
     * all during an active session (same predicate, see
     * ProductFlowPresentation.blocksGatewaySelection's own docs) - this is
     * the same guard enforced again at the one real selection boundary,
     * never relying on the UI alone. A user must disconnect first, exactly
     * like every other "select now, apply on the next real connect()"
     * setting in this ViewModel.
     */
    fun selectGateway(id: net.pocvpn.client.vpn.config.ProductionGatewayId) {
        if (!isGatewayProvisioned(id)) return
        if (transportState.value.blocksGatewaySelection()) return
        selectedGatewayStore.write(id)
        _selectedGateway.value = id
        // B16 - choosing a specific gateway manually is exactly what
        // GatewayPickerDialog's own row tap already meant pre-B16; making it
        // ALSO exit automatic mode keeps that meaning intact rather than
        // silently leaving Auto engaged with a manual pick the user can't
        // see took no effect (per task requirement 2: manual selection must
        // remain deterministic).
        if (_gatewayAutoMode.value) {
            gatewayAutoModeStore.write(false)
            _gatewayAutoMode.value = false
        }
        _activeGatewayId.value = id
    }

    // B16 - persisted automatic-gateway-selection preference (task
    // requirement 9/UI, requirement 11's "restart preserves manual/Auto
    // preference"). Read once at construction (same pattern as
    // _selectedGateway above) and updated in-place by [setGatewayAutoMode].
    private val _gatewayAutoMode = MutableStateFlow(gatewayAutoModeStore.read())
    val gatewayAutoMode: StateFlow<Boolean> = _gatewayAutoMode.asStateFlow()

    /**
     * B16 - THE one place automatic-gateway mode is toggled. Same
     * active-session guard [selectGateway] already enforces (task
     * requirement 8/"select now, apply on the next real connect()" - never
     * changes what an already-connected tunnel is doing).
     */
    fun setGatewayAutoMode(auto: Boolean) {
        if (transportState.value.blocksGatewaySelection()) return
        gatewayAutoModeStore.write(auto)
        _gatewayAutoMode.value = auto
        // B22 - kept in lockstep with the new explicit mode authority (see
        // selectGatewaySelectionMode's own docs for the reverse direction).
        // auto=false always resolves to MANUAL_MANAGED here, never PRIVATE -
        // this legacy boolean setter has no way to express PRIVATE, so it
        // must never silently downgrade an active PRIVATE selection to
        // Manual; existing pre-B22 callers only ever pass this a boolean and
        // never observe PRIVATE in the first place.
        val mode = if (auto) net.pocvpn.client.vpn.config.GatewaySelectionMode.AUTO else net.pocvpn.client.vpn.config.GatewaySelectionMode.MANUAL_MANAGED
        if (_gatewaySelectionMode.value != mode && (auto || _gatewaySelectionMode.value != net.pocvpn.client.vpn.config.GatewaySelectionMode.PRIVATE)) {
            gatewaySelectionModeStore.write(mode)
            _gatewaySelectionMode.value = mode
        }
    }

    // B22 - the explicit three-way gateway-selection authority (architecture
    // constraint 2). Read once at construction (same pattern as
    // _selectedGateway/_gatewayAutoMode above). PRIVATE can ONLY ever come
    // from [gatewaySelectionModeStore] itself (the legacy boolean has no way
    // to express it); otherwise AUTO-vs-not is derived from the legacy
    // [gatewayAutoModeStore] exactly as it already was pre-B22 - this keeps
    // every existing AUTO-mode test/call site that constructs a
    // pre-set-to-true GatewayAutoModeStore (never touching
    // gatewaySelectionModeStore at all) byte-for-byte correct, while a
    // genuinely new PRIVATE selection (which DOES persist through the new
    // store) still starts up correctly on the next launch.
    private val _gatewaySelectionMode = MutableStateFlow(
        if (gatewaySelectionModeStore.read() == net.pocvpn.client.vpn.config.GatewaySelectionMode.PRIVATE) {
            net.pocvpn.client.vpn.config.GatewaySelectionMode.PRIVATE
        } else if (_gatewayAutoMode.value) {
            net.pocvpn.client.vpn.config.GatewaySelectionMode.AUTO
        } else {
            net.pocvpn.client.vpn.config.GatewaySelectionMode.MANUAL_MANAGED
        },
    )
    val gatewaySelectionMode: StateFlow<net.pocvpn.client.vpn.config.GatewaySelectionMode> = _gatewaySelectionMode.asStateFlow()

    /**
     * B22 - THE one place [GatewaySelectionMode] is changed. Same
     * active-session guard [selectGateway]/[setGatewayAutoMode] already
     * enforce. Keeps the legacy [gatewayAutoMode] boolean in lockstep
     * (true only for [GatewaySelectionMode.AUTO]) purely so any
     * OTHER existing code still reading that boolean directly (none of
     * which this slice touches) never observes a divergent value - this
     * mode enum is the one new authority connect() itself dispatches on
     * (see [connect]).
     */
    fun selectGatewaySelectionMode(mode: net.pocvpn.client.vpn.config.GatewaySelectionMode) {
        if (transportState.value.blocksGatewaySelection()) return
        gatewaySelectionModeStore.write(mode)
        _gatewaySelectionMode.value = mode
        val auto = mode == net.pocvpn.client.vpn.config.GatewaySelectionMode.AUTO
        if (_gatewayAutoMode.value != auto) {
            gatewayAutoModeStore.write(auto)
            _gatewayAutoMode.value = auto
        }
    }

    // B22 - the currently saved private gateway config, for UI display
    // (host/port/server public key/tunnel address - NEVER the client
    // private key, which this type structurally cannot carry - see
    // PrivateGatewayConfig's own docs). null when unconfigured or with no
    // store wired.
    val privateGatewayConfig: net.pocvpn.client.vpn.config.PrivateGatewayConfig?
        get() = privateGatewayStore?.read()

    /**
     * B22 - validates BEFORE persisting (architecture "SECURITY /
     * VALIDATION": malformed input must never be saved, let alone connected
     * with) - returns the typed result so the UI can show exactly which
     * field failed, never a generic error. Only [PrivateGatewayValidationResult.Valid]
     * is ever written to [privateGatewayStore].
     */
    fun savePrivateGatewayConfig(
        host: String,
        port: Int,
        serverPublicKeyBase64: String,
        clientTunnelIp: String,
        gatewayTunnelIp: String,
        awgProfile: net.pocvpn.client.vpn.config.AwgProfile,
    ): net.pocvpn.client.vpn.config.PrivateGatewayValidationResult {
        val result = net.pocvpn.client.vpn.config.PrivateGatewayConfigValidator.validate(
            host = host,
            port = port,
            serverPublicKeyBase64 = serverPublicKeyBase64,
            clientTunnelIp = clientTunnelIp,
            gatewayTunnelIp = gatewayTunnelIp,
            awgProfile = awgProfile,
        )
        if (result is net.pocvpn.client.vpn.config.PrivateGatewayValidationResult.Valid) {
            privateGatewayStore?.write(result.config)
        }
        return result
    }

    /**
     * B22 - removes the saved config only. Deliberately does NOT switch
     * [gatewaySelectionMode] away from PRIVATE (mirrors [selectGateway]'s
     * own "select now, apply on the next real connect()" discipline) - the
     * next PRIVATE connect() attempt fails closed with
     * [net.pocvpn.client.diagnostics.VpnError.GatewayConfigurationMissing]
     * exactly as if it had never been configured, never a silent fallback
     * to a managed gateway.
     */
    fun removePrivateGatewayConfig() {
        privateGatewayStore?.clear()
    }

    /**
     * B22 - the ONLY private-gateway key material this ViewModel ever
     * exposes: the PUBLIC key, for the user to paste into their own VPS's
     * `add-peer.sh`-equivalent step (see architecture "FIRST SLICE UX":
     * "expose/copy only the client PUBLIC key"). The private key itself
     * never leaves [privateGatewayKeyRepository] except to
     * [VpnController.buildTransportConfig] at the moment of building a real
     * tunnel config - see that repository's own docs.
     */
    suspend fun privateGatewayClientPublicKey(): String? = privateGatewayKeyRepository?.getPublicKey()

    /**
     * B16 - the gateway a connect() attempt is CURRENTLY targeting/using,
     * for UI display (task requirement 9: "when connected automatically,
     * show the actual active gateway/location, not just Auto"). For MANUAL
     * mode this always mirrors [selectedGateway]. For AUTO mode this
     * updates the instant each ranked candidate is actually attempted -
     * never a stale "Auto" placeholder once a real attempt has started.
     */
    private val _activeGatewayId = MutableStateFlow(_selectedGateway.value)
    val activeGatewayId: StateFlow<net.pocvpn.client.vpn.config.ProductionGatewayId> = _activeGatewayId.asStateFlow()

    // B16 - task requirement 10's diagnostics surface. null until the first
    // Auto connect() attempt of this ViewModel's lifetime.
    private val _autoGatewayDiagnostics = MutableStateFlow<AutoGatewayDiagnostics?>(null)
    val autoGatewayDiagnostics: StateFlow<AutoGatewayDiagnostics?> = _autoGatewayDiagnostics.asStateFlow()

    // B8I - CURRENT network facts only (see NetworkProfile's own docs for
    // why this is deliberately separate from connectionOutcomeStore's
    // HISTORICAL outcomes). Falls back to a static "no profiler wired"
    // unavailable value so this StateFlow is never null. Declared BEFORE
    // [controller] (B13) so its networkProfileProvider lambda below can
    // capture this exact StateFlow - read only lazily, at the moment of an
    // authoritative outcome, never during construction.
    val networkProfile: StateFlow<NetworkProfile> =
        networkProfiler?.profile ?: MutableStateFlow(initialNetworkProfile ?: NetworkProfile.unavailable(0)).asStateFlow()

    // B13 consolidated review fix - Germany's own endpointId, used
    // throughout this class as the ONE key the legacy activation flow (and
    // every pre-B13 default) is ever allowed to write availability/identity
    // under - never a raw EndpointId(ProductionGateway.ID) literal repeated
    // at each call site.
    private val germanyEndpointId = net.pocvpn.client.vpn.config.ProductionGatewayCatalog.GERMANY.endpointId
    private val stockholmEndpointId = net.pocvpn.client.vpn.config.ProductionGatewayCatalog.STOCKHOLM.endpointId

    // B13 (audit item 5 fix) - the ONE authoritative endpoint -> repository
    // lookup VpnController.buildTransportConfig actually resolves through
    // for XRAY_REALITY/TLS_TCP - built here, at the composition root, from
    // the SAME xrayProfileRepository/xrayTlsProfileRepository/
    // stockholmXrayProfileRepository/stockholmXrayTlsProfileRepository
    // instances this ViewModel already received (never a second,
    // independently-constructed store).
    //
    // B13 consolidated review fix - now carries BOTH endpoints (when both
    // repositories are wired), not just production/Germany: a real gap had
    // Stockholm always resolve to null here regardless of whether it had
    // its own real, separately-provisioned profile on disk, silently
    // failing closed for the wrong reason (missing wiring, not missing
    // credentials). null overall only when NEITHER repository is wired
    // (matches every pre-B13 "not wired at all" call site).
    private val xrayProfileRepositoryResolver: net.pocvpn.client.identity.XrayProfileRepositoryResolver? =
        buildMap {
            xrayProfileRepository?.let { put(germanyEndpointId, it) }
            stockholmXrayProfileRepository?.let { put(stockholmEndpointId, it) }
        }.takeIf { it.isNotEmpty() }?.let { net.pocvpn.client.identity.MapXrayProfileRepositoryResolver(it) }
    private val xrayTlsProfileRepositoryResolver: net.pocvpn.client.identity.XrayTlsProfileRepositoryResolver? =
        buildMap {
            xrayTlsProfileRepository?.let { put(germanyEndpointId, it) }
            stockholmXrayTlsProfileRepository?.let { put(stockholmEndpointId, it) }
        }.takeIf { it.isNotEmpty() }?.let { net.pocvpn.client.identity.MapXrayTlsProfileRepositoryResolver(it) }

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
        xrayProfileRepositoryResolver = xrayProfileRepositoryResolver,
        xrayTlsProfileRepositoryResolver = xrayTlsProfileRepositoryResolver,
        relayXrayProfileRepositoryResolver = relayXrayProfileRepositoryResolver,
        relayXrayTlsProfileRepositoryResolver = relayXrayTlsProfileRepositoryResolver,
        // B13 - the SAME pathHistoryStore/fingerprintKeyProvider instances
        // reachabilityDiagnostics() below already reads (never a second,
        // independently-constructed pair) - this is the live-connect-path
        // writer, that remains the read-only observer.
        pathHistoryStore = pathHistoryStore,
        fingerprintKeyProvider = fingerprintKeyProvider,
        networkProfileProvider = { networkProfile.value },
        routingModeStore = routingModeStore ?: RoutingModeStore.fullVpn(),
        // B18 - RestrictionClassifier wired into RoutingDecisionEngine
        // exactly once, through this SAME supplier pattern
        // networkProfileProvider above already uses - restrictionClass()
        // recomputes fresh from live evidence on every call, never cached.
        restrictionClassProvider = { restrictionClass() },
    )

    // B8I7 - gains the endpointId of a gateway the moment a real Xray
    // profile is CONFIRMED to exist FOR THAT ENDPOINT: checked once at
    // startup for every wired repository (init block below, for a profile
    // persisted by a PRIOR session) and again the instant activateDevice()
    // saves a fresh one for Germany (XrayProfileProvisioningOutcome.Saved,
    // below) - never polled, never inferred from elapsed time.
    // buildTransportRegistry(endpointId) reads this synchronously (a plain
    // StateFlow.value read) so the registry it builds always reflects the
    // CURRENT truth for the SPECIFIC endpoint it was asked about.
    //
    // B13 consolidated review fix - was a single global Boolean, which made
    // Germany's own Xray profile silently make Stockholm's XRAY_REALITY
    // appear AVAILABLE too (and vice versa) - the exact split-authority bug
    // this Set<EndpointId> shape closes: isXrayAvailableFor(endpointId)
    // below is the ONE place availability is actually read, and it is
    // always asked about ONE specific endpoint, never "is Xray available
    // anywhere".
    private val xrayAvailableEndpoints = MutableStateFlow<Set<net.pocvpn.client.reachability.EndpointId>>(emptySet())

    // B8O2 - the TLS/TCP counterpart of [xrayAvailableEndpoints] above,
    // same per-endpoint shape and same reasoning.
    private val xrayTlsAvailableEndpoints = MutableStateFlow<Set<net.pocvpn.client.reachability.EndpointId>>(emptySet())

    private fun isXrayAvailableFor(endpointId: net.pocvpn.client.reachability.EndpointId): Boolean =
        endpointId in xrayAvailableEndpoints.value

    private fun isXrayTlsAvailableFor(endpointId: net.pocvpn.client.reachability.EndpointId): Boolean =
        endpointId in xrayTlsAvailableEndpoints.value

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
     * CURRENT [xrayAvailableEndpoints] signal, same "no caching" discipline
     * [smartConnectDecision] itself already documents. The factory closures
     * always return the SAME already-constructed `transport`/[xrayTransport]
     * instances - rebuilding this registry object never constructs a new
     * transport instance, so selection (smartConnectDecision) and execution
     * (connect()'s own orchestrator, built from THIS SAME function) can
     * never end up looking at two different Xray instances.
     *
     * B13 consolidated review fix - [endpointId] is REQUIRED (defaulted only
     * to Germany's own id, so every pre-existing call site - test or
     * production - that never named a second gateway keeps its exact prior
     * meaning): availability is evaluated for THIS SPECIFIC endpoint via
     * isXrayAvailableFor/isXrayTlsAvailableFor, never a global flag. Every
     * REAL call site below passes the endpoint the attempt actually targets
     * (never a default) - see smartConnectDecision()/connect()'s own docs.
     *
     * `internal` (not private) so tests can inspect the exact descriptors
     * this produces directly, without needing a real Android Context to
     * drive smartConnectDecision()/connect() end to end.
     */
    internal fun buildTransportRegistry(
        endpointId: net.pocvpn.client.reachability.EndpointId = germanyEndpointId,
    ): TransportRegistry {
        val descriptors = mutableListOf(
            TransportDescriptor(kind = transport.kind, status = TransportStatus.AVAILABLE, capabilities = transport.capabilities, factory = { transport }),
        )
        val xray = xrayTransport
        if (xray != null) {
            val available = isXrayAvailableFor(endpointId)
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
            val available = isXrayTlsAvailableFor(endpointId)
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
    fun smartConnectDecision(): SmartConnectDecision {
        // B13 - the candidate's id/region must match whichever gateway
        // gatewayStatus() actually resolved to (both read the SAME
        // selectedGatewayStore) - never the Germany-only default, or a
        // Stockholm selection would be truthfully connected to but
        // mislabeled/misattributed in ConnectionOutcome/PathHistory as
        // Germany.
        val selected = net.pocvpn.client.vpn.config.ProductionGatewayCatalog.byId(selectedGateway.value)
        return SmartConnectCandidateSelector.decide(
            networkProfile = networkProfile.value,
            gatewayCandidates = SmartConnectCandidateSelector.productionGatewayCandidates(
                gatewayStatus(),
                id = selected.endpointId.value,
                region = "${selected.displayCountry} / ${selected.displayCity}",
            ),
            // B13 consolidated review fix - THIS candidate's own endpoint,
            // never the default: Xray/TLS availability in the registry
            // Smart Connect scores against must correspond to the SAME
            // gateway the candidate itself names (selected.endpointId) -
            // see buildTransportRegistry(endpointId)'s own docs.
            registry = buildTransportRegistry(selected.endpointId),
            preference = userTransportPreference,
            health = transportHealth(),
            connectionHistory = recentConnectionOutcomes(),
            restrictionClass = restrictionClass(),
        )
    }

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
        // B13 consolidated review fix - the CURRENTLY selected gateway's own
        // endpoint, never the default: this is a diagnostic view of what a
        // connection attempt would score right now, and that attempt would
        // target whichever gateway is actually selected.
        val selectedEndpointId = net.pocvpn.client.vpn.config.ProductionGatewayCatalog.byId(selectedGateway.value).endpointId
        return buildTransportRegistry(selectedEndpointId).all().associate { descriptor ->
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
     *
     * B28 - also passes the REAL wall-clock now plus each probe's own
     * timestamp (restrictionMonitor.lastProbeEpochMillis/
     * lastDiverseReachabilityEpochMillis) so RestrictionClassifier.classify
     * can time-box POSSIBLE_HARD_WHITELIST/POSSIBLE_UDP_OR_AWG_FILTERING to
     * genuinely fresh evidence (see that function's own staleness docs) -
     * this is the hysteresis mechanism requirement 8 asked for, reusing
     * RestrictionMonitor's existing single-flight probe trigger rather than
     * a second polling/expiry mechanism.
     */
    fun restrictionClass(): RestrictionClass = RestrictionClassifier.classify(
        RestrictionEvidence(
            networkProfile = networkProfile.value,
            transportState = transportState.value,
            awgHandshakeFresh = recentConnectionOutcomes().lastOrNull()?.let { it.result == ConnectionOutcomeResult.SUCCESS },
            gatewayHttpsReachable = restrictionMonitor?.lastProbeResult?.value,
            diverseInternetReachable = restrictionMonitor?.lastDiverseReachabilityResult?.value,
            gatewayProbeEpochMillis = restrictionMonitor?.lastProbeEpochMillis?.value,
            diverseProbeEpochMillis = restrictionMonitor?.lastDiverseReachabilityEpochMillis?.value,
        ),
        nowEpochMillis = System.currentTimeMillis(),
    )

    /**
     * B11 - OBSERVATIONAL ONLY: assembles the current reachability fabric
     * snapshot from real evidence already computed above (transportHealth(),
     * restrictionClass(), networkProfile, buildTransportRegistry()) plus the
     * currently trusted manifest. Returns null whenever [manifestRepository]
     * was never wired (Factory always wires it in production - see below -
     * but every test call site is unaffected by this addition). Nothing
     * here is read by smartConnectDecision()/buildTransportRegistry() - see
     * ReachabilityDiagnosticsSnapshot's own "observational only" docs.
     */
    fun reachabilityDiagnostics(): net.pocvpn.client.reachability.ReachabilityDiagnosticsSnapshot? {
        val repository = manifestRepository ?: return null
        // Fail closed - see EndpointManifestRepository.trustedState()'s own
        // docs: NoneTrusted means neither LKG nor the embedded bootstrap
        // itself verified, and this accessor must not fabricate a snapshot
        // around an unverified manifest just because one is compiled in.
        val manifest = repository.trusted() ?: return null
        // B13 SECOND consolidated review fix - a manifest can name MULTIPLE
        // endpoints (Germany, Stockholm, ...), and Xray/TLS availability is
        // now genuinely per-endpoint (see buildTransportRegistry(endpointId)'s
        // own docs) - one registry built for whichever gateway happens to be
        // CURRENTLY SELECTED cannot truthfully describe every OTHER
        // endpoint's own candidates too (Germany's Xray profile existing
        // must never make a Stockholm candidate look eligible, or vice
        // versa). One registry is built per endpoint the manifest actually
        // names, and each candidate below is scored against ITS OWN
        // endpoint's registry - never the selected gateway's. Still
        // observational only: nothing here feeds back into
        // smartConnectDecision()/PathScorer is not promoted into Smart
        // Connect by this fix.
        val registriesByEndpoint: Map<net.pocvpn.client.reachability.EndpointId, TransportRegistry> =
            manifest.endpoints.associate { it.id to buildTransportRegistry(it.id) }
        val health = transportHealth()
        val restriction = restrictionClass()
        val profile = networkProfile.value
        val now = System.currentTimeMillis()

        // B12 - CONTROL PLANE evidence (the gateway's HTTPS API - manifest
        // distribution/activation/provisioning) is a SEPARATE signal from
        // DATA PLANE evidence (an actual tunnel attempt outcome for this
        // exact endpoint+transport) - see ReachabilityEvidenceSummary's own
        // "do not collapse" docs. Only the pinned production gateway's own
        // control-plane probe exists today (restrictionMonitor).
        val controlPlaneReachableByEndpoint: (net.pocvpn.client.reachability.EndpointId) -> Boolean? = { id ->
            if (id.value == net.pocvpn.client.smartconnect.ProductionGateway.ID) restrictionMonitor?.lastProbeResult?.value else null
        }
        // B12 - real per-(endpoint, transport) DATA PLANE evidence, derived
        // from ConnectionOutcomeStore's own real per-attempt history
        // (ConnectionOutcome.gatewayId/.transport) - never fabricated, and
        // never requiring any change to VpnController's proven connect
        // path: the SAME outcomes already recorded for TransportHealth are
        // reused here, just re-filtered by endpoint as well as transport.
        // (PR #24 audit fix) - the NEWEST matching outcome wins (explicit
        // maxByOrNull on its own real timestamp, not merely "last in the
        // list"), and its OWN timestamp is threaded through to
        // ReachabilityEngine.assess so stale evidence can actually decay -
        // see that function's own "never TransportHealth's age as a fake
        // proxy" docs for why this is a real, separate timestamp.
        val outcomes = recentConnectionOutcomes()

        val reachability = manifest.endpoints.flatMap { endpoint ->
            endpoint.transports.map { binding ->
                val matchedOutcome = net.pocvpn.client.reachability.EndpointOutcomeMatcher.latestMatching(outcomes, endpoint.id, binding.kind)
                net.pocvpn.client.reachability.ReachabilityEngine.assess(
                    endpoint = endpoint,
                    transportKind = binding.kind,
                    networkUsable = profile.isUsable,
                    transportHealth = health.getValue(binding.kind),
                    endpointSpecificReachable = matchedOutcome?.let { it.result == net.pocvpn.client.smartconnect.ConnectionOutcomeResult.SUCCESS },
                    restrictionClass = restriction,
                    nowEpochMillis = now,
                    controlPlaneReachable = controlPlaneReachableByEndpoint(endpoint.id),
                    endpointSpecificOutcomeEpochMillis = matchedOutcome?.timestampEpochMillis,
                )
            }
        }
        fun reachabilityFor(id: net.pocvpn.client.reachability.EndpointId, kind: TransportKind) =
            reachability.first { it.endpointId == id && it.transportKind == kind }

        val directCandidates = manifest.endpoints.flatMap { endpoint ->
            endpoint.transports.mapNotNull { binding ->
                net.pocvpn.client.reachability.PathCandidateBuilder.buildDirect(
                    endpoint,
                    binding.kind,
                    reachabilityFor(endpoint.id, binding.kind),
                )
            }
        }
        // B12 (PR #24 second audit fix) - Relayed candidates are now
        // ACTUALLY built when the manifest expresses an INGRESS -> EXIT/
        // GATEWAY relayTo relationship (previously reachabilityDiagnostics()
        // only ever produced Direct candidates, even though PathCandidate
        // has always been a sealed Direct/Relayed type - see the scoring
        // loop below for why that omission made an unsafe cast look safe
        // by coincidence, not by design). One relayed candidate per
        // INGRESS endpoint, over its FIRST declared transport for EACH hop
        // (deterministic; this slice does not yet score multiple transport
        // choices for either hop here - see AutoGatewaySelector.
        // buildRelayedCandidates for the real cross-product scorer) -
        // PathCandidateBuilder.buildRelayed itself rejects anything the
        // manifest doesn't actually support (wrong role, unsupported
        // transport, relayTo mismatch), returning null rather than a
        // fabricated candidate. B23 (PR #37 review fix) - ingress and exit
        // transports are independent inputs to buildRelayed (never assumed
        // equal); this call site already computed them separately before
        // that fix, it just wasn't able to express it.
        val relayedCandidates = manifest.endpoints.mapNotNull { ingress ->
            if (net.pocvpn.client.reachability.EndpointRole.INGRESS !in ingress.roles) return@mapNotNull null
            val exitId = ingress.relayTo ?: return@mapNotNull null
            val exit = manifest.endpoints.firstOrNull { it.id == exitId } ?: return@mapNotNull null
            val ingressTransport = ingress.transports.firstOrNull()?.kind ?: return@mapNotNull null
            val exitTransport = exit.transports.firstOrNull()?.kind ?: return@mapNotNull null
            net.pocvpn.client.reachability.PathCandidateBuilder.buildRelayed(
                ingress, exit, ingressTransport, exitTransport,
                reachabilityFor(ingress.id, ingressTransport),
                reachabilityFor(exit.id, exitTransport),
            )
        }
        val candidates: List<net.pocvpn.client.reachability.PathCandidate> = directCandidates + relayedCandidates

        val fingerprint = fingerprintKeyProvider?.let {
            net.pocvpn.client.reachability.NetworkFingerprinter.fingerprint(
                net.pocvpn.client.reachability.CoarseNetworkSignals(profile.type, profile.dnsServerAddresses),
                it.keyBytes(),
            )
        }
        // B12 (PR #24 audit fix) - DEFERRED, not implemented here: a
        // meaningful "diversity bonus" needs a per-CANDIDATE signal (does
        // choosing THIS candidate specifically add provider/ASN diversity
        // relative to some reference - e.g. the currently active
        // connection, or the rest of the ranked set), not one batch-wide
        // Boolean computed once and handed identically to every candidate -
        // that was reviewed and found to have literally no effect on
        // ranking (every candidate got the same +5 or +0). This slice has
        // no natural asymmetric reference point to diff against (nothing
        // has been selected yet at the point this is computed), and
        // inventing one risks an arbitrary provider preference PathScorer's
        // own docs explicitly warn against. PathScorer.score's
        // `diverseProviderOrAsnSeenElsewhere` parameter itself is unchanged
        // and still real/tested (see PathScorerTest) - only THIS call site
        // is deliberately disabled until a future slice defines a real
        // per-candidate reference. See docs/ROADMAP.md's own note.
        val scored = candidates.map { candidate ->
            // B23 - PathHistoryStore is now keyed networkFingerprint x
            // pathId x transportKind (pathId = PathCandidate.historyPathId -
            // see that property's own docs), so a Relayed candidate gets its
            // OWN composite "ingress->exit" history entry, never conflated
            // with either hop's Direct history and never a fabricated
            // single-hop lookup - the exact gap this call site previously
            // deferred (see git history for the prior "deliberately null
            // until a future slice designs that key" note this replaces).
            val history = fingerprint?.let { pathHistoryStore?.get(it, candidate.historyPathId, candidate.transport) }
            // B13 SECOND consolidated review fix - THIS candidate's own
            // endpoint (the client-facing hop it actually executes against:
            // the gateway itself for Direct, the ingress for Relayed - the
            // SAME hop candidate.transport describes), never the globally
            // selected gateway. Falls back to buildTransportRegistry(id) in
            // the (should-never-happen) case an endpoint referenced by a
            // candidate is somehow missing from registriesByEndpoint, rather
            // than silently reusing a different endpoint's registry.
            val candidateEndpointId = when (candidate) {
                is net.pocvpn.client.reachability.PathCandidate.Direct -> candidate.gateway.endpoint.id
                is net.pocvpn.client.reachability.PathCandidate.Relayed -> candidate.ingress.endpoint.id
            }
            val candidateRegistry = registriesByEndpoint[candidateEndpointId] ?: buildTransportRegistry(candidateEndpointId)
            val capabilities = candidateRegistry.descriptorFor(candidate.transport)?.capabilities
                ?: TransportCapabilities.notImplemented()
            net.pocvpn.client.reachability.PathScorer.score(
                candidate = candidate,
                registry = candidateRegistry,
                capabilities = capabilities,
                transportHealth = health.getValue(candidate.transport),
                history = history,
                diverseProviderOrAsnSeenElsewhere = false,
            )
        }

        return net.pocvpn.client.reachability.ReachabilityDiagnostics.snapshot(
            manifestRepository = repository,
            reachability = reachability,
            pathCandidates = candidates,
            rankedPaths = net.pocvpn.client.reachability.PathScorer.rank(scored),
        )
    }

    // B12 (PR #24 second audit fix) - guards refreshManifest() against
    // concurrent execution: the init{}-block startup trigger and any
    // future caller (a manual "check for updates" action, say) must never
    // both be in flight at once, and a second call arriving while one is
    // already running must be SKIPPED, not queued - a queued second fetch
    // right after the first completes would still be pointless (nothing
    // changed control-plane-side in that instant) and is exactly the
    // "fetch storm" this guard exists to prevent.
    private val manifestRefreshMutex = Mutex()

    // B17 - purely observational record of the last refreshManifest() outcome,
    // for diagnostics/physical-validation only (see AppRoot's
    // "Last manifest refresh:" line) - never read by any decision path.
    // Distinguishes the three states a caller/operator actually cares about:
    // null (never attempted, e.g. MANIFEST_URL unconfigured), a fetch that
    // ran but was rejected (including the EXPECTED "not newer than what's
    // already trusted" case when the live artifact matches the embedded
    // bootstrap's own version), and a fetch that was newly accepted into LKG.
    private val _lastManifestRefreshOutcome = MutableStateFlow<String?>(null)
    val lastManifestRefreshOutcome: StateFlow<String?> = _lastManifestRefreshOutcome.asStateFlow()

    /**
     * B12/B20 - attempts one bounded multi-origin manifest download+adoption
     * via [manifestDistributionClient] (see its own docs: fetch
     * failure/invalid signature/expiry/rollback all reject WITHOUT touching
     * LKG for every origin tried, exactly ManifestUpdateResult's own
     * contract - control-plane origin failure never erases a good LKG).
     * Returns null in TWO distinct, equally-benign cases a caller must treat
     * identically - "do nothing further": no client was wired (feature not
     * configured), OR a refresh was already in flight and this call was
     * skipped rather than queued (see [manifestRefreshMutex]). OBSERVATIONAL
     * in the SAME sense as reachabilityDiagnostics(): a successful adoption
     * only changes which manifest is trusted (endpoints/candidates), never
     * which transport Smart Connect automatically selects, and never gates
     * or delays connect() - this function is never awaited by any connect
     * path.
     */
    suspend fun refreshManifest(): net.pocvpn.client.reachability.MultiOriginRefreshResult? {
        val client = manifestDistributionClient ?: return null
        if (!manifestRefreshMutex.tryLock()) return null
        return try {
            client.refresh().also { result ->
                val perOriginText = result.perOrigin.joinToString("; ") { "${it.origin.id}=${it.outcome.kind}" }.ifEmpty { "no origins configured" }
                val finalText = when (val outcome = result.finalOutcome) {
                    is net.pocvpn.client.reachability.ManifestUpdateResult.Accepted -> "accepted version ${outcome.manifest.manifestVersion}"
                    is net.pocvpn.client.reachability.ManifestUpdateResult.Rejected -> "rejected: ${outcome.reason}"
                    null -> "no origins configured"
                }
                _lastManifestRefreshOutcome.value = "$perOriginText | final: $finalText"
            }
        } finally {
            manifestRefreshMutex.unlock()
        }
    }

    /**
     * B20 - debug-only manual trigger for physical validation (Diagnostics
     * dialog's "Refresh manifest" button - see DiagnosticsDialog's own
     * docs): fire-and-forget, calls the EXACT SAME [refreshManifest] the
     * real ViewModel-init startup refresh already uses - no parallel/fake
     * test client, no separate mutex, no separate fetch pipeline. Bounded by
     * the SAME [manifestRefreshMutex] refreshManifest() already enforces, so
     * a tap while a refresh is already in flight is simply skipped, never
     * queued.
     */
    fun debugRefreshManifest() {
        viewModelScope.launch { refreshManifest() }
    }

    val transportState: StateFlow<TransportState> = controller.state

    // B25 (task B) - the real Protected-gating authority UI code should
    // read for status text/visuals going forward (see [VpnSessionHealth]'s
    // own docs) - for every Direct/manual/private-gateway attempt this is
    // always exactly [VpnSessionHealth.DirectProtected] whenever
    // [transportState] is [TransportState.Connected], so existing Direct UI
    // behavior is unaffected by switching to this signal.
    val sessionHealth: StateFlow<net.pocvpn.client.vpn.VpnSessionHealth> = controller.sessionHealth
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

    // B18 - the saved (not necessarily yet-applied) top-level routing mode,
    // read once at startup and kept in sync by updateRoutingMode(). See
    // VpnController.appliedRoutingMode for what's actually live right now -
    // same "reconnect to apply" discipline as savedAppRoutingPolicy above.
    private val _savedRoutingMode = MutableStateFlow(routingModeStore?.read() ?: RoutingMode.FULL_VPN)
    val savedRoutingMode: StateFlow<RoutingMode> = _savedRoutingMode.asStateFlow()
    val appliedRoutingMode: StateFlow<RoutingMode?> = controller.appliedRoutingMode

    /** B18 - saves ONLY the local mode file; deliberately does NOT touch the transport/tunnel (same reasoning as updateAppRoutingPolicy above). */
    fun updateRoutingMode(mode: RoutingMode) {
        routingModeStore?.write(mode)
        _savedRoutingMode.value = mode
    }

    /**
     * B18-2 - the CURRENT transport preference (see [UserTransportPreference]'s
     * own "developer/debug surface" docs) - read-only exposure for
     * diagnostics; [debugSetTransportPreference] below is the only writer.
     */
    val transportPreference: UserTransportPreference get() = userTransportPreference

    /**
     * B18-2 - lets a debug-only UI action (see AppRoot's own
     * `isDebugBuild`-gated Diagnostics dialog, the SAME pattern
     * `regenerateIdentity()` already uses) drive the REAL connect() path
     * (`connectAuto`/`connectManual` -> `smartConnectDecision()` ->
     * `SmartConnectDecisionEngine.decideManual` -> `VpnController.connect`)
     * with a manually pinned transport - never a second, parallel Xray
     * connection path. Same "saved, applied only on the NEXT connect()"
     * discipline as [updateRoutingMode]/[updateAppRoutingPolicy] - does not
     * itself disconnect/reconnect. No product UI calls this; production
     * behavior (`UserTransportPreference.Auto`, unless a caller explicitly
     * wires something else - no call site does) is unaffected by this
     * function merely existing.
     */
    fun debugSetTransportPreference(preference: UserTransportPreference) {
        userTransportPreference = preference
    }

    /**
     * B19 physical-validation debug-only helper - writes a REAL FAILURE
     * [ConnectionOutcome] and a REAL failed [net.pocvpn.client.reachability
     * .PathHistoryStore] entry into the EXACT SAME [connectionOutcomeStore]/
     * [pathHistoryStore] the real Auto ranking pipeline reads
     * ([buildAutoGatewayCandidates]'s own `transportHealthFor`/`historyFor`/
     * `reachabilityFor` closures) - never a fake/parallel evidence channel,
     * never a second store. Lets a debug build physically exercise the real
     * health-aware reordering (fresh negative evidence -> lower
     * `TransportHealth`/`EndpointReachability`/cooldown) for [kind] at
     * [endpointId] without touching production server config, AWG peer
     * config, or provisioning identity - this only ever writes to this
     * device's own local, already-existing evidence stores, the same way a
     * real failed connection attempt already would via
     * `VpnController.recordConnectionOutcome`/`recordPathHistory`. See
     * [debugRecordConnectionSuccess] for the exact reverse (restore) action.
     * No product UI calls this.
     */
    fun debugRecordConnectionFailure(kind: TransportKind, endpointId: net.pocvpn.client.reachability.EndpointId) {
        recordDebugOutcome(kind, endpointId, success = false)
    }

    /** B19 physical-validation debug-only helper - see [debugRecordConnectionFailure]'s own docs; this is the exact reverse (a real SUCCESS outcome), used to physically prove a streak clears/recovers. */
    fun debugRecordConnectionSuccess(kind: TransportKind, endpointId: net.pocvpn.client.reachability.EndpointId) {
        recordDebugOutcome(kind, endpointId, success = true)
    }

    private fun recordDebugOutcome(kind: TransportKind, endpointId: net.pocvpn.client.reachability.EndpointId, success: Boolean) {
        val nowMs = System.currentTimeMillis()
        connectionOutcomeStore?.record(
            ConnectionOutcome(
                transport = kind,
                gatewayId = endpointId.value,
                result = if (success) ConnectionOutcomeResult.SUCCESS else ConnectionOutcomeResult.FAILURE,
                handshakeDurationMs = if (success) 500L else null,
                errorCategory = if (success) net.pocvpn.client.smartconnect.ConnectionErrorCategory.NONE else net.pocvpn.client.smartconnect.ConnectionErrorCategory.HANDSHAKE_TIMEOUT,
                timestampEpochMillis = nowMs,
            ),
        )
        val profile = networkProfile.value
        val fingerprint = fingerprintKeyProvider?.let {
            net.pocvpn.client.reachability.NetworkFingerprinter.fingerprint(
                net.pocvpn.client.reachability.CoarseNetworkSignals(profile.type, profile.dnsServerAddresses),
                it.keyBytes(),
            )
        }
        fingerprint?.let { pathHistoryStore?.record(it, endpointId.value, kind, success = success, nowEpochMillis = nowMs) }
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

    init {
        viewModelScope.launch {
            _publicKey.value = clientKeyRepository.getPublicKey()
        }
        restorePersistedProfile()
        // B8I7 - one-time startup check: does a real Xray profile already
        // exist from a PRIOR session? Never polled again after this - the
        // only other place xrayAvailableEndpoints changes is the real
        // XrayProfileProvisioningOutcome.Saved event in activateDevice()
        // below.
        //
        // B13 consolidated review fix - checked independently for EVERY
        // wired repository/endpoint pair (Germany AND, when wired,
        // Stockholm), each adding ONLY its own endpointId to the set on
        // success - Germany's check failing/succeeding can never affect
        // Stockholm's entry or vice versa.
        listOfNotNull(
            xrayProfileRepository?.let { germanyEndpointId to it },
            stockholmXrayProfileRepository?.let { stockholmEndpointId to it },
        ).forEach { (endpointId, repository) ->
            viewModelScope.launch {
                val available = try {
                    repository.getProfileOrNull() != null
                } catch (t: Throwable) {
                    false
                }
                if (available) xrayAvailableEndpoints.update { it + endpointId }
            }
        }
        // B8O2 fix - a decryptable-but-invalid stored profile must NOT
        // register TLS_TCP as AVAILABLE: this uses the SAME authoritative
        // validation XrayCoreController/VlessTlsTransport actually run at
        // connect time (XrayRuntimeResolver.resolveTls) - never a
        // duplicated/looser "profile exists" check that could disagree with
        // what connect() itself will accept. Same per-endpoint independence
        // as the XRAY_REALITY check above.
        listOfNotNull(
            xrayTlsProfileRepository?.let { germanyEndpointId to it },
            stockholmXrayTlsProfileRepository?.let { stockholmEndpointId to it },
        ).forEach { (endpointId, repository) ->
            viewModelScope.launch {
                val ready = XrayRuntimeResolver.resolveTls(repository) is XrayTlsRuntimeResolution.Ready
                if (ready) xrayTlsAvailableEndpoints.update { it + endpointId }
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
        // B12 (PR #24 second audit fix) - the ONE production trigger for
        // manifest distribution: fires exactly once per ViewModel instance
        // (same "one-time startup check" pattern as the xrayProfileRepository/
        // xrayTlsProfileRepository blocks above - ViewModel init runs once
        // per instance, survives configuration changes, and is NEVER
        // re-invoked by Compose recomposition, which only re-reads existing
        // state/StateFlow values from an already-constructed ViewModel).
        // No timer, no polling. refreshManifest() itself is a no-op when
        // manifestDistributionClient is null (BuildConfig.MANIFEST_URL
        // blank - see Factory), so an unconfigured client performs
        // ZERO network work here. Fire-and-forget: never awaited, never
        // gates connect() or any other user action.
        manifestDistributionClient?.let {
            viewModelScope.launch { refreshManifest() }
        }
    }

    // B8B3C requirement 6 (fail closed): NotFound and Corrupted are handled
    // identically here - neither ever calls gatewayConfigOverride.apply().
    // A corrupt/partial/tampered file can therefore never reach the AWG
    // config mapper - the effective profile simply stays whatever
    // BuildConfigGatewaySource already provides (DEV_FALLBACK), exactly as
    // if no profile had ever been persisted. This never throws/crashes -
    // ProfileStore.read() itself already converts every I/O/parse failure
    // into Corrupted (see FileProfileStore's own docs).
    //
    // B13 SECOND consolidated review fix - a STRUCTURALLY valid
    // PersistedProfile is no longer, by itself, enough to unlock Home
    // (ProfileSource.RESTORED_PERSISTED -> ProductFlowPresentation.screenFor
    // -> AppScreen.HOME). A real gap: this used to accept ANY structurally
    // well-formed profile, even one for an endpoint the CANONICAL
    // connect-time authority (SelectedProductionGatewaySource, resolved
    // from ProductionGatewayCatalog.matchGatewayId + ClientTunnelIdentityStore
    // - the SAME two checks activateDevice() itself now enforces on a live
    // response) would refuse - a dev/staging profile, a profile for a
    // rotated-away key, or (legitimately) a profile restored on a device
    // whose ClientTunnelIdentityStore entry was never actually provisioned/
    // migrated could show Home while gatewayStatus() would really resolve
    // to Invalid. RESTORED_PERSISTED now requires BOTH: (1) the profile's
    // full stable facts unambiguously match a known catalog gateway
    // (matchGatewayId - host+port+key+gatewayTunnelIp, never guessed), AND
    // (2) THIS device is actually provisioned for that exact gateway
    // (isGatewayProvisioned - the SAME per-device evidence
    // SelectedProductionGatewaySource itself resolves clientTunnelIp()
    // from). Anything short of both stays/falls back to DEV_FALLBACK -
    // Activation, never a fabricated identity, never a guessed migration
    // (ClientTunnelIdentityStore's own migration, if any, already ran in
    // the Factory before this ViewModel was even constructed - this never
    // re-runs or duplicates it).
    private fun restorePersistedProfile() {
        val store = profileStore ?: return
        when (val result = store.read()) {
            is ProfileLoadResult.Found -> {
                val p = result.profile
                val matched = net.pocvpn.client.vpn.config.ProductionGatewayCatalog.matchGatewayId(
                    endpointHost = p.endpointHost,
                    endpointPort = p.endpointPort,
                    serverPublicKeyBase64 = p.gatewayPublicKey,
                    gatewayTunnelIp = p.gatewayTunnelIp,
                )
                if (matched != null && isGatewayProvisioned(matched)) {
                    gatewayConfigOverride?.apply(
                        endpointHost = p.endpointHost,
                        endpointPort = p.endpointPort,
                        serverPublicKey = p.gatewayPublicKey,
                        clientTunnelIp = p.clientTunnelIp,
                        gatewayTunnelIp = p.gatewayTunnelIp,
                    )
                    _profileSource.value = ProfileSource.RESTORED_PERSISTED
                }
                // else: leave _profileSource at its DEV_FALLBACK default -
                // this legacy profile does not correspond to a gateway the
                // real connect path would actually accept, so it must not
                // unlock Home. Never calls gatewayConfigOverride.apply()
                // either, for the same reason NotFound/Corrupted below
                // don't - no accepted-but-unusable state.
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
     *
     * B14 - [targetGatewayId] is an EXPLICIT request parameter, defaulted
     * to [selectedGateway]'s CURRENT value only so every pre-B14 call site
     * (one argument) stays byte-for-byte unchanged - it is never re-read
     * later if the UI selection changes mid-request, and the caller (the
     * Activation screen) is free to pass a specific target regardless of
     * what happens to be selected. Routes to [activationClient] (Germany)
     * or [stockholmActivationClient] (Stockholm) accordingly, and - beyond
     * the existing matchGatewayId check - additionally REQUIRES the
     * response to match [targetGatewayId] specifically: a response that
     * validly matches some OTHER known gateway (e.g. Germany's own edge
     * somehow answering a request that was sent to Stockholm's host) is
     * rejected exactly like an unmatched one, never silently applied to
     * the wrong endpoint's identity.
     */
    fun activateDevice(
        activationCredential: String,
        targetGatewayId: net.pocvpn.client.vpn.config.ProductionGatewayId = selectedGateway.value,
    ) {
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

        val client = when (targetGatewayId) {
            net.pocvpn.client.vpn.config.ProductionGatewayId.GERMANY -> activationClient
            net.pocvpn.client.vpn.config.ProductionGatewayId.STOCKHOLM -> stockholmActivationClient
        }
        val targetXrayProvisioner = when (targetGatewayId) {
            net.pocvpn.client.vpn.config.ProductionGatewayId.GERMANY -> xrayProfileProvisioner
            net.pocvpn.client.vpn.config.ProductionGatewayId.STOCKHOLM -> stockholmXrayProfileProvisioner
        }
        val targetXrayTlsProvisioner = when (targetGatewayId) {
            net.pocvpn.client.vpn.config.ProductionGatewayId.GERMANY -> xrayTlsProfileProvisioner
            net.pocvpn.client.vpn.config.ProductionGatewayId.STOCKHOLM -> stockholmXrayTlsProfileProvisioner
        }
        val targetXrayTlsRepository = when (targetGatewayId) {
            net.pocvpn.client.vpn.config.ProductionGatewayId.GERMANY -> xrayTlsProfileRepository
            net.pocvpn.client.vpn.config.ProductionGatewayId.STOCKHOLM -> stockholmXrayTlsProfileRepository
        }
        val targetEndpointId = when (targetGatewayId) {
            net.pocvpn.client.vpn.config.ProductionGatewayId.GERMANY -> germanyEndpointId
            net.pocvpn.client.vpn.config.ProductionGatewayId.STOCKHOLM -> stockholmEndpointId
        }

        _provisioningState.value = ProvisioningUiState.Provisioning
        viewModelScope.launch {
            val result = withContext(ioDispatcher) {
                client(key, trimmedCredential)
            }
            _provisioningState.value = when (result) {
                is ProvisioningResult.Success -> {
                    // B13 consolidated review fix (finding 1/6) - THE one
                    // place a live activation response is mapped to a real
                    // ProductionGatewayId, from its FULL stable server facts
                    // (host+port+key), never from whatever the user happens
                    // to have selected in the picker right now and never
                    // from endpointHost alone - see
                    // ProductionGatewayCatalog.matchGatewayId's own docs.
                    // A response that does not unambiguously match a known
                    // catalog gateway (a rotated/wrong key, a dev/staging
                    // host, a malformed/adversarial response) is REJECTED
                    // outright: nothing below is applied or persisted for
                    // it, and no gateway's existing identity is mutated by
                    // it - this is the fix for silently "accepting" a
                    // control-plane response while the real connect-time
                    // config (ProductionGatewayCatalog/ClientTunnelIdentityStore)
                    // would have gone on ignoring it.
                    //
                    // B14 - ALSO required to equal [targetGatewayId]: a
                    // response that happens to validly match a DIFFERENT
                    // known gateway than the one this request actually
                    // targeted is a cross-endpoint mismatch, rejected the
                    // same way - never silently redirected to apply against
                    // whichever gateway the facts happened to name.
                    val matchedGatewayId = net.pocvpn.client.vpn.config.ProductionGatewayCatalog.matchGatewayId(
                        endpointHost = result.endpointHost,
                        endpointPort = result.endpointPort,
                        serverPublicKeyBase64 = result.gatewayPublicKey,
                        gatewayTunnelIp = result.gatewayTunnelIp,
                    )
                    if (matchedGatewayId != targetGatewayId) {
                        ProvisioningUiState.Error(
                            "activation response does not match the requested production gateway ($targetGatewayId) - refusing to apply it",
                        )
                    } else {
                        // B8B3B safety rule: apply() is reached ONLY inside
                        // this branch - i.e. only for a value that has
                        // already passed ProvisioningClient's own structural
                        // validation AND matched a known gateway above.
                        // Never called against a raw/unvalidated server
                        // response. The device private key is untouched - it
                        // is looked up separately from clientKeyRepository
                        // at connect time (see GatewayConfiguration's own
                        // docs) and is not part of this GatewayConfigSource
                        // at all. AWG obfuscation parameters (Jc/Jmin/Jmax/
                        // S1-4/H1-4) come from PocAwgProfile.value via
                        // DefaultGatewayConfigurationRepository's own
                        // `profile` default, untouched here.
                        //
                        // B13 note - gatewayConfigOverride/profileStore
                        // below are kept for the pre-existing activation
                        // flow's own UI-gating behavior (ProfileSource
                        // routing - see restorePersistedProfile()'s own
                        // docs); the REAL connect-time gateway infrastructure
                        // facts (host/port/key) always come from
                        // ProductionGatewayCatalog via matchedGatewayId
                        // above, which is exactly why a mismatching response
                        // is rejected rather than silently accepted-but-
                        // ignored.
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
                        // B13 consolidated review fix (finding 1) - THE
                        // canonical per-device client tunnel identity write:
                        // result.clientTunnelIp is real, per-device evidence
                        // for EXACTLY targetGatewayId - never any other
                        // gateway (matchGatewayId already proved the
                        // response is unambiguously about this one, and the
                        // B14 check above additionally proved it equals
                        // targetGatewayId specifically - using targetGatewayId
                        // here, not the nullable matchedGatewayId, needs no
                        // extra null-handling and is byte-for-byte the same
                        // value at this point).
                        clientTunnelIdentityStore?.write(targetGatewayId, result.clientTunnelIp)
                        // B13 consolidated review fix (finding 2) - a fresh
                        // identity write can change readiness for the
                        // CURRENTLY selected gateway (e.g. Stockholm was
                        // selected while unprovisioned and deliberately
                        // retained - see reconcileSelectedGateway's own
                        // docs - and this activation just provisioned
                        // Germany): re-evaluate and, if needed, switch to a
                        // now-provisioned gateway immediately, with no app
                        // restart required.
                        reconcileSelectedGatewayIfNeeded()
                        _profileSource.value = ProfileSource.PROVISIONED_LIVE
                        // B8K4B - runs only after the AWG activation above has
                        // already fully succeeded (applied + persisted). Reuses
                        // the SAME `key`/`trimmedCredential` this activation call
                        // used - no second identity, no new credential. Any
                        // outcome other than Saved (network error/401/403/503/
                        // malformed) leaves this AWG success and any previously
                        // stored Xray profile completely untouched - see
                        // XrayProfileProvisioner's own docs.
                        //
                        // B14 - runs the provisioner/repository/availability
                        // set for [targetGatewayId] specifically
                        // (targetXrayProvisioner/targetXrayTlsProvisioner/
                        // targetXrayTlsRepository/targetEndpointId, resolved
                        // once at the top of this function) - a Stockholm
                        // activation now provisions STOCKHOLM's own Xray
                        // REALITY/TLS profiles into STOCKHOLM's own
                        // endpoint-scoped storage and flips STOCKHOLM's own
                        // availability flag, never Germany's (and vice
                        // versa) - see each param's own constructor docs.
                        targetXrayProvisioner?.let { provisioner ->
                            val outcome = withContext(ioDispatcher) {
                                provisioner.provision(key, trimmedCredential)
                            }
                            _xrayProfileProvisioningState.value = outcome
                            if (outcome == XrayProfileProvisioningOutcome.Saved) {
                                // B8I7 - the real, event-driven moment Xray
                                // becomes selectable - never polled, never
                                // inferred from elapsed time (see
                                // xrayAvailableEndpoints' own docs).
                                xrayAvailableEndpoints.update { it + targetEndpointId }
                            }
                        }
                        // B8O2 - same reasoning as targetXrayProvisioner above:
                        // runs only after the AWG activation has already fully
                        // succeeded, reusing the SAME key/credential, and never
                        // touches AWG's own success/state either way. Same
                        // per-endpoint scoping as above.
                        targetXrayTlsProvisioner?.let { provisioner ->
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
                                val repository = targetXrayTlsRepository
                                if (repository != null && XrayRuntimeResolver.resolveTls(repository) is XrayTlsRuntimeResolution.Ready) {
                                    xrayTlsAvailableEndpoints.update { it + targetEndpointId }
                                }
                            }
                        }
                        ProvisioningUiState.Success(result)
                    }
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

    private val _ingressActivationState = MutableStateFlow<net.pocvpn.client.relay.IngressActivationOutcome?>(null)
    val ingressActivationState: StateFlow<net.pocvpn.client.relay.IngressActivationOutcome?> = _ingressActivationState.asStateFlow()

    // B26 review fix (round 2, blocker) - the FULL pinned context a paused
    // relayed attempt needs to be resumed EXACTLY where it left off: the
    // same already-ranked [candidate] (never rebuilt/re-scored - a fresh
    // [combinedAutoAttempts]/[buildCombinedAutoAttempts] call could rank
    // differently against then-current evidence, silently substituting a
    // different ingress/exit/transport/historyPathId - the exact defect
    // this type exists to prevent) and the exact [attempts]/[attemptedKeys]
    // [attemptCombined] was mid-sequence with when this candidate's
    // resolution first came back NotProvisioned-but-fixable (attemptedKeys
    // already includes this candidate's own key - see
    // buildCombinedAutoAttempts' dispatch site - so resuming
    // [attemptCombined] with this SAME pair can never re-select it).
    // `private` - never exposed to the UI layer, which only ever sees the
    // smaller, display-only [RelayActivationRequest] via
    // [relayActivationNeeded] below.
    private data class PendingRelayActivation(
        val candidate: net.pocvpn.client.smartconnect.AutoGatewaySelector.RelayAttemptCandidate,
        val attempts: List<net.pocvpn.client.smartconnect.AutoGatewaySelector.AutoConnectAttempt>,
        val attemptedKeys: Set<String>,
    )

    // B26 review fix (round 2, blocker) - the ONE place a paused relayed
    // attempt's full resume context lives. Non-null is what "the combined
    // Auto sequence is paused, waiting on a human activation decision"
    // MEANS - see attemptRelayedAttempt's own docs: while this is non-null,
    // NOTHING else advances the combined sequence (no attemptCombined call
    // happens until activation succeeds, fails, or is dismissed) - task
    // requirement G's own "no second concurrent Auto progression".
    private var pendingRelayActivation: PendingRelayActivation? = null

    // B26 review fix (blocker 1) - the real, product-UI-observable signal a
    // relayed Auto attempt just failed with a RelayFailureCategory an
    // explicit device activation can actually fix - see
    // RelayActivationRequest's own docs for exactly which categories and
    // why. A pure DISPLAY projection of [pendingRelayActivation] above -
    // set/cleared in lockstep with it, never independently. Set ONLY from
    // attemptRelayedAttempt's NotProvisioned branch below; cleared by
    // activateIngress() (success or failure) or dismissRelayActivationPrompt().
    private val _relayActivationNeeded = MutableStateFlow<net.pocvpn.client.relay.RelayActivationRequest?>(null)
    val relayActivationNeeded: StateFlow<net.pocvpn.client.relay.RelayActivationRequest?> = _relayActivationNeeded.asStateFlow()

    private val _ingressActivating = MutableStateFlow(false)
    val ingressActivating: StateFlow<Boolean> = _ingressActivating.asStateFlow()

    /**
     * B26 review fix (round 3, blocker) - the ONE atomic single-owner
     * claim: reads [pendingRelayActivation] and nulls it out (together with
     * its display projection, [_relayActivationNeeded]) in one synchronous,
     * non-suspending call - two field writes back to back, no suspension
     * point between the read and the clear. Whoever gets a non-null result
     * back is the ONLY caller that may ever resume/retry that context -
     * every other caller (including a second concurrent call racing for the
     * same pending activation) gets null and does nothing further.
     *
     * This is safe under plain sequential/single-dispatcher execution
     * (`viewModelScope`'s default `Dispatchers.Main.immediate`, the same
     * confinement every other mutable field on this ViewModel - e.g.
     * `pendingFailoverAttempt`, `xrayAvailableEndpoints` - already relies on
     * without an explicit lock): [activateIngress] and
     * [dismissRelayActivationPrompt] both call this SYNCHRONOUSLY, at the
     * very top of the function, strictly BEFORE either one does anything
     * suspending - so two calls arriving back to back (e.g. a rapid double
     * tap, or a dismiss racing an in-flight activation) are necessarily
     * processed in order on the same thread, and the second one always
     * observes the first one's clear.
     */
    private fun claimPendingRelayActivation(): PendingRelayActivation? {
        val pending = pendingRelayActivation
        pendingRelayActivation = null
        _relayActivationNeeded.value = null
        return pending
    }

    /**
     * B26 review fix (round 2/3, blocker) - the user backing out without
     * submitting anything (mirrors activatingGatewayId's own cancel path).
     * Task requirement F: never retries the paused candidate, and resumes
     * the ORIGINAL combined sequence (same attempts/attemptedKeys captured
     * when it paused) EXACTLY once - the candidate's key is already in
     * attemptedKeys (see [PendingRelayActivation]'s own docs), so
     * [attemptCombined] moves on to the next ranked candidate rather than
     * re-offering this same ingress.
     *
     * Round 3 fix: uses [claimPendingRelayActivation] - if an
     * [activateIngress] call already claimed the pending context (its own
     * provisioning is in flight), this call gets null and does NOTHING -
     * it must never independently resume the same combined context a
     * still-running activation will resume itself once it completes
     * (task requirement 3).
     */
    fun dismissRelayActivationPrompt() {
        val pending = claimPendingRelayActivation() ?: return
        viewModelScope.launch { attemptCombined(pending.attempts, pending.attemptedKeys) }
    }

    /**
     * B26 (task D) / review fix (round 2, blocker) - the real Android
     * control-plane path for the CURRENTLY paused ingress
     * ([pendingRelayActivation] - there is at most one at a time by
     * construction, so this takes no candidate-identifying parameter of
     * its own to go stale against): activation credential + this device's
     * existing public key (the SAME reused identity every other activation
     * in this class already uses - never a second credential/key system
     * for an ingress, mirroring [ingress_activation.py]'s own "no second
     * identity system") -> [ingressProfileProvisioner]'s bounded
     * [net.pocvpn.client.relay.IngressProfileProvisioner.ensureFreshProfile]
     * (reuses a still-valid stored profile as-is, otherwise exactly ONE
     * network attempt - never a retry loop) -> a validated, endpoint-scoped
     * [net.pocvpn.client.relay.IngressClientProfile] persisted via
     * [net.pocvpn.client.relay.FileIngressProfileStore]. The pinned
     * endpoint id/binding/transport come from [pendingRelayActivation]'s
     * own already-ranked candidate - never re-derived - and
     * [IngressProfileProvisioner.provision] itself additionally cross-
     * checks the server's own response against them (task K's own
     * "activation never changes the originally pinned ingress
     * endpoint/binding").
     *
     * On success: retries THAT EXACT SAME [PendingRelayActivation.candidate]
     * via [attemptRelayedAttempt] with `isActivationRetry = true` - never a
     * fresh [combinedAutoAttempts]/[connect] call, which could re-rank and
     * silently resolve to a different ingress/exit/transport/historyPathId
     * (task requirement B/C's own "byte-for-byte identical" /  "no fresh
     * ranking"). `isActivationRetry = true` is what makes this bounded to
     * EXACTLY one retry (task requirement D): even if that retry ALSO comes
     * back NotProvisioned-but-otherwise-fixable, attemptRelayedAttempt does
     * not pause a second time - it resumes the combined sequence via
     * [attemptCombined] instead (task requirement E).
     *
     * On any other (non-Saved) outcome - unauthorized/revoked/mismatched/
     * unavailable/unsupported-transport - fails closed (task requirement H):
     * the paused candidate is NEVER retried (no usable profile exists to
     * retry it with), and the ORIGINAL combined sequence resumes exactly
     * once via [attemptCombined], the same way [dismissRelayActivationPrompt]
     * does.
     *
     * Round 3 fix: [claimPendingRelayActivation] is called SYNCHRONOUSLY,
     * before any suspension - so a second concurrent call to this function
     * (before the first call's provisioning coroutine has even started, let
     * alone finished) observes `null` and reports
     * [net.pocvpn.client.relay.IngressActivationOutcome.Unavailable]
     * without provisioning or resuming anything (task requirement 1/2) -
     * there is only ever ONE in-flight owner of a given
     * [PendingRelayActivation], so its captured attempts/attemptedKeys
     * context is resumed/retried at most once no matter how this function
     * or [dismissRelayActivationPrompt] are interleaved (task requirement 4).
     */
    fun activateIngress(activationCredential: String) {
        val trimmedCredential = activationCredential.trim()
        val pending = claimPendingRelayActivation()
        if (pending == null) {
            _ingressActivationState.value = net.pocvpn.client.relay.IngressActivationOutcome.Unavailable
            return
        }
        val provisioner = ingressProfileProvisioner
        val key = _publicKey.value
        if (provisioner == null || key == null || trimmedCredential.isEmpty()) {
            _ingressActivationState.value = net.pocvpn.client.relay.IngressActivationOutcome.Unavailable
            viewModelScope.launch { attemptCombined(pending.attempts, pending.attemptedKeys) }
            return
        }
        _ingressActivating.value = true
        viewModelScope.launch {
            val outcome = withContext(ioDispatcher) {
                provisioner.ensureFreshProfile(
                    pending.candidate.ingressEndpointId, pending.candidate.ingressBinding, pending.candidate.ingressTransport,
                    pending.candidate.ingressKind, key, trimmedCredential,
                )
            }
            _ingressActivating.value = false
            _ingressActivationState.value = outcome
            // pendingRelayActivation/_relayActivationNeeded were already
            // cleared synchronously by claimPendingRelayActivation() above,
            // at the moment this activation attempt claimed sole ownership -
            // never redundantly re-cleared here.
            if (outcome is net.pocvpn.client.relay.IngressActivationOutcome.Saved) {
                attemptRelayedAttempt(pending.candidate, pending.attempts, pending.attemptedKeys, isActivationRetry = true)
            } else {
                attemptCombined(pending.attempts, pending.attemptedKeys)
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
            // B22 - dispatches on the explicit three-way authority now,
            // instead of the plain boolean - AUTO/MANUAL_MANAGED still call
            // the exact SAME pre-B22 functions, byte-for-byte, for every
            // existing test/behavior; PRIVATE is the one new branch.
            when (gatewaySelectionMode.value) {
                net.pocvpn.client.vpn.config.GatewaySelectionMode.AUTO -> connectAuto()
                net.pocvpn.client.vpn.config.GatewaySelectionMode.MANUAL_MANAGED -> connectManual()
                net.pocvpn.client.vpn.config.GatewaySelectionMode.PRIVATE -> connectPrivate()
            }
        }
    }

    /**
     * B22 - PRIVATE gateway mode's connect path. Deliberately much simpler
     * than [connectManual]: AWG-only (architecture constraint: no
     * Xray/REALITY/TLS/QUIC), single candidate, no [smartConnectDecision]/
     * [AwgXrayFailoverPolicy]/intra-gateway failover at all - there is
     * nothing to rank or fail over between. Resolves ONLY from
     * [privateGatewayStore] - never [net.pocvpn.client.vpn.config.ProductionGatewayCatalog],
     * never the signed manifest (architecture constraint 2) - and fails
     * closed (typed [VpnError], never a silent fallback to a managed
     * gateway) on anything missing/invalid, exactly like every other
     * malformed-config case in this ViewModel.
     */
    private suspend fun connectPrivate() {
        val store = privateGatewayStore
        val keyRepository = privateGatewayKeyRepository
        if (store == null || keyRepository == null) {
            controller.rejectPreflight(VpnError.GatewayConfigurationMissing, "Private gateway not configured on this build")
            return
        }
        val saved = store.read()
        if (saved == null) {
            controller.rejectPreflight(VpnError.GatewayConfigurationMissing, "No private gateway configured")
            return
        }
        when (val validation = net.pocvpn.client.vpn.config.PrivateGatewayConfigValidator.revalidate(saved)) {
            is net.pocvpn.client.vpn.config.PrivateGatewayValidationResult.Invalid -> {
                controller.rejectPreflight(
                    VpnError.InvalidGatewayConfiguration(validation.reason.name),
                    "Saved private gateway configuration is invalid: ${validation.reason.name}",
                )
                return
            }
            is net.pocvpn.client.vpn.config.PrivateGatewayValidationResult.Valid -> {
                _activeGatewayId.value = selectedGateway.value
                val resolved = TransportOrchestrator.Resolution.Resolved(
                    transport = transport,
                    kind = transport.kind,
                    endpointId = net.pocvpn.client.reachability.EndpointId(net.pocvpn.client.vpn.config.PrivateGatewayConfig.ID),
                    gatewayConfigSnapshot = validation.config.toGatewayConfigSnapshot(),
                    privateKeyRepository = keyRepository,
                )
                controller.connect(resolved)
            }
        }
    }

    /** B8I1 - the pre-B16 connect() body, unchanged: manual gateway, existing intra-gateway AWG->Xray failover only. */
    private suspend fun connectManual() {
        when (val decision = smartConnectDecision()) {
            is SmartConnectDecision.Selected -> {
                val kind = decision.score.candidate.transport.kind
                // B13 - the real SmartConnectCandidateSelector-chosen
                // GatewayCandidate.id (today always ProductionGateway.ID,
                // but derived, never hardcoded here) - the first place
                // this ViewModel names WHICH endpoint the attempt about
                // to be resolved/executed actually targets.
                val endpointId = net.pocvpn.client.reachability.EndpointId(decision.score.candidate.gateway.id)
                _activeGatewayId.value = selectedGateway.value
                // B13 consolidated review fix - THIS attempt's own
                // endpointId, never the default: the registry that
                // decides eligibility for an AWG -> Xray failover later
                // (armFailoverWatch/maybeFailoverToXray, both reuse THIS
                // exact retained registry, never rebuild it) must report
                // Xray/TLS availability for the SAME gateway this attempt
                // is actually connecting to.
                val registry = buildTransportRegistry(endpointId)
                val orchestrator = TransportOrchestrator(registry)
                when (val resolution = orchestrator.resolve(TransportSelectionDecision.SelectTransport(kind), endpointId)) {
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
                            preference = userTransportPreference,
                            registry = registry,
                            orchestrator = orchestrator,
                            endpointId = endpointId,
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

    /**
     * B16/B17 - builds the real, ranked candidate list for automatic gateway
     * selection, reusing the SAME evidence accessors (transportHealth(),
     * restrictionClass(), recentConnectionOutcomes(), pathHistoryStore) the
     * rest of this ViewModel already computes fresh on every call - never a
     * second, independently-derived evidence source.
     *
     * **B17 runtime-authority change**: WHICH endpoints are even eligible
     * now comes from [manifestRepository]'s verified [net.pocvpn.client.reachability.TrustedManifestState] -
     * `ProductionGatewayCatalog.all` is consulted only as a per-endpoint
     * COMPATIBILITY lookup ([gatewayFactsFor], invoked only for an endpoint
     * id the trusted manifest already named), never iterated directly to
     * decide what exists. Nothing trusted ([net.pocvpn.client.reachability.TrustedManifestState.NoneTrusted],
     * or [manifestRepository] never wired at all) yields an empty manifest
     * endpoint list, which - by construction in
     * [net.pocvpn.client.smartconnect.AutoGatewaySelector.buildCandidates] -
     * always yields an empty candidate list: task requirement 9.D's
     * fail-closed rule, never a silent fallback to the unverified catalog.
     */
    private fun buildAutoGatewayCandidates(): List<net.pocvpn.client.smartconnect.GatewayAttemptCandidate> {
        val now = System.currentTimeMillis()
        val profile = networkProfile.value
        val restriction = restrictionClass()
        val health = transportHealth()
        val outcomes = recentConnectionOutcomes()
        val fingerprint = fingerprintKeyProvider?.let {
            net.pocvpn.client.reachability.NetworkFingerprinter.fingerprint(
                net.pocvpn.client.reachability.CoarseNetworkSignals(profile.type, profile.dnsServerAddresses),
                it.keyBytes(),
            )
        }
        val gatewaysById = net.pocvpn.client.vpn.config.ProductionGatewayCatalog.all.associateBy { it.endpointId }
        val manifestEndpoints = manifestRepository?.trusted()?.endpoints.orEmpty()
        return net.pocvpn.client.smartconnect.AutoGatewaySelector.buildCandidates(
            manifestEndpoints = manifestEndpoints,
            gatewayFactsFor = { endpointId -> gatewaysById[endpointId] },
            provisioned = ::isGatewayProvisioned,
            clientTunnelIp = { id -> clientTunnelIdentityStore?.read(id) },
            registryFor = { endpointId -> buildTransportRegistry(endpointId) },
            xrayAvailableFor = ::isXrayAvailableFor,
            xrayTlsAvailableFor = ::isXrayTlsAvailableFor,
            reachabilityFor = { endpointId, kind ->
                val gateway = gatewaysById.getValue(endpointId)
                val endpoint = net.pocvpn.client.smartconnect.ProductionGatewayEndpoints.descriptorFor(
                    gateway,
                    xrayAvailable = isXrayAvailableFor(endpointId),
                    xrayTlsAvailable = isXrayTlsAvailableFor(endpointId),
                )
                val matchedOutcome = net.pocvpn.client.reachability.EndpointOutcomeMatcher.latestMatching(outcomes, endpointId, kind)
                net.pocvpn.client.reachability.ReachabilityEngine.assess(
                    endpoint = endpoint,
                    transportKind = kind,
                    networkUsable = profile.isUsable,
                    transportHealth = health.getValue(kind),
                    endpointSpecificReachable = matchedOutcome?.let { it.result == ConnectionOutcomeResult.SUCCESS },
                    restrictionClass = restriction,
                    nowEpochMillis = now,
                    controlPlaneReachable = if (endpointId.value == net.pocvpn.client.smartconnect.ProductionGateway.ID) restrictionMonitor?.lastProbeResult?.value else null,
                    endpointSpecificOutcomeEpochMillis = matchedOutcome?.timestampEpochMillis,
                )
            },
            transportHealthFor = { kind -> health.getValue(kind) },
            historyFor = { endpointId, kind -> fingerprint?.let { pathHistoryStore?.get(it, endpointId, kind) } },
            preference = userTransportPreference,
            nowEpochMillis = now,
        )
    }

    /**
     * B16 - OBSERVATIONAL: the CURRENT ranked automatic-gateway candidate
     * list, recomputed fresh on every read (same no-caching discipline as
     * smartConnectDecision()/reachabilityDiagnostics()) - for diagnostics UI
     * and tests. Does not itself start or affect any connect() attempt.
     */
    fun autoGatewayCandidates(): List<net.pocvpn.client.smartconnect.GatewayAttemptCandidate> = buildAutoGatewayCandidates()

    /**
     * B24 - OBSERVATIONAL: the CURRENT combined Direct+Relayed ranked
     * attempt list, recomputed fresh on every read (same discipline as
     * [autoGatewayCandidates]) - for diagnostics/tests. Does not itself
     * start or affect any connect() attempt. This is the SAME list
     * [connectAuto] uses to pick its winner.
     */
    fun combinedAutoAttempts(): List<net.pocvpn.client.smartconnect.AutoGatewaySelector.AutoConnectAttempt> = buildCombinedAutoAttempts()

    /**
     * B28 (requirement 10) - sanitized diagnostics explaining why Auto
     * ranked DIRECT / CHAIN_DIRECT / CHAIN_CDN the way it did, including
     * which [net.pocvpn.client.smartconnect.RestrictionClass] was in effect
     * for this read. Built purely by MAPPING the already-public,
     * already-ranked [combinedAutoAttempts] output (never a second ranking
     * pass, never a second decision authority - requirement 7) plus the
     * SAME [restrictionClass] evidence read fresh above. Deliberately a
     * NEW, separate surface rather than a change to the existing
     * Direct-only [AutoGatewayDiagnostics] shape, which B24 already
     * documented as staying Direct-only - existing consumers of that type
     * are unaffected.
     *
     * Only [PathScorer.Reason] token names, a "kind" label, and the numeric
     * score are exposed - never a UUID, endpoint host/IP, activation
     * credential, probe token, or key (see [CombinedAttemptDiagnostic]'s
     * own field list, a closed, non-secret set - same discipline as
     * [ReachabilityEvidenceSummary]).
     */
    fun combinedAutoRankingDiagnostics(): CombinedAutoRankingDiagnostics {
        val attempts = combinedAutoAttempts()
        return CombinedAutoRankingDiagnostics(
            restrictionClass = restrictionClass(),
            ranked = attempts.map { attempt ->
                val kind = when (attempt) {
                    is net.pocvpn.client.smartconnect.AutoGatewaySelector.AutoConnectAttempt.DirectAttempt -> "DIRECT"
                    is net.pocvpn.client.smartconnect.AutoGatewaySelector.AutoConnectAttempt.RelayedAttempt ->
                        if (attempt.candidate.ingressKind == net.pocvpn.client.reachability.IngressKind.CDN_FRONTED) "CHAIN_CDN" else "CHAIN_DIRECT"
                }
                CombinedAttemptDiagnostic(
                    kind = kind,
                    score = attempt.score,
                    reasons = attempt.reasons.filter { reason -> reason.all { it.isUpperCase() || it == '_' } },
                )
            },
        )
    }

    /**
     * B24 - the combined Direct+Relayed counterpart of
     * [buildAutoGatewayCandidates]: identical evidence accessors, but calls
     * [net.pocvpn.client.smartconnect.AutoGatewaySelector.buildCombinedAttempts]
     * instead of `buildCandidates` alone (task requirement 4 - "build ONE
     * combined executable attempt plan... do not maintain separate ranking/
     * execution loops that can disagree"). [buildAutoGatewayCandidates]
     * itself is intentionally left untouched - every pre-B24 caller of it
     * (and of [autoGatewayCandidates]/[AutoGatewayDiagnostics], which stay
     * Direct-only - see [connectAuto]'s own docs) is byte-for-byte
     * unaffected.
     */
    private fun buildCombinedAutoAttempts(): List<net.pocvpn.client.smartconnect.AutoGatewaySelector.AutoConnectAttempt> {
        val now = System.currentTimeMillis()
        val profile = networkProfile.value
        val restriction = restrictionClass()
        val health = transportHealth()
        val outcomes = recentConnectionOutcomes()
        val fingerprint = fingerprintKeyProvider?.let {
            net.pocvpn.client.reachability.NetworkFingerprinter.fingerprint(
                net.pocvpn.client.reachability.CoarseNetworkSignals(profile.type, profile.dnsServerAddresses),
                it.keyBytes(),
            )
        }
        val gatewaysById = net.pocvpn.client.vpn.config.ProductionGatewayCatalog.all.associateBy { it.endpointId }
        val manifestEndpoints = manifestRepository?.trusted()?.endpoints.orEmpty()
        return net.pocvpn.client.smartconnect.AutoGatewaySelector.buildCombinedAttempts(
            manifestEndpoints = manifestEndpoints,
            gatewayFactsFor = { endpointId -> gatewaysById[endpointId] },
            provisioned = ::isGatewayProvisioned,
            clientTunnelIp = { id -> clientTunnelIdentityStore?.read(id) },
            registryFor = { endpointId -> buildTransportRegistry(endpointId) },
            xrayAvailableFor = ::isXrayAvailableFor,
            xrayTlsAvailableFor = ::isXrayTlsAvailableFor,
            reachabilityFor = { endpointId, kind ->
                // B24 - relay endpoint ids (an INGRESS/EXIT the manifest
                // names but that has no ProductionGatewayCatalog entry -
                // exactly the "no RU ingress provisioning in this slice"
                // case) fall back to a manifest-only descriptor, mirroring
                // reachabilityDiagnostics()'s own catalog-optional path -
                // gatewaysById.getValue(...) (used by buildAutoGatewayCandidates)
                // would throw for such an id.
                val gateway = gatewaysById[endpointId]
                val endpoint = if (gateway != null) {
                    net.pocvpn.client.smartconnect.ProductionGatewayEndpoints.descriptorFor(
                        gateway,
                        xrayAvailable = isXrayAvailableFor(endpointId),
                        xrayTlsAvailable = isXrayTlsAvailableFor(endpointId),
                    )
                } else {
                    manifestEndpoints.first { it.id == endpointId }
                }
                val matchedOutcome = net.pocvpn.client.reachability.EndpointOutcomeMatcher.latestMatching(outcomes, endpointId, kind)
                net.pocvpn.client.reachability.ReachabilityEngine.assess(
                    endpoint = endpoint,
                    transportKind = kind,
                    networkUsable = profile.isUsable,
                    transportHealth = health.getValue(kind),
                    endpointSpecificReachable = matchedOutcome?.let { it.result == ConnectionOutcomeResult.SUCCESS },
                    restrictionClass = restriction,
                    nowEpochMillis = now,
                    controlPlaneReachable = if (endpointId.value == net.pocvpn.client.smartconnect.ProductionGateway.ID) restrictionMonitor?.lastProbeResult?.value else null,
                    endpointSpecificOutcomeEpochMillis = matchedOutcome?.timestampEpochMillis,
                )
            },
            transportHealthFor = { kind -> health.getValue(kind) },
            historyFor = { pathId, kind -> fingerprint?.let { pathHistoryStore?.get(it, pathId, kind) } },
            preference = userTransportPreference,
            nowEpochMillis = now,
        )
    }

    /**
     * B16 - the Auto counterpart of connectManual(): builds the ranked
     * combined candidate list once, then hands the winner to execution.
     *
     * B24 - the WINNER now comes from [buildCombinedAutoAttempts] (real
     * Direct+Relayed ranking - task requirement 4), never from the
     * Direct-only list alone. [AutoGatewayDiagnostics] itself stays
     * Direct-only (its own existing public shape - `rankedCandidates:
     * List<GatewayAttemptCandidate>` - is unchanged, so every pre-B24
     * diagnostics reader is unaffected); a Relayed winner is reflected
     * there only via `lastFailureReason` once it fails (there is nothing
     * else to show it as `current` yet without widening that public type,
     * left to a future slice once relay diagnostics UI is actually wanted).
     * A DIRECT winner is executed through the COMPLETELY UNCHANGED
     * [TransportOrchestrator]/[VpnController]/[PendingFailoverAttempt]
     * dial path inside [attemptAutoCandidate] - the SAME pinned
     * `GatewayAttemptCandidate.configSnapshot`, the SAME AWG->Xray
     * intra-gateway failover, byte-for-byte (task requirement 7/8: do not
     * duplicate Direct transport execution logic, do not build a second
     * connection controller). What changed (B24 review fix, PR #38) is
     * WHAT HAPPENS ON ITS OWN TERMINAL FAILURE: [attemptAutoCandidate] no
     * longer owns a Direct-only remainder list to fall back through on its
     * own - it reports back into [attemptCombined] with the SAME combined
     * `(attempts, attemptedKeys)` this function started with, so the VERY
     * NEXT globally-ranked unattempted candidate is chosen regardless of
     * shape (a Relayed candidate ranked between two Direct ones is never
     * silently skipped). A RELAYED winner is executed through
     * [attemptRelayedAttempt], which reports back into [attemptCombined]
     * the same way on failure. Either way, ONE shared
     * [AutoGatewaySelector.MAX_ATTEMPTS] budget bounds the WHOLE request
     * across both shapes, and one candidate consumes exactly one combined
     * attempt slot (its `attemptKey` is added to `attemptedKeys` the
     * moment it is chosen, in [attemptCombined] itself - never re-chosen).
     */
    private suspend fun connectAuto() {
        val attempts = buildCombinedAutoAttempts()
        if (attempts.isEmpty()) {
            _autoGatewayDiagnostics.value = AutoGatewayDiagnostics(
                rankedCandidates = emptyList(), attempted = emptyList(), current = null,
                lastFailureReason = null, exhausted = true,
            )
            controller.rejectPreflight(VpnError.NoCandidateAvailable, "No automatic gateway candidate available")
            return
        }
        val directOnly = attempts.filterIsInstance<net.pocvpn.client.smartconnect.AutoGatewaySelector.AutoConnectAttempt.DirectAttempt>().map { it.candidate }
        _autoGatewayDiagnostics.value = AutoGatewayDiagnostics(
            rankedCandidates = directOnly, attempted = emptyList(), current = null,
            lastFailureReason = null, exhausted = false,
        )
        attemptCombined(attempts, attemptedKeys = emptySet())
    }

    /**
     * B24 - advances the shared combined attempt budget and dispatches by
     * winner type - see [connectAuto]'s own docs for the full rationale.
     */
    private suspend fun attemptCombined(
        attempts: List<net.pocvpn.client.smartconnect.AutoGatewaySelector.AutoConnectAttempt>,
        attemptedKeys: Set<String>,
    ) {
        val next = net.pocvpn.client.smartconnect.AutoGatewaySelector.nextCombinedAttempt(attempts, attemptedKeys)
        if (next == null) {
            _autoGatewayDiagnostics.value = _autoGatewayDiagnostics.value?.copy(exhausted = true)
                ?: AutoGatewayDiagnostics(emptyList(), emptyList(), null, "candidate set exhausted", true)
            controller.rejectPreflight(VpnError.NoCandidateAvailable, "Automatic gateway candidates exhausted")
            return
        }
        val advancedKeys = attemptedKeys + next.attemptKey
        when (next) {
            is net.pocvpn.client.smartconnect.AutoGatewaySelector.AutoConnectAttempt.DirectAttempt -> {
                attemptAutoCandidate(next.candidate, PendingAutoGatewayContext(attempts, advancedKeys))
            }
            is net.pocvpn.client.smartconnect.AutoGatewaySelector.AutoConnectAttempt.RelayedAttempt -> {
                attemptRelayedAttempt(next.candidate, attempts, advancedKeys)
            }
        }
    }

    /**
     * B24 review fix (PR #38, round 3 - ownership boundary) - executes ONE
     * relayed attempt by asking [relayIngressResolver] to PREPARE a real
     * ingress transport (task requirement 3/13), never to own or claim its
     * state. Builds a [net.pocvpn.client.relay.RelayedExecutionPlan]
     * straight off [candidate]'s own already-pinned fields (never a
     * manifest/catalog re-resolution - task requirement 2).
     *
     * On [net.pocvpn.client.relay.RelayIngressResolution.NotProvisioned]
     * (the ONLY thing [relayIngressResolver] returns in production today -
     * see [net.pocvpn.client.relay.NotProvisionedRelayIngressResolver]'s
     * own docs), records a typed failure and advances the SHARED combined
     * budget via [attemptCombined] - never retries the same candidate,
     * never substitutes a different exit while keeping this candidate's
     * own identity (task requirement 13).
     *
     * On [net.pocvpn.client.relay.RelayIngressResolution.Resolved], the
     * prepared transport is fed into the EXACT SAME
     * [TransportOrchestrator]/[VpnController]/[PendingFailoverAttempt]/
     * [armFailoverWatch] path Direct already uses (task requirement 1/2/4 -
     * one VpnService owner, no second connection controller) - a real
     * per-endpoint `TransportRegistry`/`TransportOrchestrator` is built for
     * [plan]'s ingress endpoint id and handed to `controller.connect()`
     * exactly like a Direct candidate is. [PendingFailoverAttempt.relayPlan]
     * marks this attempt as relayed so [armFailoverWatch]'s SAME real
     * `controller.state` observation authority (never this function's own
     * belief about what happened) governs what gets recorded and whether
     * the combined sequence advances - see that function's own docs (task
     * requirement 8 - Protected/health must come from the real runtime
     * state authority, never inferred here).
     */
    // `internal` (not `private`), same "tests can inspect this directly
    // without needing a real Android Context to drive the full
    // combinedAutoAttempts()/connect() ranking pipeline" reasoning
    // buildTransportRegistry's own docs already state - a genuinely
    // eligible XRAY_REALITY/TLS_TCP relayed candidate cannot be produced
    // through that pipeline in this test harness (isXrayAvailableFor is
    // hardcoded to the Germany/Stockholm production endpoints only), so
    // pause/resume/retry tests construct a RelayAttemptCandidate directly
    // and call this function with it.
    internal suspend fun attemptRelayedAttempt(
        candidate: net.pocvpn.client.smartconnect.AutoGatewaySelector.RelayAttemptCandidate,
        attempts: List<net.pocvpn.client.smartconnect.AutoGatewaySelector.AutoConnectAttempt>,
        attemptedKeys: Set<String>,
        // B26 review fix (round 2, blocker) - true ONLY for the one bounded
        // re-invocation activateIngress() makes after a successful
        // activation (see that function's own docs). Reusing THIS SAME
        // function for the retry - never a parallel "retry" code path - is
        // what guarantees the retry dials the byte-for-byte identical
        // [candidate]/[plan] (task requirement B/C). When true, a
        // NotProvisioned result NEVER pauses again, regardless of category -
        // task requirement D's "at most one retry for that candidate": the
        // combined sequence simply resumes via attemptCombined, exactly the
        // same as any other terminal failure.
        isActivationRetry: Boolean = false,
    ) {
        val plan = net.pocvpn.client.relay.RelayedExecutionPlan.from(candidate)
        when (val resolution = relayIngressResolver.resolve(plan)) {
            is net.pocvpn.client.relay.RelayIngressResolution.NotProvisioned -> {
                val outcome = net.pocvpn.client.relay.RelayAttemptOutcome.Failure(
                    plan = plan,
                    highestStageReached = null,
                    category = resolution.category,
                    detail = resolution.detail,
                )
                recordRelayOutcome(plan, outcome)
                _autoGatewayDiagnostics.value = _autoGatewayDiagnostics.value?.copy(
                    lastFailureReason = "${outcome.category}" + (outcome.detail?.let { ": $it" } ?: ""),
                )
                // B26 review fix (round 2, blocker) - PAUSE the combined
                // sequence (never call attemptCombined here) for exactly the
                // categories a fresh activation can fix, and only on this
                // candidate's FIRST encounter (never on the bounded
                // activation-retry itself - see isActivationRetry's own
                // docs, task requirement D). Pausing means storing the FULL
                // resume context ([PendingRelayActivation]) so a later
                // success/failure/dismiss resumes EXACTLY this state, never
                // a freshly re-ranked one (task requirement G - nothing else
                // advances the combined sequence while this is set).
                if (!isActivationRetry && resolution.category in net.pocvpn.client.relay.RelayActivationRequest.ACTIVATION_FIXABLE_CATEGORIES) {
                    pendingRelayActivation = PendingRelayActivation(candidate, attempts, attemptedKeys)
                    _relayActivationNeeded.value = net.pocvpn.client.relay.RelayActivationRequest.from(plan)
                } else {
                    attemptCombined(attempts, attemptedKeys)
                }
            }
            is net.pocvpn.client.relay.RelayIngressResolution.Resolved -> {
                val registry = TransportRegistry.build(
                    listOf(
                        TransportDescriptor(
                            kind = resolution.kind,
                            status = TransportStatus.AVAILABLE,
                            capabilities = resolution.transport.capabilities,
                            factory = { resolution.transport },
                        ),
                    ),
                )
                val orchestrator = TransportOrchestrator(registry)
                val decision = TransportSelectionDecision.SelectTransport(resolution.kind)
                when (
                    val orchResolution = orchestrator.resolve(
                        decision,
                        plan.ingressEndpointId,
                        attemptContext = net.pocvpn.client.relay.VpnAttemptContext.Relayed(plan),
                    )
                ) {
                    is TransportOrchestrator.Resolution.Resolved -> {
                        val permissionPending = orchResolution.transport.preparePermissionIntent() != null
                        val attempt = PendingFailoverAttempt(
                            initialKind = resolution.kind,
                            preference = userTransportPreference,
                            registry = registry,
                            orchestrator = orchestrator,
                            endpointId = plan.ingressEndpointId,
                            autoContext = PendingAutoGatewayContext(attempts, attemptedKeys),
                            relayPlan = plan,
                            relayProfile = resolution.profile,
                        )
                        pendingFailoverAttempt = attempt
                        controller.connect(orchResolution)
                        if (!permissionPending) armFailoverWatch(attempt)
                    }
                    is TransportOrchestrator.Resolution.NotSelectable -> {
                        val outcome = net.pocvpn.client.relay.RelayAttemptOutcome.Failure(
                            plan = plan,
                            highestStageReached = null,
                            category = net.pocvpn.client.relay.RelayFailureCategory.INGRESS_HANDSHAKE_FAILED,
                            detail = "resolved ingress transport was not selectable",
                        )
                        recordRelayOutcome(plan, outcome)
                        _autoGatewayDiagnostics.value = _autoGatewayDiagnostics.value?.copy(lastFailureReason = "${outcome.category}: ${outcome.detail}")
                        attemptCombined(attempts, attemptedKeys)
                    }
                }
            }
        }
    }

    /**
     * B24 - task requirement 11/G: recorded ONLY under [RelayedExecutionPlan
     * .historyPathId] (the FULL relayed path identity), never under
     * [RelayedExecutionPlan.ingressEndpointId]/[RelayedExecutionPlan
     * .exitEndpointId] alone - either of those would poison that endpoint's
     * own Direct-mode local history with relay-specific evidence. No-op
     * without a wired [fingerprintKeyProvider]/[pathHistoryStore] - the SAME
     * additive-seam discipline every other real writer into
     * [net.pocvpn.client.reachability.PathHistoryStore] in this codebase
     * already follows.
     */
    private fun recordRelayOutcome(plan: net.pocvpn.client.relay.RelayedExecutionPlan, outcome: net.pocvpn.client.relay.RelayAttemptOutcome) {
        val store = pathHistoryStore ?: return
        val keyProvider = fingerprintKeyProvider ?: return
        val profile = networkProfile.value
        val fingerprint = net.pocvpn.client.reachability.NetworkFingerprinter.fingerprint(
            net.pocvpn.client.reachability.CoarseNetworkSignals(profile.type, profile.dnsServerAddresses),
            keyProvider.keyBytes(),
        )
        store.record(fingerprint, plan.historyPathId, plan.ingressTransport, success = outcome.isHealthy, nowEpochMillis = System.currentTimeMillis())
    }

    /**
     * B16 (consolidated review fix) - dials exactly ONE candidate, already
     * chosen by [attemptCombined] as the next globally-ranked unattempted
     * combined attempt (task requirement 6/1). [_activeGatewayId] is set
     * BEFORE calling controller.connect() for UI/diagnostics purposes only -
     * the REAL execution-time identity guarantee comes from threading THIS
     * candidate's own already-resolved [GatewayAttemptCandidate.configSnapshot]
     * straight into `orchestrator.resolve(...)` below, which carries it into
     * `TransportOrchestrator.Resolution.Resolved.gatewayConfigSnapshot` and
     * from there into `VpnController.connect()` - see that field's own docs
     * for why this is what actually makes the executed tunnel config
     * immutable for this attempt (never re-derived from SelectedGatewayStore/
     * ProductionGatewayCatalog/ClientTunnelIdentityStore once resolved here).
     * This dial path itself is BYTE-FOR-BYTE unchanged from pre-B24 (same
     * `TransportOrchestrator`/`PendingFailoverAttempt`/`armFailoverWatch`
     * machinery - task requirement 7/8's own "do not duplicate Direct
     * transport execution logic").
     *
     * B24 review fix (PR #38) - previously took the FULL Direct-only
     * candidate list and picked "the next one" itself on every terminal
     * failure (`NotSelectable` below, or a real async failure observed by
     * [armFailoverWatch]), which silently skipped any higher-ranked Relayed
     * candidate ranked in between and defeated the shared combined
     * [AutoGatewaySelector.MAX_ATTEMPTS] budget. Now takes exactly the ONE
     * [candidate] to dial plus [autoContext] (the combined
     * `(attempts, attemptedKeys)` [attemptCombined] already advanced past
     * this candidate for) - on EITHER terminal-failure path, control
     * returns to [attemptCombined] with that SAME context, so the next
     * candidate chosen is always the next globally-ranked one, regardless
     * of shape.
     */
    private suspend fun attemptAutoCandidate(
        candidate: net.pocvpn.client.smartconnect.GatewayAttemptCandidate,
        autoContext: PendingAutoGatewayContext,
    ) {
        _activeGatewayId.value = candidate.gatewayId
        _autoGatewayDiagnostics.value = (_autoGatewayDiagnostics.value ?: AutoGatewayDiagnostics(emptyList(), emptyList(), null, null, false)).let {
            it.copy(attempted = it.attempted + candidate, current = candidate)
        }
        val registry = buildTransportRegistry(candidate.endpointId)
        val orchestrator = TransportOrchestrator(registry)
        val decision = TransportSelectionDecision.SelectTransport(candidate.transport)
        when (val resolution = orchestrator.resolve(decision, candidate.endpointId, candidate.configSnapshot)) {
            is TransportOrchestrator.Resolution.Resolved -> {
                val permissionPending = resolution.transport.preparePermissionIntent() != null
                val attempt = PendingFailoverAttempt(
                    initialKind = candidate.transport,
                    preference = userTransportPreference,
                    registry = registry,
                    orchestrator = orchestrator,
                    endpointId = candidate.endpointId,
                    autoContext = autoContext,
                )
                pendingFailoverAttempt = attempt
                controller.connect(resolution)
                if (!permissionPending) armFailoverWatch(attempt)
            }
            is TransportOrchestrator.Resolution.NotSelectable -> {
                // This ranked candidate's own transport somehow isn't
                // resolvable (should-never-happen - it was eligible in the
                // registry PathScorer scored it against) - a terminal
                // failure for THIS candidate specifically. B24 review fix:
                // report back to the combined coordinator (which already
                // has this candidate marked attempted in [autoContext])
                // rather than re-deriving "the next Direct candidate"
                // locally - the next globally-ranked candidate may be
                // Relayed.
                _autoGatewayDiagnostics.value = _autoGatewayDiagnostics.value?.copy(lastFailureReason = "NotSelectable")
                attemptCombined(autoContext.combinedAttempts, autoContext.combinedAttemptedKeys)
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
        endpointId: net.pocvpn.client.reachability.EndpointId,
    ) {
        val eligible = AwgXrayFailoverPolicy.isEligibleForXrayFallback(
            initialKind = initialKind,
            preference = preference,
            awgState = controller.state.value,
            awgError = diagnosticsStore.snapshot.value.lastError,
            xrayAvailable = registry.descriptorFor(TransportKind.XRAY_REALITY)?.status == TransportStatus.AVAILABLE,
        )
        if (!eligible) return

        when (val xrayResolution = orchestrator.resolve(TransportSelectionDecision.SelectTransport(TransportKind.XRAY_REALITY), endpointId)) {
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
                val relayPlan = attempt.relayPlan
                if (relayPlan != null) {
                    // B24/B25 - a RELAYED combined attempt: this SAME real
                    // controller.state authority (never this attempt's own
                    // belief, never a resolver return value) governs both
                    // what gets recorded and whether the combined sequence
                    // advances (task requirement 8/L).
                    val autoContext = attempt.autoContext!!
                    if (state is TransportState.Connected) {
                        // B25 (task B/C) - a REAL controller-observed
                        // Connected state for the client<->ingress hop
                        // proves ONLY RelayReadinessStage.INGRESS_HANDSHAKE_OK
                        // - it says nothing about the ingress's own upstream
                        // link to the exit. Report that stage immediately
                        // (so sessionHealth never reads RelayProtected before
                        // the real probe below runs), then ask the real
                        // end-to-end proof channel (task requirement C)
                        // whether client -> ingress -> exit -> Internet is
                        // genuinely functional right now, over the tunnel
                        // this attempt just brought up.
                        controller.reportRelayStage(net.pocvpn.client.relay.RelayReadinessStage.INGRESS_HANDSHAKE_OK)
                        val profile = attempt.relayProfile
                        val probeResult = if (profile != null) {
                            relayEndToEndProbe.probe(relayPlan, profile)
                        } else {
                            net.pocvpn.client.relay.RelayProbeResult.Failure(
                                net.pocvpn.client.relay.RelayFailureCategory.EXECUTION_NOT_IMPLEMENTED,
                                "no ingress profile pinned for this attempt",
                            )
                        }
                        when (probeResult) {
                            is net.pocvpn.client.relay.RelayProbeResult.Success -> {
                                // B25 - the ONLY place a relayed attempt may
                                // ever report RelayAttemptOutcome.Success -
                                // fail-closed by construction upstream (see
                                // that sealed class's own init{}), and now
                                // fail-closed by REAL EVIDENCE here too: this
                                // branch is reached only after a genuine
                                // probe response traversed ingress -> exit.
                                controller.reportRelayStage(net.pocvpn.client.relay.RelayReadinessStage.END_TO_END_DATA_PLANE_OK)
                                recordRelayOutcome(relayPlan, net.pocvpn.client.relay.RelayAttemptOutcome.Success(relayPlan))
                                pendingFailoverAttempt = null
                                failoverObserverJob?.cancel()
                                failoverObserverJob = null
                                // Session stays Connected/RelayProtected - no
                                // advance, no further watching needed for
                                // this attempt (mirrors the Direct/Manual
                                // "settled, nothing left to watch" case).
                            }
                            is net.pocvpn.client.relay.RelayProbeResult.Failure -> {
                                recordRelayOutcome(
                                    relayPlan,
                                    net.pocvpn.client.relay.RelayAttemptOutcome.Failure(
                                        plan = relayPlan,
                                        highestStageReached = net.pocvpn.client.relay.RelayReadinessStage.INGRESS_HANDSHAKE_OK,
                                        category = probeResult.category,
                                        detail = probeResult.detail,
                                    ),
                                )
                                pendingFailoverAttempt = null
                                _autoGatewayDiagnostics.value = _autoGatewayDiagnostics.value?.copy(
                                    lastFailureReason = "${probeResult.category}" + (probeResult.detail?.let { ": $it" } ?: ""),
                                )
                                failoverObserverJob?.cancel()
                                failoverObserverJob = null
                                // B25 review fix (PR #39) - a failed
                                // end-to-end probe means this attempt's
                                // ingress transport is genuinely UP
                                // (controller.state is still Connected) but
                                // NOT healthy - controller.connect() itself
                                // refuses to do anything while state is
                                // already Connecting/Connected (see its own
                                // early-return guard), so the NEXT combined
                                // candidate's controller.connect() call below
                                // would otherwise be silently swallowed.
                                // abandonAttemptForFailover() is the ONE
                                // controller-owned teardown that tears down
                                // THIS failed attempt (never touching
                                // VpnService/transport directly from here)
                                // and leaves the controller genuinely able
                                // to accept the next real connect() call -
                                // see that function's own docs.
                                controller.abandonAttemptForFailover()
                                attemptCombined(autoContext.combinedAttempts, autoContext.combinedAttemptedKeys)
                            }
                        }
                        return@collect
                    }
                    val error = diagnosticsStore.snapshot.value.lastError
                    val eligible = net.pocvpn.client.smartconnect.AutoGatewayFailoverPolicy.isEligibleForNextCandidate(state, error)
                    if (!eligible) return@collect
                    recordRelayOutcome(
                        relayPlan,
                        net.pocvpn.client.relay.RelayAttemptOutcome.Failure(
                            plan = relayPlan,
                            highestStageReached = null,
                            category = net.pocvpn.client.relay.RelayFailureCategory.INGRESS_HANDSHAKE_FAILED,
                            detail = error?.let { it::class.simpleName } ?: state::class.simpleName,
                        ),
                    )
                    pendingFailoverAttempt = null
                    _autoGatewayDiagnostics.value = _autoGatewayDiagnostics.value?.copy(
                        lastFailureReason = error?.let { it::class.simpleName } ?: state::class.simpleName,
                    )
                    failoverObserverJob?.cancel()
                    failoverObserverJob = null
                    attemptCombined(autoContext.combinedAttempts, autoContext.combinedAttemptedKeys)
                    return@collect
                }
                val autoContext = attempt.autoContext
                if (autoContext != null) {
                    // B16 - automatic-gateway sequence: advance to the next
                    // ranked candidate rather than the intra-gateway
                    // AWG->Xray check below.
                    val error = diagnosticsStore.snapshot.value.lastError
                    val eligible = net.pocvpn.client.smartconnect.AutoGatewayFailoverPolicy.isEligibleForNextCandidate(state, error)
                    if (!eligible) return@collect
                    pendingFailoverAttempt = null
                    _autoGatewayDiagnostics.value = _autoGatewayDiagnostics.value?.copy(
                        lastFailureReason = error?.let { it::class.simpleName } ?: state::class.simpleName,
                    )
                    failoverObserverJob?.cancel()
                    failoverObserverJob = null
                    // B24 review fix (PR #38) - resumes the SHARED combined
                    // coordinator, never a Direct-only remainder list, so
                    // the next candidate chosen here can genuinely be
                    // Relayed.
                    attemptCombined(autoContext.combinedAttempts, autoContext.combinedAttemptedKeys)
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
                    endpointId = attempt.endpointId,
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
        // B16 - VpnController.disconnect() itself clears its own pinned
        // pendingConnectConfig (see that field's own docs) - a completed/
        // abandoned Auto sequence never leaves a stale candidate config
        // behind for gatewayStatus()/the next connect() to see.
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
                // B16 - VpnController.onVpnPermissionResult(false) itself
                // clears its own pinned pendingConnectConfig on denial (see
                // that function's own docs) - gatewayStatus() never keeps
                // pointing at an abandoned candidate's config.
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
            // B13 - the real product gateway-selection mechanism (see
            // SelectedGatewayStore/SelectedProductionGatewaySource's own
            // docs) - deliberately NOT gatewayConfigSource/BuildConfigGatewaySource
            // above (that remains a local dev-only convenience, never the
            // product's own selector). Same noBackupFilesDir convention as
            // every other device-local preference store in this Factory.
            val selectedGatewayStore = net.pocvpn.client.vpn.config.FileSelectedGatewayStore(context.noBackupFilesDir)
            // B8B3C - same noBackupFilesDir as the identity store
            // (ClientKeyRepositoryFactory), different file: this data is
            // non-secret but still device/session-specific, so Auto Backup
            // restoring it onto a different device would be meaningless.
            // Constructed BEFORE clientTunnelIdentityStore below - its
            // read() result is the ONLY migration evidence that store's
            // Germany seeding is allowed to use (see that call's own docs).
            val profileStore = FileProfileStore(context.noBackupFilesDir)
            // B13 review fix - per-device, per-endpoint client tunnel IP,
            // deliberately separate from selectedGatewayStore above (see
            // ClientTunnelIdentityStore's own docs for why this is
            // provisioned device identity, never a gateway fact). A SECOND
            // review found the first fix's own migration unconditionally
            // seeded EVERY install with this test device's hardcoded IPs -
            // migrateFromLegacyProvisionedProfile fixes that: it seeds
            // Germany ONLY when profileStore above already holds real,
            // per-device evidence from a genuine pre-B13 activation (never
            // Stockholm - no such evidence can exist for it - and never a
            // fresh install, which has no persisted profile at all).
            val clientTunnelIdentityStore = net.pocvpn.client.vpn.config.FileClientTunnelIdentityStore(context.noBackupFilesDir)
            clientTunnelIdentityStore.migrateFromLegacyProvisionedProfile(
                (profileStore.read() as? ProfileLoadResult.Found)?.profile
            )
            // B16 - device-local automatic-gateway-selection preference.
            val gatewayAutoModeStore = net.pocvpn.client.vpn.config.FileGatewayAutoModeStore(context.noBackupFilesDir)
            // B22 - the explicit three-way gateway-selection authority and
            // the private-gateway config/identity stores - see their own
            // docs for why these are genuinely separate from every managed-
            // gateway store above.
            val gatewaySelectionModeStore = net.pocvpn.client.vpn.config.FileGatewaySelectionModeStore(context.noBackupFilesDir)
            val privateGatewayStore = net.pocvpn.client.vpn.config.FilePrivateGatewayStore(context.noBackupFilesDir)
            val privateGatewayKeyRepository = net.pocvpn.client.identity.PrivateGatewayKeyRepositoryFactory.create(context)
            // B16 (consolidated review fix) - unchanged from pre-B16: this
            // resolves ONLY the persisted MANUAL selection. An Auto
            // candidate's real connect-time config is now threaded straight
            // from AutoGatewaySelector's own already-resolved
            // GatewayAttemptCandidate.configSnapshot through
            // TransportOrchestrator.Resolution.Resolved into
            // VpnController.connect() - see that field's own docs - so this
            // source is never consulted (and SelectedGatewayStore/
            // ClientTunnelIdentityStore never re-read) during an Auto attempt.
            val selectedProductionGatewaySource = net.pocvpn.client.vpn.config.SelectedProductionGatewaySource(
                selectedGatewayId = selectedGatewayStore::read,
                clientTunnelIp = clientTunnelIdentityStore::read,
            )
            // B8H - same noBackupFilesDir as profileStore above, different
            // file: a device-local UX preference, not something a restore
            // onto a different device should silently reapply either.
            val appRoutingPolicyStore = FileAppRoutingPolicyStore(context.noBackupFilesDir)
            // B18 - same noBackupFilesDir as appRoutingPolicyStore above,
            // different file: a device-local routing preference, not
            // something a cross-device restore should silently reapply.
            val routingModeStore = FileRoutingModeStore(context.noBackupFilesDir)
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
            // B13 (audit fix) - migrateFromLegacyUnscopedFile now defaults to
            // true for the production endpoint id (see
            // XrayProfileRepositoryFactory's own docs) - the explicit
            // `= true` here is redundant with that default but kept for
            // readability at this call site.
            val xrayProfileRepository = XrayProfileRepositoryFactory.create(context, migrateFromLegacyUnscopedFile = true)
            // B8O2 - the TLS/TCP counterpart of xrayProfileRepository above -
            // its own independent store/AndroidKeyStore alias (see
            // XrayTlsProfileRepositoryFactory's own docs), shared by its own
            // provisioner and xrayTlsTransport's own pre-flight check.
            // B13 (audit fix) - same "redundant with the default, kept for readability" note as xrayProfileRepository above.
            val xrayTlsProfileRepository = XrayTlsProfileRepositoryFactory.create(context, migrateFromLegacyUnscopedFile = true)
            // B13 consolidated review fix (finding 4) - Stockholm's OWN,
            // separately-scoped repository instances (migrateFromLegacyUnscopedFile
            // stays false, its own default for a non-production endpoint id -
            // there is no legacy unscoped file that was ever Stockholm's).
            // Reads the SAME on-disk file the debug-only
            // XrayDiagnosticsActivity manual-save path writes real,
            // operator-provisioned credentials to when Stockholm has been
            // provisioned - null profile on disk simply means not yet
            // provisioned, and MainViewModel's per-endpoint availability
            // check (xrayAvailableEndpoints) already fails that closed to
            // NOT_IMPLEMENTED, never a fabricated/hardcoded availability.
            val stockholmXrayProfileRepository = XrayProfileRepositoryFactory.create(context, endpointId = net.pocvpn.client.vpn.config.ProductionGatewayCatalog.STOCKHOLM.endpointId)
            val stockholmXrayTlsProfileRepository = XrayTlsProfileRepositoryFactory.create(context, endpointId = net.pocvpn.client.vpn.config.ProductionGatewayCatalog.STOCKHOLM.endpointId)
            // B12 - the ONE authoritative EndpointManifestRepository instance -
            // shared by reachabilityDiagnostics() (read-only) and
            // manifestDistributionClient below (the only real writer, via
            // offer()) - never a second, independently-constructed repository
            // that could disagree with what diagnostics reports.
            val manifestRepository = net.pocvpn.client.reachability.EndpointManifestRepositoryFactory.createManifestRepository(context)
            // B12/B20 - BuildConfig.MANIFEST_URLS (comma-separated, see
            // build.gradle.kts) parsed/validated via ManifestOriginConfig:
            // blank/malformed/duplicate entries never become a configured
            // origin (see its own docs). An empty resulting list means this
            // stays null: refreshManifest() becomes a no-op, and
            // manifestRepository is driven ONLY by its embedded
            // bootstrap/whatever LKG already exists on disk - never
            // constructed against zero origins (every real HTTPS fetch
            // would just fail, which is a worse failure mode than "clearly
            // not configured").
            // B26 (task A) - the real relay/ingress composition: an
            // endpoint-scoped, encrypted-at-rest ingress profile store; the
            // real RelayIngressResolverImpl reading from it (never
            // NotProvisionedRelayIngressResolver in production from here on
            // - a real profile activated via activateIngress() below is
            // what makes a relayed candidate resolvable); the real HTTPS
            // end-to-end probe; and per-ingress-endpoint Xray/TLS profile
            // repository resolvers built the SAME way the Stockholm
            // xrayTransport/xrayTlsTransport resolver lambdas above already
            // resolve an arbitrary endpoint id's own repository (never a
            // fixed map that would need a code change per ingress).
            // B26 review fix (blocker 2) - RelayCompositionFactory.build is
            // the ONE place this whole graph is assembled, now a directly
            // testable unit on its own (see MainViewModelCompositionRootTest
            // and RelayCompositionFactoryTest) rather than inline here.
            val ingressProfileStore = net.pocvpn.client.relay.IngressProfileStoreFactory.create(context)
            val relayComposition = net.pocvpn.client.relay.RelayCompositionFactory.build(context, ingressProfileStore)

            val manifestOrigins = net.pocvpn.client.reachability.ManifestOriginConfig.parse(BuildConfig.MANIFEST_URLS)
            val manifestDistributionClient = manifestOrigins.takeIf { it.isNotEmpty() }?.let { origins ->
                net.pocvpn.client.reachability.MultiOriginManifestDistributionClient(
                    origins = origins,
                    repository = manifestRepository,
                )
            }
            @Suppress("UNCHECKED_CAST")
            return MainViewModel(
                clientKeyRepository = ClientKeyRepositoryFactory.create(context),
                transport = AmneziaWgTransport(context),
                // B13 - the real, product gateway-selection source (see its
                // own docs) - gatewayConfigSource/gatewayConfigOverride
                // below is kept wired for the pre-existing activation flow's
                // own UI-gating behavior (ProfileSource routing - see
                // restorePersistedProfile()'s own docs) but no longer feeds
                // the actual connect-time config.
                gatewayConfigurationRepository = DefaultGatewayConfigurationRepository(selectedProductionGatewaySource),
                reconnectManager = AndroidReconnectManager(context),
                diagnosticsStore = DiagnosticsStore(),
                gatewayConfigOverride = gatewayConfigSource,
                selectedGatewayStore = selectedGatewayStore,
                gatewayAutoModeStore = gatewayAutoModeStore,
                // B13 review fix - the SAME instance selectedProductionGatewaySource
                // above already resolves clientTunnelIp() from, so
                // isGatewayProvisioned()/provisionedGatewayIds/the startup
                // reconciliation this feeds ALWAYS agree with what a real
                // connect() attempt would actually resolve.
                clientTunnelIdentityStore = clientTunnelIdentityStore,
                gatewaySelectionModeStore = gatewaySelectionModeStore,
                privateGatewayStore = privateGatewayStore,
                privateGatewayKeyRepository = privateGatewayKeyRepository,
                profileStore = profileStore,
                appRoutingPolicyStore = appRoutingPolicyStore,
                routingModeStore = routingModeStore,
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
                // B13 (audit item 5 fix) - a resolver lambda, not the single
                // xrayProfileRepository instance directly: resolves via the
                // Factory for whatever endpoint the attempt actually names,
                // falling back to it only for the production endpoint id
                // (the SAME instance every other collaborator in this Factory
                // already shares for it - never a fresh, independently
                // constructed one for the endpoint this repository already
                // covers).
                xrayTransport = VlessRealityTransport(context) { id ->
                    if (id.value == net.pocvpn.client.smartconnect.ProductionGateway.ID) xrayProfileRepository else XrayProfileRepositoryFactory.create(context, id)
                },
                xrayProfileRepository = xrayProfileRepository,
                // B8O2 - same reasoning as xrayTransport/xrayProfileRepository
                // above, for TLS/TCP: the SAME real VlessTlsTransport instance
                // is registered for BOTH Smart Connect selection and execution.
                xrayTlsProfileProvisioner = XrayTlsProfileProvisioner(xrayTlsProfileRepository),
                xrayTlsTransport = VlessTlsTransport(context) { id ->
                    if (id.value == net.pocvpn.client.smartconnect.ProductionGateway.ID) xrayTlsProfileRepository else XrayTlsProfileRepositoryFactory.create(context, id)
                },
                xrayTlsProfileRepository = xrayTlsProfileRepository,
                // B13 consolidated review fix (finding 4) - Stockholm's own
                // repositories, so MainViewModel's per-endpoint availability
                // (xrayAvailableEndpoints/xrayTlsAvailableEndpoints) can
                // actually see Stockholm's real credentials when present,
                // instead of only ever knowing about Germany's.
                stockholmXrayProfileRepository = stockholmXrayProfileRepository,
                stockholmXrayTlsProfileRepository = stockholmXrayTlsProfileRepository,
                // B14 - the real self-service Stockholm provisioning path:
                // Stockholm's own activation client (defaults to a real
                // request against ProductionGatewayCatalog.STOCKHOLM's own
                // edge - see MainViewModel's own constructor docs for why
                // this genuinely fails closed today, no control-plane
                // deployed yet) and its own Xray REALITY/TLS provisioners,
                // each wired to the SAME stockholmXrayProfileRepository/
                // stockholmXrayTlsProfileRepository instances above (never
                // a second, independently-constructed store) and each
                // fetching from Stockholm's own edge - never Germany's.
                stockholmXrayProfileProvisioner = XrayProfileProvisioner(
                    repository = stockholmXrayProfileRepository,
                    fetchXrayProfile = { publicKey, activationCredential ->
                        ProvisioningClient.fetchXrayProfile(publicKey, activationCredential, net.pocvpn.client.vpn.config.ProductionGatewayCatalog.STOCKHOLM.awg.endpointHost)
                    },
                ),
                stockholmXrayTlsProfileProvisioner = XrayTlsProfileProvisioner(
                    repository = stockholmXrayTlsProfileRepository,
                    fetchXrayTlsProfile = { publicKey, activationCredential ->
                        ProvisioningClient.fetchXrayTlsProfile(publicKey, activationCredential, net.pocvpn.client.vpn.config.ProductionGatewayCatalog.STOCKHOLM.awg.endpointHost)
                    },
                ),
                // B11 - real, live-wired, OBSERVATIONAL ONLY - see
                // reachabilityDiagnostics()'s own docs for why this cannot
                // change automatic selection in this slice.
                manifestRepository = manifestRepository,
                pathHistoryStore = net.pocvpn.client.reachability.EndpointManifestRepositoryFactory.createPathHistoryStore(context),
                fingerprintKeyProvider = net.pocvpn.client.reachability.EndpointManifestRepositoryFactory.createFingerprintKeyProvider(context),
                manifestDistributionClient = manifestDistributionClient,
                // B26 (task A) - the real relay/ingress composition wired
                // above: this is what supersedes NotProvisionedRelayIngressResolver/
                // NotConfiguredRelayEndToEndProbe as production defaults -
                // a relayed Auto winner now genuinely resolves against a
                // real, activated IngressClientProfile when one exists, and
                // fails closed (PROFILE_NOT_PROVISIONED) exactly as before
                // when none does yet (no relay profile -> fail closed,
                // never a silent fallback to a different ingress/profile -
                // see RelayIngressResolverImpl's own docs).
                relayIngressResolver = relayComposition.relayIngressResolver,
                relayEndToEndProbe = relayComposition.relayEndToEndProbe,
                relayXrayProfileRepositoryResolver = relayComposition.relayXrayProfileRepositoryResolver,
                relayXrayTlsProfileRepositoryResolver = relayComposition.relayXrayTlsProfileRepositoryResolver,
                ingressProfileProvisioner = relayComposition.ingressProfileProvisioner,
            ) as T
        }
    }
}
