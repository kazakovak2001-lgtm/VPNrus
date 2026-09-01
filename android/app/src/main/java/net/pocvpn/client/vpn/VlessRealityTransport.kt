package net.pocvpn.client.vpn

import android.content.Context
import android.content.Intent
import android.net.VpnService
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import net.pocvpn.client.identity.XrayProfileRepository
import net.pocvpn.client.identity.XrayProfileRepositoryFactory
import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.transport.TransportCapabilities
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.vpn.config.TransportConfig
import net.pocvpn.client.vpn.xray.NovaXrayVpnService
import net.pocvpn.client.vpn.xray.XrayRuntimeEvent
import net.pocvpn.client.vpn.xray.XrayRuntimeResolution
import net.pocvpn.client.vpn.xray.XrayRuntimeResolver
import net.pocvpn.client.vpn.xray.XrayRuntimeState
import java.util.concurrent.atomic.AtomicLong

/**
 * B8K1B - VpnTransport wrapper around NovaXrayVpnService. As of B8I7 this is
 * registered as a real production Smart Connect candidate (see
 * MainViewModel.buildTransportRegistry) whenever a persisted Xray profile is
 * actually available - not only reachable from the debug-only manual entry
 * point (see the `debug` source set) that first proved this boundary.
 *
 * B8K4C - the `config` parameter's embedded XrayVlessRealityConfig is
 * deliberately NOT what gets validated or used below (only its TYPE is
 * checked, via the require() call) - NovaXrayVpnService loads its own
 * profile straight from [XrayProfileRepository] on ACTION_START and ignores
 * anything this class might otherwise have sent it, so validating a
 * caller-supplied config object here would prove nothing about what
 * actually starts. Instead this class runs the SAME [XrayRuntimeResolver]
 * against the SAME endpoint-scoped repository (resolved via
 * [profileRepositoryFor]) as a genuine pre-flight check - one authoritative
 * configuration SOURCE (the repository), never the config object's own
 * fields. B13 - `config.endpointId` IS the one field that DOES cross this
 * boundary (both into [profileRepositoryFor] here and into the ACTION_START
 * Intent's `EXTRA_ENDPOINT_ID`) - it identifies WHICH repository to consult,
 * it is not itself the profile/credential data.
 *
 * B8I7 - a real, in-process, typed confirmation channel: [connect] assigns
 * a fresh [sessionId] (an app-lifetime-monotonic counter - never a secret),
 * threads it into the ACTION_START Intent as
 * [NovaXrayVpnService.EXTRA_SESSION_ID], and observes [XrayRuntimeState]
 * filtering for events tagged with THIS sessionId - see
 * [XrayRuntimeEvent]/[XrayRuntimeState]'s own docs for why this, not
 * polling/elapsed time, and why a stale/older session's event can never
 * flip [state] here. [observeState] therefore only ever reports
 * [TransportState.Connected] after NovaXrayVpnService's own
 * XrayCoreStartOutcome.Started - a REAL positive confirmation the Xray core
 * actually started, never merely because startService() returned.
 */
class VlessRealityTransport(
    private val context: Context,
    // B13 (audit item 5 fix) - resolves the repository for the endpoint THIS
    // specific attempt targets (TransportConfig.Xray.endpointId, threaded
    // all the way from VpnController.pendingConnectEndpointId - see that
    // field's own docs), never a single instance fixed at construction time.
    // Defaults to the SAME factory/AndroidKeyStore-alias convention
    // NovaXrayVpnService's own resolution uses (see its own docs) - a
    // pre-flight check here and NovaXrayVpnService's actual startup decision
    // always read the SAME underlying file for a given endpoint, even though
    // (like NovaXrayVpnService already did before this fix) they may
    // construct independent repository OBJECT instances against it.
    private val profileRepositoryFor: (EndpointId) -> XrayProfileRepository =
        { id -> XrayProfileRepositoryFactory.create(context, id) },
) : VpnTransport {

    override val name: String = "xray-vless-reality"
    override val kind: TransportKind = TransportKind.XRAY_REALITY
    override val capabilities: TransportCapabilities = TransportCapabilities.xrayRealityAdapterShell()

    private val state = MutableStateFlow<TransportState>(TransportState.Disconnected)

    // B8I7 - a private, isolated scope: this class has no ViewModel/Activity
    // lifecycle of its own to piggyback on (it is a long-lived singleton
    // collaborator, constructed once in MainViewModel.Factory), so it owns
    // exactly one background job for observing XrayRuntimeState, replaced
    // (never doubled) on every fresh connect() attempt.
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private var observerJob: Job? = null

    override fun preparePermissionIntent(): Intent? = VpnService.prepare(context)

    override suspend fun connect(config: TransportConfig) {
        require(config is TransportConfig.Xray) { "VlessRealityTransport only accepts TransportConfig.Xray" }

        if (preparePermissionIntent() != null) {
            state.value = TransportState.Error("VPN permission not granted")
            return
        }

        // B13 - resolved for THIS attempt's real endpoint, never a fixed instance.
        val profileRepository = profileRepositoryFor(config.endpointId)
        when (val resolution = XrayRuntimeResolver.resolve(profileRepository)) {
            is XrayRuntimeResolution.Rejected -> {
                state.value = TransportState.Error("Xray profile not ready: ${resolution.reason}")
                return
            }
            is XrayRuntimeResolution.Ready -> Unit
        }

        // B8I7 - a FRESH session id for THIS attempt, and a FRESH observer
        // filtering on it - the previous attempt's observer (if any) is
        // cancelled first so an event tagged with an OLDER sessionId can
        // never be delivered to (let alone accepted by) this new one; the
        // sessionId check inside the collector is a second, redundant guard
        // against the same race switchActiveTransport's own docs describe
        // (cancel() takes effect at the next suspension point, not
        // necessarily synchronously).
        val sessionId = nextSessionId.incrementAndGet()
        observerJob?.cancel()
        observerJob = scope.launch {
            XrayRuntimeState.events.collect { event ->
                xrayTransportStateFor(event, sessionId)?.let { state.value = it }
            }
        }

        state.value = TransportState.Connecting
        try {
            val intent = Intent(context, NovaXrayVpnService::class.java)
                .setAction(NovaXrayVpnService.ACTION_START)
                .putExtra(NovaXrayVpnService.EXTRA_SESSION_ID, sessionId)
                // B13 - the SAME real endpointId this attempt was resolved
                // against - NovaXrayVpnService reads this to pick its own
                // matching repository (see that class's own docs), never
                // defaulting silently to the production endpoint id.
                .putExtra(NovaXrayVpnService.EXTRA_ENDPOINT_ID, config.endpointId.value)
                // B18-2 - the SAME RoutingMode VpnController resolved this
                // attempt against (see TransportConfig.Xray.routingMode's own
                // docs) - NovaXrayVpnService threads it into the same
                // RoutingDecisionEngine.resolveIpv4Routes authority AWG uses.
                .putExtra(NovaXrayVpnService.EXTRA_ROUTING_MODE, config.routingMode.name)
            context.startService(intent)
            // Real confirmation arrives asynchronously via XrayRuntimeState
            // (see the observer above) - never claim Connected merely
            // because startService() returned.
        } catch (t: Throwable) {
            state.value = TransportState.Error(t.message ?: "connect failed", t)
        }
    }

    override suspend fun disconnect() {
        if (state.value is TransportState.Error) {
            // B8I7 - a prior connect() attempt already failed and
            // NovaXrayVpnService already self-stopped (Rejected/
            // EstablishFailed/CoreStartFailed all call stopSelf()) - there is
            // nothing left running to tear down, and no Stopped event will
            // ever arrive for that session. Reflect that directly instead of
            // sending ACTION_STOP and hanging at Disconnecting forever.
            state.value = TransportState.Disconnected
            return
        }
        state.value = TransportState.Disconnecting
        try {
            val intent = Intent(context, NovaXrayVpnService::class.java).setAction(NovaXrayVpnService.ACTION_STOP)
            context.startService(intent)
            // Real confirmation (Stopped, tagged with the SAME sessionId
            // connect() is still observing) arrives via the SAME observer
            // job connect() already started - deliberately does NOT force
            // Disconnected here.
        } catch (t: Throwable) {
            state.value = TransportState.Error(t.message ?: "disconnect failed", t)
        }
    }

    override fun observeState(): Flow<TransportState> = state.asStateFlow()

    private companion object {
        val nextSessionId = AtomicLong(0)
    }
}

/**
 * B8I7 - pure mapping: does THIS [event] (matched by [sessionId]) become a
 * new [TransportState], or is it stale/irrelevant (a null event, or one
 * tagged with a DIFFERENT session) and therefore must be ignored? This is
 * the exact crux of "a stale/old service event can never mark a newer Xray
 * session Connected" - kept as a free function (not inlined into
 * connect()'s collector) so it is unit-testable on the plain JVM with no
 * Context, mirroring isFreshHandshake's own reasoning in VpnController.kt.
 */
internal fun xrayTransportStateFor(event: XrayRuntimeEvent?, sessionId: Long): TransportState? {
    if (event == null || event.sessionId != sessionId) return null
    return when (event) {
        is XrayRuntimeEvent.Started -> TransportState.Connected
        is XrayRuntimeEvent.Failed -> TransportState.Error(event.reason)
        is XrayRuntimeEvent.Stopped -> TransportState.Disconnected
    }
}
