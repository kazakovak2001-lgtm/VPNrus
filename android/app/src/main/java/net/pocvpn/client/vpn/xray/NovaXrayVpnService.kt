package net.pocvpn.client.vpn.xray

import android.annotation.SuppressLint
import android.app.Service
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import net.pocvpn.client.BuildConfig
import net.pocvpn.client.identity.XrayProfileRepository
import net.pocvpn.client.identity.XrayTlsProfileRepository
import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.smartconnect.ProductionGateway
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.vpn.policy.RoutingMode

/**
 * B8K1B - the REAL Android integration for Xray/VLESS+REALITY. As of B8I7,
 * XRAY_REALITY is a genuine production Smart Connect candidate (see
 * MainViewModel.buildTransportRegistry/VlessRealityTransport's own docs) -
 * this service is reachable from a real connect() attempt whenever a
 * persisted Xray profile is available, not only from the debug-only manual
 * entry point (see the `debug` source set) that first proved this
 * service/runtime boundary end to end (see docs/B8K1A_TUN_SOCKET_PATH_AUDIT.md
 * §10/§13, and this file's own AGENTS-style invariants below).
 *
 * Recursion prevention: [buildXrayVpnPlan] always disallows this app's own
 * package (ALL_APPS only, this slice) - see docs/B8K1A_TUN_SOCKET_PATH_AUDIT.md
 * §3/§4 for why that, not VpnService.protect()/bindProcessToNetwork, is the
 * proven-sufficient mechanism (Xray's outbound sockets run in this same
 * process/UID, so they bypass the TUN at the Android routing layer before
 * ever reaching it).
 *
 * Lifecycle invariants this class must preserve (mirrors the reference
 * app's own documented invariants, adapted to this isolated shell):
 * - A start while already running, or while another start is in flight, is
 *   a no-op - never a second Builder/core/tun.
 * - establish() returning null, or startLoop(...) throwing, tears down
 *   whatever was partially created (tun fd closed) and stops the service -
 *   never leaves a half-started state running.
 * - stopLoop() is called at most once per successful start, from exactly
 *   one teardown path (ACTION_STOP, onRevoke, or onDestroy) - [isRunning]
 *   is flipped to false BEFORE stopLoop()/close() run, so a second teardown
 *   call (e.g. onDestroy() after an explicit ACTION_STOP already ran) is a
 *   guarded no-op, not a double free.
 * - The tun fd is closed exactly once on every exit path (success->stop,
 *   establish() null, startLoop() throw, onDestroy while still running).
 *
 * No raw profile/config content is ever logged - only lifecycle phase names.
 */
class NovaXrayVpnService : VpnService() {

    private var tunInterface: ParcelFileDescriptor? = null

    private val coreRuntime: XrayCoreRuntime = LibXrayCoreRuntime()

    private val supervisorJob = SupervisorJob()
    private val scope = CoroutineScope(Dispatchers.IO + supervisorJob)

    // B13 (2026-08-30 audit item 5 fix) - now endpoint-aware: [EndpointId] IN,
    // repository OUT, routed through XrayProfileRepositoryFactory (rather
    // than constructing FileXrayProfileStore/AndroidKeystoreAesGcmEncryptor
    // inline, as before B13) so this service reads the EXACT SAME
    // endpoint-scoped file/alias MainViewModel.Factory's own repository
    // writes to for that same endpoint - the "not a second, independent
    // store" invariant this field already documented now holds structurally
    // for EVERY endpoint, not just the one production endpoint a fixed
    // instance could previously represent.
    /** Overridable only for tests that construct this service directly (Robolectric-style); production always uses the real default. */
    internal var profileRepositoryFactory: (Context, EndpointId) -> XrayProfileRepository = { context, endpointId ->
        net.pocvpn.client.identity.XrayProfileRepositoryFactory.create(context, endpointId)
    }

    /** B8O2 - the TLS/TCP counterpart of [profileRepositoryFactory] above; same test-seam contract, its own AndroidKeyStore alias/file. */
    internal var tlsProfileRepositoryFactory: (Context, EndpointId) -> XrayTlsProfileRepository = { context, endpointId ->
        net.pocvpn.client.identity.XrayTlsProfileRepositoryFactory.create(context, endpointId)
    }

    // B13 (2026-08-30 PR #25 review fix) - the ONE place [XrayCoreController]
    // is ever constructed, and the ONE place its per-endpoint selection AND
    // requestStart/requestStop calls are serialized - see that class's own
    // docs for exactly why a compound check-cached-then-build sequence
    // cannot safely live directly on this Service (onStartCommand does NOT
    // run on a single-threaded path once the actual work is dispatched onto
    // `scope.launch`/Dispatchers.IO - a prior version of this file
    // incorrectly assumed otherwise). `by lazy` only to defer construction
    // until `applicationContext` is guaranteed attached - the coordinator
    // itself owns all per-endpoint caching/locking from here on.
    private val lifecycleCoordinator: NovaXrayServiceLifecycleCoordinator by lazy {
        NovaXrayServiceLifecycleCoordinator { endpointId ->
            XrayCoreController(
                repository = profileRepositoryFactory(applicationContext, endpointId),
                coreRuntime = coreRuntime,
                novaPackageId = BuildConfig.APPLICATION_ID,
                ensureCoreEnvInitialized = { coreRuntime.ensureCoreEnvInitialized(applicationContext) },
                establishTun = { plan -> establishInterface(plan)?.also { tunInterface = it }?.fd },
                closeTun = { closeTunInterface() },
                tlsRepository = tlsProfileRepositoryFactory(applicationContext, endpointId),
            )
        }
    }

    // B8I7 - the CURRENT (or most recently started) attempt's session id -
    // see XrayRuntimeEvent's own docs for why this exists at all. Defaults
    // to 0 (never a real VlessRealityTransport-assigned id) so a teardown
    // reached without ACTION_START ever having run (there is nothing this
    // could correspond to) still publishes SOMETHING rather than silently
    // doing nothing.
    @Volatile private var currentSessionId: Long = 0L

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                teardown("explicit stop")
                return Service.START_NOT_STICKY
            }

            ACTION_START -> {
                val sessionId = intent.getLongExtra(EXTRA_SESSION_ID, currentSessionId)
                currentSessionId = sessionId
                // B8O2 - defaults to XRAY_REALITY so an intent built by any
                // pre-B8O2 caller (or one that never sets this extra) is
                // byte-for-byte unaffected - VlessRealityTransport never sets
                // this extra at all.
                val kind = intent.getStringExtra(EXTRA_TRANSPORT_KIND)
                    ?.let { runCatching { TransportKind.valueOf(it) }.getOrNull() }
                    ?: TransportKind.XRAY_REALITY
                // B13 - the real endpoint VlessRealityTransport/VlessTlsTransport
                // resolved this attempt against - see parseEndpointIdExtra's
                // own docs for the fail-safe default an absent/pre-B13 extra
                // gets.
                val endpointId = parseEndpointIdExtra(intent.getStringExtra(EXTRA_ENDPOINT_ID))
                // B18-2 - the RoutingMode VpnController resolved THIS attempt
                // against (TransportConfig.Xray/XrayTls.routingMode - see
                // those types' own docs), same "default FULL_VPN for any
                // absent/pre-B18-2/malformed extra" fail-safe shape as `kind`
                // above.
                val routingMode = intent.getStringExtra(EXTRA_ROUTING_MODE)
                    ?.let { runCatching { RoutingMode.valueOf(it) }.getOrNull() }
                    ?: RoutingMode.FULL_VPN
                startIfNotAlreadyRunning(sessionId, kind, endpointId, routingMode)
                return Service.START_NOT_STICKY
            }

            else -> {
                // No system always-on-VPN support for this debug-only shell yet.
                return Service.START_NOT_STICKY
            }
        }
    }

    override fun onRevoke() {
        teardown("permission revoked")
    }

    // B13 (PR #25 review fix) - teardown is now itself async (it must
    // acquire lifecycleCoordinator's own suspend-based mutex, serialized
    // against any in-flight start), so onDestroy() can no longer cancel
    // [supervisorJob] on the very next line - that would abandon a
    // just-launched-but-not-yet-run teardown before it ever executes.
    // Instead the job this launches cancels [supervisorJob] itself, from
    // its own completion handler, so cancellation only happens AFTER
    // teardown has genuinely finished (or been safely skipped as a no-op).
    override fun onDestroy() {
        val job = scope.launch { teardownAndPublish("service destroyed") }
        job.invokeOnCompletion { supervisorJob.cancel() }
        super.onDestroy()
    }

    private fun startIfNotAlreadyRunning(sessionId: Long, kind: TransportKind, endpointId: EndpointId, routingMode: RoutingMode) {
        scope.launch {
            when (val outcome = lifecycleCoordinator.start(endpointId, kind, routingMode)) {
                is XrayCoreStartOutcome.AlreadyRunning -> Log.i(TAG, "start requested while already running - ignored")
                is XrayCoreStartOutcome.StartInFlight -> Log.i(TAG, "start requested while a start is already in flight - ignored")
                is XrayCoreStartOutcome.Rejected -> {
                    Log.w(TAG, "refusing to start: ${outcome.reason}")
                    XrayRuntimeState.publish(XrayRuntimeEvent.Failed(sessionId, outcome.reason))
                    stopSelf()
                }
                is XrayCoreStartOutcome.EstablishFailed -> {
                    Log.e(TAG, "failed to establish VPN interface: ${outcome.reason}")
                    XrayRuntimeState.publish(XrayRuntimeEvent.Failed(sessionId, outcome.reason))
                    stopSelf()
                }
                is XrayCoreStartOutcome.CoreStartFailed -> {
                    Log.e(TAG, "Xray core failed to start: ${outcome.reason}")
                    XrayRuntimeState.publish(XrayRuntimeEvent.Failed(sessionId, outcome.reason))
                    stopSelf()
                }
                is XrayCoreStartOutcome.Started -> {
                    Log.i(TAG, "Xray core started")
                    // B8I7 - the ONE real, positive confirmation
                    // VlessRealityTransport waits for before ever reporting
                    // Connected - never fabricated from startService()
                    // merely returning.
                    XrayRuntimeState.publish(XrayRuntimeEvent.Started(sessionId))
                }
            }
        }
    }

    @SuppressLint("VpnServicePolicy")
    private fun establishInterface(plan: XrayVpnBuilderPlan): ParcelFileDescriptor? {
        val builder = Builder()
        builder.setMtu(plan.mtu)
        builder.addAddress(plan.tunLocalAddressIpv4, plan.tunLocalPrefixLengthIpv4)
        plan.routesIpv4.forEach { cidr ->
            val (address, prefix) = cidr.split('/', limit = 2)
            builder.addRoute(address, prefix.toInt())
        }
        plan.dnsServers.forEach { builder.addDnsServer(it) }
        plan.disallowedApplications.forEach { pkg ->
            try {
                builder.addDisallowedApplication(pkg)
            } catch (e: android.content.pm.PackageManager.NameNotFoundException) {
                // Nova's own package is always installed (it is this process) - unreachable in
                // practice, but addDisallowedApplication's checked exception must be handled.
                Log.e(TAG, "failed to disallow $pkg: package not found")
            }
        }
        return builder.establish()
    }

    // B13 (PR #25 review fix) - dispatches onto the SAME scope/dispatcher
    // start already uses, so a STOP and a concurrent/in-flight START are
    // serialized against each other through lifecycleCoordinator's own
    // mutex (see that class's own docs) - a STOP arriving while a START is
    // still mid-flight now correctly WAITS for it rather than racing it (or
    // silently observing "nothing running yet" and being lost).
    private fun teardown(reason: String) {
        scope.launch { teardownAndPublish(reason) }
    }

    /** Caller must run this on [scope] - see [teardown]/[onDestroy], its only two call sites. */
    private suspend fun teardownAndPublish(reason: String) {
        val outcome = lifecycleCoordinator.stop()
        if (!outcome.didTeardown) {
            Log.i(TAG, "teardown($reason) requested while not running - no-op")
            return
        }
        Log.i(TAG, "tearing down: $reason")
        outcome.stopLoopFailureReason?.let { Log.e(TAG, "stopLoop failed: $it") }
        XrayRuntimeState.publish(XrayRuntimeEvent.Stopped(currentSessionId))
        stopSelf()
    }

    private fun closeTunInterface() {
        val descriptor = tunInterface ?: return
        tunInterface = null
        try {
            descriptor.close()
        } catch (t: Throwable) {
            Log.e(TAG, "failed to close tun interface: ${t.javaClass.simpleName}")
        }
    }

    companion object {
        const val ACTION_START = "net.pocvpn.client.vpn.xray.action.START"
        const val ACTION_STOP = "net.pocvpn.client.vpn.xray.action.STOP"

        // B8I7 - a plain correlation id (never a secret, never config
        // material) VlessRealityTransport assigns per connect() attempt and
        // this service echoes back via XrayRuntimeState so a stale session's
        // events can never be mistaken for the CURRENT attempt's - see
        // XrayRuntimeEvent's own docs.
        const val EXTRA_SESSION_ID = "net.pocvpn.client.vpn.xray.extra.SESSION_ID"

        // B8O2 - the transport kind to start THIS attempt with: the
        // TransportKind enum constant name (e.g. "TLS_TCP"), or absent for
        // the pre-B8O2 default (XRAY_REALITY) - see onStartCommand's own
        // parsing. VlessTlsTransport sets this; VlessRealityTransport never
        // does, so its own intents are byte-for-byte unchanged.
        const val EXTRA_TRANSPORT_KIND = "net.pocvpn.client.vpn.xray.extra.TRANSPORT_KIND"

        // B13 (audit item 5 fix) - the real endpoint id VlessRealityTransport/
        // VlessTlsTransport resolved THIS attempt against (TransportConfig.Xray/
        // XrayTls.endpointId - see those types' own docs), non-secret, a
        // stable technical identifier like every other EndpointId use in
        // this codebase. Absent for any pre-B13 caller/intent - see
        // parseEndpointIdExtra's own fail-safe default.
        const val EXTRA_ENDPOINT_ID = "net.pocvpn.client.vpn.xray.extra.ENDPOINT_ID"

        // B18-2 - the RoutingMode enum constant name (e.g. "ADAPTIVE"), or
        // absent for the pre-B18-2 default (FULL_VPN) - see onStartCommand's
        // own parsing. VlessRealityTransport/VlessTlsTransport set this from
        // TransportConfig.Xray/XrayTls.routingMode.
        const val EXTRA_ROUTING_MODE = "net.pocvpn.client.vpn.xray.extra.ROUTING_MODE"

        private const val TAG = "NovaXrayVpnService"
    }
}

/**
 * B13 (audit item 5 fix) - pure, file-scope (same reasoning as
 * [xrayTransportStateFor] in VlessRealityTransport.kt: directly
 * unit-testable, independent of any Context/Intent double). A blank/absent
 * extra (every pre-B13 caller, or a malformed intent) fails safe to the ONE
 * real production endpoint - never a crash, never an arbitrary/empty
 * EndpointId (EndpointId itself rejects blank - see its own validation).
 */
internal fun parseEndpointIdExtra(raw: String?): EndpointId =
    raw?.takeIf { it.isNotBlank() }?.let { EndpointId(it) } ?: EndpointId(ProductionGateway.ID)
