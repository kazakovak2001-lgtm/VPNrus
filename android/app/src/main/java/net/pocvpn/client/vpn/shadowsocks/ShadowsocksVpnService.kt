package net.pocvpn.client.vpn.shadowsocks

import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.File
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import net.pocvpn.client.BuildConfig
import net.pocvpn.client.identity.Shadowsocks2022CredentialGetResult
import net.pocvpn.client.identity.Shadowsocks2022CredentialRepository
import net.pocvpn.client.identity.Shadowsocks2022CredentialRepositoryFactory
import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.reachability.GenerationFence
import net.pocvpn.client.smartconnect.ProductionGateway
import net.pocvpn.client.smartconnect.RestrictionClass
import net.pocvpn.client.smartconnect.RoutingDecisionEngine
import net.pocvpn.client.vpn.config.VpnDnsPolicy
import net.pocvpn.client.vpn.policy.RoutingMode

private const val TAG = "ShadowsocksVpnService"
private const val SESSION_NAME = "Nova Shadowsocks 2022 (adapter shell - not user-selectable)"
private const val WORKING_DIR_NAME = "shadowsocks"

/**
 * B45B-3 - the production, isolated [VpnService] for the Shadowsocks 2022
 * adapter shell. Follows [net.pocvpn.client.vpn.xray.NovaXrayVpnService]'s
 * own "one VpnService owner" pattern (exactly one TUN owner, one
 * Builder.establish(), fail closed, close TUN on every failure/stop path -
 * see that class's own invariants doc) with its own independent runtime
 * stack, never a second connection authority sharing state with Xray's.
 *
 * Unreachable from real selection (Phase 15): nothing registers this
 * service's owning transport as AVAILABLE in TransportRegistry.
 *
 * No raw credential content is ever logged - only lifecycle phase names.
 */
class ShadowsocksVpnService : VpnService() {

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private var runtime: ShadowsocksRuntime? = null
    private var tunInterface: ParcelFileDescriptor? = null
    private var statusCollectionJob: Job? = null

    // B45B-4P fix - the session id [teardown] publishes its terminal STOPPED
    // status under. Set only when a session genuinely proceeds past the
    // "already running" guard in [startIfNotAlreadyRunning] - a duplicate
    // start request that gets ignored must never overwrite the id the
    // ALREADY-running session's own teardown needs to report against.
    private var activeSessionId: Long = 0L

    /**
     * Service-level lifecycle ownership. Every read or write of [runtime],
     * [tunInterface], [statusCollectionJob], [activeSessionId] and
     * [runtimeSessionId], and every status publish made on a session's
     * behalf, happens under [lifecycleLock]. These run on the main thread,
     * on Dispatchers.Default, and on the runtime's own threads.
     *
     * [lifecycle] advances on every accepted ACTION_START and on every stop
     * request (ACTION_STOP, onRevoke, onDestroy). A start attempt, its status
     * collector and an ACTION_STOP teardown each carry the generation current
     * when they were requested, and act only while it is still current:
     * - an invalidated start never spawns sslocal and closes the TUN it
     *   established;
     * - a stale collector never publishes or cleans up;
     * - a stop that a newer start has already superseded does nothing
     *   (that start's commit replaces the old session).
     *
     * Blocking under the lock:
     * - VpnService.Builder.establish() (one IPC call);
     * - runtime.start()'s synchronous part (file I/O, protect bind, spawn),
     *   which is milliseconds;
     * - ShadowsocksRuntime.stop()'s bounded process wait (up to ~4 s).
     *
     * The main thread also takes this lock: ACTION_STOP/ACTION_START
     * bookkeeping, onRevoke, onDestroy. It can therefore wait behind a
     * teardown or superseding commit that another thread is running, up to
     * that ~4 s bound plus a commit. Only overlapping lifecycle commands
     * cause this; VpnController serializes disconnect -> await -> connect.
     *
     * Never under the lock: credential loading. Nothing the runtime calls
     * back into takes this lock synchronously (status reaches the collector
     * through a StateFlow).
     */
    private val lifecycleLock = Any()
    private val lifecycle = GenerationFence()
    private var runtimeGeneration: Long = 0L
    private var runtimeSessionId: Long = 0L

    /** Test seam - same contract as NovaXrayVpnService.profileRepositoryFactory. */
    internal var credentialRepositoryFactory: (Context, EndpointId) -> Shadowsocks2022CredentialRepository = { context, endpointId ->
        Shadowsocks2022CredentialRepositoryFactory.create(context, endpointId)
    }

    /** Test seam - same reasoning as [credentialRepositoryFactory] above: lets a test run [teardown]'s dispatch synchronously (e.g. Dispatchers.Unconfined) instead of waiting on a real background dispatcher. Production default unchanged. */
    internal var teardownDispatcher: CoroutineDispatcher = Dispatchers.Default

    /** Test seam - the dispatcher [startIfNotAlreadyRunning]'s start attempt runs on. Production default unchanged. */
    internal var startDispatcher: CoroutineDispatcher = Dispatchers.Default

    /** Test seam - builds the runtime for one start attempt (fakes in tests). Production default is the real process/bridge stack. */
    internal var runtimeFactory: (protector: ShadowsocksVpnProtector, scope: CoroutineScope) -> ShadowsocksRuntime = { protector, scope ->
        ShadowsocksRuntime(
            launcher = RealShadowsocksProcessLauncher(),
            tunFdBridge = RealShadowsocksTunFdBridge(),
            protectBridge = RealShadowsocksVpnProtectBridge(),
            protector = protector,
            scope = scope,
        )
    }

    /** Test seam - establishes this attempt's TUN (VpnService.Builder in production). */
    internal var tunEstablisher: () -> ParcelFileDescriptor? = { establishInterface() }

    /** Test seam - locates the sslocal binary. */
    internal var binaryResolver: () -> ShadowsocksNativeBinaryResolver.Result = {
        ShadowsocksNativeBinaryResolver.resolve(applicationInfo.nativeLibraryDir)
    }

    /** Test seam - no-op in production; runs after the runtime is published and before runtime.start(), the window lifecycle tests gate. */
    internal var beforeRuntimeStart: () -> Unit = {}

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                // B45B-4P fix - [teardown] blocks (bounded, up to ~4s inside
                // ShadowsocksRuntime.stop's own graceful/force-stop wait) -
                // onStartCommand always runs on the main thread, so that wait
                // must never happen there. Dispatched onto [serviceScope]
                // (Dispatchers.Default), exactly like startIfNotAlreadyRunning's
                // own heavier work already is. Safe even if this races with a
                // later onDestroy()-driven teardown() call - every step inside
                // teardown() is already null-safe/idempotent by construction.
                val generation = requestStop()
                serviceScope.launch(teardownDispatcher) { teardown(generation) }
                return START_NOT_STICKY
            }
            ACTION_START -> {
                val sessionId = intent.getLongExtra(EXTRA_SESSION_ID, 0L)
                val endpointId = intent.getStringExtra(EXTRA_ENDPOINT_ID)
                    ?.takeIf { it.isNotBlank() }
                    ?.let { EndpointId(it) }
                    ?: EndpointId(ProductionGateway.ID)
                val host = intent.getStringExtra(EXTRA_HOST)
                val port = intent.getIntExtra(EXTRA_PORT, -1)
                val expectedMethod = intent.getStringExtra(EXTRA_METHOD)
                val routingMode = intent.getStringExtra(EXTRA_ROUTING_MODE)
                    ?.let { runCatching { RoutingMode.valueOf(it) }.getOrNull() }
                    ?: RoutingMode.FULL_VPN

                if (host.isNullOrBlank() || port !in 1..65535 || expectedMethod.isNullOrBlank()) {
                    Log.e(TAG, "refusing to start: missing/invalid host, port, or method")
                    publish(sessionId, ShadowsocksRuntimePhase.FAILED)
                    stopSelf()
                    return START_NOT_STICKY
                }
                startIfNotAlreadyRunning(sessionId, endpointId, host, port, expectedMethod, routingMode)
                return START_NOT_STICKY
            }
            else -> return START_NOT_STICKY
        }
    }

    override fun onRevoke() {
        teardown(requestStop())
    }

    override fun onDestroy() {
        teardown(requestStop())
        serviceScope.cancel()
        super.onDestroy()
    }

    /** Invalidates every start attempt requested so far; returns the generation this stop request owns. */
    private fun requestStop(): Long = synchronized(lifecycleLock) { lifecycle.begin() }

    private fun startIfNotAlreadyRunning(sessionId: Long, endpointId: EndpointId, host: String, port: Int, expectedMethod: String, routingMode: RoutingMode) {
        val generation = synchronized(lifecycleLock) {
            // Only a RUNNING runtime that no stop request has invalidated
            // since makes this a duplicate. A start that follows a stop
            // request proceeds and replaces the old session on commit.
            if (runtime?.status?.value?.phase == ShadowsocksRuntimePhase.RUNNING && lifecycle.isCurrent(runtimeGeneration)) {
                Log.w(TAG, "already running - ignoring duplicate start")
                return
            }
            activeSessionId = sessionId
            lifecycle.begin()
        }
        // B45B-4P (correction) - bounded, once-per-attempt, PUBLIC facts only
        // (endpointId/host/port/method identifier - never the key): the
        // physical proof this attempt targets the real signed Shadowsocks
        // port, never the AWG peer port this same endpoint also advertises.
        Log.i(TAG, "starting: endpointId=${endpointId.value} host=$host port=$port method=$expectedMethod")

        serviceScope.launch(startDispatcher) {
            // Credential absent/corrupted -> fail closed (Phase 7/16) -
            // never a silently-empty/default key reaching sslocal.
            val repository = credentialRepositoryFactory(applicationContext, endpointId)
            val credential = when (val result = repository.getCredential()) {
                is Shadowsocks2022CredentialGetResult.Absent -> {
                    Log.e(TAG, "refusing to start: no credential for endpoint")
                    failAttempt(generation, sessionId, ShadowsocksRuntimeError.CredentialAbsent(endpointId.value))
                    return@launch
                }
                is Shadowsocks2022CredentialGetResult.Corrupted -> {
                    Log.e(TAG, "refusing to start: credential corrupted")
                    failAttempt(generation, sessionId, ShadowsocksRuntimeError.CredentialCorrupted(result.reason))
                    return@launch
                }
                is Shadowsocks2022CredentialGetResult.Present -> result.credential
            }

            // B45B-4P (correction) - the signed manifest's PUBLIC method and
            // the endpoint-scoped SECRET credential's own method must agree
            // before sslocal is ever spawned. Both identifiers are safe to
            // log (never the key itself) - see EXTRA_METHOD's own docs.
            if (credential.method != expectedMethod) {
                Log.e(TAG, "refusing to start: signed profile method ($expectedMethod) does not match credential method (${credential.method})")
                failAttempt(generation, sessionId, ShadowsocksRuntimeError.ProfileMethodMismatch(expectedMethod, credential.method))
                return@launch
            }

            val resolution = binaryResolver()
            val binaryPath = when (resolution) {
                is ShadowsocksNativeBinaryResolver.Result.Found -> resolution.file
                is ShadowsocksNativeBinaryResolver.Result.Missing -> {
                    Log.e(TAG, "refusing to start: binary unavailable: ${resolution.reason}")
                    failAttempt(generation, sessionId, ShadowsocksRuntimeError.BinaryMissing(resolution.reason))
                    return@launch
                }
            }

            // Commit point: establish, publish and start happen in ONE
            // critical section, and only while this attempt is still current
            // (I1). An invalidated attempt never establishes a TUN (which on
            // Android would replace the current session's interface) and
            // never spawns sslocal.
            synchronized(lifecycleLock) {
                if (!lifecycle.isCurrent(generation)) return@launch
                val established = tunEstablisher()
                if (established == null) {
                    Log.e(TAG, "refusing to start: VpnService.Builder.establish() returned null")
                    failAttempt(generation, sessionId, ShadowsocksRuntimeError.TunEstablishFailed("establish() returned null"))
                    return@launch
                }
                // Rapid reconnect: a previous session that was not yet
                // RUNNING (or had a stop requested) is stopped here, never
                // orphaned (I2).
                releaseSessionLocked(publishStoppedFor = runtimeSessionId)
                tunInterface = established

                val newRuntime = runtimeFactory(ShadowsocksVpnProtector { fd -> protect(fd) }, serviceScope)
                runtime = newRuntime
                runtimeGeneration = generation
                runtimeSessionId = sessionId

                statusCollectionJob = serviceScope.launch collector@{
                    newRuntime.status.collect { status ->
                        val stillOwner = synchronized(lifecycleLock) {
                            // A stale collector (its session stopped or
                            // replaced) never publishes or cleans up (I3).
                            if (!lifecycle.isCurrent(generation) || runtime !== newRuntime) return@synchronized false
                            publish(sessionId, status.phase, status.lastError)
                            if (status.phase == ShadowsocksRuntimePhase.FAILED) {
                                runtime = null
                                runCatching { tunInterface?.close() }
                                tunInterface = null
                                statusCollectionJob = null
                                stopSelf()
                                return@synchronized false
                            }
                            true
                        }
                        if (!stillOwner) this@collector.cancel()
                    }
                }

                beforeRuntimeStart()
                val started = newRuntime.start(
                    binaryPath = binaryPath.absolutePath,
                    // Borrowed, never a second owner - see ShadowsocksRuntime.start's
                    // own docs. `established` (this service's own TUN ParcelFileDescriptor)
                    // remains the sole close authority throughout.
                    tunFd = established.fileDescriptor,
                    workingDir = File(filesDir, WORKING_DIR_NAME),
                    tunInterfaceAddressCidr = ShadowsocksTunConfig.CIDR,
                    target = ShadowsocksRuntimeTarget(host, port, credential.method, credential.key.base64),
                )
                if (!started) {
                    Log.w(TAG, "ShadowsocksRuntime.start() refused (already running, or immediate failure)")
                }
            }
        }
    }

    @SuppressLint("VpnServicePolicy")
    private fun establishInterface(): ParcelFileDescriptor? {
        val builder = Builder()
            .setMtu(ShadowsocksTunConfig.MTU)
            .addAddress(ShadowsocksTunConfig.ADDRESS, ShadowsocksTunConfig.PREFIX_LENGTH)
            .setSession(SESSION_NAME)
        // B45B-4P fix - root cause of zero inbound TCP at the server: this
        // TUN never carried a DNS server, unlike every other transport
        // (NovaXrayVpnService, AwgConfigMapper both call addDnsServer from
        // the same VpnDnsPolicy authority). Per VpnService.Builder.addDnsServer's
        // own contract, an interface with a route but no DNS server of a
        // given family leaves that family's DNS resolution broken for every
        // app routed through it - so routed apps never got a resolved
        // destination to open a TCP connection to in the first place,
        // meaning sslocal never saw a packet to relay. Same canonical
        // resolver list every other transport already uses (never a second,
        // transport-specific DNS decision).
        VpnDnsPolicy.servers.forEach { builder.addDnsServer(it) }
        // Full-tunnel IPv4 route via the same RoutingDecisionEngine authority
        // the Xray adapters already use (Phase 5 - never a parallel routing
        // decision system). No IPv6 route/address anywhere (fail closed).
        RoutingDecisionEngine.resolveIpv4Routes(listOf("0.0.0.0/0"), RoutingMode.FULL_VPN, RestrictionClass.UNKNOWN)
            .forEach { cidr ->
                val (address, prefix) = cidr.split('/', limit = 2)
                builder.addRoute(address, prefix.toInt())
            }
        try {
            builder.addDisallowedApplication(BuildConfig.APPLICATION_ID)
        } catch (e: android.content.pm.PackageManager.NameNotFoundException) {
            Log.e(TAG, "failed to disallow own package: package not found")
        }
        return builder.establish()
    }

    /**
     * B45B-4P fix - a real ownership/cleanup bug found on a physical device:
     * this previously set [_status] straight to `null` on a genuine stop.
     * [ShadowsocksTransport]'s own status collector explicitly ignores a
     * `null` status (see that class's own docs) - so a real, successful
     * teardown never reached it at all, leaving [ShadowsocksTransport.state]
     * stuck at [net.pocvpn.client.vpn.TransportState.Disconnecting] forever,
     * with the real `sslocal` process/TUN/bridges already torn down here but
     * nothing ever reporting that fact back. Publishing a genuine
     * [ShadowsocksRuntimePhase.STOPPED] status (mapped to
     * [net.pocvpn.client.vpn.TransportState.Disconnected] by
     * [shadowsocksTransportStateFor]) closes that gap - the ONE typed
     * terminal-stop signal, never a second one.
     */
    private fun teardown(generation: Long) {
        synchronized(lifecycleLock) {
            // A stop that a newer ACTION_START has superseded does nothing:
            // that start's commit (or its own failure) replaces the old
            // session, and this stop must neither cancel it nor publish
            // STOPPED under its session id (I3). Repeated teardowns are
            // idempotent (I4).
            if (!lifecycle.isCurrent(generation)) return
            releaseSessionLocked(publishStoppedFor = null)
            publish(activeSessionId, ShadowsocksRuntimePhase.STOPPED)
        }
        stopSelf()
    }

    /**
     * Stops and forgets the currently owned session (if any): collector,
     * runtime (bounded process wait), TUN. Caller holds [lifecycleLock].
     * [publishStoppedFor] reports STOPPED for a session replaced by a newer
     * start, which has no teardown of its own.
     */
    private fun releaseSessionLocked(publishStoppedFor: Long?) {
        statusCollectionJob?.cancel()
        statusCollectionJob = null
        val previous = runtime
        previous?.stop()
        runtime = null
        runCatching { tunInterface?.close() }
        tunInterface = null
        if (previous != null && publishStoppedFor != null) publish(publishStoppedFor, ShadowsocksRuntimePhase.STOPPED)
    }

    /**
     * Early start failure. It is reported, and the service stopped, only if
     * this attempt is still current: a stale attempt must not stop a newer
     * session (I3). A current attempt has superseded any older session
     * (including one whose STOP it made stale), so it releases that
     * session here. Otherwise the old sslocal and TUN would outlive both
     * the stop request and the failed start (I2).
     */
    private fun failAttempt(generation: Long, sessionId: Long, error: ShadowsocksRuntimeError) {
        synchronized(lifecycleLock) {
            if (!lifecycle.isCurrent(generation)) return
            releaseSessionLocked(publishStoppedFor = runtimeSessionId)
            publish(sessionId, ShadowsocksRuntimePhase.FAILED, error)
        }
        stopSelf()
    }

    private fun publish(sessionId: Long, phase: ShadowsocksRuntimePhase, error: ShadowsocksRuntimeError? = null) {
        _status.value = ShadowsocksServiceStatus(sessionId, phase, error)
    }

    companion object {
        const val ACTION_START = "net.pocvpn.client.vpn.shadowsocks.action.START"
        const val ACTION_STOP = "net.pocvpn.client.vpn.shadowsocks.action.STOP"
        const val EXTRA_SESSION_ID = "net.pocvpn.client.vpn.shadowsocks.extra.SESSION_ID"
        const val EXTRA_ENDPOINT_ID = "net.pocvpn.client.vpn.shadowsocks.extra.ENDPOINT_ID"
        const val EXTRA_HOST = "net.pocvpn.client.vpn.shadowsocks.extra.HOST"
        const val EXTRA_PORT = "net.pocvpn.client.vpn.shadowsocks.extra.PORT"
        // B45B-4P (correction) - PUBLIC signed-method identifier (e.g.
        // "2022-blake3-aes-256-gcm"), never key material - see
        // TransportConfig.Shadowsocks.method's own docs. Verified against the
        // endpoint-scoped SECRET credential's own method before sslocal is
        // ever spawned (see startIfNotAlreadyRunning's own docs).
        const val EXTRA_METHOD = "net.pocvpn.client.vpn.shadowsocks.extra.METHOD"
        const val EXTRA_ROUTING_MODE = "net.pocvpn.client.vpn.shadowsocks.extra.ROUTING_MODE"

        private val _status = MutableStateFlow<ShadowsocksServiceStatus?>(null)

        /** Observed by [ShadowsocksTransport] - process-wide, since only one instance may exist at a time (mirrors XrayRuntimeState's own single-owner discipline). */
        internal val status: StateFlow<ShadowsocksServiceStatus?> = _status.asStateFlow()
    }
}

/** Session-scoped, non-secret status snapshot - [sessionId] lets a stale prior attempt's terminal event never be mistaken for the current one's (same discipline as XrayRuntimeEvent). */
internal data class ShadowsocksServiceStatus(
    val sessionId: Long,
    val phase: ShadowsocksRuntimePhase,
    val error: ShadowsocksRuntimeError? = null,
)
