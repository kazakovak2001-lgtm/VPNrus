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
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
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

    /**
     * Service -> runtime lifecycle boundary. Every START and every teardown
     * entry point (ACTION_STOP, onRevoke, onDestroy) begins a new [lifecycle]
     * generation the moment it is received. A start attempt carries its
     * generation and may publish anything (TUN, runtime, status, stopSelf)
     * only while that generation is still current, checked under [lock] in
     * the same critical section that publishes it.
     *
     * TUN establish, [session] publication and ShadowsocksRuntime.start() run
     * in ONE critical section (see [startIfNotAlreadyRunning]), so a teardown
     * runs either entirely before it (the attempt sees a stale generation and
     * never establishes or spawns anything) or entirely after it (the
     * teardown finds the published session and stops it) - never in between.
     * A teardown only detaches sessions committed BEFORE it was received, so
     * a late ACTION_STOP never stops a session a newer START created.
     *
     * Deadlock rules:
     * - Never call ShadowsocksRuntime.stop() (bounded blocking process wait)
     *   under [lock]: a session is detached under [lock] and released outside
     *   it ([release]).
     * - The only runtime call under [lock] is start() on a runtime no other
     *   thread can reach yet. The status collector takes [lock] from its own
     *   coroutine, never from inside the runtime.
     * - Main-thread entry points (onStartCommand, onRevoke, onDestroy) take
     *   [lock] only for these short sections; the longest is the commit
     *   (TUN establish + sslocal spawn).
     */
    private val lock = Any()
    private val lifecycle = GenerationFence()

    /** The one committed session. Guarded by [lock]. */
    private var session: ShadowsocksSession? = null

    // B45B-4P fix - the session id [teardown] publishes its terminal STOPPED
    // status under. Set only when a session genuinely proceeds past the
    // "already running" guard in [startIfNotAlreadyRunning] - a duplicate
    // start request that gets ignored must never overwrite the id the
    // ALREADY-running session's own teardown needs to report against.
    // Guarded by [lock], always set together with its generation.
    private var activeSessionId: Long = 0L

    /** Test seam - same contract as NovaXrayVpnService.profileRepositoryFactory. */
    internal var credentialRepositoryFactory: (Context, EndpointId) -> Shadowsocks2022CredentialRepository = { context, endpointId ->
        Shadowsocks2022CredentialRepositoryFactory.create(context, endpointId)
    }

    /** Test seam - same reasoning as [credentialRepositoryFactory] above: lets a test run [teardown]'s dispatch synchronously (e.g. Dispatchers.Unconfined) instead of waiting on a real background dispatcher. Production default unchanged. */
    internal var teardownDispatcher: CoroutineDispatcher = Dispatchers.Default

    /** Test seams - let a JVM test drive the start path (dispatch, binary lookup, TUN establish, runtime construction) with fakes. Production defaults unchanged. */
    internal var workDispatcher: CoroutineDispatcher = Dispatchers.Default
    internal var binaryResolver: () -> ShadowsocksNativeBinaryResolver.Result = { ShadowsocksNativeBinaryResolver.resolve(applicationInfo.nativeLibraryDir) }
    internal var tunEstablisher: () -> ParcelFileDescriptor? = { establishInterface() }
    internal var runtimeFactory: (ShadowsocksVpnProtector) -> ShadowsocksRuntime = { protector ->
        ShadowsocksRuntime(
            launcher = RealShadowsocksProcessLauncher(),
            tunFdBridge = RealShadowsocksTunFdBridge(),
            protectBridge = RealShadowsocksVpnProtectBridge(),
            protector = protector,
            scope = serviceScope,
        )
    }

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
                // The generation is taken here, on receipt, so a START
                // received after this STOP is never torn down by it.
                val generation = lifecycle.begin()
                serviceScope.launch(teardownDispatcher) { teardown(generation, startId) }
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
                startIfNotAlreadyRunning(startId, sessionId, endpointId, host, port, expectedMethod, routingMode)
                return START_NOT_STICKY
            }
            else -> return START_NOT_STICKY
        }
    }

    override fun onRevoke() {
        teardown(lifecycle.begin(), startId = null)
    }

    override fun onDestroy() {
        teardown(lifecycle.begin(), startId = null)
        serviceScope.cancel()
        super.onDestroy()
    }

    private fun startIfNotAlreadyRunning(startId: Int, sessionId: Long, endpointId: EndpointId, host: String, port: Int, expectedMethod: String, routingMode: RoutingMode) {
        val attempt = synchronized(lock) {
            val current = session
            // A RUNNING session that a later STOP already doomed is not a
            // duplicate - this START is the reconnect after that STOP.
            if (current != null && lifecycle.isCurrent(current.attempt.generation) &&
                current.runtime.status.value.phase == ShadowsocksRuntimePhase.RUNNING
            ) {
                Log.w(TAG, "already running - ignoring duplicate start")
                return
            }
            activeSessionId = sessionId
            ShadowsocksStartAttempt(lifecycle.begin(), sessionId, startId)
        }
        // B45B-4P (correction) - bounded, once-per-attempt, PUBLIC facts only
        // (endpointId/host/port/method identifier - never the key): the
        // physical proof this attempt targets the real signed Shadowsocks
        // port, never the AWG peer port this same endpoint also advertises.
        Log.i(TAG, "starting: endpointId=${endpointId.value} host=$host port=$port method=$expectedMethod")

        serviceScope.launch(workDispatcher) {
            // Credential absent/corrupted -> fail closed (Phase 7/16) -
            // never a silently-empty/default key reaching sslocal.
            val repository = credentialRepositoryFactory(applicationContext, endpointId)
            val credential = when (val result = repository.getCredential()) {
                is Shadowsocks2022CredentialGetResult.Absent -> {
                    Log.e(TAG, "refusing to start: no credential for endpoint")
                    failAttempt(attempt, ShadowsocksRuntimeError.CredentialAbsent(endpointId.value))
                    return@launch
                }
                is Shadowsocks2022CredentialGetResult.Corrupted -> {
                    Log.e(TAG, "refusing to start: credential corrupted")
                    failAttempt(attempt, ShadowsocksRuntimeError.CredentialCorrupted(result.reason))
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
                failAttempt(attempt, ShadowsocksRuntimeError.ProfileMethodMismatch(expectedMethod, credential.method))
                return@launch
            }

            val binaryPath = when (val resolution = binaryResolver()) {
                is ShadowsocksNativeBinaryResolver.Result.Found -> resolution.file
                is ShadowsocksNativeBinaryResolver.Result.Missing -> {
                    Log.e(TAG, "refusing to start: binary unavailable: ${resolution.reason}")
                    failAttempt(attempt, ShadowsocksRuntimeError.BinaryMissing(resolution.reason))
                    return@launch
                }
            }

            // A superseded, not-yet-RUNNING session (a current RUNNING one
            // made this START a no-op above) is released before this attempt
            // establishes its own TUN - one TUN owner at a time.
            val superseded = synchronized(lock) {
                if (!lifecycle.isCurrent(attempt.generation)) return@launch
                session.also { session = null }
            }
            superseded?.let(::release)

            val committed = synchronized(lock) {
                if (!lifecycle.isCurrent(attempt.generation)) return@launch
                val established = tunEstablisher()
                if (established == null) {
                    Log.e(TAG, "refusing to start: VpnService.Builder.establish() returned null")
                    publish(attempt.sessionId, ShadowsocksRuntimePhase.FAILED, ShadowsocksRuntimeError.TunEstablishFailed("establish() returned null"))
                    return@synchronized false
                }
                val newSession = ShadowsocksSession(attempt, established, runtimeFactory(ShadowsocksVpnProtector { fd -> protect(fd) }))
                newSession.statusCollection = serviceScope.launch(workDispatcher, start = CoroutineStart.LAZY) {
                    newSession.runtime.status.first { status -> onRuntimeStatus(newSession, status) }
                }
                // Published only together with its TUN and collector, never half-built.
                session = newSession
                newSession.statusCollection.start()

                // A teardown/START received since the check above has begun a
                // newer generation and will release this session as soon as
                // it gets [lock] - spawning sslocal for it would be wasted.
                if (!lifecycle.isCurrent(attempt.generation)) return@synchronized true
                val started = newSession.runtime.start(
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
                true
            }
            if (!committed) stopSelfResult(attempt.startId)
        }
    }

    /** Fails [attempt] before anything was established - reported and acted on only if no newer START/teardown was received since. */
    private fun failAttempt(attempt: ShadowsocksStartAttempt, error: ShadowsocksRuntimeError) {
        val current = synchronized(lock) {
            lifecycle.isCurrent(attempt.generation).also { current ->
                if (current) publish(attempt.sessionId, ShadowsocksRuntimePhase.FAILED, error)
            }
        }
        if (current) stopSelfResult(attempt.startId)
    }

    /**
     * Status collector of one committed [owned] session; returns true once it
     * no longer needs collecting. A collector whose session was already
     * detached (by a teardown or a superseding START, which released it)
     * never publishes, closes, or stops anything again.
     */
    private fun onRuntimeStatus(owned: ShadowsocksSession, status: ShadowsocksRuntimeStatus): Boolean {
        val current = synchronized(lock) {
            if (session !== owned) return true
            val current = lifecycle.isCurrent(owned.attempt.generation)
            if (current) publish(owned.attempt.sessionId, status.phase, status.lastError)
            if (status.phase != ShadowsocksRuntimePhase.FAILED) return false
            session = null
            current
        }
        // The runtime already tore its own process/bridges down on FAILED; the TUN is this service's to close.
        runCatching { owned.tun.close() }
        if (current) stopSelfResult(owned.attempt.startId)
        return true
    }

    /** Stops everything [detached] owns. Only ever called by whoever detached it from [session] under [lock], so exactly once, and never under [lock]. */
    private fun release(detached: ShadowsocksSession) {
        detached.statusCollection.cancel()
        detached.runtime.stop()
        runCatching { detached.tun.close() }
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
    private fun teardown(generation: Long, startId: Int?) {
        val detached = synchronized(lock) {
            session?.takeIf { it.attempt.generation < generation }?.also { session = null }
        }
        detached?.let(::release)
        val current = synchronized(lock) {
            lifecycle.isCurrent(generation).also { current ->
                if (current) publish(activeSessionId, ShadowsocksRuntimePhase.STOPPED)
            }
        }
        // A START received after this teardown owns the service now.
        if (!current) return
        if (startId == null) stopSelf() else stopSelfResult(startId)
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

private data class ShadowsocksStartAttempt(val generation: Long, val sessionId: Long, val startId: Int)

/** Everything one committed start owns - published to ShadowsocksVpnService's session as one unit and released as one unit. */
private class ShadowsocksSession(
    val attempt: ShadowsocksStartAttempt,
    val tun: ParcelFileDescriptor,
    val runtime: ShadowsocksRuntime,
) {
    lateinit var statusCollection: Job
}
