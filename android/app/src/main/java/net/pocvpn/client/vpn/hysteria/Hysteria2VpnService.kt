package net.pocvpn.client.vpn.hysteria

import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.File
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import net.pocvpn.client.BuildConfig
import net.pocvpn.client.identity.Hysteria2CredentialGetResult
import net.pocvpn.client.identity.Hysteria2CredentialRepository
import net.pocvpn.client.identity.Hysteria2CredentialRepositoryFactory
import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.smartconnect.ProductionGateway
import net.pocvpn.client.smartconnect.RestrictionClass
import net.pocvpn.client.smartconnect.RoutingDecisionEngine
import net.pocvpn.client.vpn.config.VpnDnsPolicy
import net.pocvpn.client.vpn.policy.RoutingMode

private const val TAG = "Hysteria2VpnService"
private const val SESSION_NAME = "Nova Hysteria2 (production, process-isolated)"
private const val WORKING_DIR_NAME = "hysteria2"
private const val TUN_ADDRESS = "10.206.49.1"
private const val TUN_PREFIX_LENGTH = 24
private const val MTU = 1400
private const val LOCAL_SOCKS_ADDR = "127.0.0.1:41080"
private const val TUN2SOCKS_CONTROL_SOCKET_FILENAME = "hysteria2-tun2socks-control.sock"

/** Typed, session-scoped lifecycle phase - mirrors `ShadowsocksRuntimePhase`'s own shape. */
enum class Hysteria2RuntimePhase { STOPPED, STARTING, RUNNING, STOPPING, FAILED }

/** Typed, non-secret failure reason - never a raw exception message that could echo secret-shaped input. */
sealed interface Hysteria2RuntimeError {
    data class CredentialAbsent(val endpointId: String) : Hysteria2RuntimeError
    data class CredentialCorrupted(val reason: String) : Hysteria2RuntimeError
    data class UnsupportedAbi(val deviceAbis: List<String>) : Hysteria2RuntimeError
    data class BinaryUnavailable(val reason: String) : Hysteria2RuntimeError
    data class UnsupportedRoutingMode(val requested: String) : Hysteria2RuntimeError
    data class TunEstablishFailed(val reason: String) : Hysteria2RuntimeError
    data class HysteriaChildFailed(val reason: String) : Hysteria2RuntimeError
    data class Tun2SocksChildFailed(val reason: String) : Hysteria2RuntimeError
    data class ChildDiedUnexpectedly(val which: String, val exitCode: Int) : Hysteria2RuntimeError
}

/** Session-scoped, non-secret status snapshot - [sessionId] lets a stale prior attempt's terminal event never be mistaken for the current one's (mirrors `ShadowsocksServiceStatus`). */
internal data class Hysteria2ServiceStatus(
    val sessionId: Long,
    val phase: Hysteria2RuntimePhase,
    val error: Hysteria2RuntimeError? = null,
)

/**
 * B46-4A - the production, isolated [VpnService] for Hysteria2. Preserves
 * the THREE-PROCESS-BOUNDARY architecture B46-3A physically demanded and
 * B46-3B/B46-3C physically proved (see
 * docs/B46_4A_HYSTERIA2_PRODUCTION_INTEGRATION.md's "process isolation"
 * section): this app/VpnService process never loads a tun2socks or Hysteria
 * Go runtime; [Hysteria2Tun2SocksChildRuntime] owns a separate tun2socks
 * child process; [Hysteria2ChildRuntime] owns a separate, minimal Hysteria2
 * child process. Startup order (Hysteria2 child first, so tun2socks has a
 * live SOCKS5 listener to dial) and whole-session teardown on either
 * child's unexpected death are both unchanged from B46-3C's own physically
 * proven ordering.
 *
 * SECRET HANDLING (the load-bearing correction this production slice makes
 * over B46-3C's debug spike): the Hysteria auth secret and optional
 * Salamander obfuscation secret are loaded HERE, independently, from
 * `Hysteria2CredentialRepository` - never accepted from the start [Intent].
 * `EXTRA_SNI`/`EXTRA_HOST`/`EXTRA_PORT`/`EXTRA_OBFUSCATION_MODE` are the
 * ONLY connection-shaping extras, and every one of them is a PUBLIC,
 * already-signed fact - never a credential.
 *
 * TLS: production Hysteria2 MUST NOT use `insecure=true` - see
 * [Hysteria2ChildConfig.insecure]'s own hard-gate doc. This service always
 * constructs `insecure = false`; there is no code path in this class that
 * can set it otherwise.
 *
 * CONNECTED DEFINITION: [Hysteria2RuntimePhase.RUNNING] is published only
 * after the Hysteria2 child has reported `SOCKS5_LISTENING` AND a
 * successful QUIC connect (`hysteriaRuntime.quicConnected`) AND the
 * tun2socks child has itself started (a real SCM_RIGHTS TUN-fd handoff ack)
 * - never merely "TUN established" or "a child process object exists".
 *
 * ROUTING: this slice wires FULL_VPN only (see `TransportConfig.Hysteria2`'s
 * own doc) - any other requested [RoutingMode] fails closed
 * ([Hysteria2RuntimeError.UnsupportedRoutingMode]), never silently treated
 * as full tunnel.
 *
 * No raw credential content is ever logged - only lifecycle phase names and
 * public facts (endpointId/host/port/sni/obfuscation mode identifier).
 */
class Hysteria2VpnService : VpnService() {

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val tun2socksRuntime = Hysteria2Tun2SocksChildRuntime()
    private val hysteriaRuntime = Hysteria2ChildRuntime()
    private var tunFd: ParcelFileDescriptor? = null
    private var activeSessionId: Long = 0L
    private var sessionActive = false

    /** Test seam - same contract as `ShadowsocksVpnService.credentialRepositoryFactory`. */
    internal var credentialRepositoryFactory: (Context, EndpointId) -> Hysteria2CredentialRepository = { context, endpointId ->
        Hysteria2CredentialRepositoryFactory.create(context, endpointId)
    }

    init {
        tun2socksRuntime.onUnexpectedExit = { code -> handleUnexpectedExit("tun2socks", code) }
        hysteriaRuntime.onUnexpectedExit = { code -> handleUnexpectedExit("hysteria", code) }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                serviceScope.launch { teardown() }
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
                val sni = intent.getStringExtra(EXTRA_SNI)
                val obfuscationMode = intent.getStringExtra(EXTRA_OBFUSCATION_MODE) ?: "NONE"
                val routingMode = intent.getStringExtra(EXTRA_ROUTING_MODE)
                    ?.let { runCatching { RoutingMode.valueOf(it) }.getOrNull() }
                    ?: RoutingMode.FULL_VPN

                if (host.isNullOrBlank() || port !in 1..65535 || sni.isNullOrBlank()) {
                    Log.e(TAG, "refusing to start: missing/invalid host, port, or sni")
                    publish(sessionId, Hysteria2RuntimePhase.FAILED)
                    stopSelf()
                    return START_NOT_STICKY
                }
                if (routingMode != RoutingMode.FULL_VPN) {
                    Log.e(TAG, "refusing to start: unsupported routing mode $routingMode (HYSTERIA2 is FULL_VPN only this slice)")
                    publish(sessionId, Hysteria2RuntimePhase.FAILED, Hysteria2RuntimeError.UnsupportedRoutingMode(routingMode.name))
                    stopSelf()
                    return START_NOT_STICKY
                }
                startIfNotAlreadyRunning(sessionId, endpointId, host, port, sni, obfuscationMode)
                return START_NOT_STICKY
            }
            else -> return START_NOT_STICKY
        }
    }

    override fun onRevoke() {
        serviceScope.launch { teardown() }
    }

    override fun onDestroy() {
        // Best-effort synchronous teardown - onDestroy cannot itself suspend,
        // and the process may be torn down immediately after returning.
        runCatching {
            tun2socksRuntime.stop()
            hysteriaRuntime.stop()
        }
        runCatching { tunFd?.close() }
        tunFd = null
        sessionActive = false
        serviceScope.cancel()
        super.onDestroy()
    }

    private fun startIfNotAlreadyRunning(
        sessionId: Long,
        endpointId: EndpointId,
        host: String,
        port: Int,
        sni: String,
        obfuscationMode: String,
    ) {
        if (sessionActive) {
            Log.w(TAG, "already running - ignoring duplicate start")
            return
        }
        activeSessionId = sessionId
        publish(sessionId, Hysteria2RuntimePhase.STARTING)
        // Bounded, once-per-attempt, PUBLIC facts only - never the secret.
        Log.i(TAG, "starting: endpointId=${endpointId.value} host=$host port=$port sni=$sni obfuscationMode=$obfuscationMode")

        serviceScope.launch {
            val abiEligibility = Hysteria2AdapterEligibilityChecker.check(
                deviceAbis = Build.SUPPORTED_ABIS.toList(),
                nativeLibraryDir = applicationInfo.nativeLibraryDir,
            )
            val (tun2socksBinaryPath, hysteriaBinaryPath) = when (abiEligibility) {
                is Hysteria2BinaryEligibility.UnsupportedAbi -> {
                    Log.e(TAG, "refusing to start: unsupported ABI ${abiEligibility.deviceAbis}")
                    publish(sessionId, Hysteria2RuntimePhase.FAILED, Hysteria2RuntimeError.UnsupportedAbi(abiEligibility.deviceAbis))
                    stopSelf()
                    return@launch
                }
                is Hysteria2BinaryEligibility.BinaryUnavailable -> {
                    Log.e(TAG, "refusing to start: binary unavailable: ${abiEligibility.reason}")
                    publish(sessionId, Hysteria2RuntimePhase.FAILED, Hysteria2RuntimeError.BinaryUnavailable(abiEligibility.reason))
                    stopSelf()
                    return@launch
                }
                Hysteria2BinaryEligibility.Eligible -> {
                    val t2s = (Hysteria2Tun2SocksChildBinaryResolver.resolve(applicationInfo.nativeLibraryDir) as Hysteria2Tun2SocksChildBinaryResolver.Result.Found).file.absolutePath
                    val hy = (Hysteria2ChildBinaryResolver.resolve(applicationInfo.nativeLibraryDir) as Hysteria2ChildBinaryResolver.Result.Found).file.absolutePath
                    t2s to hy
                }
            }

            // Credential absent/corrupted -> fail closed - never a silently-empty/default secret reaching the child.
            val repository = credentialRepositoryFactory(applicationContext, endpointId)
            val credential = when (val result = repository.getCredential()) {
                is Hysteria2CredentialGetResult.Absent -> {
                    Log.e(TAG, "refusing to start: no credential for endpoint")
                    publish(sessionId, Hysteria2RuntimePhase.FAILED, Hysteria2RuntimeError.CredentialAbsent(endpointId.value))
                    stopSelf()
                    return@launch
                }
                is Hysteria2CredentialGetResult.Corrupted -> {
                    Log.e(TAG, "refusing to start: credential corrupted")
                    publish(sessionId, Hysteria2RuntimePhase.FAILED, Hysteria2RuntimeError.CredentialCorrupted(result.reason))
                    stopSelf()
                    return@launch
                }
                is Hysteria2CredentialGetResult.Present -> result.credential
            }

            val established = establishInterface()
            if (established == null) {
                Log.e(TAG, "refusing to start: VpnService.Builder.establish() returned null")
                publish(sessionId, Hysteria2RuntimePhase.FAILED, Hysteria2RuntimeError.TunEstablishFailed("establish() returned null"))
                stopSelf()
                return@launch
            }
            tunFd = established

            // Hysteria2 child FIRST - tun2socks needs its SOCKS5 listener ready (unchanged from B46-3C's own proven ordering).
            val hysteriaResult = hysteriaRuntime.start(
                config = Hysteria2ChildConfig(
                    server = "$host:$port",
                    auth = credential.authSecret.value,
                    sni = sni,
                    insecure = false, // Hard production gate - see Hysteria2ChildConfig.insecure's own doc.
                    obfsSalamander = credential.obfuscationSecret?.value ?: "",
                    socksListen = LOCAL_SOCKS_ADDR,
                ),
                binaryPath = hysteriaBinaryPath,
                workingDir = File(filesDir, WORKING_DIR_NAME),
                protector = { fd -> protect(fd) },
            )
            if (hysteriaResult is Hysteria2ChildResult.Failed) {
                Log.w(TAG, "hysteria child start failed: ${hysteriaResult.reason}")
                publish(sessionId, Hysteria2RuntimePhase.FAILED, Hysteria2RuntimeError.HysteriaChildFailed(hysteriaResult.reason))
                closeTunFd()
                stopSelf()
                return@launch
            }

            val dupFd = ParcelFileDescriptor.dup(established.fileDescriptor).detachFd()
            val controlSocketPath = File(filesDir, TUN2SOCKS_CONTROL_SOCKET_FILENAME)
            val tun2socksResult = tun2socksRuntime.start(dupFd, MTU, LOCAL_SOCKS_ADDR, tun2socksBinaryPath, controlSocketPath)
            when (tun2socksResult) {
                is Hysteria2Tun2SocksChildResult.Ok -> {
                    sessionActive = true
                    Log.i(TAG, "hysteria2 session started: tun2socksPid=${tun2socksResult.pid} quicConnected=${hysteriaRuntime.quicConnected}")
                    publish(sessionId, Hysteria2RuntimePhase.RUNNING)
                }
                is Hysteria2Tun2SocksChildResult.Failed -> {
                    Log.w(TAG, "tun2socks child start failed: ${tun2socksResult.reason}")
                    publish(sessionId, Hysteria2RuntimePhase.FAILED, Hysteria2RuntimeError.Tun2SocksChildFailed(tun2socksResult.reason))
                    hysteriaRuntime.stop()
                    closeTunFd()
                    stopSelf()
                }
            }
        }
    }

    @SuppressLint("VpnServicePolicy")
    private fun establishInterface(): ParcelFileDescriptor? {
        val builder = Builder()
            .setMtu(MTU)
            .addAddress(TUN_ADDRESS, TUN_PREFIX_LENGTH)
            .setSession(SESSION_NAME)
            .setBlocking(false)
        VpnDnsPolicy.servers.forEach { builder.addDnsServer(it) }
        // Full-tunnel IPv4 route via the same RoutingDecisionEngine authority
        // every other transport already uses (never a parallel routing
        // decision system). No IPv6 route/address (fail closed - see
        // TransportCapabilities.hysteria2AdapterShell().supportsIpv6).
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

    /** Either child dying unexpectedly tears down the WHOLE session - never a half-alive state (unchanged from B46-3C's own proven rule). */
    private fun handleUnexpectedExit(which: String, exitCode: Int) {
        Log.w(TAG, "$which child exited unexpectedly: code=$exitCode - tearing down the whole session")
        sessionActive = false
        tun2socksRuntime.stop()
        hysteriaRuntime.stop()
        closeTunFd()
        publish(activeSessionId, Hysteria2RuntimePhase.FAILED, Hysteria2RuntimeError.ChildDiedUnexpectedly(which, exitCode))
        stopSelf()
    }

    private suspend fun teardown() {
        if (!sessionActive && tunFd == null) {
            publish(activeSessionId, Hysteria2RuntimePhase.STOPPED)
            stopSelf()
            return
        }
        publish(activeSessionId, Hysteria2RuntimePhase.STOPPING)
        sessionActive = false
        tun2socksRuntime.stop()
        hysteriaRuntime.stop()
        closeTunFd()
        publish(activeSessionId, Hysteria2RuntimePhase.STOPPED)
        stopSelf()
    }

    private fun closeTunFd() {
        runCatching { tunFd?.close() }
        tunFd = null
    }

    private fun publish(sessionId: Long, phase: Hysteria2RuntimePhase, error: Hysteria2RuntimeError? = null) {
        _status.value = Hysteria2ServiceStatus(sessionId, phase, error)
    }

    companion object {
        const val ACTION_START = "net.pocvpn.client.vpn.hysteria.action.START"
        const val ACTION_STOP = "net.pocvpn.client.vpn.hysteria.action.STOP"
        const val EXTRA_SESSION_ID = "net.pocvpn.client.vpn.hysteria.extra.SESSION_ID"
        const val EXTRA_ENDPOINT_ID = "net.pocvpn.client.vpn.hysteria.extra.ENDPOINT_ID"
        const val EXTRA_HOST = "net.pocvpn.client.vpn.hysteria.extra.HOST"
        const val EXTRA_PORT = "net.pocvpn.client.vpn.hysteria.extra.PORT"
        // PUBLIC signed facts only - see TransportConfig.Hysteria2's own doc.
        // Deliberately NO EXTRA_AUTH / EXTRA_OBFS_PASSWORD / any secret extra
        // (correcting B46-3C's own debug-spike Intent-based auth pattern).
        const val EXTRA_SNI = "net.pocvpn.client.vpn.hysteria.extra.SNI"
        const val EXTRA_OBFUSCATION_MODE = "net.pocvpn.client.vpn.hysteria.extra.OBFUSCATION_MODE"
        const val EXTRA_ROUTING_MODE = "net.pocvpn.client.vpn.hysteria.extra.ROUTING_MODE"

        private val _status = MutableStateFlow<Hysteria2ServiceStatus?>(null)

        /** Observed by [Hysteria2Transport] - process-wide, since only one instance may exist at a time (mirrors `ShadowsocksVpnService.status`). */
        internal val status: StateFlow<Hysteria2ServiceStatus?> = _status.asStateFlow()
    }
}
