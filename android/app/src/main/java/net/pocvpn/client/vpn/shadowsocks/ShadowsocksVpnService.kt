package net.pocvpn.client.vpn.shadowsocks

import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.File
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
import net.pocvpn.client.smartconnect.ProductionGateway
import net.pocvpn.client.smartconnect.RestrictionClass
import net.pocvpn.client.smartconnect.RoutingDecisionEngine
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

    /** Test seam - same contract as NovaXrayVpnService.profileRepositoryFactory. */
    internal var credentialRepositoryFactory: (Context, EndpointId) -> Shadowsocks2022CredentialRepository = { context, endpointId ->
        Shadowsocks2022CredentialRepositoryFactory.create(context, endpointId)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                teardown()
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
                val routingMode = intent.getStringExtra(EXTRA_ROUTING_MODE)
                    ?.let { runCatching { RoutingMode.valueOf(it) }.getOrNull() }
                    ?: RoutingMode.FULL_VPN

                if (host.isNullOrBlank() || port !in 1..65535) {
                    Log.e(TAG, "refusing to start: missing/invalid host or port")
                    publish(sessionId, ShadowsocksRuntimePhase.FAILED)
                    stopSelf()
                    return START_NOT_STICKY
                }
                startIfNotAlreadyRunning(sessionId, endpointId, host, port, routingMode)
                return START_NOT_STICKY
            }
            else -> return START_NOT_STICKY
        }
    }

    override fun onRevoke() {
        teardown()
    }

    override fun onDestroy() {
        teardown()
        serviceScope.cancel()
        super.onDestroy()
    }

    private fun startIfNotAlreadyRunning(sessionId: Long, endpointId: EndpointId, host: String, port: Int, routingMode: RoutingMode) {
        if (runtime?.status?.value?.phase == ShadowsocksRuntimePhase.RUNNING) {
            Log.w(TAG, "already running - ignoring duplicate start")
            return
        }

        serviceScope.launch {
            // Credential absent/corrupted -> fail closed (Phase 7/16) -
            // never a silently-empty/default key reaching sslocal.
            val repository = credentialRepositoryFactory(applicationContext, endpointId)
            val credential = when (val result = repository.getCredential()) {
                is Shadowsocks2022CredentialGetResult.Absent -> {
                    Log.e(TAG, "refusing to start: no credential for endpoint")
                    publish(sessionId, ShadowsocksRuntimePhase.FAILED, ShadowsocksRuntimeError.CredentialAbsent(endpointId.value))
                    stopSelf()
                    return@launch
                }
                is Shadowsocks2022CredentialGetResult.Corrupted -> {
                    Log.e(TAG, "refusing to start: credential corrupted")
                    publish(sessionId, ShadowsocksRuntimePhase.FAILED, ShadowsocksRuntimeError.CredentialCorrupted(result.reason))
                    stopSelf()
                    return@launch
                }
                is Shadowsocks2022CredentialGetResult.Present -> result.credential
            }

            val resolution = ShadowsocksNativeBinaryResolver.resolve(applicationInfo.nativeLibraryDir)
            val binaryPath = when (resolution) {
                is ShadowsocksNativeBinaryResolver.Result.Found -> resolution.file
                is ShadowsocksNativeBinaryResolver.Result.Missing -> {
                    Log.e(TAG, "refusing to start: binary unavailable: ${resolution.reason}")
                    publish(sessionId, ShadowsocksRuntimePhase.FAILED, ShadowsocksRuntimeError.BinaryMissing(resolution.reason))
                    stopSelf()
                    return@launch
                }
            }

            val established = establishInterface()
            if (established == null) {
                Log.e(TAG, "refusing to start: VpnService.Builder.establish() returned null")
                publish(sessionId, ShadowsocksRuntimePhase.FAILED, ShadowsocksRuntimeError.TunEstablishFailed("establish() returned null"))
                stopSelf()
                return@launch
            }
            tunInterface = established

            val newRuntime = ShadowsocksRuntime(
                launcher = RealShadowsocksProcessLauncher(),
                tunFdBridge = RealShadowsocksTunFdBridge(),
                protectBridge = RealShadowsocksVpnProtectBridge(),
                protector = ShadowsocksVpnProtector { fd -> protect(fd) },
                scope = serviceScope,
            )
            runtime = newRuntime

            statusCollectionJob = serviceScope.launch collector@{
                newRuntime.status.collect { status ->
                    publish(sessionId, status.phase, status.lastError)
                    if (status.phase == ShadowsocksRuntimePhase.FAILED) {
                        runtime = null
                        runCatching { tunInterface?.close() }
                        tunInterface = null
                        statusCollectionJob = null
                        this@collector.cancel()
                        stopSelf()
                    }
                }
            }

            val started = newRuntime.start(
                binaryPath = binaryPath.absolutePath,
                tunFd = established.fd,
                workingDir = File(filesDir, WORKING_DIR_NAME),
                tunInterfaceAddressCidr = ShadowsocksTunConfig.CIDR,
                target = ShadowsocksRuntimeTarget(host, port, credential.method, credential.key.base64),
            )
            if (!started) {
                Log.w(TAG, "ShadowsocksRuntime.start() refused (already running, or immediate failure)")
            }
        }
    }

    @SuppressLint("VpnServicePolicy")
    private fun establishInterface(): ParcelFileDescriptor? {
        val builder = Builder()
            .setMtu(ShadowsocksTunConfig.MTU)
            .addAddress(ShadowsocksTunConfig.ADDRESS, ShadowsocksTunConfig.PREFIX_LENGTH)
            .setSession(SESSION_NAME)
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

    private fun teardown() {
        statusCollectionJob?.cancel()
        statusCollectionJob = null
        runtime?.stop()
        runtime = null
        runCatching { tunInterface?.close() }
        tunInterface = null
        _status.value = null
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
