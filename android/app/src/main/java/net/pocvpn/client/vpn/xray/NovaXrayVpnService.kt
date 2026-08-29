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

/**
 * B8K1B - the first REAL Android integration for Xray/VLESS+REALITY. This is
 * an ISOLATED, debug-only test service: it is not started by
 * VpnController/TransportOrchestrator, is not reachable from Smart Connect,
 * and XRAY_REALITY stays NOT_IMPLEMENTED in TransportRegistry regardless of
 * this class existing (see docs/B8K1A_TUN_SOCKET_PATH_AUDIT.md §10/§13 for
 * why this is the smallest safe next slice, and this file's own AGENTS-style
 * invariants below).
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

    private val lifecycleGate = XrayServiceLifecycleGate()

    private var tunInterface: ParcelFileDescriptor? = null

    private val coreRuntime: XrayCoreRuntime = LibXrayCoreRuntime()

    private val supervisorJob = SupervisorJob()
    private val scope = CoroutineScope(Dispatchers.IO + supervisorJob)

    /** Overridable only for tests that construct this service directly (Robolectric-style); production always uses the real default. */
    internal var profileRepositoryFactory: (Context) -> XrayProfileRepository = { context ->
        net.pocvpn.client.identity.SecureXrayProfileRepository(
            store = net.pocvpn.client.identity.FileXrayProfileStore(context.noBackupFilesDir),
            encryptor = net.pocvpn.client.identity.AndroidKeystoreAesGcmEncryptor(KEYSTORE_ALIAS),
        )
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                teardown("explicit stop")
                return Service.START_NOT_STICKY
            }

            ACTION_START -> {
                startIfNotAlreadyRunning()
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

    override fun onDestroy() {
        teardown("service destroyed")
        supervisorJob.cancel()
        super.onDestroy()
    }

    private fun startIfNotAlreadyRunning() {
        when (lifecycleGate.tryBeginStart()) {
            XrayServiceStartDecision.IGNORE_ALREADY_RUNNING -> Log.i(TAG, "start requested while already running - ignored")
            XrayServiceStartDecision.IGNORE_START_IN_FLIGHT -> Log.i(TAG, "start requested while a start is already in flight - ignored")
            XrayServiceStartDecision.PROCEED -> scope.launch {
                var success = false
                try {
                    success = doStart()
                } finally {
                    lifecycleGate.endStart(success)
                }
            }
        }
    }

    @SuppressLint("VpnServicePolicy")
    private suspend fun doStart(): Boolean {
        val repository = profileRepositoryFactory(applicationContext)
        val profile = try {
            repository.getProfileOrNull()
        } catch (t: Throwable) {
            Log.e(TAG, "failed to load Xray profile: ${t.javaClass.simpleName}")
            stopSelf()
            return false
        }
        if (profile == null) {
            Log.w(TAG, "no Xray profile configured - refusing to start")
            stopSelf()
            return false
        }

        val config = profile.toXrayVlessRealityConfig()
        val validation = validateXrayVlessRealityConfig(config)
        if (validation is XrayConfigValidationResult.Invalid) {
            Log.e(TAG, "stored Xray profile failed validation: ${validation.errors.size} error(s)")
            stopSelf()
            return false
        }

        val plan = buildXrayVpnPlan(config, BuildConfig.APPLICATION_ID)
        val establishedInterface = try {
            establishInterface(plan)
        } catch (t: Throwable) {
            Log.e(TAG, "failed to establish VPN interface: ${t.javaClass.simpleName}")
            stopSelf()
            return false
        }
        if (establishedInterface == null) {
            Log.e(TAG, "VpnService.Builder.establish() returned null")
            stopSelf()
            return false
        }

        tunInterface = establishedInterface
        val renderedConfig = XrayConfigRenderer.render(config)

        try {
            coreRuntime.ensureCoreEnvInitialized(applicationContext)
            coreRuntime.startLoop(renderedConfig, establishedInterface.fd)
        } catch (t: Throwable) {
            Log.e(TAG, "Xray core failed to start: ${t.javaClass.simpleName}")
            closeTunInterface()
            stopSelf()
            return false
        }

        Log.i(TAG, "Xray core started")
        return true
    }

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

    private fun teardown(reason: String) {
        if (!lifecycleGate.tryBeginTeardown()) {
            Log.i(TAG, "teardown($reason) requested while not running - no-op")
            return
        }
        Log.i(TAG, "tearing down: $reason")

        try {
            coreRuntime.stopLoop()
        } catch (t: Throwable) {
            Log.e(TAG, "stopLoop failed: ${t.javaClass.simpleName}")
        }

        closeTunInterface()
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

        private const val TAG = "NovaXrayVpnService"
        private const val KEYSTORE_ALIAS = "nova_xray_profile_key"
    }
}
