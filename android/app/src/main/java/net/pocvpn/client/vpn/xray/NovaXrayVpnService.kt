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

    // B8K4C - the ONE authoritative configuration source (constraint: prefer
    // the encrypted XrayProfileRepository over Intent extras): loads the
    // CURRENT stored profile fresh on first use, resolves/validates/renders
    // it, and sequences the actual startLoop/stopLoop calls - see
    // XrayCoreController's own docs for why this is a separate, plain-JVM-
    // testable class rather than inline here. `by lazy` so
    // profileRepositoryFactory can still be swapped before first
    // ACTION_START (matches the field's own test-seam contract) and so
    // applicationContext is guaranteed attached before this reads it.
    private val controller: XrayCoreController by lazy {
        XrayCoreController(
            repository = profileRepositoryFactory(applicationContext),
            coreRuntime = coreRuntime,
            novaPackageId = BuildConfig.APPLICATION_ID,
            ensureCoreEnvInitialized = { coreRuntime.ensureCoreEnvInitialized(applicationContext) },
            establishTun = { plan -> establishInterface(plan)?.also { tunInterface = it }?.fd },
            closeTun = { closeTunInterface() },
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
        scope.launch {
            when (val outcome = controller.requestStart()) {
                is XrayCoreStartOutcome.AlreadyRunning -> Log.i(TAG, "start requested while already running - ignored")
                is XrayCoreStartOutcome.StartInFlight -> Log.i(TAG, "start requested while a start is already in flight - ignored")
                is XrayCoreStartOutcome.Rejected -> {
                    Log.w(TAG, "refusing to start: ${outcome.reason}")
                    stopSelf()
                }
                is XrayCoreStartOutcome.EstablishFailed -> {
                    Log.e(TAG, "failed to establish VPN interface: ${outcome.reason}")
                    stopSelf()
                }
                is XrayCoreStartOutcome.CoreStartFailed -> {
                    Log.e(TAG, "Xray core failed to start: ${outcome.reason}")
                    stopSelf()
                }
                is XrayCoreStartOutcome.Started -> Log.i(TAG, "Xray core started")
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

    private fun teardown(reason: String) {
        val outcome = controller.requestStop()
        if (!outcome.didTeardown) {
            Log.i(TAG, "teardown($reason) requested while not running - no-op")
            return
        }
        Log.i(TAG, "tearing down: $reason")
        outcome.stopLoopFailureReason?.let { Log.e(TAG, "stopLoop failed: $it") }
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
