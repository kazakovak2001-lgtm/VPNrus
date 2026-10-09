package net.pocvpn.client.vpn.xray

import android.app.ActivityManager
import android.app.Application
import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.ServiceConnection
import android.os.Build
import android.os.IBinder
import android.util.Log
import androidx.core.content.ContextCompat
import net.pocvpn.client.transport.TransportStats
import net.pocvpn.client.vpn.TransportFailureKind
import java.io.File

/**
 * Xray runs in its own process (`:xray`, see AndroidManifest). Two Go
 * runtimes - AmneziaWG's libwg-go and Xray's libgojni - in one process crash
 * it (`E/Go: SIGSEGV`, ApplicationExitInfo EXIT_SELF status=2), reproduced
 * 3/3 by the field test whenever an Xray session followed an AWG session
 * in the same process. One Go runtime per process removes the conflict.
 *
 * This bridge carries the ONLY state the service shared in memory with the
 * main process:
 *  - [XrayRuntimeEvent]s (service -> main): an app-private broadcast
 *    (setPackage + RECEIVER_NOT_EXPORTED), re-published into the main
 *    process' [XrayRuntimeState] so the transports keep observing exactly
 *    the StateFlow they always did. Events carry no secret.
 *  - process death (main learns when `:xray` dies mid-session): a
 *    zero-flag bind + linkToDeath while a session is Started, turned into a
 *    [XrayRuntimeEvent.Failed] - before, the whole app died with it.
 *  - B-WL7 tunnel byte totals (main asks, service answers): two counts
 *    and a session id, see [queryTrafficCounters].
 *  - an orphaned `:xray` tunnel (main process died, Xray kept running) is
 *    stopped when a new main process starts, so the app never shows
 *    Disconnected over a live tunnel it no longer controls.
 * XHTTP configs (they contain the VLESS uuid) never cross Intent/Binder:
 * see [XhttpSessionConfigStore]'s encrypted file handoff.
 */
object XrayProcessBridge {
    const val ACTION_RUNTIME_EVENT = "net.pocvpn.client.vpn.xray.action.RUNTIME_EVENT"
    const val ACTION_WATCH = "net.pocvpn.client.vpn.xray.action.WATCH"
    const val PROCESS_SUFFIX = ":xray"
    const val ACTION_MEASURE = "net.pocvpn.client.vpn.xray.action.MEASURE"
    const val ACTION_MEASURE_RESULT = "net.pocvpn.client.vpn.xray.action.MEASURE_RESULT"
    const val ACTION_QUERY_TRAFFIC = "net.pocvpn.client.vpn.xray.action.QUERY_TRAFFIC"
    const val ACTION_TRAFFIC_RESULT = "net.pocvpn.client.vpn.xray.action.TRAFFIC_RESULT"
    const val EXTRA_REQUEST_ID = "requestId"
    const val EXTRA_URLS = "urls"
    private const val EXTRA_DELAYS = "delays"
    private const val EXTRA_ERRORS = "errors"
    private const val EXTRA_TRAFFIC_SESSION_ID = "trafficSessionId"
    private const val EXTRA_UPLINK = "uplinkBytes"
    private const val EXTRA_DOWNLINK = "downlinkBytes"

    private const val EXTRA_TYPE = "type"
    private const val EXTRA_SESSION_ID = "sessionId"
    private const val EXTRA_REASON = "reason"
    private const val EXTRA_FAILURE_KIND = "failureKind"
    private const val TAG = "XrayProcessBridge"

    // --- event codec (pure) ---------------------------------------------------

    internal data class Encoded(val type: String, val sessionId: Long, val reason: String?, val failureKind: String?)

    internal fun encode(event: XrayRuntimeEvent): Encoded = when (event) {
        is XrayRuntimeEvent.Started -> Encoded("started", event.sessionId, null, null)
        is XrayRuntimeEvent.Stopped -> Encoded("stopped", event.sessionId, null, null)
        is XrayRuntimeEvent.Failed -> Encoded("failed", event.sessionId, event.reason, event.failureKind?.name)
    }

    internal fun decode(encoded: Encoded): XrayRuntimeEvent? = when (encoded.type) {
        "started" -> XrayRuntimeEvent.Started(encoded.sessionId)
        "stopped" -> XrayRuntimeEvent.Stopped(encoded.sessionId)
        "failed" -> XrayRuntimeEvent.Failed(
            encoded.sessionId,
            encoded.reason ?: "unknown",
            encoded.failureKind?.let { name -> TransportFailureKind.entries.firstOrNull { it.name == name } },
        )
        else -> null
    }

    // --- service side -----------------------------------------------------------

    /** Called by NovaXrayVpnService instead of XrayRuntimeState.publish. */
    fun publishFromService(context: Context, event: XrayRuntimeEvent) {
        XrayRuntimeState.publish(event)
        val e = encode(event)
        val intent = Intent(ACTION_RUNTIME_EVENT)
            .setPackage(context.packageName)
            .putExtra(EXTRA_TYPE, e.type)
            .putExtra(EXTRA_SESSION_ID, e.sessionId)
            .putExtra(EXTRA_REASON, e.reason)
            .putExtra(EXTRA_FAILURE_KIND, e.failureKind)
        context.sendBroadcast(intent, dynamicReceiverPermission(context))
    }

    /** Service side of [measureThroughCore]. */
    fun publishMeasureResult(context: Context, requestId: Long, urls: Array<String>, results: List<Pair<Long, String?>>) {
        val intent = Intent(ACTION_MEASURE_RESULT)
            .setPackage(context.packageName)
            .putExtra(EXTRA_REQUEST_ID, requestId)
            .putExtra(EXTRA_URLS, urls)
            .putExtra(EXTRA_DELAYS, results.map { it.first }.toLongArray())
            .putExtra(EXTRA_ERRORS, results.map { it.second ?: "" }.toTypedArray())
        context.sendBroadcast(intent, dynamicReceiverPermission(context))
    }

    /** One URL measured by the running Xray core through its own tunnel. */
    data class CoreMeasurement(val url: String, val delayMs: Long, val error: String?) {
        val ok: Boolean get() = delayMs >= 0 && error == null
    }

    private val measureRequests = java.util.concurrent.atomic.AtomicLong(System.nanoTime())

    /**
     * Main process: ask the `:xray` process to run Xray's own measureDelay
     * for each URL through the live tunnel. Null when no answer arrives
     * within [timeoutMs] (service not running / process gone).
     */
    suspend fun measureThroughCore(context: Context, urls: List<String>, timeoutMs: Long = 45_000): List<CoreMeasurement>? {
        val app = context.applicationContext
        val requestId = measureRequests.incrementAndGet()
        val result = kotlinx.coroutines.CompletableDeferred<List<CoreMeasurement>>()
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(c: Context, intent: Intent) {
                if (intent.getLongExtra(EXTRA_REQUEST_ID, -1) != requestId) return
                val u = intent.getStringArrayExtra(EXTRA_URLS).orEmpty()
                val d = intent.getLongArrayExtra(EXTRA_DELAYS) ?: LongArray(0)
                val e = intent.getStringArrayExtra(EXTRA_ERRORS).orEmpty()
                result.complete(u.indices.map { i -> CoreMeasurement(u[i], d.getOrElse(i) { -1 }, e.getOrNull(i)?.ifBlank { null }) })
            }
        }
        ContextCompat.registerReceiver(app, receiver, IntentFilter(ACTION_MEASURE_RESULT), ContextCompat.RECEIVER_NOT_EXPORTED)
        return try {
            app.startService(
                Intent(app, NovaXrayVpnService::class.java)
                    .setAction(ACTION_MEASURE)
                    .putExtra(EXTRA_REQUEST_ID, requestId)
                    .putExtra(EXTRA_URLS, urls.toTypedArray()),
            )
            kotlinx.coroutines.withTimeoutOrNull(timeoutMs) { result.await() }
        } catch (e: IllegalStateException) {
            null
        } finally {
            app.unregisterReceiver(receiver)
        }
    }

    /** Service side of [queryTrafficCounters]; [totals] null = core not running / no reading. */
    fun publishTrafficResult(context: Context, requestId: Long, totals: XrayTrafficCounters.Totals?) {
        val intent = Intent(ACTION_TRAFFIC_RESULT)
            .setPackage(context.packageName)
            .putExtra(EXTRA_REQUEST_ID, requestId)
        if (totals != null) {
            intent.putExtra(EXTRA_TRAFFIC_SESSION_ID, totals.sessionId)
                .putExtra(EXTRA_UPLINK, totals.uplinkBytes)
                .putExtra(EXTRA_DOWNLINK, totals.downlinkBytes)
        }
        context.sendBroadcast(intent, dynamicReceiverPermission(context))
    }

    /**
     * B-WL7 - main process: the `:xray` core's cumulative tunnel-outbound
     * byte totals for its current session. Null when no answer arrives
     * within [timeoutMs], the service cannot be reached (e.g. background
     * start not allowed), or the core is not running - the caller treats
     * null as "no sample", never as progress or as failure.
     */
    suspend fun queryTrafficCounters(context: Context, timeoutMs: Long = 2_000): XrayTrafficCounters.Totals? {
        val app = context.applicationContext
        val requestId = measureRequests.incrementAndGet()
        val result = kotlinx.coroutines.CompletableDeferred<XrayTrafficCounters.Totals?>()
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(c: Context, intent: Intent) {
                if (intent.getLongExtra(EXTRA_REQUEST_ID, -1) != requestId) return
                result.complete(
                    if (intent.hasExtra(EXTRA_TRAFFIC_SESSION_ID)) {
                        XrayTrafficCounters.Totals(
                            intent.getLongExtra(EXTRA_TRAFFIC_SESSION_ID, 0L),
                            intent.getLongExtra(EXTRA_UPLINK, 0L),
                            intent.getLongExtra(EXTRA_DOWNLINK, 0L),
                        )
                    } else {
                        null
                    },
                )
            }
        }
        ContextCompat.registerReceiver(app, receiver, IntentFilter(ACTION_TRAFFIC_RESULT), ContextCompat.RECEIVER_NOT_EXPORTED)
        return try {
            app.startService(
                Intent(app, NovaXrayVpnService::class.java)
                    .setAction(ACTION_QUERY_TRAFFIC)
                    .putExtra(EXTRA_REQUEST_ID, requestId),
            )
            kotlinx.coroutines.withTimeoutOrNull(timeoutMs) { result.await() }
        } catch (e: IllegalStateException) {
            null
        } catch (e: SecurityException) {
            null
        } finally {
            app.unregisterReceiver(receiver)
        }
    }

    /**
     * B-WL7 - maps one [queryTrafficCounters] answer onto [TransportStats] for
     * the transport that owns [sessionId]: uplink = sent, downlink =
     * received. Unavailable (never Unsupported, so the bounded sampler keeps
     * polling) when there is no answer or it belongs to another session.
     */
    internal suspend fun dataPlaneStats(context: Context, sessionId: Long?): TransportStats {
        // Only ask while this process' mirror says THIS session is Started:
        // a startService() to a stopped `:xray` would otherwise spawn an idle
        // service just to answer "not running".
        val current = XrayRuntimeState.events.value
        if (sessionId == null || current !is XrayRuntimeEvent.Started || current.sessionId != sessionId) return TransportStats.Unavailable
        return dataPlaneStatsFor(sessionId, queryTrafficCounters(context))
    }

    internal fun dataPlaneStatsFor(sessionId: Long?, totals: XrayTrafficCounters.Totals?): TransportStats =
        if (sessionId == null || totals == null || totals.sessionId != sessionId) {
            TransportStats.Unavailable
        } else {
            TransportStats.Counters(bytesReceived = totals.downlinkBytes, bytesSent = totals.uplinkBytes, lastHandshakeEpochMillis = null)
        }

    // --- main process side --------------------------------------------------------

    @Volatile private var installed = false
    private var watcher: XrayProcessWatcher? = null

    /** Main process only (NovaVpnApplication). Idempotent. */
    fun installMainProcess(context: Context) {
        if (installed) return
        installed = true
        val app = context.applicationContext
        val w = XrayProcessWatcher(app)
        watcher = w
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(c: Context, intent: Intent) {
                val event = decode(
                    Encoded(
                        intent.getStringExtra(EXTRA_TYPE) ?: return,
                        intent.getLongExtra(EXTRA_SESSION_ID, 0L),
                        intent.getStringExtra(EXTRA_REASON),
                        intent.getStringExtra(EXTRA_FAILURE_KIND),
                    ),
                ) ?: return
                XrayRuntimeState.publish(event)
                w.onEvent(event)
            }
        }
        ContextCompat.registerReceiver(app, receiver, IntentFilter(ACTION_RUNTIME_EVENT), ContextCompat.RECEIVER_NOT_EXPORTED)
        stopOrphanedXrayProcess(app)
    }

    private fun stopOrphanedXrayProcess(context: Context) {
        val am = context.getSystemService(ActivityManager::class.java) ?: return
        val orphan = am.runningAppProcesses.orEmpty().any { it.processName == context.packageName + PROCESS_SUFFIX }
        if (!orphan) return
        Log.w(TAG, "found an Xray process from a previous app process - stopping its tunnel")
        try {
            context.startService(Intent(context, NovaXrayVpnService::class.java).setAction(NovaXrayVpnService.ACTION_STOP))
        } catch (e: IllegalStateException) {
            // background start not allowed right now; the next connect() replaces the session anyway
            Log.w(TAG, "could not stop orphaned Xray process: ${e.javaClass.simpleName}")
        }
    }

    fun isXrayProcess(context: Context): Boolean = currentProcessName(context)?.endsWith(PROCESS_SUFFIX) == true

    private fun currentProcessName(context: Context): String? =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            Application.getProcessName()
        } else {
            try {
                File("/proc/self/cmdline").readText().trimEnd('\u0000')
            } catch (e: Exception) {
                null
            }
        }

    /** The signature-level permission ContextCompat uses for NOT_EXPORTED receivers below API 33. */
    private fun dynamicReceiverPermission(context: Context): String? =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) null else "${context.packageName}.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION"
}

/**
 * Main-process watch on the `:xray` process for the CURRENT Started session.
 * A zero-flag bind never creates or restarts the service; it only gives us
 * the service's binder, whose death means the Xray process died.
 */
internal class XrayProcessWatcher(private val context: Context) : ServiceConnection {
    @Volatile private var watchedSession: Long? = null
    @Volatile private var bound = false
    private var binder: IBinder? = null
    private val handler = android.os.Handler(android.os.Looper.getMainLooper())
    private val deathRecipient = IBinder.DeathRecipient { processDied() }

    fun onEvent(event: XrayRuntimeEvent) {
        when (event) {
            is XrayRuntimeEvent.Started -> watch(event.sessionId)
            is XrayRuntimeEvent.Stopped, is XrayRuntimeEvent.Failed -> unwatch()
        }
    }

    @Synchronized
    private fun watch(sessionId: Long) {
        unwatch()
        watchedSession = sessionId
        bound = try {
            context.bindService(Intent(context, NovaXrayVpnService::class.java).setAction(XrayProcessBridge.ACTION_WATCH), this, 0)
        } catch (e: SecurityException) {
            false
        }
    }

    @Synchronized
    private fun unwatch() {
        watchedSession = null
        binder?.let { b -> try { b.unlinkToDeath(deathRecipient, 0) } catch (e: java.util.NoSuchElementException) {} }
        binder = null
        if (bound) {
            bound = false
            try { context.unbindService(this) } catch (e: IllegalArgumentException) {}
        }
    }

    @Synchronized
    override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
        binder = service
        try {
            service?.linkToDeath(deathRecipient, 0)
        } catch (e: android.os.RemoteException) {
            processDied()
        }
    }

    override fun onServiceDisconnected(name: ComponentName?) = processDied()

    /**
     * A normal stop also ends `:xray` (stopSelf, and some OEMs reap the empty
     * process at once) - possibly before its Stopped broadcast reaches us.
     * So a death only becomes Failed if, after a short grace, the session
     * is STILL Started: a real crash never sends Stopped.
     */
    @Synchronized
    private fun processDied() {
        val session = watchedSession ?: return
        unwatch()
        handler.postDelayed({
            val current = XrayRuntimeState.events.value
            if (current is XrayRuntimeEvent.Started && current.sessionId == session) {
                Log.e("XrayProcessBridge", "Xray process died during session $session")
                XrayRuntimeState.publish(XrayRuntimeEvent.Failed(session, "xray process died"))
            }
        }, DEATH_GRACE_MS)
    }

    private companion object {
        const val DEATH_GRACE_MS = 2_000L
    }
}
