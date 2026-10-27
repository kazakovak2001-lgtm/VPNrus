package net.pocvpn.client.vpn.traffic

import android.annotation.SuppressLint
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.PowerManager
import android.os.SystemClock
import androidx.core.app.NotificationChannelCompat
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.flow.distinctUntilChanged
import net.pocvpn.client.MainActivity
import net.pocvpn.client.R

/**
 * Live speed indicator - ONE low-importance, silent, ongoing notification
 * (fixed id, updated in place, never one per second) showing the smoothed
 * tunnel throughput. Nova had no VPN notification before this; it is a plain
 * notification, NOT a foreground-service notification, so no VpnService
 * lifecycle or foreground-service type changes. It is a notification-shade
 * entry, not text in the status bar - Android gives third-party apps no API
 * for that (only the small icon appears there).
 *
 * - Posts nothing without notification permission (POST_NOTIFICATIONS on
 *   API 33+, or notifications blocked by the user).
 * - Unchanged text is not re-posted, except every [REFRESH_MILLIS] so the
 *   [TIMEOUT_MILLIS] auto-cancel never fires during a live session but does
 *   remove a stale entry if this process dies with the notification up.
 * - Android 14+ lets users swipe ongoing notifications away; the delete
 *   intent then suppresses the indicator until the Connected period ends.
 *
 * Main thread only (the indicator runs on viewModelScope).
 */
class VpnTrafficNotifier(
    context: Context,
    private val texts: Texts = Texts.from(context),
) : VpnTrafficIndicatorSink {
    /** User-visible strings, resolved once (a seam for JVM tests, which have no app resources). */
    data class Texts(
        val title: String,
        val measuring: String,
        val unavailable: String,
        val channelName: String,
        val channelDescription: String,
    ) {
        companion object {
            fun from(context: Context) = Texts(
                title = context.getString(R.string.traffic_notification_title),
                measuring = context.getString(R.string.traffic_notification_measuring),
                unavailable = context.getString(R.string.traffic_notification_unavailable),
                channelName = context.getString(R.string.traffic_notification_channel_name),
                channelDescription = context.getString(R.string.traffic_notification_channel_description),
            )
        }
    }

    private val app = context.applicationContext
    private val manager = NotificationManagerCompat.from(app)
    private var channelCreated = false
    private var receiverRegistered = false
    private var lastText: String? = null
    private var lastPostedAt = 0L
    @Volatile private var dismissedThisSession = false

    private val dismissReceiver = object : BroadcastReceiver() {
        override fun onReceive(c: Context, intent: Intent) {
            dismissedThisSession = true
            lastText = null
        }
    }

    @SuppressLint("MissingPermission") // areNotificationsEnabled() covers POST_NOTIFICATIONS on API 33+
    override fun show(rate: TrafficRate) {
        if (dismissedThisSession || !manager.areNotificationsEnabled()) return
        val text = contentText(rate)
        val now = SystemClock.elapsedRealtime()
        if (text == lastText && now - lastPostedAt < REFRESH_MILLIS) return
        ensureChannel()
        ensureDismissReceiver()
        try {
            manager.notify(NOTIFICATION_ID, build(text))
            lastText = text
            lastPostedAt = now
        } catch (e: SecurityException) {
            lastText = null
        }
    }

    override fun hide(sessionEnded: Boolean) {
        manager.cancel(NOTIFICATION_ID)
        lastText = null
        if (sessionEnded) dismissedThisSession = false
    }

    override fun release() {
        if (!receiverRegistered) return
        receiverRegistered = false
        try { app.unregisterReceiver(dismissReceiver) } catch (e: IllegalArgumentException) { }
    }

    internal fun contentText(rate: TrafficRate): String = when (rate) {
        is TrafficRate.Rate -> TrafficRateFormat.line(rate)
        TrafficRate.Measuring -> texts.measuring
        TrafficRate.Unavailable -> texts.unavailable
    }

    private fun build(text: String) = NotificationCompat.Builder(app, CHANNEL_ID)
        .setSmallIcon(R.drawable.ic_stat_vpn_traffic)
        .setContentTitle(texts.title)
        .setContentText(text)
        .setCategory(NotificationCompat.CATEGORY_STATUS)
        .setPriority(NotificationCompat.PRIORITY_LOW)
        .setOngoing(true)
        .setOnlyAlertOnce(true)
        .setSilent(true)
        .setShowWhen(false)
        .setLocalOnly(true)
        .setTimeoutAfter(TIMEOUT_MILLIS)
        .setContentIntent(openAppIntent())
        .setDeleteIntent(
            PendingIntent.getBroadcast(app, 0, Intent(ACTION_DISMISSED).setPackage(app.packageName), PendingIntent.FLAG_IMMUTABLE),
        )
        .build()

    // Same shape as a launcher tap: brings the existing task forward, never a second Activity.
    private fun openAppIntent(): PendingIntent = PendingIntent.getActivity(
        app,
        0,
        Intent(app, MainActivity::class.java)
            .setAction(Intent.ACTION_MAIN)
            .addCategory(Intent.CATEGORY_LAUNCHER)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
        PendingIntent.FLAG_IMMUTABLE,
    )

    private fun ensureChannel() {
        if (channelCreated) return
        manager.createNotificationChannel(
            NotificationChannelCompat.Builder(CHANNEL_ID, NotificationManagerCompat.IMPORTANCE_LOW)
                .setName(texts.channelName)
                .setDescription(texts.channelDescription)
                .setShowBadge(false)
                .build(),
        )
        channelCreated = true
    }

    private fun ensureDismissReceiver() {
        if (receiverRegistered) return
        ContextCompat.registerReceiver(app, dismissReceiver, IntentFilter(ACTION_DISMISSED), ContextCompat.RECEIVER_NOT_EXPORTED)
        receiverRegistered = true
    }

    companion object {
        const val CHANNEL_ID = "vpn_traffic_speed"
        const val NOTIFICATION_ID = 0x5EED
        internal const val REFRESH_MILLIS = 5_000L
        internal const val TIMEOUT_MILLIS = 15_000L
        private const val ACTION_DISMISSED = "net.pocvpn.client.action.TRAFFIC_NOTIFICATION_DISMISSED"
    }
}

/** Screen on/off as a Flow, so [VpnTrafficIndicator] does not sample (or post) while nobody can see it. */
fun screenInteractiveFlow(context: Context): Flow<Boolean> = callbackFlow {
    val app = context.applicationContext
    val receiver = object : BroadcastReceiver() {
        override fun onReceive(c: Context, intent: Intent) {
            trySend(intent.action == Intent.ACTION_SCREEN_ON)
        }
    }
    ContextCompat.registerReceiver(
        app,
        receiver,
        IntentFilter().apply {
            addAction(Intent.ACTION_SCREEN_ON)
            addAction(Intent.ACTION_SCREEN_OFF)
        },
        ContextCompat.RECEIVER_NOT_EXPORTED,
    )
    trySend(app.getSystemService(PowerManager::class.java)?.isInteractive ?: true)
    awaitClose { app.unregisterReceiver(receiver) }
}.distinctUntilChanged()
