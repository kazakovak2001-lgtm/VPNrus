package net.pocvpn.client.vpn.traffic

import android.app.NotificationManager
import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.shadows.ShadowSystemClock
import java.time.Duration

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class VpnTrafficNotifierTest {

    private lateinit var context: Context
    private lateinit var manager: NotificationManager

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        manager = context.getSystemService(NotificationManager::class.java)
        shadowOf(manager).setNotificationsEnabled(true)
    }

    private fun newNotifier() = VpnTrafficNotifier(
        context,
        VpnTrafficNotifier.Texts("VPN connected", "Measuring speed…", "Speed not available", "VPN speed", "Live speed"),
    )

    private fun posted() = shadowOf(manager).allNotifications

    @Test
    fun `updates ONE notification in place on a low-importance channel`() {
        val notifier = newNotifier()
        notifier.show(TrafficRate.Measuring)
        notifier.show(TrafficRate.Rate(2_400_000, 180_000))
        notifier.show(TrafficRate.Rate(1_000, 0))

        assertEquals(1, posted().size)
        val n = shadowOf(manager).getNotification(VpnTrafficNotifier.NOTIFICATION_ID)
        assertEquals("↓ 1.0 kB/s  ↑ 0 B/s", n.extras.getCharSequence("android.text").toString())
        assertTrue(n.flags and android.app.Notification.FLAG_ONGOING_EVENT != 0)
        assertNotNull(n.contentIntent)
        assertNotNull(n.deleteIntent)
        val channel = manager.getNotificationChannel(VpnTrafficNotifier.CHANNEL_ID)
        assertEquals(NotificationManager.IMPORTANCE_LOW, channel.importance)
        assertEquals(VpnTrafficNotifier.TIMEOUT_MILLIS, n.timeoutAfter)
    }

    @Test
    fun `unavailable and measuring are distinct from zero`() {
        val notifier = newNotifier()
        val zero = notifier.contentText(TrafficRate.Rate(0, 0))
        assertEquals("↓ 0 B/s  ↑ 0 B/s", zero)
        assertTrue(notifier.contentText(TrafficRate.Unavailable) != zero)
        assertTrue(notifier.contentText(TrafficRate.Measuring) != zero)
        assertTrue(notifier.contentText(TrafficRate.Unavailable) != notifier.contentText(TrafficRate.Measuring))
    }

    @Test
    fun `hide removes the notification`() {
        val notifier = newNotifier()
        notifier.show(TrafficRate.Rate(1, 1))
        notifier.hide(sessionEnded = true)
        assertEquals(0, posted().size)
        notifier.release()
    }

    @Test
    fun `posts nothing when notifications are not allowed`() {
        shadowOf(manager).setNotificationsEnabled(false)
        newNotifier().show(TrafficRate.Rate(1, 1))
        assertEquals(0, posted().size)
    }

    @Test
    fun `user dismissal suppresses the indicator until the session ends`() {
        val notifier = newNotifier()
        notifier.show(TrafficRate.Rate(1, 1))
        // What the delete intent delivers when the user swipes it away.
        manager.cancel(VpnTrafficNotifier.NOTIFICATION_ID)
        context.sendBroadcast(android.content.Intent("net.pocvpn.client.action.TRAFFIC_NOTIFICATION_DISMISSED").setPackage(context.packageName))
        shadowOf(android.os.Looper.getMainLooper()).idle()

        notifier.show(TrafficRate.Rate(2, 2))
        assertEquals(0, posted().size)
        notifier.hide(sessionEnded = false) // screen off: still suppressed
        notifier.show(TrafficRate.Rate(3, 3))
        assertEquals(0, posted().size)

        notifier.hide(sessionEnded = true)
        notifier.show(TrafficRate.Rate(4, 4))
        assertEquals(1, posted().size)
        notifier.release()
    }

    @Test
    fun `unchanged text is re-posted periodically so the timeout never fires mid-session`() {
        val notifier = newNotifier()
        notifier.show(TrafficRate.Rate(0, 0))
        val first = shadowOf(manager).getNotification(VpnTrafficNotifier.NOTIFICATION_ID)
        notifier.show(TrafficRate.Rate(0, 0))
        assertTrue("identical update within the refresh window is skipped", first === shadowOf(manager).getNotification(VpnTrafficNotifier.NOTIFICATION_ID))
        ShadowSystemClock.advanceBy(Duration.ofMillis(VpnTrafficNotifier.REFRESH_MILLIS))
        notifier.show(TrafficRate.Rate(0, 0))
        assertTrue(first !== shadowOf(manager).getNotification(VpnTrafficNotifier.NOTIFICATION_ID))
        notifier.release()
    }
}
