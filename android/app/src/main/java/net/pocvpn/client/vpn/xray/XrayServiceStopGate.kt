package net.pocvpn.client.vpn.xray

/**
 * Decides whether work belonging to one lifecycle request may stop
 * [NovaXrayVpnService]. A bare `stopSelf()` is `stopSelf(-1)`, which Android
 * honours even when a newer `startService` was already delivered: session
 * N's failure (or N's STOP teardown) could destroy the service right after
 * ACTION_START N+1 arrived, and `onDestroy` would then tear down N+1 and
 * cancel the queue holding its start.
 *
 * Every ACTION_START / ACTION_STOP / revoke takes a new [onLifecycleRequest]
 * token. Work of that request may stop the service only while no newer
 * lifecycle request exists, and then only with `stopSelf(startId)` for the
 * newest start id seen at that moment ([stopStartIdFor]). Android stops the
 * service only when that id is still the most recent one, so a start
 * delivered after the decision keeps it alive.
 *
 * Read order matters: the start id is read BEFORE the token. A request
 * delivered before the read changes the token (skip); one delivered after it
 * carries a higher start id (Android ignores the stop).
 */
internal class XrayServiceStopGate {
    @Volatile private var lastStartId = 0
    @Volatile private var lifecycleToken = 0L

    /** Main thread, first thing in every onStartCommand (measure/traffic queries too). */
    fun onStartCommand(startId: Int) {
        lastStartId = startId
    }

    /** Main thread, for ACTION_START / ACTION_STOP / revoke, after [onStartCommand]. Returns this request's token. */
    fun onLifecycleRequest(): Long = ++lifecycleToken

    /** The start id to pass to `stopSelf(startId)`, or null when a newer lifecycle request owns the service. */
    fun stopStartIdFor(token: Long): Int? {
        val startId = lastStartId
        return if (lifecycleToken == token) startId else null
    }
}
