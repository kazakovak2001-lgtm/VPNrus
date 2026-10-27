package net.pocvpn.client.vpn.xray

import android.os.Binder
import android.os.IBinder
import android.os.Parcel
import android.os.Process
import android.os.RemoteException

/**
 * Live speed indicator - a side-effect-free read of the `:xray` byte totals.
 *
 * [XrayProcessBridge.queryTrafficCounters] (B-WL7) asks with startService:
 * fine for one bounded post-connect check, but polled every second a read
 * racing a service-side teardown can bump the start id after the stop
 * decision (Android then ignores `stopSelf(startId)`) or re-create the
 * service after it stopped. This read instead transacts on the binder the
 * main process already holds through [XrayProcessWatcher]'s zero-flag bind
 * (never creates, restarts or starts the service, never touches start ids),
 * so it can only reach a service instance that already exists.
 *
 * Reply: int 1 + sessionId, uplink, downlink; or int 0 (core not running).
 */
internal object XrayLiveTraffic {
    const val TRANSACTION_QUERY_TRAFFIC = IBinder.FIRST_CALL_TRANSACTION

    fun writeTotals(reply: Parcel, totals: XrayTrafficCounters.Totals?) {
        if (totals == null) {
            reply.writeInt(0)
        } else {
            reply.writeInt(1)
            reply.writeLong(totals.sessionId)
            reply.writeLong(totals.uplinkBytes)
            reply.writeLong(totals.downlinkBytes)
        }
    }

    fun readTotals(reply: Parcel): XrayTrafficCounters.Totals? =
        if (reply.readInt() != 1) null else XrayTrafficCounters.Totals(reply.readLong(), reply.readLong(), reply.readLong())

    /** Blocking binder call - run off the main thread. Null on any failure (dead or foreign binder). */
    fun query(binder: IBinder): XrayTrafficCounters.Totals? {
        val data = Parcel.obtain()
        val reply = Parcel.obtain()
        return try {
            if (binder.transact(TRANSACTION_QUERY_TRAFFIC, data, reply, 0)) readTotals(reply) else null
        } catch (e: RemoteException) {
            null
        } catch (e: RuntimeException) {
            null
        } finally {
            data.recycle()
            reply.recycle()
        }
    }
}

/**
 * Service side: [NovaXrayVpnService]'s ACTION_WATCH binder (the one the
 * death watch links to) also answers [XrayLiveTraffic.TRANSACTION_QUERY_TRAFFIC],
 * for this app's own uid only. [readTotals] is the SAME fold the
 * ACTION_QUERY_TRAFFIC path uses, so both readers see one set of totals.
 */
internal class XrayLiveTrafficBinder(private val readTotals: () -> XrayTrafficCounters.Totals?) : Binder() {
    override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean {
        if (code != XrayLiveTraffic.TRANSACTION_QUERY_TRAFFIC) return super.onTransact(code, data, reply, flags)
        if (reply == null || Binder.getCallingUid() != Process.myUid()) return false
        XrayLiveTraffic.writeTotals(reply, readTotals())
        return true
    }
}
