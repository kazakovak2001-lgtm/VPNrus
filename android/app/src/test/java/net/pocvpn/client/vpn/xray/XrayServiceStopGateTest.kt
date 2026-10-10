package net.pocvpn.client.vpn.xray

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * [XrayServiceStopGate] against a model of Android's started-service rule:
 * `stopSelf(startId)` stops the service only when [startId] is the most
 * recently delivered start id (`stopSelf()` == `stopSelf(-1)` always stops).
 * Each test drives one N / N+1 interleaving step by step.
 */
class XrayServiceStopGateTest {

    /** The framework side: delivers start ids and applies stopSelf(startId). */
    private class FakeServiceRecord(private val gate: XrayServiceStopGate) {
        private var nextStartId = 0
        var lastDeliveredStartId = 0
            private set
        var stopped = false
            private set

        fun deliverStart(): Int {
            val id = ++nextStartId
            lastDeliveredStartId = id
            gate.onStartCommand(id)
            return id
        }

        fun deliverLifecycleRequest(): Long {
            deliverStart()
            return gate.onLifecycleRequest()
        }

        fun stopSelfIfOwned(token: Long) {
            val startId = gate.stopStartIdFor(token) ?: return
            if (startId == lastDeliveredStartId) stopped = true
        }

        fun legacyStopSelf() {
            stopped = true
        }
    }

    @Test
    fun `failure of start N after START N+1 was delivered does not stop the service`() {
        val gate = XrayServiceStopGate()
        val service = FakeServiceRecord(gate)
        val startN = service.deliverLifecycleRequest()
        service.deliverLifecycleRequest() // START N+1 arrives while N is failing

        service.stopSelfIfOwned(startN)

        assertFalse(service.stopped)
    }

    @Test
    fun `the old bare stopSelf did stop it - the race this gate closes`() {
        val gate = XrayServiceStopGate()
        val service = FakeServiceRecord(gate)
        service.deliverLifecycleRequest()
        service.deliverLifecycleRequest()

        service.legacyStopSelf()

        assertTrue(service.stopped)
    }

    @Test
    fun `START N+1 delivered after the stop decision keeps the service alive`() {
        val gate = XrayServiceStopGate()
        val service = FakeServiceRecord(gate)
        val stopN = service.deliverLifecycleRequest()

        // Decision taken first (N's teardown), then START N+1 is delivered,
        // then the framework processes stopSelf(decidedId).
        val decidedId = gate.stopStartIdFor(stopN)!!
        service.deliverLifecycleRequest()
        val stops = decidedId == service.lastDeliveredStartId

        assertFalse(stops)
    }

    @Test
    fun `the last lifecycle request stops the service`() {
        val gate = XrayServiceStopGate()
        val service = FakeServiceRecord(gate)
        service.deliverLifecycleRequest() // START N
        val stopN = service.deliverLifecycleRequest()

        service.stopSelfIfOwned(stopN)

        assertTrue(service.stopped)
    }

    @Test
    fun `a measure or traffic query does not block the stop`() {
        val gate = XrayServiceStopGate()
        val service = FakeServiceRecord(gate)
        val startN = service.deliverLifecycleRequest()
        service.deliverStart() // ACTION_MEASURE / ACTION_QUERY_TRAFFIC

        service.stopSelfIfOwned(startN)

        assertTrue(service.stopped)
    }

    @Test
    fun `a stale STOP of N delivered after START N+1 owns the token but cannot outlive N+1's own work`() {
        val gate = XrayServiceStopGate()
        val service = FakeServiceRecord(gate)
        val startN1 = service.deliverLifecycleRequest()
        val staleStopN = service.deliverLifecycleRequest()

        // START N+1's own failure path no longer owns the service...
        assertNull(gate.stopStartIdFor(startN1))
        // ...and the stale STOP's token is current; the service keeps N+1
        // because a refused stale stop never calls stopSelfIfOwned (see
        // NovaXrayVpnService.teardownAndPublish, otherRunningSessionId).
        assertEquals(service.lastDeliveredStartId, gate.stopStartIdFor(staleStopN))
    }
}
