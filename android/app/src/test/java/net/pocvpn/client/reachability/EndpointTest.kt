package net.pocvpn.client.reachability

import net.pocvpn.client.transport.TransportKind
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class EndpointTest {

    private fun binding(kind: TransportKind = TransportKind.AMNEZIA_WG) = EndpointTransportBinding(kind, "203.0.113.1", 51820)

    @Test
    fun `a lone endpoint may hold more than one role at once`() {
        val e = EndpointDescriptor(EndpointId("e1"), setOf(EndpointRole.GATEWAY, EndpointRole.EXIT), "eu", "acme", transports = listOf(binding()))
        assertTrue(EndpointRole.GATEWAY in e.roles)
        assertTrue(EndpointRole.EXIT in e.roles)
    }

    @Test
    fun `supports() and bindingFor() reflect the declared transport bindings only`() {
        val e = EndpointDescriptor(EndpointId("e1"), setOf(EndpointRole.GATEWAY), "eu", "acme", transports = listOf(binding(TransportKind.AMNEZIA_WG)))
        assertTrue(e.supports(TransportKind.AMNEZIA_WG))
        assertFalse(e.supports(TransportKind.TLS_TCP))
        assertEquals(TransportKind.AMNEZIA_WG, e.bindingFor(TransportKind.AMNEZIA_WG)?.kind)
    }

    @Test
    fun `malformed endpoint - no roles - is rejected`() {
        assertThrows(IllegalArgumentException::class.java) {
            EndpointDescriptor(EndpointId("e1"), emptySet(), "eu", "acme", transports = listOf(binding()))
        }
    }

    @Test
    fun `malformed endpoint - no transports - is rejected`() {
        assertThrows(IllegalArgumentException::class.java) {
            EndpointDescriptor(EndpointId("e1"), setOf(EndpointRole.GATEWAY), "eu", "acme", transports = emptyList())
        }
    }

    @Test
    fun `malformed endpoint - blank id - is rejected`() {
        assertThrows(IllegalArgumentException::class.java) { EndpointId("") }
        assertThrows(IllegalArgumentException::class.java) { EndpointId("   ") }
    }

    @Test
    fun `malformed endpoint - blank region or provider - is rejected`() {
        assertThrows(IllegalArgumentException::class.java) {
            EndpointDescriptor(EndpointId("e1"), setOf(EndpointRole.GATEWAY), "", "acme", transports = listOf(binding()))
        }
        assertThrows(IllegalArgumentException::class.java) {
            EndpointDescriptor(EndpointId("e1"), setOf(EndpointRole.GATEWAY), "eu", "", transports = listOf(binding()))
        }
    }

    @Test
    fun `malformed endpoint - invalid port - is rejected`() {
        assertThrows(IllegalArgumentException::class.java) {
            EndpointTransportBinding(TransportKind.AMNEZIA_WG, "203.0.113.1", 0)
        }
        assertThrows(IllegalArgumentException::class.java) {
            EndpointTransportBinding(TransportKind.AMNEZIA_WG, "203.0.113.1", 70000)
        }
    }

    @Test
    fun `malformed endpoint - self relay - is rejected`() {
        assertThrows(IllegalArgumentException::class.java) {
            EndpointDescriptor(EndpointId("e1"), setOf(EndpointRole.INGRESS), "eu", "acme", transports = listOf(binding()), relayTo = EndpointId("e1"))
        }
    }

    @Test
    fun `malformed endpoint - duplicate TransportKind registration - is rejected`() {
        assertThrows(IllegalArgumentException::class.java) {
            EndpointDescriptor(
                EndpointId("e1"),
                setOf(EndpointRole.GATEWAY),
                "eu",
                "acme",
                transports = listOf(binding(TransportKind.AMNEZIA_WG), binding(TransportKind.AMNEZIA_WG)),
            )
        }
    }

    @Test
    fun `negative or zero ASN is rejected`() {
        assertThrows(IllegalArgumentException::class.java) {
            EndpointDescriptor(EndpointId("e1"), setOf(EndpointRole.GATEWAY), "eu", "acme", asn = 0, transports = listOf(binding()))
        }
    }
}
