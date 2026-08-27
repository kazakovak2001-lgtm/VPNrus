package net.pocvpn.client.transport

import net.pocvpn.client.vpn.FakeVpnTransport
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class TransportRegistryTest {

    @Test
    fun `defaults registers AmneziaWG as AVAILABLE`() {
        val registry = TransportRegistry.defaults { FakeVpnTransport() }
        val descriptor = registry.descriptorFor(TransportKind.AMNEZIA_WG)
        assertNotNull(descriptor)
        assertEquals(TransportStatus.AVAILABLE, descriptor!!.status)
    }

    @Test
    fun `defaults registers XRay QUIC and TLS_TCP as NOT_IMPLEMENTED`() {
        val registry = TransportRegistry.defaults { FakeVpnTransport() }
        for (kind in listOf(TransportKind.XRAY_REALITY, TransportKind.QUIC, TransportKind.TLS_TCP)) {
            val descriptor = registry.descriptorFor(kind)
            assertNotNull("expected a descriptor for $kind", descriptor)
            assertEquals("$kind must be NOT_IMPLEMENTED", TransportStatus.NOT_IMPLEMENTED, descriptor!!.status)
        }
    }

    @Test
    fun `available() returns only AmneziaWG in the default registry`() {
        val registry = TransportRegistry.defaults { FakeVpnTransport() }
        assertEquals(listOf(TransportKind.AMNEZIA_WG), registry.available().map { it.kind })
    }

    @Test
    fun `createTransport returns null for a NOT_IMPLEMENTED transport - never a fake instance`() {
        val registry = TransportRegistry.defaults { FakeVpnTransport() }
        assertNull(registry.createTransport(TransportKind.XRAY_REALITY))
        assertNull(registry.createTransport(TransportKind.QUIC))
        assertNull(registry.createTransport(TransportKind.TLS_TCP))
    }

    @Test
    fun `createTransport returns a real instance for AmneziaWG`() {
        val registry = TransportRegistry.defaults { FakeVpnTransport() }
        val transport = registry.createTransport(TransportKind.AMNEZIA_WG)
        assertNotNull(transport)
        assertEquals(TransportKind.AMNEZIA_WG, transport!!.kind)
    }

    @Test
    fun `build rejects a duplicate registration for the same kind`() {
        val descriptor = TransportDescriptor(
            kind = TransportKind.AMNEZIA_WG,
            status = TransportStatus.AVAILABLE,
            capabilities = TransportCapabilities.amneziaWg(),
            factory = { FakeVpnTransport() },
        )
        assertThrows(IllegalArgumentException::class.java) {
            TransportRegistry.build(listOf(descriptor, descriptor))
        }
    }

    @Test
    fun `descriptor construction rejects AVAILABLE without a factory`() {
        assertThrows(IllegalArgumentException::class.java) {
            TransportDescriptor(
                kind = TransportKind.AMNEZIA_WG,
                status = TransportStatus.AVAILABLE,
                capabilities = TransportCapabilities.amneziaWg(),
                factory = null,
            )
        }
    }

    @Test
    fun `descriptor construction rejects NOT_IMPLEMENTED with a factory`() {
        assertThrows(IllegalArgumentException::class.java) {
            TransportDescriptor(
                kind = TransportKind.XRAY_REALITY,
                status = TransportStatus.NOT_IMPLEMENTED,
                capabilities = TransportCapabilities.notImplemented(),
                factory = { FakeVpnTransport() },
            )
        }
    }

    @Test
    fun `all() lists every registered kind regardless of status`() {
        val registry = TransportRegistry.defaults { FakeVpnTransport() }
        assertEquals(TransportKind.entries.toSet(), registry.all().map { it.kind }.toSet())
        assertTrue(registry.all().size == 4)
    }
}
