package net.pocvpn.client.reachability

import net.pocvpn.client.network.NetworkType
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test

class NetworkFingerprinterTest {

    private val key = "a-fixed-per-install-key".toByteArray()

    @Test
    fun `the same coarse signals and key always produce the same fingerprint`() {
        val signals = CoarseNetworkSignals(NetworkType.WIFI, listOf("1.1.1.1", "8.8.8.8"))
        val a = NetworkFingerprinter.fingerprint(signals, key)
        val b = NetworkFingerprinter.fingerprint(signals, key)
        assertEquals(a, b)
    }

    @Test
    fun `fingerprint is independent of DNS server list order (still the same network)`() {
        val a = NetworkFingerprinter.fingerprint(CoarseNetworkSignals(NetworkType.WIFI, listOf("1.1.1.1", "8.8.8.8")), key)
        val b = NetworkFingerprinter.fingerprint(CoarseNetworkSignals(NetworkType.WIFI, listOf("8.8.8.8", "1.1.1.1")), key)
        assertEquals(a, b)
    }

    @Test
    fun `a different network (different resolvers) produces a different fingerprint`() {
        val a = NetworkFingerprinter.fingerprint(CoarseNetworkSignals(NetworkType.WIFI, listOf("1.1.1.1")), key)
        val b = NetworkFingerprinter.fingerprint(CoarseNetworkSignals(NetworkType.WIFI, listOf("9.9.9.9")), key)
        assertNotEquals(a, b)
    }

    @Test
    fun `a different network type alone produces a different fingerprint`() {
        val a = NetworkFingerprinter.fingerprint(CoarseNetworkSignals(NetworkType.WIFI, listOf("1.1.1.1")), key)
        val b = NetworkFingerprinter.fingerprint(CoarseNetworkSignals(NetworkType.CELLULAR, listOf("1.1.1.1")), key)
        assertNotEquals(a, b)
    }

    @Test
    fun `a duplicated resolver entry does not change the fingerprint versus the same network reported once`() {
        val a = NetworkFingerprinter.fingerprint(CoarseNetworkSignals(NetworkType.WIFI, listOf("1.1.1.1", "1.1.1.1", "8.8.8.8")), key)
        val b = NetworkFingerprinter.fingerprint(CoarseNetworkSignals(NetworkType.WIFI, listOf("1.1.1.1", "8.8.8.8")), key)
        assertEquals(a, b)
    }

    @Test
    fun `an empty resolver list still produces a stable, deterministic fingerprint`() {
        val a = NetworkFingerprinter.fingerprint(CoarseNetworkSignals(NetworkType.CELLULAR, emptyList()), key)
        val b = NetworkFingerprinter.fingerprint(CoarseNetworkSignals(NetworkType.CELLULAR, emptyList()), key)
        assertEquals(a, b)
    }

    @Test
    fun `mixed IPv4 and IPv6 resolver addresses are handled the same as any other coarse string signal`() {
        val a = NetworkFingerprinter.fingerprint(CoarseNetworkSignals(NetworkType.WIFI, listOf("1.1.1.1", "2606:4700:4700::1111")), key)
        val b = NetworkFingerprinter.fingerprint(CoarseNetworkSignals(NetworkType.WIFI, listOf("2606:4700:4700::1111", "1.1.1.1")), key)
        assertEquals(a, b)
    }

    @Test
    fun `a different per-install key produces a different fingerprint for the SAME network - not a global tracking id`() {
        val signals = CoarseNetworkSignals(NetworkType.WIFI, listOf("1.1.1.1"))
        val a = NetworkFingerprinter.fingerprint(signals, key)
        val b = NetworkFingerprinter.fingerprint(signals, "a-different-install-key".toByteArray())
        assertNotEquals(a, b)
    }

    // B13 - Section H privacy audit regression: PathHistoryStore persists
    // ONLY the derived fingerprint string - never the raw CoarseNetworkSignals
    // (dnsServerAddresses) that produced it. Proves the persisted bytes
    // structurally cannot contain the raw resolver address, not merely that
    // nobody currently writes it there.
    @Test
    fun `the persisted PathHistoryStore file never contains the raw resolver address, only the derived fingerprint`() {
        val distinctiveResolverAddress = "203.0.113.77"
        val signals = CoarseNetworkSignals(NetworkType.WIFI, listOf(distinctiveResolverAddress))
        val fingerprint = NetworkFingerprinter.fingerprint(signals, key)

        val dir = java.nio.file.Files.createTempDirectory("path-history-privacy-test").toFile()
        val store = FilePathHistoryStore(dir)
        store.record(fingerprint, EndpointId("gw"), net.pocvpn.client.transport.TransportKind.AMNEZIA_WG, success = true, nowEpochMillis = 1L)

        val bytesOnDisk = java.io.File(dir, "path_history.bin").readBytes()
        val onDiskText = String(bytesOnDisk, Charsets.ISO_8859_1)

        // The fingerprint IS expected on disk (that's the whole point of the store).
        org.junit.Assert.assertTrue(onDiskText.contains(fingerprint))
        // The raw resolver address that produced it must never appear.
        org.junit.Assert.assertFalse(onDiskText.contains(distinctiveResolverAddress))
    }
}
