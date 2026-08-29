package net.pocvpn.client.network

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B8I - narrow tests for buildNetworkProfile/RawNetworkSignals, the pure
 * core NetworkProfiler.emit() delegates to after extracting real
 * NetworkCapabilities/LinkProperties into plain booleans (see that file's
 * own docs for why the mapping is split out this way - no android.net.*
 * type is constructable in a plain JVM unit test). Covers this feature's
 * own required cases 1-4; case 5 (network loss -> unavailable) is already
 * proven directly against NetworkProfile.unavailable() by
 * NetworkProfileTest - the exact same call NetworkProfiler.onLost() makes.
 */
class NetworkProfilerCoreTest {

    private fun wifiSignals(
        validatedInternet: Boolean = true,
        notMetered: Boolean = true,
        notRoaming: Boolean = true,
        captivePortal: Boolean = false,
        hasIpv4Address: Boolean = true,
        hasIpv6Address: Boolean = false,
    ) = RawNetworkSignals(
        hasWifi = true, hasCellular = false, hasEthernet = false,
        validatedInternet = validatedInternet, notMetered = notMetered, notRoaming = notRoaming,
        captivePortal = captivePortal, hasIpv4Address = hasIpv4Address, hasIpv6Address = hasIpv6Address,
        isVpnTransport = false,
    )

    @Test
    fun `Wi-Fi capabilities produce a WIFI snapshot`() {
        val profile = buildNetworkProfile(wifiSignals(), generation = 1)
        assertEquals(NetworkType.WIFI, profile.type)
    }

    @Test
    fun `cellular capabilities produce a CELLULAR snapshot`() {
        val signals = wifiSignals().copy(hasWifi = false, hasCellular = true)
        val profile = buildNetworkProfile(signals, generation = 1)
        assertEquals(NetworkType.CELLULAR, profile.type)
    }

    @Test
    fun `ethernet capabilities produce an ETHERNET snapshot, and none of WIFI-CELLULAR-ETHERNET falls back to OTHER`() {
        val signals = wifiSignals().copy(hasWifi = false, hasEthernet = true)
        val profile = buildNetworkProfile(signals, generation = 1)
        assertEquals(NetworkType.ETHERNET, profile.type)

        val unknownTransport = wifiSignals().copy(hasWifi = false)
        assertEquals(NetworkType.OTHER, buildNetworkProfile(unknownTransport, generation = 1).type)
    }

    @Test
    fun `validated and metered flags map correctly - metered is the negation of NOT_METERED`() {
        val validatedUnmetered = buildNetworkProfile(wifiSignals(validatedInternet = true, notMetered = true), generation = 1)
        assertTrue(validatedUnmetered.validatedInternet)
        assertFalse(validatedUnmetered.metered)

        val unvalidatedMetered = buildNetworkProfile(wifiSignals(validatedInternet = false, notMetered = false), generation = 1)
        assertFalse(unvalidatedMetered.validatedInternet)
        assertTrue(unvalidatedMetered.metered)
    }

    @Test
    fun `roaming is the negation of NOT_ROAMING`() {
        val roaming = buildNetworkProfile(wifiSignals(notRoaming = false), generation = 1)
        assertEquals(true, roaming.roaming)

        val notRoaming = buildNetworkProfile(wifiSignals(notRoaming = true), generation = 1)
        assertEquals(false, notRoaming.roaming)
    }

    @Test
    fun `IPv4 and IPv6 availability map straight from the raw link-address signals`() {
        val dualStack = buildNetworkProfile(wifiSignals(hasIpv4Address = true, hasIpv6Address = true), generation = 1)
        assertTrue(dualStack.ipv4Available)
        assertTrue(dualStack.ipv6Available)

        val ipv4Only = buildNetworkProfile(wifiSignals(hasIpv4Address = true, hasIpv6Address = false), generation = 1)
        assertTrue(ipv4Only.ipv4Available)
        assertFalse(ipv4Only.ipv6Available)

        val ipv6Only = buildNetworkProfile(wifiSignals(hasIpv4Address = false, hasIpv6Address = true), generation = 1)
        assertFalse(ipv6Only.ipv4Available)
        assertTrue(ipv6Only.ipv6Available)
    }

    @Test
    fun `generation is forwarded verbatim, never recomputed`() {
        assertEquals(42L, buildNetworkProfile(wifiSignals(), generation = 42L).generation)
    }
}
