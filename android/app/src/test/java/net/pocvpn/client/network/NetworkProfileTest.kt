package net.pocvpn.client.network

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class NetworkProfileTest {

    @Test
    fun `unavailable() is truthfully NONE and not usable`() {
        val profile = NetworkProfile.unavailable(generation = 5)
        assertEquals(NetworkType.NONE, profile.type)
        assertFalse(profile.validatedInternet)
        assertFalse(profile.isUsable)
        assertEquals(5, profile.generation)
    }

    @Test
    fun `IPv4-only profile is usable and reports ipv6 unavailable`() {
        val profile = NetworkProfile(
            type = NetworkType.WIFI, validatedInternet = true, metered = false,
            roaming = false, captivePortal = false,
            ipv4Available = true, ipv6Available = false, vpnActive = false, generation = 1,
        )
        assertTrue(profile.isUsable)
        assertTrue(profile.ipv4Available)
        assertFalse(profile.ipv6Available)
    }

    @Test
    fun `IPv6-only profile is usable and reports ipv4 unavailable`() {
        val profile = NetworkProfile(
            type = NetworkType.WIFI, validatedInternet = true, metered = false,
            roaming = false, captivePortal = false,
            ipv4Available = false, ipv6Available = true, vpnActive = false, generation = 1,
        )
        assertTrue(profile.isUsable)
        assertFalse(profile.ipv4Available)
        assertTrue(profile.ipv6Available)
    }

    @Test
    fun `dual-stack profile reports both IPv4 and IPv6 available`() {
        val profile = NetworkProfile(
            type = NetworkType.WIFI, validatedInternet = true, metered = false,
            roaming = false, captivePortal = false,
            ipv4Available = true, ipv6Available = true, vpnActive = false, generation = 1,
        )
        assertTrue(profile.ipv4Available)
        assertTrue(profile.ipv6Available)
    }

    @Test
    fun `network loss produces a truthful unavailable profile, not a stale connected one`() {
        val connected = NetworkProfile(
            type = NetworkType.WIFI, validatedInternet = true, metered = false,
            roaming = false, captivePortal = false,
            ipv4Available = true, ipv6Available = false, vpnActive = false, generation = 1,
        )
        val afterLoss = NetworkProfile.unavailable(generation = connected.generation + 1)
        assertTrue(connected.isUsable)
        assertFalse(afterLoss.isUsable)
        assertEquals(NetworkType.NONE, afterLoss.type)
        assertTrue(afterLoss.generation > connected.generation)
    }

    @Test
    fun `WIFI to CELLULAR transition is a distinct, newer generation`() {
        val onWifi = NetworkProfile(
            type = NetworkType.WIFI, validatedInternet = true, metered = false,
            roaming = false, captivePortal = false,
            ipv4Available = true, ipv6Available = false, vpnActive = false, generation = 1,
        )
        val onCellular = onWifi.copy(type = NetworkType.CELLULAR, metered = true, generation = onWifi.generation + 1)
        assertEquals(NetworkType.WIFI, onWifi.type)
        assertEquals(NetworkType.CELLULAR, onCellular.type)
        assertTrue(onCellular.generation > onWifi.generation)
        assertTrue(onCellular.isUsable)
    }

    @Test
    fun `future probe signals default to Unknown, never a fabricated value`() {
        val profile = NetworkProfile.unavailable(0)
        assertEquals(ProbeSignal.Unknown, profile.udpReachability)
        assertEquals(ProbeSignal.Unknown, profile.quicReachability)
        assertEquals(ProbeSignal.Unknown, profile.tcp443Reachability)
        assertEquals(ProbeSignal.Unknown, profile.restrictiveNetworkScore)
    }

    @Test
    fun `no secret-shaped material can appear in NetworkProfile - it has no such field`() {
        val profile = NetworkProfile(
            type = NetworkType.WIFI, validatedInternet = true, metered = false,
            roaming = false, captivePortal = false,
            ipv4Available = true, ipv6Available = false, vpnActive = false, generation = 1,
        )
        val text = profile.toString()
        assertFalse(text.contains("PrivateKey", ignoreCase = true))
        assertFalse(text.contains("private_key", ignoreCase = true))
    }
}
