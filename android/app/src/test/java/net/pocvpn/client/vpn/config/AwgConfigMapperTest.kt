package net.pocvpn.client.vpn.config

import org.amnezia.awg.crypto.KeyPair
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AwgConfigMapperTest {

    private fun sampleConfig(profile: AwgProfile): AwgConfig {
        val clientKey = KeyPair()
        val serverKey = KeyPair()
        return AwgConfig(
            privateKeyBase64 = clientKey.privateKey.toBase64(),
            localAddresses = listOf("10.8.0.2/32"),
            dnsServers = listOf("10.8.0.1"),
            profile = profile,
            peer = AwgPeer(
                publicKeyBase64 = serverKey.publicKey.toBase64(),
                endpointHost = "203.0.113.10",
                endpointPort = 51820,
            ),
        )
    }

    @Test
    fun `maps interface, address, dns and peer fields`() {
        val backendConfig = AwgConfigMapper.toBackendConfig(sampleConfig(AwgProfile.none()))
        val ifaceString = backendConfig.getInterface().toAwgQuickString()

        assertTrue(ifaceString.contains("Address = 10.8.0.2/32"))
        assertTrue(ifaceString.contains("DNS = 10.8.0.1"))
        assertEquals(1, backendConfig.getPeers().size)
        val peerString = backendConfig.getPeers()[0].toAwgQuickString()
        assertTrue(peerString.contains("Endpoint = 203.0.113.10:51820"))
    }

    @Test
    fun `maps AWG obfuscation profile fields onto the interface`() {
        val profile = AwgProfile(
            junkPacketCount = 4,
            junkPacketMinSize = 40,
            junkPacketMaxSize = 100,
            initPacketJunkSize = 15,
            responsePacketJunkSize = 12,
            initPacketMagicHeader = "1",
            responsePacketMagicHeader = "2",
            underloadPacketMagicHeader = "3",
            transportPacketMagicHeader = "4",
            specialJunkI1 = "<b 0xabcd>",
            randomTrailers = true,
            disableCookies = false,
        )

        val backendConfig = AwgConfigMapper.toBackendConfig(sampleConfig(profile))
        val ifaceString = backendConfig.getInterface().toAwgQuickString()

        assertTrue(ifaceString.contains("Jc = 4"))
        assertTrue(ifaceString.contains("Jmin = 40"))
        assertTrue(ifaceString.contains("Jmax = 100"))
        assertTrue(ifaceString.contains("S1 = 15"))
        assertTrue(ifaceString.contains("S2 = 12"))
        assertTrue(ifaceString.contains("H1 = 1"))
        assertTrue(ifaceString.contains("H4 = 4"))
        assertTrue(ifaceString.contains("I1 = <b 0xabcd>"))
        assertTrue(ifaceString.contains("RandomTrailers = on"))
        // disableCookies=false must not silently render as absent-vs-off ambiguity: absent when null,
        // but here it's explicitly false so it should be present and off.
        assertFalse(ifaceString.contains("DisableCookies = on"))
    }

    @Test
    fun `does not throw for the plain no-obfuscation profile`() {
        // Diagnostic baseline: mapper must not require any AWG-specific field to build a valid config.
        AwgConfigMapper.toBackendConfig(sampleConfig(AwgProfile.none()))
    }
}
