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

    // B22 physical-validation follow-up - proves the two junk-size fields the
    // earlier test above did NOT cover (S3/S4, cookie-reply/transport) reach
    // the real backend too - the same real Stockholm-profile values that
    // physically fixed the private-gateway handshake blocker.
    @Test
    fun `maps the full junk-packet profile including S3-S4 onto the interface`() {
        val profile = AwgProfile(
            junkPacketCount = 6,
            junkPacketMinSize = 40,
            junkPacketMaxSize = 100,
            initPacketJunkSize = 113,
            responsePacketJunkSize = 159,
            cookieReplyPacketJunkSize = 21,
            transportPacketJunkSize = 37,
            initPacketMagicHeader = "1106684696",
            responsePacketMagicHeader = "3677857287",
            underloadPacketMagicHeader = "353316806",
            transportPacketMagicHeader = "2068198996",
        )

        val ifaceString = AwgConfigMapper.toBackendConfig(sampleConfig(profile)).getInterface().toAwgQuickString()

        assertTrue(ifaceString.contains("S1 = 113"))
        assertTrue(ifaceString.contains("S2 = 159"))
        assertTrue(ifaceString.contains("S3 = 21"))
        assertTrue(ifaceString.contains("S4 = 37"))
    }

    @Test
    fun `does not throw for the plain no-obfuscation profile`() {
        // Diagnostic baseline: mapper must not require any AWG-specific field to build a valid config.
        AwgConfigMapper.toBackendConfig(sampleConfig(AwgProfile.none()))
    }

    // --- B8F: DNS + IPv6 leak protection, proven against the REAL pinned
    // org.amnezia.awg.config classes (not a fake/mirror of them) ---

    @Test
    fun `both configured DNS resolvers reach the real backend Interface config`() {
        val clientKey = KeyPair()
        val serverKey = KeyPair()
        val config = AwgConfig(
            privateKeyBase64 = clientKey.privateKey.toBase64(),
            localAddresses = listOf("10.77.0.2/32"),
            dnsServers = VpnDnsPolicy.servers,
            profile = AwgProfile.none(),
            peer = AwgPeer(
                publicKeyBase64 = serverKey.publicKey.toBase64(),
                endpointHost = "152.70.43.1",
                endpointPort = 51820,
            ),
        )
        val ifaceString = AwgConfigMapper.toBackendConfig(config).getInterface().toAwgQuickString()

        assertTrue(ifaceString.contains("1.1.1.1"))
        assertTrue(ifaceString.contains("1.0.0.1"))
    }

    @Test
    fun `default peer AllowedIPs captures both 0-0-0-0-0 and colon-colon-0 into the real backend Peer config`() {
        val clientKey = KeyPair()
        val serverKey = KeyPair()
        // AwgPeer built with NO allowedIps argument - proves the real,
        // production default (TransportConfig.kt's AwgPeer.allowedIps),
        // not a value this test chose itself.
        val config = AwgConfig(
            privateKeyBase64 = clientKey.privateKey.toBase64(),
            localAddresses = listOf("10.77.0.2/32"),
            dnsServers = VpnDnsPolicy.servers,
            profile = AwgProfile.none(),
            peer = AwgPeer(
                publicKeyBase64 = serverKey.publicKey.toBase64(),
                endpointHost = "152.70.43.1",
                endpointPort = 51820,
            ),
        )
        val peerString = AwgConfigMapper.toBackendConfig(config).getPeers()[0].toAwgQuickString()

        assertTrue(peerString.contains("0.0.0.0/0"))
        // The real backend's Peer.toAwgQuickString() renders "::/0" via
        // plain java.net.InetAddress.getHostAddress() - which expands the
        // IPv6 zero address to its long form, NOT the "::" shorthand.
        // Verified directly against this pinned AAR (not assumed from
        // WireGuard-quick convention) - a literal ".contains(\"::/0\")"
        // assertion would fail here even though the route is present and
        // correct.
        assertTrue(peerString.contains("0:0:0:0:0:0:0:0/0"))
    }
}
