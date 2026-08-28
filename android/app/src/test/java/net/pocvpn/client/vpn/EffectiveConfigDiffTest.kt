package net.pocvpn.client.vpn

import net.pocvpn.client.vpn.config.AwgConfig
import net.pocvpn.client.vpn.config.AwgConfigMapper
import net.pocvpn.client.vpn.config.AwgPeer
import net.pocvpn.client.vpn.config.BuildConfigGatewaySource
import net.pocvpn.client.vpn.config.DefaultGatewayConfigurationRepository
import net.pocvpn.client.vpn.config.GatewayConfigSource
import net.pocvpn.client.vpn.config.GatewayConfiguration
import net.pocvpn.client.vpn.config.MutableGatewayConfigSource
import net.pocvpn.client.vpn.config.PocAwgProfile
import org.amnezia.awg.crypto.KeyPair
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B8B3B handshake-failure investigation. Mirrors VpnController.buildTransportConfig's
 * EXACT construction (same field-by-field mapping, same AwgConfigMapper call) so the
 * effective peer/interface config actually reaching the AmneziaWG backend after a
 * provisioning apply() can be inspected and diffed against the last-known-working
 * pre-B8B3B config, without needing a live device. Does not touch the real private key -
 * uses a disposable KeyPair(), matching AwgConfigMapperTest's existing pattern.
 */
class EffectiveConfigDiffTest {

    // Values from C:\Users\akaza\Downloads\VPN\android\app\gateway-dev.properties -
    // the main checkout's copy, i.e. the config believed to have last worked against
    // the real Oracle server, pre-B8B3B (BuildConfigGatewaySource read directly, no
    // provisioning involved).
    private class WorkingDevSource : GatewayConfigSource {
        override fun endpointHost() = "152.70.43.1"
        override fun endpointPort() = "51820"
        override fun serverPublicKey() = "9WewKC/zyUPyPnKyzaI0bZrEN2c73PqjK7f+fRXHYRU="
        override fun clientTunnelIp() = "10.77.0.2"
        override fun gatewayTunnelIp() = "10.77.0.1"
        override fun allowedIps() = "" // absent key in that file -> full-tunnel default
    }

    // THIS worktree's own gateway-dev.properties (gitignored, machine-local) - what
    // BuildConfigGatewaySource actually delegates to in every debug APK built from
    // this worktree, including the one B8B3A/B8B3B were tested with.
    private class ThisWorktreeStaleDevSource : GatewayConfigSource {
        override fun endpointHost() = "172.27.193.89" // WSL2 local dev gateway, NOT Oracle
        override fun endpointPort() = "51820"
        override fun serverPublicKey() = "Vqd6OFZzy/Kq76VtxhSp4u9h818UNvSgYu25TwPL/U8=" // WSL2 test key, NOT the Oracle server key
        override fun clientTunnelIp() = "10.77.0.2"
        override fun gatewayTunnelIp() = "10.77.0.1"
        override fun allowedIps() = "10.77.0.0/24" // narrow local-test route
    }

    // The real B8B2A/B8B3A live provisioning response values (POC-01 §"LIVE EXPECTED PROFILE").
    private fun applyLiveProvisioningResult(source: MutableGatewayConfigSource) {
        source.apply(
            endpointHost = "152.70.43.1",
            endpointPort = 51820,
            serverPublicKey = "9WewKC/zyUPyPnKyzaI0bZrEN2c73PqjK7f+fRXHYRU=",
            clientTunnelIp = "10.77.0.2",
            gatewayTunnelIp = "10.77.0.1",
        )
    }

    /** Exact mirror of VpnController.buildTransportConfig's AwgConfig construction. */
    private fun buildAwgConfig(config: GatewayConfiguration.Configured, privateKeyBase64: String): AwgConfig =
        AwgConfig(
            privateKeyBase64 = privateKeyBase64,
            localAddresses = listOf("${config.clientTunnelIp}/32"),
            dnsServers = config.dnsServers,
            profile = config.profile,
            peer = AwgPeer(
                publicKeyBase64 = config.serverPublicKeyBase64,
                endpointHost = config.endpointHost,
                endpointPort = config.endpointPort,
                allowedIps = config.allowedIps,
                persistentKeepaliveSeconds = config.persistentKeepaliveSeconds,
            ),
        )

    @Test
    fun `post-apply effective peer config matches the last-known-working host, port, key and address exactly`() {
        val source = MutableGatewayConfigSource(ThisWorktreeStaleDevSource())
        applyLiveProvisioningResult(source)
        val configured = DefaultGatewayConfigurationRepository(source).get() as GatewayConfiguration.Configured

        val workingConfigured = DefaultGatewayConfigurationRepository(WorkingDevSource()).get() as GatewayConfiguration.Configured

        // The 4 fields that actually reach the AmneziaWG peer/interface must be
        // IDENTICAL to the last-known-working config - proves the provisioning
        // override itself introduces no discrepancy in these fields.
        assertEquals(workingConfigured.endpointHost, configured.endpointHost)
        assertEquals(workingConfigured.endpointPort, configured.endpointPort)
        assertEquals(workingConfigured.serverPublicKeyBase64, configured.serverPublicKeyBase64)
        assertEquals(workingConfigured.clientTunnelIp, configured.clientTunnelIp)
    }

    @Test
    fun `AllowedIPs is NOT overridden by provisioning - this worktree's stale narrow route survives apply()`() {
        val source = MutableGatewayConfigSource(ThisWorktreeStaleDevSource())
        applyLiveProvisioningResult(source)
        val configured = DefaultGatewayConfigurationRepository(source).get() as GatewayConfiguration.Configured

        // DOCUMENTS the one real difference found: this worktree's gitignored
        // gateway-dev.properties still carries a narrow WSL2-local-test AllowedIPs
        // override ("10.77.0.0/24"), and MutableGatewayConfigSource deliberately never
        // touches allowedIps() (the provisioning response carries no such field - see
        // its own class doc). The main checkout's gateway-dev.properties has NO
        // allowedIps key at all, so the last-known-working config used the full-tunnel
        // default (0.0.0.0/0, ::/0) instead.
        assertEquals(listOf("10.77.0.0/24"), configured.allowedIps)

        val workingConfigured = DefaultGatewayConfigurationRepository(WorkingDevSource()).get() as GatewayConfiguration.Configured
        assertEquals(listOf("0.0.0.0/0", "::/0"), workingConfigured.allowedIps)
    }

    @Test
    fun `effective backend peer and interface strings are otherwise identical to the working config`() {
        val keyPair = KeyPair()

        val source = MutableGatewayConfigSource(ThisWorktreeStaleDevSource())
        applyLiveProvisioningResult(source)
        val configured = DefaultGatewayConfigurationRepository(source).get() as GatewayConfiguration.Configured
        val backend = AwgConfigMapper.toBackendConfig(buildAwgConfig(configured, keyPair.privateKey.toBase64()))

        val workingConfigured = DefaultGatewayConfigurationRepository(WorkingDevSource()).get() as GatewayConfiguration.Configured
        val workingBackend = AwgConfigMapper.toBackendConfig(buildAwgConfig(workingConfigured, keyPair.privateKey.toBase64()))

        val peerString = backend.getPeers()[0].toAwgQuickString()
        val workingPeerString = workingBackend.getPeers()[0].toAwgQuickString()

        // Both must target the same peer public key and endpoint - the two things
        // that actually matter for handshake acceptance. AllowedIps legitimately
        // differs (see the test above) and is expected here, not a bug in this line.
        assertEquals(
            workingPeerString.lineSequence().first { it.startsWith("PublicKey") },
            peerString.lineSequence().first { it.startsWith("PublicKey") },
        )
        assertEquals(
            workingPeerString.lineSequence().first { it.startsWith("Endpoint") },
            peerString.lineSequence().first { it.startsWith("Endpoint") },
        )

        // Interface obfuscation parameters (Jc/Jmin/Jmax/S1-4/H1-4) come from the
        // SAME PocAwgProfile.value in both cases (untouched by B8B3B - see
        // MutableGatewayConfigSourceTest's identity check) - the full interface
        // string must therefore be byte-identical modulo the private key/address.
        val ifaceString = backend.getInterface().toAwgQuickString()
        val workingIfaceString = workingBackend.getInterface().toAwgQuickString()
        for (field in listOf("Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4")) {
            // firstOrNull, not first: the backend's quick-config renderer omits a
            // zero-valued junk-size field entirely (observed for S3=0/S4=0 here) -
            // that is a rendering detail, not a mismatch, as long as BOTH sides
            // (which share the exact same PocAwgProfile.value instance) agree on
            // presence/absence and, when present, on the value.
            val line = ifaceString.lineSequence().firstOrNull { it.startsWith("$field ") || it.startsWith("$field=") }
            val workingLine = workingIfaceString.lineSequence().firstOrNull { it.startsWith("$field ") || it.startsWith("$field=") }
            assertEquals("mismatch on $field", workingLine, line)
        }

        // Direct proof (not just internal self-consistency) that the actual
        // live-server-matching values are what gets rendered.
        assertTrue(ifaceString.contains("S1 = 113"))
        assertTrue(ifaceString.contains("S2 = 159"))
        assertTrue(ifaceString.contains("H1 = 1106684696"))
        assertTrue(ifaceString.contains("H2 = 3677857287"))
        assertTrue(ifaceString.contains("H3 = 353316806"))
        assertTrue(ifaceString.contains("H4 = 2068198996"))
    }

    @Test
    fun `real BuildConfigGatewaySource now yields full-tunnel AllowedIPs (B8B3B fix, not the fake fixture above)`() {
        // Reads the ACTUAL compiled-in gateway-dev.properties value via the
        // real production wiring (Factory uses MutableGatewayConfigSource(
        // BuildConfigGatewaySource) exactly like this) - proves the stale
        // WSL-local "10.77.0.0/24" override is gone from this worktree's
        // gateway-dev.properties, not just demonstrated against a fake source.
        val source = MutableGatewayConfigSource(BuildConfigGatewaySource)
        val configured = DefaultGatewayConfigurationRepository(source).get() as GatewayConfiguration.Configured
        assertEquals(listOf("0.0.0.0/0", "::/0"), configured.allowedIps)
    }

    @Test
    fun `PocAwgProfile S1-S4-H1-H4 match the LIVE Oracle awg0 server values (B8B3B fix)`() {
        // Pinned to the live server's actual values (confirmed live - see
        // PocAwgProfile's own updated doc comment), not gateway/config/awg-profile.env's
        // template (which had drifted). Jc/Jmin/Jmax are the client-only values,
        // unaffected by this fix.
        val p = PocAwgProfile.value
        assertEquals(6, p.junkPacketCount)
        assertEquals(40, p.junkPacketMinSize)
        assertEquals(100, p.junkPacketMaxSize)
        assertEquals(113, p.initPacketJunkSize)
        assertEquals(159, p.responsePacketJunkSize)
        assertEquals(0, p.cookieReplyPacketJunkSize)
        assertEquals(0, p.transportPacketJunkSize)
        assertEquals("1106684696", p.initPacketMagicHeader)
        assertEquals("3677857287", p.responsePacketMagicHeader)
        assertEquals("353316806", p.underloadPacketMagicHeader)
        assertEquals("2068198996", p.transportPacketMagicHeader)
    }
}
