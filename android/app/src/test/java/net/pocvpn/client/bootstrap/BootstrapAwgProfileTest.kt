package net.pocvpn.client.bootstrap

import net.pocvpn.client.vpn.config.ProductionGatewayCatalog
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B36 (task requirement 7/test H) - proves, structurally, that the
 * bootstrap AWG config genuinely routes
 * [net.pocvpn.client.provisioning.ProvisioningClient]'s own activation
 * traffic into the bootstrap tunnel, and does NOT quietly exclude Nova's
 * own process the way [net.pocvpn.client.vpn.xray.buildXrayVpnPlan] must
 * for Xray - see that file's own docs and BootstrapAwgProfile.kt's docs for
 * the full "why AWG, not Xray" reasoning this test makes concrete.
 */
class BootstrapAwgProfileTest {

    @Test
    fun `bootstrap allowedIps is restricted to exactly the gateway's own control-plane host, never full tunnel`() {
        for (gateway in ProductionGatewayCatalog.all) {
            val config = buildBootstrapAwgConfig(gateway)
            assertEquals(listOf("${gateway.awg.endpointHost}/32"), config.peer.allowedIps)
            assertFalse("bootstrap must never carry a full-tunnel IPv4 default route", config.peer.allowedIps.contains("0.0.0.0/0"))
            assertFalse("bootstrap must never carry a full-tunnel IPv6 default route", config.peer.allowedIps.contains("::/0"))
        }
    }

    @Test
    fun `the exact host ProvisioningClient dials for this gateway is a member of the bootstrap allowedIps set`() {
        for (gateway in ProductionGatewayCatalog.all) {
            val config = buildBootstrapAwgConfig(gateway)
            val dialedHost = bootstrapControlPlaneHost(gateway)
            assertTrue(
                "activation traffic to $dialedHost must be captured by this bootstrap interface's own routing",
                config.peer.allowedIps.any { it == "$dialedHost/32" },
            )
        }
    }

    @Test
    fun `bootstrap config never excludes Nova's own package, unlike the Xray self-exclusion workaround`() {
        for (gateway in ProductionGatewayCatalog.all) {
            val config = buildBootstrapAwgConfig(gateway)
            // No app-exclusion set at all - every app, including Nova's own
            // in-process HTTPS calls, is captured by this interface. This is
            // what makes ProvisioningClient's plain HttpsURLConnection calls
            // (made from Nova's own process, exactly like
            // HttpRelayEndToEndProbe's B33-round-2 bug) actually traverse the
            // tunnel - the SAME reason net.pocvpn.client.vpn.AmneziaWgTransport
            // never calls addDisallowedApplication for the normal AWG tunnel.
            assertTrue(config.includedApplications.isEmpty())
            assertTrue(config.excludedApplications.isEmpty())
        }
    }

    @Test
    fun `bootstrap identity and tunnel address are identical across candidates - one shared public bootstrap peer`() {
        val germany = buildBootstrapAwgConfig(ProductionGatewayCatalog.GERMANY)
        val stockholm = buildBootstrapAwgConfig(ProductionGatewayCatalog.STOCKHOLM)
        assertEquals(germany.privateKeyBase64, stockholm.privateKeyBase64)
        assertEquals(germany.localAddresses, stockholm.localAddresses)
        // But the server-side peer public key/endpoint genuinely differs per gateway - never dialing the wrong server.
        assertNotEquals(germany.peer.publicKeyBase64, stockholm.peer.publicKeyBase64)
        assertNotEquals(germany.peer.endpointHost, stockholm.peer.endpointHost)
    }

    @Test
    fun `bootstrap config is never mistaken for the normal production profile shape (test G)`() {
        // A normal (non-bootstrap) AwgPeer defaults to full-tunnel allowedIps
        // (see AwgPeer's own default) - the bootstrap builder must never
        // reproduce that default, and must never reuse a device's own real
        // per-device identity fields (this function takes no client
        // private-key/credential parameter at all - only the gateway's own
        // already-public catalog facts and the shared bootstrap identity).
        for (gateway in ProductionGatewayCatalog.all) {
            val config = buildBootstrapAwgConfig(gateway)
            assertEquals(BootstrapIdentity.PLACEHOLDER_PRIVATE_KEY_BASE64, config.privateKeyBase64)
            assertNotEquals(listOf("0.0.0.0/0", "::/0"), config.peer.allowedIps)
        }
    }
}
