package net.pocvpn.client.smartconnect

import net.pocvpn.client.network.NetworkProfile
import net.pocvpn.client.network.NetworkType
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.transport.TransportRegistry
import net.pocvpn.client.transport.UserTransportPreference
import net.pocvpn.client.vpn.FakeVpnTransport
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

private fun usableProfile(type: NetworkType = NetworkType.WIFI) = NetworkProfile(
    type = type,
    validatedInternet = true,
    metered = false,
    roaming = false,
    captivePortal = false,
    ipv4Available = true,
    ipv6Available = false,
    vpnActive = false,
    generation = 1,
)

class SmartConnectDecisionEngineTest {

    private val registryWithAwg = TransportRegistry.defaults { FakeVpnTransport() }
    private val emptyRegistry = TransportRegistry.build(emptyList())

    @Test
    fun `usable network and AWG available selects AWG`() {
        val decision = SmartConnectDecisionEngine.decide(usableProfile(), registryWithAwg)
        assertEquals(TransportSelectionDecision.SelectTransport(TransportKind.AMNEZIA_WG), decision)
    }

    @Test
    fun `no network yields NetworkUnavailable, not a fake selection`() {
        val decision = SmartConnectDecisionEngine.decide(NetworkProfile.unavailable(0), registryWithAwg)
        assertEquals(TransportSelectionDecision.NetworkUnavailable, decision)
    }

    @Test
    fun `unvalidated network yields NetworkUnavailable even if the network type is present`() {
        val profile = usableProfile().copy(validatedInternet = false)
        val decision = SmartConnectDecisionEngine.decide(profile, registryWithAwg)
        assertEquals(TransportSelectionDecision.NetworkUnavailable, decision)
    }

    @Test
    fun `no transports registered yields NoTransportAvailable, never a fake success`() {
        val decision = SmartConnectDecisionEngine.decide(usableProfile(), emptyRegistry)
        assertEquals(TransportSelectionDecision.NoTransportAvailable, decision)
    }

    @Test
    fun `NOT_IMPLEMENTED transports are never selected under AUTO`() {
        val decision = SmartConnectDecisionEngine.decide(usableProfile(), registryWithAwg, UserTransportPreference.Auto)
        assertTrue(decision is TransportSelectionDecision.SelectTransport)
        val selected = (decision as TransportSelectionDecision.SelectTransport).kind
        assertEquals(TransportKind.AMNEZIA_WG, selected)
        assertTrue(selected != TransportKind.XRAY_REALITY && selected != TransportKind.QUIC && selected != TransportKind.TLS_TCP)
    }

    @Test
    fun `manual selection of an implemented transport succeeds`() {
        val decision = SmartConnectDecisionEngine.decide(
            usableProfile(), registryWithAwg, UserTransportPreference.Manual(TransportKind.AMNEZIA_WG),
        )
        assertEquals(TransportSelectionDecision.SelectTransport(TransportKind.AMNEZIA_WG), decision)
    }

    @Test
    fun `manual selection of a NOT_IMPLEMENTED transport is blocked, never faked`() {
        for (kind in listOf(TransportKind.XRAY_REALITY, TransportKind.QUIC, TransportKind.TLS_TCP)) {
            val decision = SmartConnectDecisionEngine.decide(usableProfile(), registryWithAwg, UserTransportPreference.Manual(kind))
            assertEquals("manual $kind must be blocked", TransportSelectionDecision.UserPolicyBlocked, decision)
        }
    }

    @Test
    fun `manual selection of an unknown transport (empty registry) is blocked`() {
        val decision = SmartConnectDecisionEngine.decide(usableProfile(), emptyRegistry, UserTransportPreference.Manual(TransportKind.AMNEZIA_WG))
        assertEquals(TransportSelectionDecision.UserPolicyBlocked, decision)
    }

    @Test
    fun `FASTEST and STEALTH do not fabricate a score - they fall back to the same deterministic result as AUTO`() {
        val auto = SmartConnectDecisionEngine.decide(usableProfile(), registryWithAwg, UserTransportPreference.Auto)
        val fastest = SmartConnectDecisionEngine.decide(usableProfile(), registryWithAwg, UserTransportPreference.Fastest)
        val stealth = SmartConnectDecisionEngine.decide(usableProfile(), registryWithAwg, UserTransportPreference.Stealth)
        assertEquals(auto, fastest)
        assertEquals(auto, stealth)
    }

    @Test
    fun `selection is deterministic across repeated calls with identical input`() {
        val results = (1..10).map { SmartConnectDecisionEngine.decide(usableProfile(), registryWithAwg) }
        assertTrue(results.all { it == results.first() })
    }

    @Test
    fun `WIFI and CELLULAR both select AWG identically - selection does not depend on network type beyond usability`() {
        val wifi = SmartConnectDecisionEngine.decide(usableProfile(NetworkType.WIFI), registryWithAwg)
        val cellular = SmartConnectDecisionEngine.decide(usableProfile(NetworkType.CELLULAR), registryWithAwg)
        assertEquals(wifi, cellular)
    }
}
