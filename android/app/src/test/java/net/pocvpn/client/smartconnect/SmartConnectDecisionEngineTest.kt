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
        assertTrue(selected != TransportKind.XRAY_REALITY && selected != TransportKind.XRAY_XHTTP && selected != TransportKind.QUIC && selected != TransportKind.TLS_TCP)
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
        for (kind in listOf(TransportKind.XRAY_REALITY, TransportKind.XRAY_XHTTP, TransportKind.QUIC, TransportKind.TLS_TCP)) {
            val decision = SmartConnectDecisionEngine.decide(usableProfile(), registryWithAwg, UserTransportPreference.Manual(kind))
            assertEquals("manual $kind must be blocked", TransportSelectionDecision.UserPolicyBlocked, decision)
        }
    }


    @Test
    fun `preferred order explicitly contains every transport kind, SHADOWSOCKS_2022 appended last`() {
        // B45B-4 - SHADOWSOCKS_2022 selection wiring: appended to the END of
        // PREFERRED_ORDER, never inserted earlier or reordering an existing
        // entry (task requirement - "do not reorder AMNEZIA_WG/XRAY_REALITY
        // blindly"). Registry-level AVAILABLE/NOT_IMPLEMENTED (see
        // TransportRegistry/MainViewModel.buildTransportRegistry) remains the
        // real gate on whether it is ever actually selectable.
        assertEquals(TransportKind.entries.toSet(), SmartConnectDecisionEngine.PREFERRED_ORDER.toSet())
        assertEquals(
            listOf(
                TransportKind.AMNEZIA_WG,
                TransportKind.QUIC,
                TransportKind.XRAY_REALITY,
                TransportKind.XRAY_XHTTP,
                TransportKind.TLS_TCP,
                TransportKind.SHADOWSOCKS_2022,
                // B-WL-R6 - appended after SHADOWSOCKS_2022; nothing earlier moved.
                TransportKind.XRAY_REALITY_XHTTP,
            ),
            SmartConnectDecisionEngine.PREFERRED_ORDER,
        )
    }

    @Test
    fun `SHADOWSOCKS_2022 is only chosen under AUTO when nothing else is AVAILABLE`() {
        val shadowsocks = FakeVpnTransport(kind = TransportKind.SHADOWSOCKS_2022)
        val registryWithBoth = TransportRegistry.build(
            listOf(
                net.pocvpn.client.transport.TransportDescriptor(
                    kind = TransportKind.AMNEZIA_WG,
                    status = net.pocvpn.client.transport.TransportStatus.AVAILABLE,
                    capabilities = net.pocvpn.client.transport.TransportCapabilities.amneziaWg(),
                    factory = { FakeVpnTransport() },
                ),
                net.pocvpn.client.transport.TransportDescriptor(
                    kind = TransportKind.SHADOWSOCKS_2022,
                    status = net.pocvpn.client.transport.TransportStatus.AVAILABLE,
                    capabilities = net.pocvpn.client.transport.TransportCapabilities.shadowsocks2022AdapterShell(),
                    factory = { shadowsocks },
                ),
            ),
        )
        val decision = SmartConnectDecisionEngine.decide(usableProfile(), registryWithBoth)
        assertEquals(TransportSelectionDecision.SelectTransport(TransportKind.AMNEZIA_WG), decision)

        val registryWithOnlyShadowsocks = TransportRegistry.build(
            listOf(
                net.pocvpn.client.transport.TransportDescriptor(
                    kind = TransportKind.SHADOWSOCKS_2022,
                    status = net.pocvpn.client.transport.TransportStatus.AVAILABLE,
                    capabilities = net.pocvpn.client.transport.TransportCapabilities.shadowsocks2022AdapterShell(),
                    factory = { shadowsocks },
                ),
            ),
        )
        val onlyDecision = SmartConnectDecisionEngine.decide(usableProfile(), registryWithOnlyShadowsocks)
        assertEquals(TransportSelectionDecision.SelectTransport(TransportKind.SHADOWSOCKS_2022), onlyDecision)
    }

    @Test
    fun `manual selection of SHADOWSOCKS_2022 succeeds when it is AVAILABLE`() {
        val shadowsocks = FakeVpnTransport(kind = TransportKind.SHADOWSOCKS_2022)
        val registry = TransportRegistry.build(
            listOf(
                net.pocvpn.client.transport.TransportDescriptor(
                    kind = TransportKind.SHADOWSOCKS_2022,
                    status = net.pocvpn.client.transport.TransportStatus.AVAILABLE,
                    capabilities = net.pocvpn.client.transport.TransportCapabilities.shadowsocks2022AdapterShell(),
                    factory = { shadowsocks },
                ),
            ),
        )
        val decision = SmartConnectDecisionEngine.decide(
            usableProfile(), registry, UserTransportPreference.Manual(TransportKind.SHADOWSOCKS_2022),
        )
        assertEquals(TransportSelectionDecision.SelectTransport(TransportKind.SHADOWSOCKS_2022), decision)
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
