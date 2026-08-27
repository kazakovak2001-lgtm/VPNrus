package net.pocvpn.client.smartconnect

import net.pocvpn.client.vpn.policy.ClientRoutingPolicy
import org.junit.Assert.assertEquals
import org.junit.Test

class RoutingDecisionEngineTest {

    @Test
    fun `FULL_TUNNEL routes any candidate to VPN`() {
        val decision = RoutingDecisionEngine.decide(RoutingCandidate(packageName = "com.example.app"), ClientRoutingPolicy.FullTunnel)
        assertEquals(RoutingDecision.VPN, decision)
    }

    @Test
    fun `VPN_APP_ALLOWLIST routes a listed package to VPN`() {
        val policy = ClientRoutingPolicy.VpnAppAllowlist(setOf("com.example.allowed"))
        val decision = RoutingDecisionEngine.decide(RoutingCandidate(packageName = "com.example.allowed"), policy)
        assertEquals(RoutingDecision.VPN, decision)
    }

    @Test
    fun `VPN_APP_ALLOWLIST routes an unlisted package DIRECT, not blocked`() {
        val policy = ClientRoutingPolicy.VpnAppAllowlist(setOf("com.example.allowed"))
        val decision = RoutingDecisionEngine.decide(RoutingCandidate(packageName = "com.example.other"), policy)
        assertEquals(RoutingDecision.DIRECT, decision)
    }

    @Test
    fun `DIRECT_APP_LIST returns DIRECT for a bypass package`() {
        val policy = ClientRoutingPolicy.DirectAppList(setOf("com.example.bypass"))
        val decision = RoutingDecisionEngine.decide(RoutingCandidate(packageName = "com.example.bypass"), policy)
        assertEquals(RoutingDecision.DIRECT, decision)
    }

    @Test
    fun `DIRECT_APP_LIST routes every other package through the VPN`() {
        val policy = ClientRoutingPolicy.DirectAppList(setOf("com.example.bypass"))
        val decision = RoutingDecisionEngine.decide(RoutingCandidate(packageName = "com.example.other"), policy)
        assertEquals(RoutingDecision.VPN, decision)
    }

    @Test
    fun `IP_CIDR_POLICY routes a destination in outsideVpn DIRECT`() {
        val policy = ClientRoutingPolicy.IpCidrPolicy(throughVpn = emptyList(), outsideVpn = listOf("192.168.1.0/24"))
        val decision = RoutingDecisionEngine.decide(RoutingCandidate(destinationIp = "192.168.1.42"), policy)
        assertEquals(RoutingDecision.DIRECT, decision)
    }

    @Test
    fun `IP_CIDR_POLICY routes a destination in throughVpn to VPN`() {
        val policy = ClientRoutingPolicy.IpCidrPolicy(throughVpn = listOf("10.0.0.0/8"), outsideVpn = emptyList())
        val decision = RoutingDecisionEngine.decide(RoutingCandidate(destinationIp = "10.1.2.3"), policy)
        assertEquals(RoutingDecision.VPN, decision)
    }

    @Test
    fun `IP_CIDR_POLICY fails safe to VPN for an unlisted destination`() {
        val policy = ClientRoutingPolicy.IpCidrPolicy(throughVpn = listOf("10.0.0.0/8"), outsideVpn = listOf("192.168.0.0/16"))
        val decision = RoutingDecisionEngine.decide(RoutingCandidate(destinationIp = "8.8.8.8"), policy)
        assertEquals(RoutingDecision.VPN, decision)
    }

    @Test
    fun `IP_CIDR_POLICY fails safe to VPN when no destination IP is known`() {
        val policy = ClientRoutingPolicy.IpCidrPolicy(throughVpn = listOf("10.0.0.0/8"), outsideVpn = listOf("192.168.0.0/16"))
        val decision = RoutingDecisionEngine.decide(RoutingCandidate(), policy)
        assertEquals(RoutingDecision.VPN, decision)
    }

    @Test
    fun `routing decision does not depend on transport selection - only ClientRoutingPolicy`() {
        // RoutingDecisionEngine.decide takes no TransportRegistry/TransportKind/health input at all -
        // "should this go through the VPN" stays fully independent of "which transport carries it".
        val decision = RoutingDecisionEngine.decide(RoutingCandidate(packageName = "any.app"), ClientRoutingPolicy.FullTunnel)
        assertEquals(RoutingDecision.VPN, decision)
    }
}
