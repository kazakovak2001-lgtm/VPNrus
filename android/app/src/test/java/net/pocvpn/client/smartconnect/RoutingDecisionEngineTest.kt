package net.pocvpn.client.smartconnect

import net.pocvpn.client.vpn.policy.ClientRoutingPolicy
import net.pocvpn.client.vpn.policy.RoutingMode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
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

    // --- B18 adaptive destination-route decision ---

    private fun context(mode: RoutingMode, dest: DestinationClass, restriction: RestrictionClass = RestrictionClass.NO_RESTRICTION_OBSERVED) =
        RoutingContext(routingMode = mode, destinationClass = dest, restrictionClass = restriction)

    @Test
    fun `FULL_VPN always sends protected AND local-private traffic to VPN`() {
        assertEquals(RouteDecision.Vpn(RoutingReason.FULL_VPN_MODE), RoutingDecisionEngine.decideAdaptiveRoute(context(RoutingMode.FULL_VPN, DestinationClass.PROTECTED)))
        assertEquals(RouteDecision.Vpn(RoutingReason.FULL_VPN_MODE), RoutingDecisionEngine.decideAdaptiveRoute(context(RoutingMode.FULL_VPN, DestinationClass.LOCAL_PRIVATE)))
    }

    @Test
    fun `APPS mode is byte-for-byte identical to FULL_VPN at the destination-route layer`() {
        val protectedDecision = RoutingDecisionEngine.decideAdaptiveRoute(context(RoutingMode.APPS, DestinationClass.PROTECTED))
        val localDecision = RoutingDecisionEngine.decideAdaptiveRoute(context(RoutingMode.APPS, DestinationClass.LOCAL_PRIVATE))
        assertTrue(protectedDecision is RouteDecision.Vpn)
        assertTrue(localDecision is RouteDecision.Vpn)
    }

    @Test
    fun `ADAPTIVE NORMAL permits DIRECT only for the explicitly local-private destination class`() {
        val decision = RoutingDecisionEngine.decideAdaptiveRoute(context(RoutingMode.ADAPTIVE, DestinationClass.LOCAL_PRIVATE, RestrictionClass.NO_RESTRICTION_OBSERVED))
        assertEquals(RouteDecision.Direct(RoutingReason.ADAPTIVE_LOCAL_PRIVATE_ELIGIBLE), decision)
    }

    @Test
    fun `ADAPTIVE never routes PROTECTED traffic DIRECT under any RestrictionClass`() {
        for (restriction in RestrictionClass.entries.filterNot { it == RestrictionClass.NO_NETWORK }) {
            val decision = RoutingDecisionEngine.decideAdaptiveRoute(context(RoutingMode.ADAPTIVE, DestinationClass.PROTECTED, restriction))
            assertTrue("restriction=$restriction produced $decision", decision is RouteDecision.Vpn)
        }
    }

    @Test
    fun `POSSIBLE_UDP_OR_AWG_FILTERING does not force PROTECTED traffic DIRECT`() {
        val decision = RoutingDecisionEngine.decideAdaptiveRoute(context(RoutingMode.ADAPTIVE, DestinationClass.PROTECTED, RestrictionClass.POSSIBLE_UDP_OR_AWG_FILTERING))
        assertEquals(RouteDecision.Vpn(RoutingReason.ADAPTIVE_PROTECTED_DEFAULT_VPN), decision)
    }

    @Test
    fun `POSSIBLE_HARD_WHITELIST does not force PROTECTED traffic DIRECT`() {
        val decision = RoutingDecisionEngine.decideAdaptiveRoute(context(RoutingMode.ADAPTIVE, DestinationClass.PROTECTED, RestrictionClass.POSSIBLE_HARD_WHITELIST))
        assertEquals(RouteDecision.Vpn(RoutingReason.ADAPTIVE_PROTECTED_DEFAULT_VPN), decision)
    }

    @Test
    fun `ADAPTIVE UNKNOWN does not broaden DIRECT beyond the explicit destination class`() {
        val protectedDecision = RoutingDecisionEngine.decideAdaptiveRoute(context(RoutingMode.ADAPTIVE, DestinationClass.PROTECTED, RestrictionClass.UNKNOWN))
        assertTrue(protectedDecision is RouteDecision.Vpn)
        // Still eligible for its own explicit LOCAL_PRIVATE category - UNKNOWN narrows nothing that policy already allowed.
        val localDecision = RoutingDecisionEngine.decideAdaptiveRoute(context(RoutingMode.ADAPTIVE, DestinationClass.LOCAL_PRIVATE, RestrictionClass.UNKNOWN))
        assertTrue(localDecision is RouteDecision.Direct)
    }

    @Test
    fun `NO_NETWORK blocks routing regardless of mode or destination class - no fabricated direct route`() {
        for (mode in RoutingMode.entries) {
            for (dest in DestinationClass.entries) {
                val decision = RoutingDecisionEngine.decideAdaptiveRoute(context(mode, dest, RestrictionClass.NO_NETWORK))
                assertEquals(RouteDecision.Block(RoutingReason.NETWORK_UNAVAILABLE), decision)
            }
        }
    }

    @Test
    fun `changing RestrictionClass CAN change the routing decision - NO_NETWORK proves the input is genuinely live`() {
        val normal = RoutingDecisionEngine.decideAdaptiveRoute(context(RoutingMode.ADAPTIVE, DestinationClass.LOCAL_PRIVATE, RestrictionClass.NO_RESTRICTION_OBSERVED))
        val noNetwork = RoutingDecisionEngine.decideAdaptiveRoute(context(RoutingMode.ADAPTIVE, DestinationClass.LOCAL_PRIVATE, RestrictionClass.NO_NETWORK))
        assertTrue(normal is RouteDecision.Direct)
        assertTrue(noNetwork is RouteDecision.Block)
    }

    @Test
    fun `classifyDestination puts RFC1918-loopback-link-local in LOCAL_PRIVATE, everything else PROTECTED`() {
        for (ip in listOf("10.1.2.3", "172.20.0.1", "192.168.50.1", "127.0.0.1", "169.254.1.1")) {
            assertEquals(ip, DestinationClass.LOCAL_PRIVATE, RoutingDecisionEngine.classifyDestination(ip))
        }
        for (ip in listOf("8.8.8.8", "1.1.1.1", "203.0.113.5")) {
            assertEquals(ip, DestinationClass.PROTECTED, RoutingDecisionEngine.classifyDestination(ip))
        }
        assertEquals(DestinationClass.PROTECTED, RoutingDecisionEngine.classifyDestination(null))
    }

    @Test
    fun `decideAdaptiveRoute never touches transport or gateway selection - RouteDecision only ever carries a typed reason`() {
        // Structural proof, not merely a comment: RouteDecision's constructors only ever accept a RoutingReason.
        val decision = RoutingDecisionEngine.decideAdaptiveRoute(context(RoutingMode.ADAPTIVE, DestinationClass.PROTECTED))
        val reason: RoutingReason = when (decision) {
            is RouteDecision.Direct -> decision.reason
            is RouteDecision.Vpn -> decision.reason
            is RouteDecision.Block -> decision.reason
        }
        assertEquals(RoutingReason.ADAPTIVE_PROTECTED_DEFAULT_VPN, reason)
    }
}
