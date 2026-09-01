package net.pocvpn.client.vpn.xray

import net.pocvpn.client.smartconnect.RestrictionClass
import net.pocvpn.client.smartconnect.RoutingDecisionEngine
import net.pocvpn.client.vpn.policy.RoutingMode

/**
 * Everything [NovaXrayVpnService] needs to configure its
 * android.net.VpnService.Builder, computed as a pure function so the
 * self-exclusion/route/DNS/IPv6 decisions are unit-testable without a real
 * Android framework Builder (this test target has no Robolectric
 * dependency - see build.gradle.kts's `unitTests.isReturnDefaultValues`).
 *
 * B8K1B scope: ALL_APPS only (see [novaPackageId] - always disallowed, never
 * combined with an allow-list; BYPASS_SELECTED/VPN_ONLY_SELECTED parity with
 * B8H is explicitly not implemented yet). B8F intent preserved where
 * technically applicable: [dnsServers] are applied to the interface.
 * B18-2 - [routesIpv4] is FULL_VPN/APPS's `0.0.0.0/0` by default, or the
 * SAME `RoutingDecisionEngine.resolveIpv4Routes`-derived exclusion set AWG's
 * `VpnController.resolveAdaptiveAllowedIps` uses in `ADAPTIVE` mode (see
 * [buildXrayVpnPlan]'s own docs) - never a second, transport-specific
 * decision. There is deliberately NO ipv6 field anywhere on this type - per
 * android.net.VpnService.Builder's own documented contract ("if no address,
 * route or DNS server of a specific family is added to this VPN, then all
 * outgoing traffic of that family is blocked"), omitting every IPv6 call is
 * itself the fail-closed behavior: IPv6 traffic is blocked outright rather
 * than being tunneled or leaked around the tunnel, in EVERY RoutingMode -
 * this file's own routing-mode change never touches that. This is a
 * stricter (simpler, more clearly truthful) mechanism than B8F's AWG policy
 * (VpnIpv6Policy/Ipv6LeakPolicy.FAIL_CLOSED), which captures IPv6 into a
 * tunnel that then drops it server-side; this adapter has no IPv6 plumbing
 * to capture it with in the first place, so it is blocked at the OS level
 * instead. Do not add an IPv6 address/route here without also making
 * supportsIpv6 true somewhere real IPv6 forwarding exists end to end.
 */
data class XrayVpnBuilderPlan(
    val mtu: Int,
    val tunLocalAddressIpv4: String,
    val tunLocalPrefixLengthIpv4: Int,
    val routesIpv4: List<String>,
    val dnsServers: List<String>,
    val disallowedApplications: Set<String>,
)

/**
 * Pure - see [XrayVpnBuilderPlan]'s own docs for why this has no ipv6
 * branch. [routingMode]/[restrictionClass] default to `FULL_VPN`/`UNKNOWN`
 * so every pre-B18-2 call site (real or test) is byte-for-byte unaffected -
 * `routesIpv4` stays exactly `["0.0.0.0/0"]` unless a caller explicitly
 * opts into `ADAPTIVE`. [restrictionClass] deliberately defaults to
 * `UNKNOWN` rather than being live-threaded from `RestrictionClassifier`
 * for this transport today (see `NovaXrayVpnService`'s own docs) - this is
 * safe because only `RestrictionClass.NO_NETWORK` ever changes
 * `resolveIpv4Routes`'s output, and `UNKNOWN` produces the SAME route set
 * `AMNEZIA_WG` produces for every other restriction class, so the two
 * transports' ADAPTIVE route sets remain identical for every reachable
 * live case.
 */
fun buildXrayVpnPlan(
    config: XrayVlessRealityConfig,
    novaPackageId: String,
    routingMode: RoutingMode = RoutingMode.FULL_VPN,
    restrictionClass: RestrictionClass = RestrictionClass.UNKNOWN,
): XrayVpnBuilderPlan = XrayVpnBuilderPlan(
    mtu = config.mtu,
    tunLocalAddressIpv4 = config.tunLocalAddressIpv4,
    tunLocalPrefixLengthIpv4 = config.tunLocalPrefixLengthIpv4,
    routesIpv4 = RoutingDecisionEngine.resolveIpv4Routes(listOf("0.0.0.0/0"), routingMode, restrictionClass),
    dnsServers = config.dnsServers,
    disallowedApplications = setOf(novaPackageId),
)

/** B8O2 - the TLS/TCP counterpart of [buildXrayVpnPlan] above; identical shape, same fields, no security-mode-specific plan differences. */
fun buildXrayVpnPlan(
    config: XrayVlessTlsConfig,
    novaPackageId: String,
    routingMode: RoutingMode = RoutingMode.FULL_VPN,
    restrictionClass: RestrictionClass = RestrictionClass.UNKNOWN,
): XrayVpnBuilderPlan = XrayVpnBuilderPlan(
    mtu = config.mtu,
    tunLocalAddressIpv4 = config.tunLocalAddressIpv4,
    tunLocalPrefixLengthIpv4 = config.tunLocalPrefixLengthIpv4,
    routesIpv4 = RoutingDecisionEngine.resolveIpv4Routes(listOf("0.0.0.0/0"), routingMode, restrictionClass),
    dnsServers = config.dnsServers,
    disallowedApplications = setOf(novaPackageId),
)
