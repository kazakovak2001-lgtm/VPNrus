package net.pocvpn.client.vpn.config

import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.smartconnect.ProductionGateway
import net.pocvpn.client.vpn.policy.RoutingMode

/** A single AmneziaWG peer (the gateway) to connect to. */
data class AwgPeer(
    val publicKeyBase64: String,
    val endpointHost: String,
    val endpointPort: Int,
    val allowedIps: List<String> = listOf("0.0.0.0/0", "::/0"),
    val persistentKeepaliveSeconds: Int? = 25,
)

/**
 * Full AmneziaWG interface + single-peer config for the POC.
 * privateKeyBase64 is expected to already be decrypted by the caller
 * (from Android Keystore-backed storage) - it is held only in memory here,
 * for the duration of a single connect() call, and is never logged.
 */
data class AwgConfig(
    val privateKeyBase64: String,
    val localAddresses: List<String>,
    val dnsServers: List<String>,
    val listenPort: Int? = null,
    val mtu: Int? = null,
    val profile: AwgProfile,
    val peer: AwgPeer,
    // B8H - split-tunneling (see net.pocvpn.client.vpn.policy.AppRoutingLists,
    // the only place that decides these). Default empty/empty reproduces the
    // exact pre-B8H full-tunnel behavior, so every existing call site
    // (including test fixtures) is unaffected. Mutual exclusivity is
    // AppRoutingLists' own invariant, not re-checked here.
    val includedApplications: Set<String> = emptySet(),
    val excludedApplications: Set<String> = emptySet(),
)

/** Transport-agnostic config passed into VpnTransport.connect(). */
sealed class TransportConfig {
    data class Awg(val config: AwgConfig) : TransportConfig()

    /**
     * B8K1B - config for the isolated VlessRealityTransport/NovaXrayVpnService
     * adapter shell. TransportKind.XRAY_REALITY stays NOT_IMPLEMENTED in
     * TransportRegistry, so nothing in production ever constructs this yet.
     *
     * B13 (audit item 5 fix) - [endpointId] is the REAL endpoint this exact
     * attempt was resolved against (VpnController.buildTransportConfig sets
     * it to `pendingConnectEndpointId`, never a hardcoded literal) - it is
     * how VlessRealityTransport/NovaXrayVpnService know WHICH endpoint's
     * repository to actually read the profile from, closing the gap where
     * this config object was previously built correctly but then ignored by
     * the real runtime (see VlessRealityTransport's own docs on why its
     * `config` param's embedded XrayVlessRealityConfig itself is deliberately
     * unused - endpointId is the one field that DOES need to cross this
     * boundary). Defaults to the one real production endpoint so every
     * pre-B13 construction (every existing test) is unaffected.
     */
    data class Xray(
        val config: net.pocvpn.client.vpn.xray.XrayVlessRealityConfig,
        val endpointId: EndpointId = EndpointId(ProductionGateway.ID),
        // B18-2 - the RoutingMode VpnController resolved THIS attempt
        // against, threaded through VlessRealityTransport into
        // NovaXrayVpnService's EXTRA_ROUTING_MODE (see that class's own
        // docs) so its route plan uses the SAME RoutingDecisionEngine
        // authority AWG's config already does. Defaults to FULL_VPN so every
        // pre-B18-2 construction (every existing test) is byte-for-byte
        // unaffected.
        val routingMode: RoutingMode = RoutingMode.FULL_VPN,
        // B33 relay follow-up - true only when VpnController's own
        // pendingAttemptContext is VpnAttemptContext.Relayed for THIS
        // attempt (see VpnController.buildTransportConfig's own docs) -
        // threaded through NovaXrayVpnService.EXTRA_IS_RELAYED so that
        // service can build the correct XrayCoreController.RemoteConfirmationContext
        // (Direct vs Relayed - see that sealed class's own docs) without
        // itself hardcoding any endpoint id. Defaults to false so every
        // pre-existing construction (every existing test, every Direct
        // attempt) is byte-for-byte unaffected.
        val isRelayed: Boolean = false,
    ) : TransportConfig()

    /** B8O2/B13/B18-2/B33 - the TLS/TCP counterpart of [Xray], including the same [endpointId]/[routingMode]/[isRelayed] threading - see those fields' own docs. */
    data class XrayTls(
        val config: net.pocvpn.client.vpn.xray.XrayVlessTlsConfig,
        val endpointId: EndpointId = EndpointId(ProductionGateway.ID),
        val routingMode: RoutingMode = RoutingMode.FULL_VPN,
        val isRelayed: Boolean = false,
    ) : TransportConfig()
}
