package net.pocvpn.client.vpn.config

import net.pocvpn.client.reachability.EndpointId

/**
 * B13 - the real, hardcoded set of production gateways this app can connect
 * a device to. Two real gateways exist as of 2026-08-30: the original Oracle
 * Cloud gateway (Frankfurt, "Germany") and a second, independently-provisioned
 * AWS gateway (Stockholm) added for B13's multi-provider validation slice -
 * see docs/ROADMAP.md's Gateway Pool row for the full history.
 *
 * Deliberately GATEWAY-SIDE FACTS ONLY (endpoint host/port, the gateway's
 * OWN WireGuard/AmneziaWG public key and tunnel address, its AWG obfuscation
 * profile). This catalog does NOT carry any per-device client tunnel IP -
 * that is THIS DEVICE'S provisioned peer address on a given gateway (each
 * physical device gets its own AllowedIPs assignment from that gateway's
 * own add-peer.sh-managed peer list), never a fact about the gateway itself.
 * See ClientTunnelIdentityStore for where that's actually resolved from -
 * a real B13 review blocker found a single hardcoded clientTunnelIp baked in
 * here, which is exactly the same class of bug root-caused for Germany
 * below: a per-device value silently assumed to be a global constant.
 *
 * Committing real public IPs/AWG public keys here is consistent with this
 * codebase's own existing practice - ProvisioningClient/GatewayReachabilityProbe
 * already hardcode the Oracle gateway's real IP, and a WireGuard/AmneziaWG
 * public key is exactly as non-secret as an SSH public key (the matching
 * private key never leaves each gateway's own VPS). This is deliberately
 * NOT sourced from the gitignored android/app/gateway-dev.properties file -
 * that remains a genuinely LOCAL, per-developer override for raw AWG
 * smoke-testing, never the product's own gateway-selection mechanism (see
 * SelectedProductionGatewaySource's own docs for what replaces it here).
 */
enum class ProductionGatewayId { GERMANY, STOCKHOLM }

/**
 * The AWG-specific connection facts for one gateway that are genuinely
 * gateway infrastructure, not per-device identity - mirrors
 * GatewayConfigSource's own field shape minus clientTunnelIp (see this
 * file's own top-level docs for why that field does not belong here).
 */
data class AwgGatewayConnection(
    val endpointHost: String,
    val endpointPort: Int,
    val serverPublicKeyBase64: String,
    val gatewayTunnelIp: String,
)

/**
 * Everything the product needs to know about one real gateway. [endpointId]
 * is the SAME technical identifier this codebase's endpoint-scoped machinery
 * already keys everything else by (ConnectionOutcome.gatewayId,
 * PathHistoryStore, XrayProfileRepositoryResolver - see those classes' own
 * docs) - Germany's is EndpointId(ProductionGateway.ID) ("frankfurt"), the
 * exact same value every pre-B13 default already assumed, so selecting
 * Germany is byte-for-byte the historical single-gateway behavior. It is
 * also the SAME key ClientTunnelIdentityStore is looked up by (via
 * [ProductionGatewayId] one level up) for this device's own client tunnel
 * IP on this gateway.
 *
 * [awgProfile] is this gateway's OWN AmneziaWG obfuscation/timing profile -
 * B13's audit found `PocAwgProfile` was a single GLOBAL value silently
 * assumed correct for every gateway, which is what caused Stockholm's
 * physical validation to fail its first handshake attempt (see that
 * incident's own notes) - each gateway now carries its own, and
 * SelectedProductionGatewaySource.profile() resolves whichever one is
 * actually selected, never a single hardcoded default.
 */
data class ProductionGatewayDescriptor(
    val id: ProductionGatewayId,
    val endpointId: EndpointId,
    val displayCountry: String,
    val displayCity: String,
    val provider: String,
    val awg: AwgGatewayConnection,
    val awgProfile: AwgProfile,
)

object ProductionGatewayCatalog {

    /** The original Oracle Cloud gateway - unchanged from every pre-B13 default. */
    val GERMANY = ProductionGatewayDescriptor(
        id = ProductionGatewayId.GERMANY,
        endpointId = EndpointId("frankfurt"),
        displayCountry = "Germany",
        displayCity = "Frankfurt",
        provider = "Oracle Cloud",
        awg = AwgGatewayConnection(
            endpointHost = "152.70.43.1",
            endpointPort = 51820,
            serverPublicKeyBase64 = "9WewKC/zyUPyPnKyzaI0bZrEN2c73PqjK7f+fRXHYRU=",
            gatewayTunnelIp = "10.77.0.1",
        ),
        awgProfile = AwgProfile(
            junkPacketCount = 6,
            junkPacketMinSize = 40,
            junkPacketMaxSize = 100,
            initPacketJunkSize = 113,
            responsePacketJunkSize = 159,
            cookieReplyPacketJunkSize = 0,
            transportPacketJunkSize = 0,
            initPacketMagicHeader = "1106684696",
            responsePacketMagicHeader = "3677857287",
            underloadPacketMagicHeader = "353316806",
            transportPacketMagicHeader = "2068198996",
            randomTrailers = false,
            disableCookies = false,
        ),
    )

    /**
     * The second, independently-provisioned AWS gateway (eu-north-1,
     * Stockholm) - B13's multi-provider/ASN validation target. AWG
     * physically handshake-verified 2026-08-30 (real device, real 8-second
     * timeout window, "Received handshake response" in 48ms, exit IP
     * 16.170.208.231 confirmed via two independent services). REALITY and
     * TLS_TCP are ALSO physically validated on this gateway as of B13 Part 2
     * (2026-08-30) - see docs/ROADMAP.md's Gateway Pool row for the full
     * evidence trail; this gateway is no longer AWG-only.
     */
    val STOCKHOLM = ProductionGatewayDescriptor(
        id = ProductionGatewayId.STOCKHOLM,
        endpointId = EndpointId("stockholm"),
        displayCountry = "Sweden",
        displayCity = "Stockholm",
        provider = "AWS",
        awg = AwgGatewayConnection(
            endpointHost = "16.170.208.231",
            endpointPort = 51820,
            serverPublicKeyBase64 = "XgskJjlpQrp+75Bdnz+yDGJYnv7E6Zd60BJWWj1j5Wk=",
            gatewayTunnelIp = "10.77.0.1",
        ),
        awgProfile = AwgProfile(
            junkPacketCount = 6,
            junkPacketMinSize = 40,
            junkPacketMaxSize = 100,
            initPacketJunkSize = 113,
            responsePacketJunkSize = 159,
            cookieReplyPacketJunkSize = 0,
            transportPacketJunkSize = 0,
            initPacketMagicHeader = "1106684696",
            responsePacketMagicHeader = "3677857287",
            underloadPacketMagicHeader = "353316806",
            transportPacketMagicHeader = "2068198996",
            randomTrailers = false,
            disableCookies = false,
        ),
    )

    val all: List<ProductionGatewayDescriptor> = listOf(GERMANY, STOCKHOLM)

    fun byId(id: ProductionGatewayId): ProductionGatewayDescriptor = when (id) {
        ProductionGatewayId.GERMANY -> GERMANY
        ProductionGatewayId.STOCKHOLM -> STOCKHOLM
    }

    /**
     * B13 consolidated review fix - the ONE place a validated control-plane
     * response (ProvisioningResult.Success) is mapped to a
     * [ProductionGatewayId]. Matches on the FULL set of stable server facts
     * a response carries (host AND port AND the gateway's own public key),
     * never endpointHost alone (a shared/reused host+port with a rotated or
     * wrong key must not be treated as a match) and never the caller's
     * current UI gateway selection (a response is evidence about WHICH
     * gateway actually issued it, not about whatever the user happened to
     * have tapped in the picker).
     *
     * Returns null for anything that does not unambiguously match exactly
     * ONE catalog entry - an unrecognized combination (a dev/staging
     * server, a rotated production key not yet in this catalog, or a
     * malformed/adversarial response) is never guessed at or forced onto
     * the nearest entry. Callers (MainViewModel.activateDevice) MUST treat
     * null as "reject this response", never as "fall back to whichever
     * gateway is currently selected" - see that function's own docs.
     */
    fun matchGatewayId(endpointHost: String, endpointPort: Int, serverPublicKeyBase64: String): ProductionGatewayId? =
        all.singleOrNull {
            it.awg.endpointHost == endpointHost &&
                it.awg.endpointPort == endpointPort &&
                it.awg.serverPublicKeyBase64 == serverPublicKeyBase64
        }?.id
}
