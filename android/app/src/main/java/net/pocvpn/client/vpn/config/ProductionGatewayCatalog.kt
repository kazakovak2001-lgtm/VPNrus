package net.pocvpn.client.vpn.config

import net.pocvpn.client.reachability.EndpointId

/**
 * B13 - the real, hardcoded set of production gateways this app can connect
 * a device to. Two real gateways exist as of 2026-08-30: the original Oracle
 * Cloud gateway (Frankfurt, "Germany") and a second, independently-provisioned
 * AWS gateway (Stockholm) added for B13's multi-provider validation slice -
 * see docs/ROADMAP.md's Gateway Pool row for the full history.
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

/** The AWG-specific connection facts for one gateway - mirrors GatewayConfigSource's own field shape. */
data class AwgGatewayConnection(
    val endpointHost: String,
    val endpointPort: Int,
    val serverPublicKeyBase64: String,
    val clientTunnelIp: String,
    val gatewayTunnelIp: String,
)

/**
 * Everything the product needs to know about one real gateway. [endpointId]
 * is the SAME technical identifier this codebase's endpoint-scoped machinery
 * already keys everything else by (ConnectionOutcome.gatewayId,
 * PathHistoryStore, XrayProfileRepositoryResolver - see those classes' own
 * docs) - Germany's is EndpointId(ProductionGateway.ID) ("frankfurt"), the
 * exact same value every pre-B13 default already assumed, so selecting
 * Germany is byte-for-byte the historical single-gateway behavior.
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
        // B13 (2026-08-30 Germany data-plane root cause) - clientTunnelIp
        // MUST match the gateway's OWN live peer registration for this
        // device's public key, never an assumed/stale value: SSH diagnosis
        // found the server's add-peer.sh-managed peer list assigns THIS
        // device's real public key AllowedIPs = 10.77.0.5/32 (a later
        // re-provisioning, label provision-peer-1788077883) - the app was
        // still configured with the OLDER 10.77.0.2, which now belongs to a
        // DIFFERENT peer entirely. WireGuard's AllowedIPs is both a route
        // table AND a source-IP ingress filter, so packets from the wrong
        // local address get silently dropped post-handshake (the handshake
        // itself doesn't check AllowedIPs, which is exactly why it kept
        // succeeding while all data traffic timed out). Zero server-side
        // change was needed - gateway A's firewall/NAT/forwarding were
        // already correct; this was purely a stale client-side value.
        awg = AwgGatewayConnection(
            endpointHost = "152.70.43.1",
            endpointPort = 51820,
            serverPublicKeyBase64 = "9WewKC/zyUPyPnKyzaI0bZrEN2c73PqjK7f+fRXHYRU=",
            clientTunnelIp = "10.77.0.5",
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
     * 16.170.208.231 confirmed via two independent services). REALITY/TLS
     * are not yet deployed on this gateway - see docs/ROADMAP.md.
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
            clientTunnelIp = "10.77.0.2",
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
}
