package net.pocvpn.client.vpn.config

/**
 * B22 - a user's own compatible VPS running the same pinned AmneziaWG
 * gateway (`gateway/provision.sh`) - architecture principle 9 ("Private
 * Gateway Mode is a first-class capability, not a fallback"). Deliberately
 * carries NO client private key field (architecture constraint 1) - the
 * client keypair lives only in a dedicated, AndroidKeyStore-encrypted
 * [net.pocvpn.client.identity.ClientKeyRepository] instance (see
 * [net.pocvpn.client.identity.PrivateGatewayKeyRepositoryFactory]), reusing
 * the EXACT same encrypted-identity architecture
 * [net.pocvpn.client.identity.AwgClientKeyRepository] already provides for
 * the managed network - never a second secret-storage model, never the SAME
 * keypair as the managed identity (a private gateway is a distinct WG peer
 * identity, never linked to the managed-network device fingerprint).
 *
 * [id] is a stable constant (see [ID]) - this slice supports exactly one
 * private gateway (first-slice scope), so there is nothing to disambiguate
 * yet; the field exists so a future multi-private-gateway slice does not
 * need to change this type's shape, only [PrivateGatewayStore]'s.
 *
 * AWG-only (architecture constraint: no Xray/REALITY/TLS/QUIC field exists
 * here at all - this type is structurally incapable of describing anything
 * else). Never enters [ProductionGatewayCatalog] or any signed-manifest
 * type - there is no conversion function to either, by construction.
 */
data class PrivateGatewayConfig(
    val id: String = ID,
    val host: String,
    val port: Int,
    val serverPublicKeyBase64: String,
    val clientTunnelIp: String,
    val gatewayTunnelIp: String,
    val awgProfile: AwgProfile,
) {
    companion object {
        /** Single-slot first-slice scope (FIRST SLICE UX: "exactly one private gateway"). */
        const val ID = "private-gateway"
    }
}

/** Typed, non-secret failure reasons - never a free-text string a UI/log could accidentally leak input into. */
enum class PrivateGatewayConfigFailureReason {
    BLANK_HOST,
    INVALID_HOST_SYNTAX,
    INVALID_PORT,
    INVALID_SERVER_PUBLIC_KEY,
    INVALID_CLIENT_TUNNEL_IP,
    INVALID_GATEWAY_TUNNEL_IP,
    MISSING_REQUIRED_OBFUSCATION_HEADER,
    INVALID_JUNK_PACKET_PARAMETERS,
}

sealed class PrivateGatewayValidationResult {
    data class Valid(val config: PrivateGatewayConfig) : PrivateGatewayValidationResult()
    data class Invalid(val reason: PrivateGatewayConfigFailureReason) : PrivateGatewayValidationResult()
}

/**
 * B22 - fails closed on anything structurally wrong (architecture
 * "SECURITY / VALIDATION" requirement). Reuses the EXISTING
 * [Ipv4Format]/[WgKeyFormat] validators verbatim - the same shape rules
 * [GatewayConfigSnapshotValidator] already applies to managed gateways,
 * never a second/looser copy.
 *
 * The four magic-header obfuscation fields ([AwgProfile.initPacketMagicHeader]/
 * [AwgProfile.responsePacketMagicHeader]/[AwgProfile.underloadPacketMagicHeader]/
 * [AwgProfile.transportPacketMagicHeader]) are required (non-blank) - per
 * [PocAwgProfile]'s own documented distinction, a mismatch on these four is a
 * REAL handshake blocker against `gateway/provision.sh`'s AmneziaWG server,
 * not a cosmetic difference.
 *
 * B22 physical-validation follow-up: the junk packet count/size fields
 * ([AwgProfile.junkPacketCount]/[AwgProfile.junkPacketMinSize]/
 * [AwgProfile.junkPacketMaxSize]/[AwgProfile.initPacketJunkSize]/
 * [AwgProfile.responsePacketJunkSize]/[AwgProfile.cookieReplyPacketJunkSize]/
 * [AwgProfile.transportPacketJunkSize]) remain OPTIONAL here (null is a
 * legal value the validator accepts) - but null is NOT proven sufficient
 * against `gateway/provision.sh`. The actual physical record (see
 * docs/ROADMAP.md's B22 history for the full evidence): with H1-H4 matching
 * the live Stockholm server exactly, but these seven left null, real UDP
 * packets reached the server (confirmed via `tcpdump`) yet no AWG handshake
 * ever completed - `null` produced a real, reproducible connection failure
 * against that exact server, not a working baseline. The physical
 * re-validation that actually succeeded (real handshake, real RX/TX, real
 * distinct exit IP) only happened once the client was configured with the
 * live Stockholm server's FULL profile, these seven fields included
 * (`Jc=6/Jmin=40/Jmax=100/S1=113/S2=159/S3=0/S4=0`).
 *
 * They stay optional here anyway, at the GENERAL-model level, because a
 * DIFFERENT user-operated AmneziaWG VPS is a separate deployment that may
 * genuinely use different values, or a build/config where they are not
 * required at all - this validator has no way to know another operator's
 * server-side profile, so it cannot correctly demand these be non-blank the
 * way it does for H1-H4. `null` here means "the operator did not supply a
 * value" - it must never be read as "these are known unnecessary for a
 * successful connection" for any given server, `gateway/provision.sh`
 * included. [PrivateGatewayDialog] exposes them, unset by default, so the
 * operator can supply their own server's real values - never
 * hardcoded/invented here, only ever the operator's own typed input. When
 * present, each must be a non-negative integer, and a min/max pair must not
 * be inverted - malformed input fails closed with
 * [PrivateGatewayConfigFailureReason.INVALID_JUNK_PACKET_PARAMETERS], never
 * silently dropped or replaced with a guessed default.
 */
object PrivateGatewayConfigValidator {
    private val HOSTNAME = Regex("^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")

    fun validate(
        host: String,
        port: Int,
        serverPublicKeyBase64: String,
        clientTunnelIp: String,
        gatewayTunnelIp: String,
        awgProfile: AwgProfile,
    ): PrivateGatewayValidationResult {
        val trimmedHost = host.trim()
        if (trimmedHost.isEmpty()) {
            return PrivateGatewayValidationResult.Invalid(PrivateGatewayConfigFailureReason.BLANK_HOST)
        }
        if (!Ipv4Format.isValid(trimmedHost) && !HOSTNAME.matches(trimmedHost)) {
            return PrivateGatewayValidationResult.Invalid(PrivateGatewayConfigFailureReason.INVALID_HOST_SYNTAX)
        }
        if (port !in 1..65535) {
            return PrivateGatewayValidationResult.Invalid(PrivateGatewayConfigFailureReason.INVALID_PORT)
        }
        val trimmedKey = serverPublicKeyBase64.trim()
        if (!WgKeyFormat.isValid(trimmedKey)) {
            return PrivateGatewayValidationResult.Invalid(PrivateGatewayConfigFailureReason.INVALID_SERVER_PUBLIC_KEY)
        }
        val trimmedClientIp = clientTunnelIp.trim()
        if (!Ipv4Format.isValid(trimmedClientIp)) {
            return PrivateGatewayValidationResult.Invalid(PrivateGatewayConfigFailureReason.INVALID_CLIENT_TUNNEL_IP)
        }
        val trimmedGatewayIp = gatewayTunnelIp.trim()
        if (!Ipv4Format.isValid(trimmedGatewayIp)) {
            return PrivateGatewayValidationResult.Invalid(PrivateGatewayConfigFailureReason.INVALID_GATEWAY_TUNNEL_IP)
        }
        if (awgProfile.initPacketMagicHeader.isNullOrBlank() ||
            awgProfile.responsePacketMagicHeader.isNullOrBlank() ||
            awgProfile.underloadPacketMagicHeader.isNullOrBlank() ||
            awgProfile.transportPacketMagicHeader.isNullOrBlank()
        ) {
            return PrivateGatewayValidationResult.Invalid(PrivateGatewayConfigFailureReason.MISSING_REQUIRED_OBFUSCATION_HEADER)
        }
        val junkFields = listOf(
            awgProfile.junkPacketCount,
            awgProfile.junkPacketMinSize,
            awgProfile.junkPacketMaxSize,
            awgProfile.initPacketJunkSize,
            awgProfile.responsePacketJunkSize,
            awgProfile.cookieReplyPacketJunkSize,
            awgProfile.transportPacketJunkSize,
        )
        if (junkFields.any { it != null && it < 0 }) {
            return PrivateGatewayValidationResult.Invalid(PrivateGatewayConfigFailureReason.INVALID_JUNK_PACKET_PARAMETERS)
        }
        val jmin = awgProfile.junkPacketMinSize
        val jmax = awgProfile.junkPacketMaxSize
        if (jmin != null && jmax != null && jmin > jmax) {
            return PrivateGatewayValidationResult.Invalid(PrivateGatewayConfigFailureReason.INVALID_JUNK_PACKET_PARAMETERS)
        }

        return PrivateGatewayValidationResult.Valid(
            PrivateGatewayConfig(
                host = trimmedHost,
                port = port,
                serverPublicKeyBase64 = trimmedKey,
                clientTunnelIp = trimmedClientIp,
                gatewayTunnelIp = trimmedGatewayIp,
                awgProfile = awgProfile,
            ),
        )
    }

    /** Re-validates an already-persisted config (defense in depth - see [net.pocvpn.client.vpn.config.PrivateGatewayStore]'s own docs on why a stored value is never trusted blindly at connect time). */
    fun revalidate(config: PrivateGatewayConfig): PrivateGatewayValidationResult = validate(
        host = config.host,
        port = config.port,
        serverPublicKeyBase64 = config.serverPublicKeyBase64,
        clientTunnelIp = config.clientTunnelIp,
        gatewayTunnelIp = config.gatewayTunnelIp,
        awgProfile = config.awgProfile,
    )
}

/**
 * B22 - maps into the EXISTING [GatewayConfigSnapshot]/[GatewayConfigSnapshotValidator]
 * pipeline verbatim (architecture requirement: "converge downstream into the
 * existing immutable GatewayConfigSnapshot") - never a second, parallel
 * config-resolution type. Full-tunnel [allowedIps] (blank -> the validator's
 * own full-tunnel default), matching every other AWG gateway's default.
 */
fun PrivateGatewayConfig.toGatewayConfigSnapshot(): GatewayConfigSnapshot = GatewayConfigSnapshot(
    endpointHost = host,
    endpointPort = port.toString(),
    serverPublicKey = serverPublicKeyBase64,
    clientTunnelIp = clientTunnelIp,
    gatewayTunnelIp = gatewayTunnelIp,
    allowedIps = "",
    profile = awgProfile,
)
