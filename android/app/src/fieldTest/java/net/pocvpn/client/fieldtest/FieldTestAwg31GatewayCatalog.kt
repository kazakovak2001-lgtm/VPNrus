package net.pocvpn.client.fieldtest

import net.pocvpn.client.vpn.config.AwgGatewayConnection
import net.pocvpn.client.vpn.config.AwgProfile
import net.pocvpn.client.vpn.config.ProductionGatewayDescriptor
import net.pocvpn.client.vpn.config.ProductionGatewayId

/**
 * B37 - the AWG 3.1 field-test gateway facts, deliberately SEPARATE from
 * [net.pocvpn.client.vpn.config.ProductionGatewayCatalog]. Same two physical
 * hosts (Frankfurt/Oracle, Stockholm/AWS - [ProductionGatewayId] is reused
 * unchanged, this is still "the same gateway", just a different interface on
 * it) but a DIFFERENT, isolated AmneziaWG interface on each:
 *
 * - isolated UDP port `51821` (never the production `51820`),
 * - isolated interface name `awg-ft31` (never production `awg0`),
 * - isolated subnet `10.77.31.0/24` (never production `10.77.0.0/24`),
 * - a dedicated per-gateway server keypair and `HeaderProtectionKey` that
 *   exist ONLY on that isolated interface.
 *
 * Why isolated rather than an in-place peer on the existing `awg0`: this
 * repo's OWN history (see `PocAwgProfile`'s "B8B3B correction" doc)
 * previously found that `gateway/README.md`'s B5A audit had WRONGLY
 * classified some AmneziaWG parameters (S1-S4/H1-H4) as "client-side only,
 * no need to match" when they actually must match the live server exactly
 * or the handshake silently fails. The same audit made an unverified
 * "client-side only" claim about the genuinely NEW AWG 3.1 fields this
 * profile turns on for the first time (I1-I5, HeaderProtectionKey,
 * ContentPaddingAddition) - given that exact class of claim has already
 * been wrong once in this codebase, enabling `HeaderProtectionKey`
 * (an interface-level setting shared by every peer on that interface) on
 * the SHARED production `awg0` would risk silently breaking every existing
 * production peer if the claim is wrong again. An isolated interface with
 * exactly one peer removes that risk entirely: if a parameter is
 * misconfigured, only this one field-test peer fails to handshake, and
 * production traffic is provably unaffected because `awg0` itself is never
 * touched (see the B37 task report's server-change list: peer/interface
 * ADDITIONS only, zero edits to the existing `awg0.conf`/`pocvpn.nft`
 * runtime).
 *
 * All values below are grounded in this repo's own verified facts:
 * - [ProductionGatewayDescriptor.awg.endpointHost] is the SAME real host IP
 *   already committed in `ProductionGatewayCatalog` (non-secret, same
 *   posture that file documents for gateway public keys).
 * - [AwgGatewayConnection.serverPublicKeyBase64]/the `HeaderProtectionKey`
 *   below are REAL, freshly generated X25519/random 32-byte keys generated
 *   the same way [FieldTestAwg31Identity]'s client key was (Python
 *   `cryptography`, RFC 7748 raw encoding - the same wire shape
 *   `awg genkey`/`awg pubkey` produce), NOT placeholders - but the matching
 *   PRIVATE halves are not committed here (never committed to git, same
 *   posture as every other server private key in this repo - see the B37
 *   task report for the exact, not-yet-applied `awg-ft31.conf` deployment
 *   commands that carry them).
 * - The junk/padding/magic-header values (`Jc/Jmin/Jmax`, `S1-S4`, `H1-H4`)
 *   are the ORIGINAL POC-01 profile declared in
 *   `gateway/config/awg-profile.env` (not the live-drifted values
 *   `PocAwgProfile` had to correct to for the ALREADY-RUNNING `awg0` - this
 *   is a brand-new interface with no drift history, so the originally
 *   declared profile is used directly), bumped nowhere except where the
 *   newly-enabled `HeaderProtectionKey` feature itself requires it: the
 *   pinned `amneziawg-go` README (fetched 2026-09-06, see B37 task report)
 *   documents "`S1-S4` must be >= 12 when `HeaderProtectionKey` is set" -
 *   `awg-profile.env`'s declared 15/20/15/20 already satisfies this.
 * - `I1-I5` use the pinned `amneziawg-go` README's own documented tag
 *   syntax (`<r N>` = N random bytes, `<t>` = a UNIX timestamp field) -
 *   never an invented format.
 */
object FieldTestAwg31GatewayCatalog {

    /** Isolated AWG 3.1 field-test interface facts shared by both gateways. */
    const val FIELD_TEST_PORT: Int = 51821
    const val FIELD_TEST_INTERFACE_NAME: String = "awg-ft31"
    const val FIELD_TEST_SUBNET_CIDR: String = "10.77.31.0/24"

    private val FIELD_TEST_PROFILE_BASE = AwgProfile(
        junkPacketCount = 6,
        junkPacketMinSize = 40,
        junkPacketMaxSize = 100,
        initPacketJunkSize = 15,
        responsePacketJunkSize = 20,
        cookieReplyPacketJunkSize = 15,
        transportPacketJunkSize = 20,
        initPacketMagicHeader = "1190494288",
        responsePacketMagicHeader = "1190494289",
        underloadPacketMagicHeader = "1190494290",
        transportPacketMagicHeader = "1190494291",
        // Genuine AWG 3.1 differentiators - never enabled on production awg0
        // (see this file's own top-level docs for why an isolated interface
        // is required to turn these on safely).
        specialJunkI1 = "<r 40>",
        specialJunkI2 = "<r 60>",
        specialJunkI3 = "<r 30>",
        specialJunkI4 = "<r 50>",
        specialJunkI5 = "<t>",
        contentPaddingAddition = "0-64",
        randomTrailers = false,
        disableCookies = false,
    )

    val GERMANY = ProductionGatewayDescriptor(
        id = ProductionGatewayId.GERMANY,
        endpointId = net.pocvpn.client.reachability.EndpointId("frankfurt"),
        displayCountry = "Germany",
        displayCity = "Frankfurt",
        provider = "Oracle Cloud",
        awg = AwgGatewayConnection(
            endpointHost = "152.70.43.1",
            endpointPort = FIELD_TEST_PORT,
            serverPublicKeyBase64 = "8BcUTaT7bNtj2yBie55/JvjCTyN/WWyusuAO3DpujCo=",
            gatewayTunnelIp = "10.77.31.1",
        ),
        awgProfile = FIELD_TEST_PROFILE_BASE.copy(
            headerProtectionKeyBase64 = "WG34LjocwsgXzyzJ1qa6ebvCTmmAEwVPJ7pbxiWXdWA=",
        ),
    )

    val STOCKHOLM = ProductionGatewayDescriptor(
        id = ProductionGatewayId.STOCKHOLM,
        endpointId = net.pocvpn.client.reachability.EndpointId("stockholm"),
        displayCountry = "Sweden",
        displayCity = "Stockholm",
        provider = "AWS",
        awg = AwgGatewayConnection(
            endpointHost = "16.170.208.231",
            endpointPort = FIELD_TEST_PORT,
            serverPublicKeyBase64 = "+IQC4V9RVrLkjJ+PSGJN4HwtfZK8TqekKKqic0vHcyU=",
            gatewayTunnelIp = "10.77.31.1",
        ),
        awgProfile = FIELD_TEST_PROFILE_BASE.copy(
            headerProtectionKeyBase64 = "2JsP+5LZgiF/L7NZ3NrKN6dP9UxxK+/simxOyoBt72Y=",
        ),
    )

    fun byId(id: ProductionGatewayId): ProductionGatewayDescriptor = when (id) {
        ProductionGatewayId.GERMANY -> GERMANY
        ProductionGatewayId.STOCKHOLM -> STOCKHOLM
    }
}
