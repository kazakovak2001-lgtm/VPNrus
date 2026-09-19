package net.pocvpn.client.fieldtest

/**
 * B37 - dedicated AWG 3.1 field-test client identity, used ONLY on the
 * isolated `awg-ft31` interface (see [FieldTestAwg31GatewayCatalog]) - never
 * the shared production `awg0` interface.
 *
 * DELIBERATELY a fresh keypair, not a reuse of [FieldTestIdentity] (B36's
 * disposable field-test identity): this identity is provisioned against a
 * DIFFERENT server-side interface/port/subnet (`awg-ft31`, isolated UDP
 * port, isolated `10.77.31.0/24` subnet - see [FieldTestAwg31GatewayCatalog]
 * and `gateway/config/awg-ft31.conf.example`), so reusing the old
 * `10.77.0.251/32` tunnel address here would be a real, wrong-subnet
 * assignment, not merely a stylistic choice.
 *
 * Same non-secrecy posture as [FieldTestIdentity]: embedded in a disposable
 * diagnostic APK, must be considered public/extractable. Never reuse this
 * identity for anything other than this AWG 3.1 field test; rotate (new
 * keypair, new isolated peer) rather than reuse if this build is ever
 * produced again.
 *
 * [FIELD_TEST_AWG31_PRIVATE_KEY_BASE64]/[FIELD_TEST_AWG31_PUBLIC_KEY_BASE64]
 * are a REAL, freshly generated Curve25519/X25519 keypair (generated locally
 * via Python's `cryptography` library, RFC 7748 raw scalar/point encoding -
 * the same wire shape `awg genkey`/`awg pubkey` produce), not a placeholder.
 * The matching peer entry must be added to the isolated `awg-ft31` interface
 * on BOTH Frankfurt and Stockholm before this build can complete a real
 * handshake - see the B37 task report for the exact, not-yet-applied
 * deployment commands (not committed to this repository).
 */
object FieldTestAwg31Identity {
    const val FIELD_TEST_AWG31_PRIVATE_KEY_BASE64: String = "OD1MXbRDgeqEAqZVVb/2JVVFJ1grO6SCV7ijmZd86Uw="
    const val FIELD_TEST_AWG31_PUBLIC_KEY_BASE64: String = "Pue7LA2UDHl6dfCmXnpLhV6P4q667O3GRAKqe8W7lVY="

    /**
     * This field-test peer's own fixed tunnel-interface address on the
     * isolated `awg-ft31` subnet (`10.77.31.0/24`), reused identically on
     * both gateways (each gateway's own isolated AWG 3.1 subnet is
     * independent - no collision risk). Distinct from
     * [FieldTestIdentity.CLIENT_TUNNEL_ADDRESS_CIDR] (10.77.0.251/32, the
     * legacy field-test identity's address on the SHARED production `awg0`
     * subnet) and from the isolated interface's own gateway address
     * (10.77.31.1).
     */
    const val CLIENT_TUNNEL_ADDRESS_CIDR: String = "10.77.31.2/32"
}
