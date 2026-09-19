package net.pocvpn.client.fieldtest

/**
 * Russia field-test build (FIELD_TEST_ONLY) - a dedicated, disposable AWG
 * client identity used ONLY by this diagnostic build to test whether the
 * existing real AWG data plane can carry general Internet traffic from a
 * restricted Russian network, with registration/provisioning/activation
 * completely removed from the equation.
 *
 * This identity is DELIBERATELY SEPARATE from:
 * - [net.pocvpn.client.bootstrap.BootstrapIdentity] (B36's restricted,
 *   control-plane-only pre-activation peer - this identity is a NORMAL,
 *   full-tunnel peer, never restricted the way that one is server-side);
 * - any real user's production per-device profile
 *   ([net.pocvpn.client.vpn.config.ClientTunnelIdentityStore]/
 *   [net.pocvpn.client.vpn.config.ProvisionedProfileStore]);
 * - any other test device's identity.
 *
 * **Trust boundary, explicit**: this key is embedded in a disposable
 * diagnostic APK and MUST be considered public/extractable - exactly the
 * same non-secrecy posture [net.pocvpn.client.bootstrap.BootstrapIdentity]
 * already documents for the same reason. That is acceptable for this
 * one-off field test only because the matching server-side peer carries
 * normal Internet access (not restricted like bootstrap) but is otherwise
 * an ordinary, revocable AWG peer - never a production user's own credential.
 * Never reuse this identity for anything other than this field test; rotate
 * (new keypair, new server-side peer) rather than reuse if this build is
 * ever produced again.
 *
 * [FIELD_TEST_PRIVATE_KEY_BASE64]/[FIELD_TEST_PUBLIC_KEY_BASE64] are a REAL,
 * freshly generated Curve25519/X25519 keypair (generated locally via
 * Python's `cryptography` library, RFC 7748 raw scalar/point encoding, the
 * same wire shape `awg genkey`/`awg pubkey` produce) - not a placeholder.
 * The matching peer entry must be added to BOTH Frankfurt and Stockholm
 * before this build can complete a real handshake - see the field-test
 * server-side setup commands recorded alongside this change (not committed
 * to this repository - see the task report for the exact, not-yet-applied
 * commands).
 */
object FieldTestIdentity {
    const val FIELD_TEST_PRIVATE_KEY_BASE64: String = "4FItbS5xOT2BnyNcnGV/5QA6FA7d6NsCbScbboSJk00="
    const val FIELD_TEST_PUBLIC_KEY_BASE64: String = "MWF0412X2xLalQD1BrW39z/yCPW/Hy3z1O19WvTIbSs="

    /**
     * This field-test peer's own fixed AmneziaWG tunnel-interface address,
     * reused identically on both gateways (each gateway's own AWG subnet is
     * independent - no collision risk). Distinct from
     * [net.pocvpn.client.bootstrap.BootstrapIdentity.CLIENT_TUNNEL_ADDRESS_CIDR]
     * (10.77.0.250) and from the gateway's own address (10.77.0.1).
     */
    const val CLIENT_TUNNEL_ADDRESS_CIDR: String = "10.77.0.251/32"
}
