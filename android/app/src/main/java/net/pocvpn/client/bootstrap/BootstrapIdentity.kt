package net.pocvpn.client.bootstrap

/**
 * B36 - the bootstrap AmneziaWG client identity used ONLY to reach a
 * restricted, provisioning-only control-plane path before this device has
 * any activation/profile of its own (see
 * docs/B36_BOOTSTRAP_PRE_ACTIVATION_TUNNEL.md).
 *
 * **This is deliberately treated as PUBLIC bootstrap material, never a
 * secret** (task requirement 3/14): every APK ships the exact same
 * [privateKeyBase64], so anyone can extract it and dial the same gateways as
 * this exact peer. That is by design - a WireGuard/AmneziaWG private key
 * being "private" only means "the matching public key was derived from it";
 * it says nothing about whether the key is safe to make widely known, the
 * same way this codebase already treats [net.pocvpn.client.vpn.config.ProductionGatewayCatalog]'s
 * own gateway public keys as non-secret (see that file's own docs). What
 * makes this identity safe to embed is NOT secrecy - it is the server-side
 * restriction a gateway operator must apply to this exact peer's public key
 * before it is usable at all: [PLACEHOLDER_PUBLIC_KEY_BASE64] must be added
 * as an AmneziaWG peer on Frankfurt AND Stockholm with normal internet
 * access explicitly denied (only this device's own reachable-and-restricted
 * control-plane path, port 443 on that SAME gateway's own public IP - see
 * the plan document for the exact firewall rule). Until that server-side
 * peer/firewall work is done, this identity cannot complete a real
 * handshake against either production gateway - that is intentional: this
 * PR ships ONLY the client-side plumbing, per its own task's "do not deploy
 * anything" constraint.
 *
 * **[privateKeyBase64]/[publicKeyBase64] below are PLACEHOLDER, locally
 * generated 32-byte values for wiring/shape purposes only** - they are
 * ordinary random bytes, not a real Curve25519 keypair (no scalar
 * clamping/point derivation was performed, and [publicKeyBase64] is NOT
 * mathematically derived from [privateKeyBase64]). They exist so this
 * module's types/tests compile and exercise real-shaped data end to end.
 * **Before any real server-side bootstrap peer is added, the repository
 * owner must generate a genuine keypair** (e.g. `awg genkey | tee
 * bootstrap.key | awg pubkey`, the same tooling already used for every real
 * gateway/peer key in this codebase) and replace both constants here -
 * never reuse these placeholder bytes as a live credential.
 *
 * [clientTunnelAddressCidr] is this bootstrap peer's own fixed tunnel
 * address, reused identically against both gateways (each gateway's own
 * AmneziaWG subnet is independent - no collision risk, mirrors how every
 * other peer already gets a small fixed AllowedIPs address). It must match
 * whatever address the real server-side peer entry assigns this key.
 */
object BootstrapIdentity {
    const val PLACEHOLDER_PRIVATE_KEY_BASE64: String = "JbbK2npF4/GgmH0wy2qYYdmYZMpK6rR6zJjXWPOWhL0="
    const val PLACEHOLDER_PUBLIC_KEY_BASE64: String = "7wnNxp6oYnoG6KKUd17Aqlq4xk762aLDc3emsGPyujQ="

    /** This bootstrap peer's own AmneziaWG tunnel-interface address (client side of the tunnel). */
    const val CLIENT_TUNNEL_ADDRESS_CIDR: String = "10.77.0.250/32"
}
