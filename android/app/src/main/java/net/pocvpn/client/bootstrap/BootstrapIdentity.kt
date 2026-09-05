package net.pocvpn.client.bootstrap

/**
 * B36 - the bootstrap AmneziaWG client identity used ONLY to reach a
 * restricted, provisioning-only control-plane path before this device has
 * any activation/profile of its own (see
 * docs/B36_BOOTSTRAP_PRE_ACTIVATION_TUNNEL.md).
 *
 * **This is deliberately treated as PUBLIC bootstrap material, never a
 * secret** (task requirement 3/14): every APK ships the exact same
 * [BOOTSTRAP_PRIVATE_KEY_BASE64], so anyone can extract it and dial the same
 * gateways as this exact peer. That is by design - a WireGuard/AmneziaWG
 * private key being "private" only means "the matching public key was
 * derived from it"; it says nothing about whether the key is safe to make
 * widely known, the same way this codebase already treats
 * [net.pocvpn.client.vpn.config.ProductionGatewayCatalog]'s own gateway
 * public keys as non-secret (see that file's own docs). What makes this
 * identity safe to embed is NOT secrecy - it is the server-side restriction
 * a gateway operator must apply to this exact peer's public key before it
 * is usable at all: [BOOTSTRAP_PUBLIC_KEY_BASE64] must be added as an
 * AmneziaWG peer on Frankfurt AND Stockholm with normal internet access
 * explicitly denied (only this device's own reachable-and-restricted
 * control-plane path, port 443 on that SAME gateway's own public IP - see
 * docs/B36_SERVER_DEPLOYMENT_PLAN.md for the exact nftables rules). Until
 * that server-side peer/firewall work is applied, this identity cannot
 * complete a real handshake against either production gateway - that is
 * intentional: this slice ships the client-side plumbing plus the exact
 * server-side plan, never an automatic deployment.
 *
 * **[BOOTSTRAP_PRIVATE_KEY_BASE64]/[BOOTSTRAP_PUBLIC_KEY_BASE64] below are a
 * REAL, freshly generated Curve25519/X25519 keypair** (generated locally via
 * Python's `cryptography` library - RFC 7748 X25519 raw scalar/point
 * encoding, base64, the exact same wire shape `awg genkey`/`awg pubkey`
 * produce) - not a placeholder, not random unrelated bytes. It is used ONLY
 * as this shared bootstrap identity - never as a per-device production
 * credential, never derived from or related to any real gateway's own
 * server keypair in [net.pocvpn.client.vpn.config.ProductionGatewayCatalog].
 * The matching peer entry has NOT been added to either gateway yet - see
 * docs/B36_SERVER_DEPLOYMENT_PLAN.md for the exact, not-yet-applied
 * commands using [BOOTSTRAP_PUBLIC_KEY_BASE64] verbatim. If this identity is
 * ever rotated, generate a fresh keypair with the same tooling and replace
 * both constants together - never reuse an old private key with a new
 * public key or vice versa.
 *
 * [clientTunnelAddressCidr] is this bootstrap peer's own fixed tunnel
 * address, reused identically against both gateways (each gateway's own
 * AmneziaWG subnet is independent - no collision risk, mirrors how every
 * other peer already gets a small fixed AllowedIPs address). It must match
 * whatever address the real server-side peer entry assigns this key.
 */
object BootstrapIdentity {
    const val BOOTSTRAP_PRIVATE_KEY_BASE64: String = "WBz4VryPzCSpZ6N0+Jq0636pZYjD34W4RqkIdWyBQ0s="
    const val BOOTSTRAP_PUBLIC_KEY_BASE64: String = "I/Kv8Kkebdtb5Rem+vdmkq0N3DK/ojQVbQWtoOFxyFE="

    /** This bootstrap peer's own AmneziaWG tunnel-interface address (client side of the tunnel). */
    const val CLIENT_TUNNEL_ADDRESS_CIDR: String = "10.77.0.250/32"
}
