package net.pocvpn.client.vpn

/**
 * Abstraction for a VPN data-plane implementation. Additional transports
 * (fallback, TLS-based, etc.) are added by implementing this interface -
 * no other layer depends on a specific tunnel technology.
 */
interface VpnTransport {
    val name: String
}
