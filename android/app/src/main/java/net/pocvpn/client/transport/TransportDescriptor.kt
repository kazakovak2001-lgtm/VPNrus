package net.pocvpn.client.transport

import net.pocvpn.client.vpn.VpnTransport

/**
 * Everything the rest of the app can know about one transport without
 * touching protocol-specific code: what it is, whether it's really
 * implemented, what it can do, and (only when AVAILABLE) how to get a real
 * VpnTransport instance for it.
 *
 * [factory] is null whenever [status] is NOT_IMPLEMENTED - there is nothing
 * to construct, and nothing here may fabricate one.
 */
data class TransportDescriptor(
    val kind: TransportKind,
    val status: TransportStatus,
    val capabilities: TransportCapabilities,
    val factory: (() -> VpnTransport)? = null,
) {
    init {
        require((status == TransportStatus.AVAILABLE) == (factory != null)) {
            "TransportDescriptor for $kind: status=$status must have a factory iff AVAILABLE"
        }
    }
}
