package net.pocvpn.client.transport

/** Whether a transport is real (AVAILABLE) or exists only as a named future slot. */
enum class TransportStatus {
    AVAILABLE,
    NOT_IMPLEMENTED,
}
