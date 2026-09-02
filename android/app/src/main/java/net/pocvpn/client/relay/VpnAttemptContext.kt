package net.pocvpn.client.relay

/**
 * B25 (task A) - the real, typed session/attempt identity threaded through
 * the existing MainViewModel -> TransportOrchestrator -> VpnController ->
 * Xray/VpnService runtime path, without a second controller. Pinned exactly
 * once, at the moment a candidate is resolved into a
 * [net.pocvpn.client.transport.TransportOrchestrator.Resolution.Resolved]
 * (the SAME pinning discipline B16's [net.pocvpn.client.vpn.config.GatewayConfigSnapshot]
 * already established for gateway identity), and carried unchanged for the
 * whole attempt via [net.pocvpn.client.vpn.VpnController]'s own pinned
 * field - never re-derived mid-attempt from a transport kind or endpoint
 * name (the task's own "without guessing from endpoint names or transport
 * type" requirement).
 *
 * [Direct] is the default for every pre-B25 caller - byte-for-byte the same
 * behavior as before this type existed. [Relayed] carries the exact
 * [RelayedExecutionPlan] this attempt was built from, so downstream code
 * (Protected gating, path-history ownership - see [net.pocvpn.client.vpn.VpnSessionHealth]
 * and [net.pocvpn.client.vpn.VpnController]'s own docs) never needs a
 * second, independent way to ask "is this attempt relayed".
 */
sealed class VpnAttemptContext {
    object Direct : VpnAttemptContext()
    data class Relayed(val plan: RelayedExecutionPlan) : VpnAttemptContext()
}
