package net.pocvpn.client.smartconnect

import net.pocvpn.client.diagnostics.VpnError
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.transport.UserTransportPreference
import net.pocvpn.client.vpn.TransportState

/**
 * Whether a completed Direct XRAY_REALITY attempt on a manually selected
 * gateway may fall back to TLS_TCP on the SAME gateway, once. Same
 * stateless, no-I/O shape as [AwgXrayFailoverPolicy]: MainViewModel's
 * failover watch consults it both for an initial REALITY attempt and for
 * the REALITY attempt an AWG -> Xray fallback started.
 *
 * Without it, AWG refused (managed reactivation) -> REALITY failed (for
 * example `remote handshake not confirmed`) ended the connect with
 * "Connection failed" while TLS_TCP on that gateway still worked
 * (OPPO CPH2173, Frankfurt, 2026-10-21).
 */
object RealityTlsFailoverPolicy {
    fun isEligibleForTlsFallback(
        initialKind: TransportKind,
        preference: UserTransportPreference,
        realityState: TransportState,
        realityError: VpnError?,
        tlsAvailable: Boolean,
    ): Boolean {
        if (initialKind != TransportKind.XRAY_REALITY) return false
        // A pinned transport is never silently substituted.
        if (preference is UserTransportPreference.Manual) return false
        if (!tlsAvailable) return false
        if (realityState !is TransportState.HandshakeFailed && realityState !is TransportState.Error) return false
        // Only genuine connection failures. VpnController records every
        // terminal Xray Error (including an unconfirmed remote handshake) as
        // HandshakeTimeout; profile/config, permission and preflight errors
        // stay ineligible.
        return when (realityError) {
            is VpnError.HandshakeTimeout -> true
            is VpnError.DataPlaneNoTraffic -> true
            is VpnError.BackendStartFailure -> true
            else -> false
        }
    }
}
