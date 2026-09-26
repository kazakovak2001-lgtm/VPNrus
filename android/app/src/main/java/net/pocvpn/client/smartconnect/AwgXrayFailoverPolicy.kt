package net.pocvpn.client.smartconnect

import net.pocvpn.client.diagnostics.VpnError
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.transport.UserTransportPreference
import net.pocvpn.client.vpn.TransportState

/**
 * B8I8 - the ONE place "should this already-completed AWG attempt fall back
 * to Xray" is decided. Pure/no I/O, no coroutines - never touches
 * VpnController/VpnTransport itself, only interprets the ALREADY-observed
 * outcome of an attempt Smart Connect (SmartConnectCandidateSelector - THE
 * one selection authority, untouched by this class) already made and
 * MainViewModel already executed. Deliberately NOT part of
 * TransportOrchestrator (which only ever resolves a kind into an instance,
 * never decides a retry - see its own docs) and NOT a second lifecycle
 * state machine inside VpnController - this is a narrow, stateless
 * eligibility check MainViewModel consults once per connect() attempt.
 *
 * [awgState]/[awgError] are always set together, atomically, by
 * VpnController.doConnectAttempt() for every branch (see that function's
 * own code) - by the time controller.connect(resolution) (a suspend call)
 * returns, both truthfully describe THIS attempt's own outcome, never a
 * stale value left over from an earlier attempt. Both are required (not
 * just [awgError] alone) specifically so a caller that forgets to check the
 * CURRENT state can't accidentally treat a stale VpnError from a PRIOR
 * failed attempt as if it applied to a brand new, actually-successful one.
 */
object AwgXrayFailoverPolicy {

    fun isEligibleForXrayFallback(
        initialKind: TransportKind,
        preference: UserTransportPreference,
        awgState: TransportState,
        awgError: VpnError?,
        xrayAvailable: Boolean,
    ): Boolean {
        // Nothing to "fall back FROM" unless the initial Smart Connect
        // selection (and therefore the attempt just executed) was AWG
        // itself - a direct XRAY_REALITY selection never triggers this.
        if (initialKind != TransportKind.AMNEZIA_WG) return false

        // A user who pinned a specific transport gets exactly that
        // transport, success or failure - never a silent substitute. This
        // also covers "Manual AMNEZIA_WG -> no automatic Xray fallback" and
        // "Manual XRAY_REALITY -> no AWG attempt in the first place" (the
        // latter is already unreachable here via the initialKind check
        // above, but excluded again here for clarity/defense in depth).
        if (preference is UserTransportPreference.Manual) return false

        if (!xrayAvailable) return false

        // Only a genuine TERMINAL failure of THIS attempt is eligible -
        // Connected (success), Connecting/Disconnected/Disconnecting (not a
        // completed attempt at all - e.g. still awaiting a VPN permission
        // prompt, or a user-initiated disconnect/cancellation), and
        // Reconnecting are all excluded by this alone.
        if (awgState !is TransportState.HandshakeFailed && awgState !is TransportState.Error) return false

        // The exact, enumerated "real AWG connection failure" categories -
        // never a catch-all "any Error". Every other VpnError
        // doConnectAttempt can produce (GatewayConfigurationMissing,
        // InvalidGatewayConfiguration, SplitTunnelingNoAppsSelected,
        // ConfigurationMappingFailure, PermissionDenied, AlreadyInProgress) -
        // and every rejectPreflight() error (NoCandidateAvailable,
        // UnsupportedTransportSelected) - represents a preflight/local-
        // configuration/permission problem, never a real connection
        // failure, and is deliberately NOT eligible for fallback.
        return when (awgError) {
            is VpnError.HandshakeTimeout -> true
            is VpnError.BackendStartFailure -> true
            // Recorded only by VpnController.reconnectLoop() - an async,
            // post-Connected retry-exhaustion signal for an attempt that
            // already succeeded once, never the outcome of THIS (the
            // just-executed, still-pending-first-connect) attempt. Listed
            // explicitly rather than folded into the catch-all below so this
            // exclusion is a deliberate, reviewable decision, not an
            // accident of "every other VpnError happens to be false".
            is VpnError.ReconnectExhausted -> false
            else -> false
        }
    }

    /**
     * B66.18 - given that AWG failover is ALREADY eligible (see
     * [isEligibleForXrayFallback], unchanged, still the one gate that
     * decides WHETHER to fail over at all), decides WHICH Xray transport to
     * fail over to. Pure/deterministic, same "no I/O, no second-guessing"
     * discipline as this object's existing function.
     *
     * Prefers the Direct EXIT [TransportKind.XRAY_XHTTP] path B64 already
     * implemented ONLY when the CURRENT restriction evidence specifically
     * points at UDP/AWG-SPECIFIC filtering - never a general internet/
     * gateway problem, which [RestrictionClass.POSSIBLE_UDP_OR_AWG_FILTERING]
     * already exists precisely to distinguish (see RestrictionClassifier's
     * own priority-ordered docs) - with at least [RestrictionEvidenceQuality
     * .MEDIUM] confidence (never [RestrictionEvidenceQuality.LOW]/
     * [RestrictionEvidenceQuality.INSUFFICIENT], which mean the evidence
     * itself is stale/contradictory/incomplete), AND a real Direct EXIT
     * XHTTP profile is available for THIS endpoint. [directXhttpAvailable]
     * is deliberately a plain Boolean, not re-derived here from
     * [net.pocvpn.client.reachability.EndpointId] or any registry - the
     * caller passes `registry.descriptorFor(TransportKind.XRAY_XHTTP)
     * ?.status == TransportStatus.AVAILABLE` for the SAME per-endpoint
     * [net.pocvpn.client.transport.TransportRegistry] instance
     * [isEligibleForXrayFallback] itself was already evaluated against -
     * for a real (non-ingress) gateway endpoint that registry entry's
     * AVAILABLE status is ITSELF backed by MainViewModel's
     * `isXrayXhttpAvailableFor(endpointId)` (see
     * MainViewModel.buildTransportRegistry's B62 docs), never the separate
     * CDN/relay `cdnRuntimeCapabilities.isPinnedXhttpExecutable()` flag - so
     * this function never needs to know about that distinction itself, it
     * only ever sees the already-correctly-gated per-endpoint result.
     *
     * Every other case (wrong/insufficient restriction evidence, or no
     * Direct XHTTP profile for this endpoint) returns the pre-existing
     * [TransportKind.XRAY_REALITY] target, byte-for-byte the same choice
     * this policy always made before this function existed.
     */
    fun selectXrayFailoverTarget(
        restrictionClass: RestrictionClass,
        restrictionEvidenceQuality: RestrictionEvidenceQuality,
        directXhttpAvailable: Boolean,
    ): TransportKind {
        val filteringEvidenceSufficient =
            restrictionClass == RestrictionClass.POSSIBLE_UDP_OR_AWG_FILTERING &&
                (
                    restrictionEvidenceQuality == RestrictionEvidenceQuality.HIGH ||
                        restrictionEvidenceQuality == RestrictionEvidenceQuality.MEDIUM
                    )
        return if (filteringEvidenceSufficient && directXhttpAvailable) {
            TransportKind.XRAY_XHTTP
        } else {
            TransportKind.XRAY_REALITY
        }
    }
}
