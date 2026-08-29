package net.pocvpn.client.smartconnect

import net.pocvpn.client.network.NetworkProfile
import net.pocvpn.client.network.NetworkType
import net.pocvpn.client.vpn.TransportState

/**
 * B8J - conservative, evidence-based classes ONLY. Deliberately has no
 * DPI_BLOCKED/TSPU_BLOCKED/RUSSIA_BLOCK (or similar) value - this app has no
 * way to observe DPI/TSPU/country-level blocking directly, only the weaker
 * signals below, so no code path may ever claim one of those from
 * insufficient evidence. See RestrictionClassifier.classify's own docs for
 * exactly which evidence produces which class.
 */
enum class RestrictionClass {
    NO_NETWORK,
    CAPTIVE_PORTAL,
    INTERNET_NOT_VALIDATED,
    GATEWAY_HTTPS_UNREACHABLE,
    POSSIBLE_UDP_OR_AWG_FILTERING,
    NETWORK_RECOVERING,
    NO_RESTRICTION_OBSERVED,
    UNKNOWN,
}

/**
 * Everything RestrictionClassifier.classify() is allowed to look at - a
 * closed, non-secret set (see RestrictionEvidenceTest's own field-closure
 * proof, same pattern as ConnectionOutcome). [awgHandshakeFresh] and
 * [gatewayHttpsReachable] are nullable because BOTH are "unknown until
 * observed" - a null never gets treated as false; see classify()'s own
 * UNKNOWN fallback for why that distinction matters.
 */
data class RestrictionEvidence(
    val networkProfile: NetworkProfile,
    val transportState: TransportState,
    /** From the most recent REAL ConnectionOutcome (see VpnController's own recordConnectionOutcome) - null if none yet observed this session. */
    val awgHandshakeFresh: Boolean?,
    /** From the most recent bounded HTTPS probe (see GatewayReachabilityProbe) - null if never probed. */
    val gatewayHttpsReachable: Boolean?,
)

/**
 * B8J - THE ONE place restriction evidence becomes a RestrictionClass. Pure
 * and deterministic - no I/O, no probing, no VpnController/VpnTransport
 * access (see class docs for the enum's own "never claim from insufficient
 * evidence" invariant). Priority order (first match wins), matching the
 * task's own CORE RULES with NETWORK_RECOVERING and the "healthy handshake"
 * short-circuit slotted in where they make evidentiary sense:
 *
 *  1. No network at all (strongest, most fundamental signal)
 *  2. Captive portal (specific, actionable signal)
 *  3. Actively reconnecting, not yet exhausted - don't jump to a filtering
 *     conclusion mid-attempt (see VpnController.reconnectLoop's own docs)
 *  4. A genuinely fresh AWG handshake - the strongest possible "fine" signal
 *  5. Internet present but not validated
 *  6. Validated internet, but the gateway itself is HTTPS-unreachable
 *  7. Validated internet, gateway HTTPS-reachable, but AWG handshake failed
 *     -> the ONLY case allowed to suggest UDP/AWG-specific filtering, and
 *     even then only as "possible", never a confirmed DPI/TSPU/country claim
 *  8. Anything else (missing/contradictory evidence) -> UNKNOWN, never a guess
 */
object RestrictionClassifier {

    fun classify(evidence: RestrictionEvidence): RestrictionClass {
        val profile = evidence.networkProfile
        return when {
            profile.type == NetworkType.NONE -> RestrictionClass.NO_NETWORK
            profile.captivePortal == true -> RestrictionClass.CAPTIVE_PORTAL
            evidence.transportState is TransportState.Reconnecting -> RestrictionClass.NETWORK_RECOVERING
            evidence.awgHandshakeFresh == true -> RestrictionClass.NO_RESTRICTION_OBSERVED
            !profile.validatedInternet -> RestrictionClass.INTERNET_NOT_VALIDATED
            evidence.gatewayHttpsReachable == false -> RestrictionClass.GATEWAY_HTTPS_UNREACHABLE
            evidence.gatewayHttpsReachable == true && evidence.awgHandshakeFresh == false -> RestrictionClass.POSSIBLE_UDP_OR_AWG_FILTERING
            else -> RestrictionClass.UNKNOWN
        }
    }
}
