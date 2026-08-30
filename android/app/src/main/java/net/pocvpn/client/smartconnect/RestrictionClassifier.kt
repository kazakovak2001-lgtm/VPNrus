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
    /**
     * B8M - architecture principle 3's "HARD_WHITELIST" failure condition,
     * named POSSIBLE (never a confirmed claim, same discipline as
     * POSSIBLE_UDP_OR_AWG_FILTERING) - see classify()'s own docs for
     * exactly which evidence produces it. Passive/observational only (only
     * ever set from real HTTPS reachability results already observed) -
     * never implemented by impersonating any third-party service
     * (architecture principle 4).
     */
    POSSIBLE_HARD_WHITELIST,
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
    /**
     * B8M - whether a STRICT MAJORITY of several diverse, unrelated,
     * well-known real HTTPS destinations were reachable in the most recent
     * round of probes (see DiverseReachabilityEvaluator/RestrictionMonitor's
     * own docs) - never the same host as [gatewayHttpsReachable], and never
     * a single destination (see DiverseReachabilityEvaluator's own
     * majority-not-any/all reasoning). Null if never probed.
     */
    val diverseInternetReachable: Boolean? = null,
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
 *  6. Validated internet, gateway unreachable via BOTH HTTPS AND AWG (never
 *     either alone - a CONFIRMED-reachable HTTPS control-plane is positive
 *     evidence against a narrow allowlist, even if AWG itself failed; that
 *     specific case is rule 8's own, more precise claim, not this one), AND
 *     a STRICT MAJORITY of several diverse, unrelated real destinations are
 *     ALSO unreachable -> the ONLY case allowed to suggest a possible fixed
 *     allowlist (architecture principle 3's HARD_WHITELIST condition), and
 *     even then only as "possible" (see POSSIBLE_HARD_WHITELIST's own
 *     docs) - MUST be checked before rules 7/8 below, since it is a more
 *     specific refinement of the same underlying gateway failure they
 *     describe, requiring strictly more (diverse AND dual-protocol, not
 *     just gateway-only) evidence
 *  7. Validated internet, but the gateway itself is HTTPS-unreachable
 *  8. Validated internet, gateway HTTPS-reachable, but AWG handshake failed
 *     -> the ONLY case allowed to suggest UDP/AWG-specific filtering, and
 *     even then only as "possible", never a confirmed DPI/TSPU/country claim
 *  9. Anything else (missing/contradictory evidence) -> UNKNOWN, never a guess
 */
object RestrictionClassifier {

    fun classify(evidence: RestrictionEvidence): RestrictionClass {
        val profile = evidence.networkProfile
        val gatewayUnreachable = evidence.gatewayHttpsReachable == false && evidence.awgHandshakeFresh == false
        return when {
            profile.type == NetworkType.NONE -> RestrictionClass.NO_NETWORK
            profile.captivePortal == true -> RestrictionClass.CAPTIVE_PORTAL
            evidence.transportState is TransportState.Reconnecting -> RestrictionClass.NETWORK_RECOVERING
            evidence.awgHandshakeFresh == true -> RestrictionClass.NO_RESTRICTION_OBSERVED
            !profile.validatedInternet -> RestrictionClass.INTERNET_NOT_VALIDATED
            gatewayUnreachable && evidence.diverseInternetReachable == false -> RestrictionClass.POSSIBLE_HARD_WHITELIST
            evidence.gatewayHttpsReachable == false -> RestrictionClass.GATEWAY_HTTPS_UNREACHABLE
            evidence.gatewayHttpsReachable == true && evidence.awgHandshakeFresh == false -> RestrictionClass.POSSIBLE_UDP_OR_AWG_FILTERING
            else -> RestrictionClass.UNKNOWN
        }
    }
}
