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
    // B28 - real wall-clock timestamps of the probes behind
    // [gatewayHttpsReachable]/[diverseInternetReachable] (see
    // RestrictionMonitor.lastProbeEpochMillis/lastDiverseReachabilityEpochMillis's
    // own docs) - null means "no timestamp supplied", which [classify]
    // treats as legacy behavior (staleness check skipped entirely, the
    // raw value trusted as-is) rather than "immediately stale", so every
    // pre-B28 caller/test constructing this type without these two fields
    // is byte-for-byte unaffected. [awgHandshakeFresh]'s own freshness is
    // deliberately NOT re-modeled here - it already comes from a real,
    // recency-ordered ConnectionOutcome lookup (see MainViewModel
    // .restrictionClass's own "recentConnectionOutcomes().lastOrNull()")
    // which is a narrower, already-real freshness signal; only the
    // RestrictionMonitor-sourced probes had NO staleness handling at all
    // before this field existed.
    val gatewayProbeEpochMillis: Long? = null,
    val diverseProbeEpochMillis: Long? = null,
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

    /** B28 - same 30-minute window ReachabilityEngine.DEFAULT_STALE_AFTER_MILLIS already uses - not a shared constant (this object stays self-contained/pure with no cross-module dependency), but a deliberately identical value so the two staleness disciplines feel like ONE consistent policy, not two independently-tuned ones. */
    const val DEFAULT_STALE_AFTER_MILLIS: Long = 30 * 60 * 1000L

    /**
     * B28 - [nowEpochMillis]/[staleAfterMillis] add explicit, time-bound
     * hysteresis to the two RestrictionMonitor-sourced signals
     * ([RestrictionEvidence.gatewayHttpsReachable]/[RestrictionEvidence
     * .diverseInternetReachable]): once their own probe is older than
     * [staleAfterMillis], [classify] treats them as unknown (null) rather
     * than trusting a possibly-hours-old snapshot forever - the SAME
     * "an expired signal is never trusted indefinitely" discipline
     * ReachabilityEngine.assess already applies to endpoint-specific
     * reachability (see that function's own docs), reused here rather than
     * a second, independently-invented staleness model. [nowEpochMillis]
     * defaults to [Long.MAX_VALUE] (mirrors PathScorer.score's own
     * additive-seam default) so every pre-B28 caller - which never
     * supplied a probe timestamp either - computes byte-for-byte the same
     * classification as before this parameter existed.
     */
    fun classify(evidence: RestrictionEvidence, nowEpochMillis: Long = Long.MAX_VALUE, staleAfterMillis: Long = DEFAULT_STALE_AFTER_MILLIS): RestrictionClass {
        val profile = evidence.networkProfile
        val gatewayHttpsReachable = freshOrTrusted(evidence.gatewayHttpsReachable, evidence.gatewayProbeEpochMillis, nowEpochMillis, staleAfterMillis)
        val diverseInternetReachable = freshOrTrusted(evidence.diverseInternetReachable, evidence.diverseProbeEpochMillis, nowEpochMillis, staleAfterMillis)
        val gatewayUnreachable = gatewayHttpsReachable == false && evidence.awgHandshakeFresh == false
        return when {
            profile.type == NetworkType.NONE -> RestrictionClass.NO_NETWORK
            profile.captivePortal == true -> RestrictionClass.CAPTIVE_PORTAL
            evidence.transportState is TransportState.Reconnecting -> RestrictionClass.NETWORK_RECOVERING
            evidence.awgHandshakeFresh == true -> RestrictionClass.NO_RESTRICTION_OBSERVED
            !profile.validatedInternet -> RestrictionClass.INTERNET_NOT_VALIDATED
            gatewayUnreachable && diverseInternetReachable == false -> RestrictionClass.POSSIBLE_HARD_WHITELIST
            gatewayHttpsReachable == false -> RestrictionClass.GATEWAY_HTTPS_UNREACHABLE
            gatewayHttpsReachable == true && evidence.awgHandshakeFresh == false -> RestrictionClass.POSSIBLE_UDP_OR_AWG_FILTERING
            else -> RestrictionClass.UNKNOWN
        }
    }

    /**
     * Returns [value] unchanged when no timestamp was supplied (legacy
     * trust - see [RestrictionEvidence.gatewayProbeEpochMillis]'s own
     * docs), or when the timestamp is genuinely fresh (non-negative age,
     * no older than [staleAfterMillis] - the same negative-age clock-skew
     * guard ReachabilityEngine.assess already uses). Returns null (never
     * trusted) once stale or future-dated - a stale/expired probe result
     * loses its influence on classification entirely, falling back to
     * whatever a genuinely fresher or absent signal would produce.
     */
    private fun freshOrTrusted(value: Boolean?, epochMillis: Long?, nowEpochMillis: Long, staleAfterMillis: Long): Boolean? {
        if (value == null || epochMillis == null) return value
        val age = nowEpochMillis - epochMillis
        if (age < 0 || age > staleAfterMillis) return null
        return value
    }
}
