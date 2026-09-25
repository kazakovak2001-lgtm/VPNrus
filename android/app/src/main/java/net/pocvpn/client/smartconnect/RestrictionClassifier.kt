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
    /**
     * B-WL1 - TCP flows connect, handshake and receive an initial payload,
     * then stop progressing without a reset (see TransportBehaviorAnalyzer).
     * Behavioral, never a byte-count rule; only ever produced from supplied
     * [RestrictionEvidence.transportObservations].
     */
    POSSIBLE_EARLY_DROP,
    /**
     * B-WL1 - UDP attempts got no response while TCP handshakes/progress on
     * the same network succeeded. Deliberately distinct from
     * [POSSIBLE_UDP_OR_AWG_FILTERING], whose trigger (the last outcome of ANY
     * transport failing plus a reachable gateway) is not UDP-specific: only
     * this behavior-derived class drives transport-level (UDP vs TCP) ranking
     * in PathScorer.
     */
    POSSIBLE_UDP_FILTERING,
    /**
     * B-WL1 - the OS cannot validate internet AND every observed attempt,
     * across at least two distinct destinations, failed before any payload.
     * Still "possible": this app cannot see the operator's side.
     */
    POSSIBLE_FULL_SHUTDOWN,
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
    /**
     * B-WL1 - recent per-attempt transport behavior (see
     * [TransportAttemptObservation]'s own no-secrets contract). Empty by
     * default, in which case [RestrictionClassifier.classify] is
     * byte-for-byte its pre-B-WL1 self.
     */
    val transportObservations: List<TransportAttemptObservation> = emptyList(),
)

/** B40 - qualitative strength of the currently supplied evidence. This is
 * deliberately not a probability and is never used as a second routing
 * authority. */
enum class RestrictionEvidenceQuality { HIGH, MEDIUM, LOW, INSUFFICIENT }

enum class RestrictionContradictionState { NONE, PRESENT }

enum class RestrictionEvidenceReason {
    NETWORK_ABSENT, CAPTIVE_PORTAL_PRESENT, ACTIVE_RECONNECT,
    FRESH_AWG_SUCCESS, INTERNET_NOT_VALIDATED, GATEWAY_HTTPS_FAILED,
    DIVERSE_REACHABILITY_FAILED, DIVERSE_REACHABILITY_SUCCEEDED,
    AWG_FAILED, EVIDENCE_STALE, EVIDENCE_INCOMPLETE, EVIDENCE_CONTRADICTORY,
    // B-WL1 - the transport-behavior pattern that drove (or informed) the class.
    TRANSPORT_SUSTAINED_PROGRESS, TRANSPORT_EARLY_DROP, TRANSPORT_REPEATED_EARLY_DROP,
    TRANSPORT_EARLY_DROP_MULTI_DESTINATION, TRANSPORT_UDP_NO_RESPONSE, TRANSPORT_ALL_CONNECT_FAILED,
}

data class RestrictionAssessment(
    val classification: RestrictionClass,
    val evidenceQuality: RestrictionEvidenceQuality,
    val contradictionState: RestrictionContradictionState,
    val reasons: Set<RestrictionEvidenceReason>,
    /** B-WL1 - the transport-behavior assessment behind this result; null when no observations were supplied. */
    val transportBehavior: TransportBehaviorAssessment? = null,
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

    /** B40 - additive assessment view over the same single classify() authority. */
    fun assess(evidence: RestrictionEvidence, nowEpochMillis: Long = Long.MAX_VALUE, staleAfterMillis: Long = DEFAULT_STALE_AFTER_MILLIS): RestrictionAssessment {
        val behavior = behaviorOf(evidence, nowEpochMillis, staleAfterMillis)
        val (classification, behaviorDriven) = decide(evidence, behavior, nowEpochMillis, staleAfterMillis)
        val reasons = linkedSetOf<RestrictionEvidenceReason>()
        val gatewayFresh = freshOrTrusted(evidence.gatewayHttpsReachable, evidence.gatewayProbeEpochMillis, nowEpochMillis, staleAfterMillis)
        val diverseFresh = freshOrTrusted(evidence.diverseInternetReachable, evidence.diverseProbeEpochMillis, nowEpochMillis, staleAfterMillis)
        if (evidence.networkProfile.type == NetworkType.NONE) reasons += RestrictionEvidenceReason.NETWORK_ABSENT
        if (evidence.networkProfile.captivePortal == true) reasons += RestrictionEvidenceReason.CAPTIVE_PORTAL_PRESENT
        if (evidence.transportState is TransportState.Reconnecting) reasons += RestrictionEvidenceReason.ACTIVE_RECONNECT
        if (evidence.awgHandshakeFresh == true) reasons += RestrictionEvidenceReason.FRESH_AWG_SUCCESS
        if (!evidence.networkProfile.validatedInternet) reasons += RestrictionEvidenceReason.INTERNET_NOT_VALIDATED
        if (gatewayFresh == false) reasons += RestrictionEvidenceReason.GATEWAY_HTTPS_FAILED
        if (diverseFresh == false) reasons += RestrictionEvidenceReason.DIVERSE_REACHABILITY_FAILED
        if (diverseFresh == true) reasons += RestrictionEvidenceReason.DIVERSE_REACHABILITY_SUCCEEDED
        if (evidence.awgHandshakeFresh == false) reasons += RestrictionEvidenceReason.AWG_FAILED
        if ((evidence.gatewayHttpsReachable != null && gatewayFresh == null) || (evidence.diverseInternetReachable != null && diverseFresh == null)) {
            reasons += RestrictionEvidenceReason.EVIDENCE_STALE
        }
        if (gatewayFresh == null || diverseFresh == null || (classification == RestrictionClass.UNKNOWN && evidence.awgHandshakeFresh == null)) {
            reasons += RestrictionEvidenceReason.EVIDENCE_INCOMPLETE
        }
        val contradiction = evidence.awgHandshakeFresh == true && gatewayFresh == false || gatewayFresh == true && diverseFresh == false
        if (contradiction) reasons += RestrictionEvidenceReason.EVIDENCE_CONTRADICTORY
        behavior?.let { reasons += behaviorReason(it.pattern) ?: return@let }
        val quality = when {
            // B-WL1 - a class reached through transport behavior carries that
            // behavior's own qualitative confidence (single occurrence LOW,
            // reproduced HIGH), downgraded on contradiction - never the
            // probe-completeness rule below, which does not describe it.
            behaviorDriven && behavior != null -> if (contradiction && behavior.quality != RestrictionEvidenceQuality.INSUFFICIENT) RestrictionEvidenceQuality.LOW else behavior.quality
            classification == RestrictionClass.UNKNOWN || reasons.contains(RestrictionEvidenceReason.EVIDENCE_INCOMPLETE) -> RestrictionEvidenceQuality.INSUFFICIENT
            contradiction -> RestrictionEvidenceQuality.LOW
            classification == RestrictionClass.POSSIBLE_HARD_WHITELIST && gatewayFresh != null && diverseFresh != null -> RestrictionEvidenceQuality.HIGH
            evidence.awgHandshakeFresh != null || gatewayFresh != null || diverseFresh != null -> RestrictionEvidenceQuality.MEDIUM
            else -> RestrictionEvidenceQuality.LOW
        }
        return RestrictionAssessment(classification, quality, if (contradiction) RestrictionContradictionState.PRESENT else RestrictionContradictionState.NONE, reasons, behavior)
    }

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
    fun classify(evidence: RestrictionEvidence, nowEpochMillis: Long = Long.MAX_VALUE, staleAfterMillis: Long = DEFAULT_STALE_AFTER_MILLIS): RestrictionClass =
        decide(evidence, behaviorOf(evidence, nowEpochMillis, staleAfterMillis), nowEpochMillis, staleAfterMillis).first

    /**
     * B-WL1 - the single priority chain behind [classify]/[assess]. Returns the
     * class plus whether transport BEHAVIOR (rather than the pre-existing
     * probe rules) decided it. With no observations every behavior branch is
     * skipped and the chain is exactly the documented 1-9 order above. The
     * behavior branches slot in where they are strictly more specific:
     *  - 4b sustained end-to-end progress -> NO_RESTRICTION_OBSERVED (a real
     *       working-flow signal, as strong as rule 4's fresh AWG handshake);
     *  - 5  unvalidated internet + ALL_CONNECT_FAILED across >=2 destinations
     *       -> POSSIBLE_FULL_SHUTDOWN (a refinement of INTERNET_NOT_VALIDATED);
     *  - 6  ALL_CONNECT_FAILED while diverse probes also fail -> POSSIBLE_HARD_WHITELIST
     *       (the only behavior branch contrasting blocked vs. otherwise-reachable);
     *  - 6b early drop (single, repeated, or across destinations) -> POSSIBLE_EARLY_DROP -
     *       never HARD_WHITELIST: stalls on many foreign destinations say nothing
     *       about an allowlist without an allowed-reference contrast;
     *  - 8b UDP no-response while TCP works -> POSSIBLE_UDP_FILTERING.
     */
    private fun decide(
        evidence: RestrictionEvidence,
        behavior: TransportBehaviorAssessment?,
        nowEpochMillis: Long,
        staleAfterMillis: Long,
    ): Pair<RestrictionClass, Boolean> {
        val profile = evidence.networkProfile
        val gatewayHttpsReachable = freshOrTrusted(evidence.gatewayHttpsReachable, evidence.gatewayProbeEpochMillis, nowEpochMillis, staleAfterMillis)
        val diverseInternetReachable = freshOrTrusted(evidence.diverseInternetReachable, evidence.diverseProbeEpochMillis, nowEpochMillis, staleAfterMillis)
        val gatewayUnreachable = gatewayHttpsReachable == false && evidence.awgHandshakeFresh == false
        val pattern = behavior?.pattern
        return when {
            profile.type == NetworkType.NONE -> RestrictionClass.NO_NETWORK to false
            profile.captivePortal == true -> RestrictionClass.CAPTIVE_PORTAL to false
            evidence.transportState is TransportState.Reconnecting -> RestrictionClass.NETWORK_RECOVERING to false
            evidence.awgHandshakeFresh == true -> RestrictionClass.NO_RESTRICTION_OBSERVED to false
            pattern == TransportBehaviorPattern.SUSTAINED_PROGRESS -> RestrictionClass.NO_RESTRICTION_OBSERVED to true
            !profile.validatedInternet && pattern == TransportBehaviorPattern.ALL_CONNECT_FAILED -> RestrictionClass.POSSIBLE_FULL_SHUTDOWN to true
            !profile.validatedInternet -> RestrictionClass.INTERNET_NOT_VALIDATED to false
            gatewayUnreachable && diverseInternetReachable == false -> RestrictionClass.POSSIBLE_HARD_WHITELIST to false
            pattern == TransportBehaviorPattern.ALL_CONNECT_FAILED && diverseInternetReachable == false -> RestrictionClass.POSSIBLE_HARD_WHITELIST to true
            pattern == TransportBehaviorPattern.EARLY_DROP || pattern == TransportBehaviorPattern.REPEATED_EARLY_DROP ||
                pattern == TransportBehaviorPattern.REPEATED_EARLY_DROP_MULTI_DESTINATION -> RestrictionClass.POSSIBLE_EARLY_DROP to true
            gatewayHttpsReachable == false -> RestrictionClass.GATEWAY_HTTPS_UNREACHABLE to false
            gatewayHttpsReachable == true && evidence.awgHandshakeFresh == false -> RestrictionClass.POSSIBLE_UDP_OR_AWG_FILTERING to false
            pattern == TransportBehaviorPattern.UDP_NO_RESPONSE_TCP_OK -> RestrictionClass.POSSIBLE_UDP_FILTERING to true
            else -> RestrictionClass.UNKNOWN to false
        }
    }

    private fun behaviorOf(evidence: RestrictionEvidence, nowEpochMillis: Long, staleAfterMillis: Long): TransportBehaviorAssessment? =
        if (evidence.transportObservations.isEmpty()) null
        else TransportBehaviorAnalyzer.assess(evidence.transportObservations, nowEpochMillis, staleAfterMillis)

    private fun behaviorReason(pattern: TransportBehaviorPattern): RestrictionEvidenceReason? = when (pattern) {
        TransportBehaviorPattern.SUSTAINED_PROGRESS -> RestrictionEvidenceReason.TRANSPORT_SUSTAINED_PROGRESS
        TransportBehaviorPattern.EARLY_DROP -> RestrictionEvidenceReason.TRANSPORT_EARLY_DROP
        TransportBehaviorPattern.REPEATED_EARLY_DROP -> RestrictionEvidenceReason.TRANSPORT_REPEATED_EARLY_DROP
        TransportBehaviorPattern.REPEATED_EARLY_DROP_MULTI_DESTINATION -> RestrictionEvidenceReason.TRANSPORT_EARLY_DROP_MULTI_DESTINATION
        TransportBehaviorPattern.UDP_NO_RESPONSE_TCP_OK -> RestrictionEvidenceReason.TRANSPORT_UDP_NO_RESPONSE
        TransportBehaviorPattern.ALL_CONNECT_FAILED -> RestrictionEvidenceReason.TRANSPORT_ALL_CONNECT_FAILED
        TransportBehaviorPattern.INSUFFICIENT -> null
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
