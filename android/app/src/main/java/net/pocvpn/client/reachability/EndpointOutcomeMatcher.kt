package net.pocvpn.client.reachability

import net.pocvpn.client.smartconnect.ConnectionOutcome
import net.pocvpn.client.transport.TransportKind

/**
 * B12 (PR #24 audit fix) - pure, extracted so it's independently testable:
 * which real [ConnectionOutcome] (if any) is the current data-plane
 * evidence for one specific (endpointId, transportKind) pairing. The
 * NEWEST matching outcome wins by its OWN [ConnectionOutcome.timestampEpochMillis]
 * (explicit `maxByOrNull`, never merely "last in the list" - a caller must
 * not assume [outcomes] arrives in any particular order). Evidence for a
 * DIFFERENT endpoint or a DIFFERENT transport never matches - see
 * [ConnectionOutcome.gatewayId]/[ConnectionOutcome.transport] being both
 * required to match, exactly this function's whole job.
 */
object EndpointOutcomeMatcher {
    fun latestMatching(outcomes: List<ConnectionOutcome>, endpointId: EndpointId, transport: TransportKind): ConnectionOutcome? =
        outcomes.filter { it.gatewayId == endpointId.value && it.transport == transport }
            .maxByOrNull { it.timestampEpochMillis }
}
