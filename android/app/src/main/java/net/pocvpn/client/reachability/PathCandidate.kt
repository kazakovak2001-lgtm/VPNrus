package net.pocvpn.client.reachability

import net.pocvpn.client.transport.TransportKind

/**
 * One hop in a path, paired with the role it plays there (an endpoint may
 * hold more roles than this - see EndpointDescriptor.roles).
 *
 * B23 (PR #37 review fix) - [binding] is the EXACT, immutable
 * [EndpointTransportBinding] this hop was pinned against (never merely
 * re-derivable via `endpoint.bindingFor(transport)` after the fact) - this
 * is what makes a hop's transport/binding genuinely part of candidate
 * identity, not something a caller could accidentally re-resolve mid-attempt
 * against a since-rotated manifest. `binding.kind` is this hop's own
 * transport - see [PathCandidate.Relayed]'s own docs for why the ingress and
 * exit hops are never assumed to share one.
 */
data class PathHop(val endpoint: EndpointDescriptor, val role: EndpointRole, val reachability: EndpointReachability, val binding: EndpointTransportBinding)

/**
 * B11 - a candidate way to reach the internet: an ordered hop chain, plus the
 * reachability evidence for every hop. This slice only ever builds [Direct]
 * (today's real shape - Client -> GATEWAY, one transport) and [Relayed]
 * (Client -> INGRESS -> EXIT/GATEWAY - see PathCandidateBuilder). Relayed
 * does NOT implement forwarding; it exists so PathScorer/diagnostics have a
 * real typed shape to reason about ahead of an actual relay protocol (out of
 * scope for this slice - see task docs).
 */
sealed class PathCandidate {
    abstract val id: String

    /**
     * The transport the CLIENT actually dials for this candidate - for
     * [Direct] the only transport there is; for [Relayed] the
     * client<->ingress hop's own transport (see that class's own docs on why
     * this is the one meaningful "transport" for local registry/health
     * lookups - [Relayed.exitTransport] is the SEPARATE ingress<->exit
     * upstream transport, never assumed equal to this one).
     */
    abstract val transport: TransportKind
    abstract val hops: List<PathHop>

    /**
     * B23 - the key [PathHistoryStore] local connection memory is recorded/
     * read under for THIS candidate, network-fingerprint-scoped by the
     * caller (see PathHistoryStore's own docs) - a single endpoint id for
     * [Direct] (unchanged from B11/B19), or a composite id for [Relayed]
     * encoding BOTH hop endpoints AND both hop transports (see that class's
     * own docs), so a relay's own local success/failure history is never
     * confused with either hop's Direct history, two relays sharing the same
     * ingress but different exits (or the same endpoints over different
     * per-hop transports) are never conflated. Deliberately NOT [id] itself
     * (same reasoning as before B23: keeping these independent leaves room
     * for a future non-transport-prefixed id shape without touching
     * PathHistoryStore's own key semantics).
     */
    abstract val historyPathId: String

    data class Direct(
        val gateway: PathHop,
        override val transport: TransportKind,
    ) : PathCandidate() {
        override val hops: List<PathHop> = listOf(gateway)
        override val id: String = "direct:${transport}:${gateway.endpoint.id.value}"
        override val historyPathId: String = gateway.endpoint.id.value
    }

    /**
     * B23 (PR #37 review fix) - the ingress and exit/upstream hops are
     * pinned INDEPENDENTLY: [ingress]/[exit] each carry their own
     * [PathHop.binding], and there is no assumption anywhere in this class
     * that `ingress.binding.kind == exit.binding.kind`. A real future
     * topology may legitimately dial the ingress over XRAY_REALITY while the
     * ingress's own upstream to the exit speaks TLS_TCP (or vice versa) -
     * this candidate's identity ([id]/[historyPathId]) encodes BOTH
     * transports precisely so such a chain is never confused with a
     * same-endpoints-different-transport alternative.
     */
    data class Relayed(
        val ingress: PathHop,
        val exit: PathHop,
    ) : PathCandidate() {
        override val transport: TransportKind = ingress.binding.kind

        /** The SEPARATE ingress<->exit upstream transport - never assumed equal to [transport] (the client<->ingress transport). */
        val exitTransport: TransportKind = exit.binding.kind

        override val hops: List<PathHop> = listOf(ingress, exit)
        override val id: String = "relayed:${transport}->${exitTransport}:${ingress.endpoint.id.value}->${exit.endpoint.id.value}"
        override val historyPathId: String = "${ingress.endpoint.id.value}:${transport}->${exit.endpoint.id.value}:${exitTransport}"
    }
}

/**
 * B11 - builds [PathCandidate]s from already-verified endpoint descriptors
 * and already-computed reachability. Never constructs a candidate for a
 * chain the endpoints themselves don't actually support - an unsupported
 * chain returns null rather than a candidate PathScorer would have to
 * discover is bogus later.
 */
object PathCandidateBuilder {

    /** Client -> [gateway], directly. Requires [gateway] to hold GATEWAY or EXIT (a lone endpoint acting as both) and support [transport]. */
    fun buildDirect(gateway: EndpointDescriptor, transport: TransportKind, reachability: EndpointReachability): PathCandidate.Direct? {
        if (EndpointRole.GATEWAY !in gateway.roles && EndpointRole.EXIT !in gateway.roles) return null
        val binding = gateway.bindingFor(transport) ?: return null
        require(reachability.endpointId == gateway.id && reachability.transportKind == transport) {
            "reachability does not match the requested gateway/transport pairing"
        }
        return PathCandidate.Direct(PathHop(gateway, EndpointRole.GATEWAY, reachability, binding), transport)
    }

    /**
     * Client -> [ingress] (over [ingressTransport]) -> [exit] (over
     * [exitTransport], the SEPARATE ingress<->exit upstream transport -
     * B23/PR #37 review fix: never assumed equal to [ingressTransport]; a
     * real ingress may legitimately dial its own upstream to the exit over a
     * different transport than the one the client dials the ingress over).
     * Requires [ingress] to declare INGRESS and support [ingressTransport],
     * and [exit] to declare EXIT or GATEWAY and support [exitTransport].
     * Rejects a chain where [ingress] doesn't actually name [exit] as its
     * relay target - the manifest's own relayTo relationship is the source
     * of truth for which chains are legitimate, not caller intent.
     */
    fun buildRelayed(
        ingress: EndpointDescriptor,
        exit: EndpointDescriptor,
        ingressTransport: TransportKind,
        exitTransport: TransportKind,
        ingressReachability: EndpointReachability,
        exitReachability: EndpointReachability,
    ): PathCandidate.Relayed? {
        if (EndpointRole.INGRESS !in ingress.roles) return null
        if (EndpointRole.EXIT !in exit.roles && EndpointRole.GATEWAY !in exit.roles) return null
        if (ingress.relayTo != exit.id) return null
        val ingressBinding = ingress.bindingFor(ingressTransport) ?: return null
        val exitBinding = exit.bindingFor(exitTransport) ?: return null
        require(ingressReachability.endpointId == ingress.id && ingressReachability.transportKind == ingressTransport) {
            "ingressReachability does not match the requested ingress/transport pairing"
        }
        require(exitReachability.endpointId == exit.id && exitReachability.transportKind == exitTransport) {
            "exitReachability does not match the requested exit/transport pairing"
        }
        return PathCandidate.Relayed(
            PathHop(ingress, EndpointRole.INGRESS, ingressReachability, ingressBinding),
            PathHop(exit, EndpointRole.EXIT, exitReachability, exitBinding),
        )
    }
}
