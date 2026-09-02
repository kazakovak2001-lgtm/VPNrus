package net.pocvpn.client.reachability

import net.pocvpn.client.transport.TransportKind

/** One hop in a path, paired with the role it plays there (an endpoint may hold more roles than this - see EndpointDescriptor.roles). */
data class PathHop(val endpoint: EndpointDescriptor, val role: EndpointRole, val reachability: EndpointReachability)

/**
 * B11 - a candidate way to reach the internet: an ordered hop chain over one
 * transport, plus the reachability evidence for every hop. This slice only
 * ever builds [Direct] (today's real shape - Client -> GATEWAY) and
 * [Relayed] (Client -> INGRESS -> EXIT/GATEWAY) - see PathCandidateBuilder.
 * Relayed does NOT implement forwarding; it exists so PathScorer/diagnostics
 * have a real typed shape to reason about ahead of an actual relay protocol
 * (out of scope for this slice - see task docs).
 */
sealed class PathCandidate {
    abstract val id: String
    abstract val transport: TransportKind
    abstract val hops: List<PathHop>

    /**
     * B23 - the key [PathHistoryStore] local connection memory is recorded/
     * read under for THIS candidate, network-fingerprint-scoped by the
     * caller (see PathHistoryStore's own docs) - a single endpoint id for
     * [Direct] (unchanged from B11/B19), or a composite "ingress->exit" id
     * for [Relayed] so a relay's own local success/failure history is never
     * confused with either hop's Direct history, and two relays sharing the
     * same ingress but different exits are never conflated. Deliberately
     * NOT [id] itself (which also encodes [transport] - the SAME transport
     * pinned to a different, unrelated history entry per PathHistoryStore's
     * own (fingerprint x pathId x transport) key shape would double-encode
     * it).
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

    data class Relayed(
        val ingress: PathHop,
        val exit: PathHop,
        override val transport: TransportKind,
    ) : PathCandidate() {
        override val hops: List<PathHop> = listOf(ingress, exit)
        override val id: String = "relayed:${transport}:${ingress.endpoint.id.value}->${exit.endpoint.id.value}"
        override val historyPathId: String = "${ingress.endpoint.id.value}->${exit.endpoint.id.value}"
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
        if (!gateway.supports(transport)) return null
        require(reachability.endpointId == gateway.id && reachability.transportKind == transport) {
            "reachability does not match the requested gateway/transport pairing"
        }
        return PathCandidate.Direct(PathHop(gateway, EndpointRole.GATEWAY, reachability), transport)
    }

    /**
     * Client -> [ingress] -> [exit]. Requires [ingress] to declare INGRESS
     * and support [transport] (the client<->ingress hop is what actually
     * needs to speak [transport] in this model), and [exit] to declare EXIT
     * or GATEWAY. Rejects a chain where [ingress] doesn't actually name
     * [exit] as its relay target - the manifest's own relayTo relationship
     * is the source of truth for which chains are legitimate, not caller
     * intent.
     */
    fun buildRelayed(
        ingress: EndpointDescriptor,
        exit: EndpointDescriptor,
        transport: TransportKind,
        ingressReachability: EndpointReachability,
        exitReachability: EndpointReachability,
    ): PathCandidate.Relayed? {
        if (EndpointRole.INGRESS !in ingress.roles) return null
        if (EndpointRole.EXIT !in exit.roles && EndpointRole.GATEWAY !in exit.roles) return null
        if (!ingress.supports(transport)) return null
        if (ingress.relayTo != exit.id) return null
        require(ingressReachability.endpointId == ingress.id && ingressReachability.transportKind == transport) {
            "ingressReachability does not match the requested ingress/transport pairing"
        }
        require(exitReachability.endpointId == exit.id) { "exitReachability does not match the requested exit endpoint" }
        return PathCandidate.Relayed(
            PathHop(ingress, EndpointRole.INGRESS, ingressReachability),
            PathHop(exit, EndpointRole.EXIT, exitReachability),
            transport,
        )
    }
}
