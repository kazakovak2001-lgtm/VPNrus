package net.pocvpn.client.reachability

import net.pocvpn.client.transport.TransportKind

/**
 * A stable, non-secret technical identifier for one endpoint - the same
 * discipline as ConnectionOutcome.gatewayId/GatewayCandidate.id (never a raw
 * host/IP, never something that changes across a re-deploy of the same
 * logical endpoint).
 */
data class EndpointId(val value: String) {
    init {
        require(value.isNotBlank()) { "EndpointId must not be blank" }
        require(value.length <= MAX_LENGTH) { "EndpointId exceeds max length ($MAX_LENGTH): ${value.length}" }
    }

    private companion object {
        const val MAX_LENGTH = 128
    }
}

/**
 * What an endpoint does in a path. A single deployment may hold more than
 * one role at once (e.g. today's one pinned gateway is simultaneously the
 * only GATEWAY and the only EXIT) - see EndpointDescriptor.roles, a Set, not
 * a single value.
 */
enum class EndpointRole {
    /** First hop from the client in a relayed path - see PathCandidate.Relayed. */
    INGRESS,

    /** A direct client-facing endpoint that also carries traffic onward (today's only real shape). */
    GATEWAY,

    /** Final hop before the open internet in a relayed path. */
    EXIT,
}

/**
 * One transport this endpoint can be reached over, and the connection
 * metadata specific to that transport/endpoint pairing. [metadata] is a
 * generic, transport-specific string map (e.g. SNI, ALPN) - never key
 * material or credentials, which stay in the existing per-profile encrypted
 * stores (XrayProfileRepository/XrayTlsProfileRepository) and are never
 * duplicated into a manifest.
 */
data class EndpointTransportBinding(
    val kind: TransportKind,
    val host: String,
    val port: Int,
    val metadata: Map<String, String> = emptyMap(),
) {
    init {
        require(host.isNotBlank()) { "EndpointTransportBinding host must not be blank" }
        require(port in 1..65535) { "EndpointTransportBinding port out of range: $port" }
    }
}

/**
 * Everything the reachability fabric can know about one endpoint. Deliberately
 * has NO Russia-specific provider names or hardcoded commercial infrastructure
 * baked in - [provider]/[region] are opaque, caller-supplied labels, same
 * discipline as GatewayCandidate.region being display text only.
 *
 * [relayTo] names a next-hop EndpointId for a future relay path
 * (Client -> INGRESS -> [relayTo]) - this slice models the relationship, it
 * does not implement forwarding (see PathCandidate.Relayed's own docs).
 */
data class EndpointDescriptor(
    val id: EndpointId,
    val roles: Set<EndpointRole>,
    val region: String,
    val provider: String,
    val asn: Int? = null,
    val transports: List<EndpointTransportBinding>,
    val relayTo: EndpointId? = null,
) {
    init {
        require(roles.isNotEmpty()) { "EndpointDescriptor ${id.value} must declare at least one role" }
        require(transports.isNotEmpty()) { "EndpointDescriptor ${id.value} must declare at least one transport binding" }
        require(region.isNotBlank()) { "EndpointDescriptor ${id.value} region must not be blank" }
        require(provider.isNotBlank()) { "EndpointDescriptor ${id.value} provider must not be blank" }
        asn?.let { require(it > 0) { "EndpointDescriptor ${id.value} ASN must be positive: $it" } }
        require(relayTo != id) { "EndpointDescriptor ${id.value} must not relay to itself" }
        val distinctKinds = transports.map { it.kind }
        require(distinctKinds.size == distinctKinds.toSet().size) {
            "EndpointDescriptor ${id.value} declares the same TransportKind more than once"
        }
    }

    fun supports(kind: TransportKind): Boolean = transports.any { it.kind == kind }

    fun bindingFor(kind: TransportKind): EndpointTransportBinding? = transports.firstOrNull { it.kind == kind }
}
