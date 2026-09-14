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
 * B23 - how the client actually reaches an INGRESS binding at the network
 * level. A DIRECT_IP ingress is dialed by its own IP/host directly; a
 * CDN_FRONTED ingress is an operator-controlled backend legitimately
 * reachable through a CDN/origin architecture (never a spoof/impersonation
 * of a named third-party service - architecture principle 3's own "do not
 * impersonate" requirement). Deliberately only meaningful for INGRESS
 * bindings - a GATEWAY/EXIT-only binding has no ingress-kind classification.
 */
enum class IngressKind { DIRECT_IP, CDN_FRONTED }

/** B23 - the reserved [EndpointTransportBinding.metadata] key [ingressKind]/[withIngressKind] read/write - never touched directly by callers. */
private const val INGRESS_KIND_METADATA_KEY = "ingressKind"
private const val FAILURE_DOMAIN_OPERATOR_KEY = "failureDomain.operator"
private const val FAILURE_DOMAIN_NETWORK_KEY = "failureDomain.network"
private const val FAILURE_DOMAIN_REGION_KEY = "failureDomain.region"
private const val FAILURE_DOMAIN_CDN_KEY = "failureDomain.cdn"
private const val FAILURE_DOMAIN_CONTROL_PLANE_KEY = "failureDomain.controlPlane"
private val FAILURE_DOMAIN_METADATA_KEYS = setOf(
    FAILURE_DOMAIN_OPERATOR_KEY,
    FAILURE_DOMAIN_NETWORK_KEY,
    FAILURE_DOMAIN_REGION_KEY,
    FAILURE_DOMAIN_CDN_KEY,
    FAILURE_DOMAIN_CONTROL_PLANE_KEY,
)

/** Opaque, signed equality label; it is deliberately not a provider name, ASN, hostname, or IP address. */
data class FailureDomainId(val value: String) {
    init {
        require(value.length in 1..64 && value.all { it.isLetterOrDigit() || it == '-' || it == '_' || it == '.' }) {
            "invalid failure-domain identifier"
        }
    }
}

/** Correlation labels only. Missing or malformed labels are unknown, never evidence of independence. */
data class InfrastructureFailureDomains(
    val operator: FailureDomainId?,
    val network: FailureDomainId?,
    val region: FailureDomainId?,
    val cdn: FailureDomainId?,
    val controlPlane: FailureDomainId?,
) {
    val isCompleteForNonCdnPath: Boolean get() = operator != null && network != null && region != null && controlPlane != null
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
 * B23 - the typed [IngressKind] this binding declares, or null when none was
 * set (a GATEWAY/EXIT binding, or an INGRESS binding from before this field
 * existed). Stored through [EndpointTransportBinding.metadata] rather than a
 * new EndpointDescriptor/binary-schema field so every already-signed manifest
 * (including the embedded production bootstrap - see EmbeddedBootstrapManifest)
 * keeps verifying byte-for-byte against ManifestCanonicalizer with zero
 * re-signing ceremony - metadata is already part of the signed wire format
 * and already round-trips arbitrary string pairs.
 */
fun EndpointTransportBinding.ingressKind(): IngressKind? =
    metadata[INGRESS_KIND_METADATA_KEY]?.let { raw -> IngressKind.entries.firstOrNull { it.name == raw } }

/** B23 - returns a copy of this binding with [kind] recorded as its [IngressKind] (see [ingressKind]'s own docs). */
fun EndpointTransportBinding.withIngressKind(kind: IngressKind): EndpointTransportBinding =
    copy(metadata = metadata + (INGRESS_KIND_METADATA_KEY to kind.name))

fun EndpointTransportBinding.failureDomains(): InfrastructureFailureDomains {
    fun domain(key: String): FailureDomainId? = metadata[key]?.let { raw -> runCatching { FailureDomainId(raw) }.getOrNull() }
    return InfrastructureFailureDomains(
        operator = domain(FAILURE_DOMAIN_OPERATOR_KEY),
        network = domain(FAILURE_DOMAIN_NETWORK_KEY),
        region = domain(FAILURE_DOMAIN_REGION_KEY),
        cdn = domain(FAILURE_DOMAIN_CDN_KEY),
        controlPlane = domain(FAILURE_DOMAIN_CONTROL_PLANE_KEY),
    )
}

/** Writes only opaque IDs into metadata, which existing manifest canonicalization already signs. */
fun EndpointTransportBinding.withFailureDomains(domains: InfrastructureFailureDomains): EndpointTransportBinding {
    val updates = mapOf(
        FAILURE_DOMAIN_OPERATOR_KEY to domains.operator,
        FAILURE_DOMAIN_NETWORK_KEY to domains.network,
        FAILURE_DOMAIN_REGION_KEY to domains.region,
        FAILURE_DOMAIN_CDN_KEY to domains.cdn,
        FAILURE_DOMAIN_CONTROL_PLANE_KEY to domains.controlPlane,
    ).mapNotNull { (key, value) -> value?.let { key to it.value } }.toMap()
    val withoutOldDomains = metadata.filterKeys { it !in FAILURE_DOMAIN_METADATA_KEYS }
    return copy(metadata = withoutOldDomains + updates)
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
