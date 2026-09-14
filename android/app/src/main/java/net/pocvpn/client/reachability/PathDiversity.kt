package net.pocvpn.client.reachability

/**
 * B38's local, deterministic correlation model. It never discovers providers
 * at runtime: only signed binding metadata participates. A partially-known
 * path has no diversity preference, so missing values cannot fabricate an
 * independent alternative.
 */
object PathDiversity {
    private enum class FailureDomainKind { OPERATOR, NETWORK, REGION, CDN, CONTROL_PLANE }
    private data class FailureDomainToken(val kind: FailureDomainKind, val id: FailureDomainId)
    private data class Signature(val values: Set<FailureDomainToken>)

    private fun signature(candidate: PathCandidate): Signature? {
        val domains = candidate.hops.map { it.binding.failureDomains() }
        if (domains.any { !it.isCompleteForNonCdnPath }) return null
        if (candidate is PathCandidate.Relayed && candidate.ingressKind == IngressKind.CDN_FRONTED && domains.first().cdn == null) return null
        return Signature(buildSet {
            domains.forEach {
                add(FailureDomainToken(FailureDomainKind.OPERATOR, requireNotNull(it.operator)))
                add(FailureDomainToken(FailureDomainKind.NETWORK, requireNotNull(it.network)))
                add(FailureDomainToken(FailureDomainKind.REGION, requireNotNull(it.region)))
                add(FailureDomainToken(FailureDomainKind.CONTROL_PLANE, requireNotNull(it.controlPlane)))
            }
            domains.first().cdn?.let { add(FailureDomainToken(FailureDomainKind.CDN, it)) }
        })
    }

    /** A capped tie-break: prefer only a fully-known path carrying a domain unique in this batch. */
    fun independentlyDiverseCandidateIds(candidates: Collection<PathCandidate>): Set<String> {
        val signatures = candidates.mapNotNull { candidate -> signature(candidate)?.let { candidate.id to it } }
        if (signatures.size < 2) return emptySet()
        val occurrence = signatures.flatMap { it.second.values }.groupingBy { it }.eachCount()
        return signatures.filter { (_, signature) -> signature.values.any { occurrence[it] == 1 } }.mapTo(linkedSetOf()) { it.first }
    }
}
