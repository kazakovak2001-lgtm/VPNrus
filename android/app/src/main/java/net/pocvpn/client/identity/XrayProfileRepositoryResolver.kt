package net.pocvpn.client.identity

import net.pocvpn.client.reachability.EndpointId

/**
 * B13 (2026-08-30 audit item 5 fix) - resolves the [XrayProfileRepository]
 * that actually holds the REALITY credential for a given endpoint. This is
 * the ONE authoritative lookup [net.pocvpn.client.vpn.VpnController.buildTransportConfig]
 * consults for XRAY_REALITY - never a second, independently-constructed
 * store built ad hoc inside `VpnController`, `NovaXrayVpnService`, or any
 * transport. Returns null for an endpoint this resolver has no repository
 * for - the caller fails closed on that (never silently substitutes a
 * DIFFERENT endpoint's repository, and never falls back to
 * `ProductionGateway.ID` implicitly).
 */
fun interface XrayProfileRepositoryResolver {
    fun resolve(endpointId: EndpointId): XrayProfileRepository?
}

/** The TLS/TCP counterpart of [XrayProfileRepositoryResolver] - same contract, same fail-closed discipline. */
fun interface XrayTlsProfileRepositoryResolver {
    fun resolve(endpointId: EndpointId): XrayTlsProfileRepository?
}

/** B21 - the QUIC counterpart of [XrayProfileRepositoryResolver] - same contract, same fail-closed discipline. */
fun interface XrayQuicProfileRepositoryResolver {
    fun resolve(endpointId: EndpointId): XrayQuicProfileRepository?
}

/**
 * Map-backed resolver. B13 consolidated review fix - now genuinely carries
 * TWO real endpoint -> repository entries in production (Germany AND
 * Stockholm, when Stockholm's own repository is wired - see
 * MainViewModel's own docs), proving out the shape this class's docs always
 * described: adding a real second endpoint was exactly one more map entry,
 * no resolver-contract change and no change to any consumer of
 * [XrayProfileRepositoryResolver].
 */
class MapXrayProfileRepositoryResolver(private val repositories: Map<EndpointId, XrayProfileRepository>) : XrayProfileRepositoryResolver {
    override fun resolve(endpointId: EndpointId): XrayProfileRepository? = repositories[endpointId]
}

/** The TLS/TCP counterpart of [MapXrayProfileRepositoryResolver]. */
class MapXrayTlsProfileRepositoryResolver(private val repositories: Map<EndpointId, XrayTlsProfileRepository>) : XrayTlsProfileRepositoryResolver {
    override fun resolve(endpointId: EndpointId): XrayTlsProfileRepository? = repositories[endpointId]
}

/** B21 - the QUIC counterpart of [MapXrayProfileRepositoryResolver]. */
class MapXrayQuicProfileRepositoryResolver(private val repositories: Map<EndpointId, XrayQuicProfileRepository>) : XrayQuicProfileRepositoryResolver {
    override fun resolve(endpointId: EndpointId): XrayQuicProfileRepository? = repositories[endpointId]
}
