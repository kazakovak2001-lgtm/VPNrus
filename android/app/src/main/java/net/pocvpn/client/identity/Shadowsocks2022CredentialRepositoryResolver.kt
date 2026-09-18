package net.pocvpn.client.identity

import net.pocvpn.client.reachability.EndpointId

/**
 * B45B-4 (review fix) - resolves the [Shadowsocks2022CredentialRepository]
 * that actually holds the AEAD-2022 credential for a given endpoint. Same
 * contract/shape as [XrayProfileRepositoryResolver] - the ONE authoritative,
 * endpoint-scoped lookup, never a second independently-constructed store,
 * never a fixed single-endpoint field (no country/provider name decides
 * availability - see [MainViewModel.isShadowsocksAvailableFor]'s own docs).
 * Returns null for an endpoint this resolver has no repository for - the
 * caller fails closed on that, never substituting a DIFFERENT endpoint's
 * repository.
 */
fun interface Shadowsocks2022CredentialRepositoryResolver {
    fun resolve(endpointId: EndpointId): Shadowsocks2022CredentialRepository?
}

/**
 * Map-backed resolver - one entry per endpoint this device has a real
 * credential store for. Adding a new endpoint (a future gateway-pool member)
 * is exactly one more map entry, no resolver-contract change.
 */
class MapShadowsocks2022CredentialRepositoryResolver(
    private val repositories: Map<EndpointId, Shadowsocks2022CredentialRepository>,
) : Shadowsocks2022CredentialRepositoryResolver {
    override fun resolve(endpointId: EndpointId): Shadowsocks2022CredentialRepository? = repositories[endpointId]
}
