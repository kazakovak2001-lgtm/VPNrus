package net.pocvpn.client.identity

import net.pocvpn.client.reachability.EndpointId

/**
 * B46-4A - resolves the [Hysteria2CredentialRepository] that actually holds
 * the Hysteria2 credential for a given endpoint. Mirrors
 * [Shadowsocks2022CredentialRepositoryResolver] exactly - the ONE
 * authoritative, endpoint-scoped lookup, never a second independently-
 * constructed store, never a fixed single-endpoint field. Returns null for
 * an endpoint this resolver has no repository for - the caller fails closed
 * on that, never substituting a DIFFERENT endpoint's repository.
 */
fun interface Hysteria2CredentialRepositoryResolver {
    fun resolve(endpointId: EndpointId): Hysteria2CredentialRepository?
}

/**
 * Map-backed resolver - one entry per endpoint this device has a real
 * credential store for. Adding a new endpoint (a future gateway-pool member)
 * is exactly one more map entry, no resolver-contract change.
 */
class MapHysteria2CredentialRepositoryResolver(
    private val repositories: Map<EndpointId, Hysteria2CredentialRepository>,
) : Hysteria2CredentialRepositoryResolver {
    override fun resolve(endpointId: EndpointId): Hysteria2CredentialRepository? = repositories[endpointId]
}
