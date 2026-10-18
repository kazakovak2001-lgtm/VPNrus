package net.pocvpn.client.identity

import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.vpn.config.ProductionGatewayCatalog
import net.pocvpn.client.vpn.config.ProductionGatewayId

/** Managed AWG refused for this gateway; [reason] is never [ManagedAwgEligibilityReason.AWG_ACTIVE]. */
class ManagedAwgNotEligibleException(val reason: ManagedAwgEligibilityReason) :
    Exception("managed AWG identity not eligible: $reason")

/**
 * Phase B step 2 - the ONE pairing of the shared lifecycle lock (L) with the
 * managed AWG binding store. The factory builds exactly one instance and hands
 * the SAME object to MainViewModel and (through it) VpnController, so every
 * managed identity mutation, activation commit and managed AWG config build
 * serializes on the same L. A null guard (tests/legacy wiring) keeps the
 * pre-Phase-B behavior; production always passes one.
 *
 * Lock order: connectMutex -> L -> binding-store lock -> managed key repository mutex.
 * The PRIVATE gateway identity never goes through this guard.
 */
class ManagedAwgIdentityGuard(
    val lifecycle: ManagedIdentityLifecycle,
    val bindingStore: ManagedAwgBindingStore,
    /**
     * N-1 - the CURRENT stored client tunnel IP for a gateway (production:
     * ClientTunnelIdentityStore.read - a plain lock-free file read, written only
     * by the activation commit under L). Read under L, never creates anything.
     */
    private val currentTunnelIp: (ProductionGatewayId) -> String?,
) {

    /**
     * MUST be called while holding [lifecycle] (L). Returns the existing managed
     * private key only if [gatewayId] is bound to the fingerprint of the public
     * key DERIVED from that exact private key (pair validated by
     * [ClientKeyRepository.getExistingPrivateKeyForTunnel]). Never creates a key.
     *
     * @throws ManagedAwgNotEligibleException on every other outcome.
     */
    suspend fun requireEligiblePrivateKeyLocked(
        gatewayId: ProductionGatewayId?,
        repository: ClientKeyRepository,
        /** The tunnel IP the caller's (possibly pre-L) config snapshot will use. */
        expectedTunnelIp: String,
    ): String {
        if (gatewayId == null) throw ManagedAwgNotEligibleException(ManagedAwgEligibilityReason.REACTIVATION_REQUIRED)
        val bindings = bindingStore.read()
        val existing = repository.getExistingPrivateKeyForTunnel()
        val peek = when (existing) {
            is ExistingPrivateKeyResult.Present -> ManagedKeyPeek.Present(existing.publicKeyBase64)
            ExistingPrivateKeyResult.Missing -> ManagedKeyPeek.Absent
            is ExistingPrivateKeyResult.Unavailable -> ManagedKeyPeek.Unavailable(existing.reason)
        }
        // No journal exists yet in Phase B, so nothing can raise a lifecycle block here.
        val reason = ManagedAwgEligibility.evaluate(gatewayId, lifecycleBlocked = false, bindings = bindings, currentKey = peek)
        if (!ManagedAwgEligibility.isEligible(reason) || existing !is ExistingPrivateKeyResult.Present) {
            throw ManagedAwgNotEligibleException(reason)
        }
        // N-1 - the snapshot's tunnel IP must still be the one the binding was
        // committed with; a missing or different current IP refuses this attempt
        // (never substituted into the stale config).
        val current = currentTunnelIp(gatewayId)?.trim()
        if (current == null || current != expectedTunnelIp.trim()) {
            throw ManagedAwgNotEligibleException(ManagedAwgEligibilityReason.TUNNEL_IDENTITY_CHANGED)
        }
        return existing.privateKeyBase64
    }

    companion object {
        /** The production gateway whose managed AWG endpoint is [endpointId], or null (never guessed). */
        fun gatewayIdFor(endpointId: EndpointId): ProductionGatewayId? =
            ProductionGatewayCatalog.all.firstOrNull { it.endpointId == endpointId }?.id
    }
}
