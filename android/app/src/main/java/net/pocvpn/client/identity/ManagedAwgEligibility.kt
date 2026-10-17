package net.pocvpn.client.identity

import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.vpn.config.ProductionGatewayId

/**
 * Phase A - why (or why not) managed AWG may use a gateway's stored tunnel
 * identity. [REACTIVATION_REQUIRED] means only that LOCAL authorization has
 * not been established for the current key - it says nothing about whether
 * any server-side credential is still valid.
 */
enum class ManagedAwgEligibilityReason {
    AWG_ACTIVE,
    REACTIVATION_REQUIRED,
    IDENTITY_UNAVAILABLE,
    BINDING_STORE_UNREADABLE,
    IDENTITY_LIFECYCLE_BLOCKED,
    /** N-1 - the attempt's tunnel IP is no longer the gateway's current one; never returned by [ManagedAwgEligibility.evaluate]. */
    TUNNEL_IDENTITY_CHANGED,
}

/**
 * Pure, fail-closed decision. Only [ManagedAwgEligibilityReason.AWG_ACTIVE]
 * is eligible; every other input combination is not. Tunnel-IP presence is
 * deliberately NOT an input - it can never establish eligibility.
 */
object ManagedAwgEligibility {

    /** The gate applies to managed AMNEZIA_WG only - never to Xray/Hysteria2/other transports. */
    fun appliesTo(kind: TransportKind): Boolean = kind == TransportKind.AMNEZIA_WG

    fun evaluate(
        gatewayId: ProductionGatewayId,
        lifecycleBlocked: Boolean,
        bindings: ManagedAwgBindingLoadResult,
        currentKey: ManagedKeyPeek,
    ): ManagedAwgEligibilityReason {
        if (lifecycleBlocked) return ManagedAwgEligibilityReason.IDENTITY_LIFECYCLE_BLOCKED
        val currentFingerprint = when (currentKey) {
            is ManagedKeyPeek.Present -> try {
                ManagedAwgKeyFingerprint.of(currentKey.publicKeyBase64)
            } catch (e: IllegalArgumentException) {
                return ManagedAwgEligibilityReason.IDENTITY_UNAVAILABLE
            }
            ManagedKeyPeek.Absent, is ManagedKeyPeek.Unavailable -> return ManagedAwgEligibilityReason.IDENTITY_UNAVAILABLE
        }
        val bound = when (bindings) {
            is ManagedAwgBindingLoadResult.Unreadable -> return ManagedAwgEligibilityReason.BINDING_STORE_UNREADABLE
            ManagedAwgBindingLoadResult.Absent -> null
            is ManagedAwgBindingLoadResult.Valid -> bindings.bindings[gatewayId]
        }
        return if (bound != null && bound == currentFingerprint) {
            ManagedAwgEligibilityReason.AWG_ACTIVE
        } else {
            ManagedAwgEligibilityReason.REACTIVATION_REQUIRED
        }
    }

    fun isEligible(reason: ManagedAwgEligibilityReason): Boolean = reason == ManagedAwgEligibilityReason.AWG_ACTIVE
}
