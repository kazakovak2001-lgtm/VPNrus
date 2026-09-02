package net.pocvpn.client.relay

import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.reachability.EndpointTransportBinding
import net.pocvpn.client.reachability.IngressKind
import net.pocvpn.client.transport.TransportKind

/**
 * B26 review fix (blocker 1) - the real, UI-observable signal that a
 * relayed Auto attempt just hit a [RelayFailureCategory] an explicit
 * device activation can actually fix
 * ([RelayFailureCategory.PROFILE_NOT_PROVISIONED]/
 * [RelayFailureCategory.PROFILE_EXPIRED]/
 * [RelayFailureCategory.PROFILE_MISMATCH] - never any other category,
 * which fail closed with no activation prompt at all). Carries ONLY the
 * caller's own already-pinned facts from the attempted
 * [RelayedExecutionPlan] - never re-derived, never mutated by activation
 * (see [IngressProfileProvisioner.provision]'s own cross-check).
 *
 * [net.pocvpn.client.MainViewModel.relayActivationNeeded] exposes this;
 * the product UI (`AppRoot`) reuses the EXISTING `ActivationScreen`
 * composable to collect the SAME kind of activation credential every
 * other endpoint's activation already uses - never a manual UUID/REALITY-
 * key/probe-token paste field (task's own explicit prohibition).
 */
data class RelayActivationRequest(
    val ingressEndpointId: EndpointId,
    val ingressBinding: EndpointTransportBinding,
    val ingressTransport: TransportKind,
    // B27 - carried through so a real UI can show/label which ingress
    // strategy this activation is for (never inferred from host/provider -
    // see IngressKind's own docs); [IngressProfileProvisioner.provision]
    // pins it as part of the request it cross-checks the server's response
    // against.
    val ingressKind: IngressKind,
) {
    companion object {
        /** The ONLY [RelayFailureCategory] values a fresh activation can fix - see this type's own docs. */
        val ACTIVATION_FIXABLE_CATEGORIES: Set<RelayFailureCategory> = setOf(
            RelayFailureCategory.PROFILE_NOT_PROVISIONED,
            RelayFailureCategory.PROFILE_EXPIRED,
            RelayFailureCategory.PROFILE_MISMATCH,
        )

        fun from(plan: RelayedExecutionPlan): RelayActivationRequest = RelayActivationRequest(
            ingressEndpointId = plan.ingressEndpointId,
            ingressBinding = plan.ingressBinding,
            ingressTransport = plan.ingressTransport,
            ingressKind = plan.ingressKind,
        )
    }
}
