package net.pocvpn.client.relay

import android.content.Context
import net.pocvpn.client.identity.XrayProfileRepositoryFactory
import net.pocvpn.client.identity.XrayTlsProfileRepositoryFactory
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.vpn.VlessRealityTransport
import net.pocvpn.client.vpn.VlessTlsTransport

/**
 * B25 (task F) - the real, production-capable [RelayIngressResolver]:
 *
 * 1. receives the immutable pinned [RelayedExecutionPlan] (never
 *    re-resolved from the manifest/catalog - see that type's own docs);
 * 2. loads the endpoint-scoped provisioned [IngressClientProfile] via
 *    [ingressProfileStore] (task E's own store);
 * 3. validates it matches the pinned ingress endpoint/binding/transport
 *    ([IngressClientProfile.matches]) and has not expired
 *    ([IngressClientProfile.isExpired]) - fails closed with a typed
 *    [RelayFailureCategory] on any mismatch, never silently re-binding or
 *    substituting a different profile/ingress (task requirement F's own
 *    "no fallback to a different ingress", "no binding re-resolution mid-
 *    attempt");
 * 4. writes the matched credential into the SAME per-endpoint encrypted
 *    store ([net.pocvpn.client.identity.XrayProfileRepository]/
 *    [net.pocvpn.client.identity.XrayTlsProfileRepository]) the EXISTING
 *    [VlessRealityTransport]/[VlessTlsTransport] already read from by
 *    endpoint id (see those classes' own docs) - this is what makes step 5
 *    below reuse the EXISTING Xray transport/service stack VERBATIM,
 *    never a bespoke networking path;
 * 5. returns [RelayIngressResolution.Resolved] with a real, already-
 *    constructed transport instance for [plan.ingressEndpointId];
 * 6. NEVER calls `connect()`/`disconnect()` on anything, never starts a
 *    VpnService, never owns any state of its own - a pure preparation
 *    boundary (see [RelayIngressResolver]'s own docs on why this shape,
 *    not a dialer, is correct).
 *
 * Writing the credential into the shared per-endpoint store on every
 * resolve() call is intentionally idempotent/cheap (a local encrypted file
 * write, not a network call) and correct even under retries: the profile
 * this device holds for a given ingress endpoint never changes without a
 * fresh control-plane activation, so re-writing the identical bytes on a
 * second attempt is a no-op in effect. It also means a stale on-disk
 * profile from a PRIOR ingress activation can never be silently reused
 * for an attempt whose current, freshly-checked [IngressClientProfile]
 * profile differs (e.g. after a re-activation) - this resolver is the
 * one place that decides "is that profile a real match right now", not the
 * transport's own fallback lookup.
 */
class RelayIngressResolverImpl(
    private val context: Context,
    private val ingressProfileStore: IngressProfileStore,
    private val nowProvider: () -> Long = System::currentTimeMillis,
) : RelayIngressResolver {

    override suspend fun resolve(plan: RelayedExecutionPlan): RelayIngressResolution {
        val profile = ingressProfileStore.getProfileOrNull(plan.ingressEndpointId)
            ?: return RelayIngressResolution.NotProvisioned(
                category = RelayFailureCategory.PROFILE_NOT_PROVISIONED,
                detail = "no ingress profile stored for ${plan.ingressEndpointId.value}",
            )

        if (!profile.matches(plan)) {
            return RelayIngressResolution.NotProvisioned(
                category = RelayFailureCategory.PROFILE_MISMATCH,
                detail = "stored ingress profile does not match the pinned endpoint/binding/transport for ${plan.ingressEndpointId.value}",
            )
        }

        if (profile.isExpired(nowProvider())) {
            return RelayIngressResolution.NotProvisioned(
                category = RelayFailureCategory.PROFILE_EXPIRED,
                detail = "ingress profile for ${plan.ingressEndpointId.value} expired at ${profile.expiresAtEpochMillis}",
            )
        }

        return when (plan.ingressTransport) {
            TransportKind.XRAY_REALITY -> {
                val realityProfile = profile.realityProfile
                    ?: return RelayIngressResolution.NotProvisioned(RelayFailureCategory.PROFILE_MISMATCH, "profile declares XRAY_REALITY but carries no realityProfile")
                XrayProfileRepositoryFactory.create(context, plan.ingressEndpointId, migrateFromLegacyUnscopedFile = false)
                    .saveProfile(realityProfile)
                RelayIngressResolution.Resolved(
                    transport = VlessRealityTransport(context),
                    kind = TransportKind.XRAY_REALITY,
                    profile = profile,
                )
            }
            TransportKind.TLS_TCP -> {
                val tlsProfile = profile.tlsProfile
                    ?: return RelayIngressResolution.NotProvisioned(RelayFailureCategory.PROFILE_MISMATCH, "profile declares TLS_TCP but carries no tlsProfile")
                XrayTlsProfileRepositoryFactory.create(context, plan.ingressEndpointId, migrateFromLegacyUnscopedFile = false)
                    .saveProfile(tlsProfile)
                RelayIngressResolution.Resolved(
                    transport = VlessTlsTransport(context),
                    kind = TransportKind.TLS_TCP,
                    profile = profile,
                )
            }
            else -> RelayIngressResolution.NotProvisioned(
                category = RelayFailureCategory.EXECUTION_NOT_IMPLEMENTED,
                detail = "no real transport builder for ${plan.ingressTransport} yet (AMNEZIA_WG upstream chaining is out of scope - see PROJECT_ARCHITECTURE.md's B24 relay matrix)",
            )
        }
    }
}
