package net.pocvpn.client.relay

import android.content.Context
import net.pocvpn.client.identity.XrayProfileRepositoryFactory
import net.pocvpn.client.identity.XrayProfileRepositoryResolver
import net.pocvpn.client.identity.XrayTlsProfileRepositoryFactory
import net.pocvpn.client.identity.XrayTlsProfileRepositoryResolver

/**
 * B26 review fix (blocker 2) - the real production relay/ingress
 * dependency graph, extracted into its OWN directly-testable unit rather
 * than left inline inside [net.pocvpn.client.MainViewModel.Factory.create]
 * (see [MainViewModelCompositionRootTest][net.pocvpn.client.MainViewModelCompositionRootTest]
 * - a test that could not exist while this construction was buried inside
 * a function that ALSO eagerly touches unrelated AndroidKeyStore-backed
 * repositories at construction time, which is incompatible with this
 * project's Robolectric setup - see that test's own docs for why THIS
 * function, unlike the rest of `Factory.create`, never touches
 * AndroidKeyStore/crypto at all: every relay object built here either
 * takes [ingressProfileStore] as an already-constructed INPUT (never
 * builds its own encryptor) or defers any Keystore-backed work into a
 * lambda that only runs later, inside a real [resolve]/[provision] call).
 *
 * [net.pocvpn.client.MainViewModel.Factory.create] is the ONE production
 * caller - it constructs [ingressProfileStore] via
 * [IngressProfileStoreFactory] (the one piece that DOES need a real
 * AndroidKeyStore) and passes it straight in here, then threads every
 * field of the returned [RelayComposition] into [net.pocvpn.client.MainViewModel]'s
 * constructor verbatim - see that call site's own comments. No second
 * composition root: this function's caller count is exactly one in
 * production code, by construction (it is not itself a
 * `ViewModelProvider.Factory`, it is a plain builder Factory.create calls).
 */
object RelayCompositionFactory {

    data class RelayComposition(
        val relayIngressResolver: RelayIngressResolver,
        val relayEndToEndProbe: RelayEndToEndProbe,
        val relayXrayProfileRepositoryResolver: XrayProfileRepositoryResolver,
        val relayXrayTlsProfileRepositoryResolver: XrayTlsProfileRepositoryResolver,
        val ingressProfileProvisioner: IngressProfileProvisioner,
    )

    fun build(context: Context, ingressProfileStore: IngressProfileStore): RelayComposition = RelayComposition(
        relayIngressResolver = RelayIngressResolverImpl(context, ingressProfileStore),
        relayEndToEndProbe = HttpRelayEndToEndProbe(),
        // Same "resolve an arbitrary endpoint id's own repository, never a
        // fixed map" shape MainViewModel.Factory's own Stockholm
        // xrayTransport/xrayTlsTransport resolver lambdas already use -
        // this lambda touches AndroidKeyStore only when actually INVOKED
        // (inside a real relayed attempt), never at construction time.
        relayXrayProfileRepositoryResolver = XrayProfileRepositoryResolver { id ->
            XrayProfileRepositoryFactory.create(context, id, migrateFromLegacyUnscopedFile = false)
        },
        relayXrayTlsProfileRepositoryResolver = XrayTlsProfileRepositoryResolver { id ->
            XrayTlsProfileRepositoryFactory.create(context, id, migrateFromLegacyUnscopedFile = false)
        },
        ingressProfileProvisioner = IngressProfileProvisioner(ingressProfileStore),
    )
}
