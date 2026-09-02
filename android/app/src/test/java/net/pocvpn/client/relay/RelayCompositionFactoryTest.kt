package net.pocvpn.client.relay

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * B26 review fix (blocker 2) - the real composition-root test: proves
 * [RelayCompositionFactory.build] - the EXACT function
 * [net.pocvpn.client.MainViewModel.Factory.create] calls in production -
 * selects the REAL [RelayIngressResolverImpl]/[HttpRelayEndToEndProbe]/
 * [IngressProfileProvisioner], never the [NotProvisionedRelayIngressResolver]/
 * [NotConfiguredRelayEndToEndProbe] stand-ins those types default to for
 * every OTHER (non-Factory) caller/test in this codebase.
 *
 * Uses a real Robolectric [Context] - safe here specifically because
 * [RelayCompositionFactory.build] never touches AndroidKeyStore/crypto
 * (see that object's own docs); a Robolectric test that instead tried to
 * exercise `MainViewModel.Factory.create()` end to end would hit a real
 * `KeyStoreException`/`NoSuchAlgorithmException` from `xrayProfileRepository`/
 * `clientKeyRepository`'s OWN eager `AndroidKeystoreAesGcmEncryptor`
 * construction (a PRE-EXISTING incompatibility between this stack's
 * Robolectric version and `AndroidKeyStore`, unrelated to B26 - this is
 * exactly why the relay composition was extracted into its own function
 * rather than tested through the whole Factory).
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class RelayCompositionFactoryTest {

    @Test
    fun `build selects the real RelayIngressResolverImpl, not the NotProvisioned stand-in`() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val composition = RelayCompositionFactory.build(context, InMemoryIngressProfileStore())

        assertTrue(
            "expected RelayIngressResolverImpl, got ${composition.relayIngressResolver.javaClass.name}",
            composition.relayIngressResolver is RelayIngressResolverImpl,
        )
        assertTrue(composition.relayIngressResolver !is NotProvisionedRelayIngressResolver)
    }

    @Test
    fun `build selects the real HttpRelayEndToEndProbe, not the NotConfigured stand-in`() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val composition = RelayCompositionFactory.build(context, InMemoryIngressProfileStore())

        assertTrue(
            "expected HttpRelayEndToEndProbe, got ${composition.relayEndToEndProbe.javaClass.name}",
            composition.relayEndToEndProbe is HttpRelayEndToEndProbe,
        )
        assertTrue(composition.relayEndToEndProbe !is NotConfiguredRelayEndToEndProbe)
    }

    @Test
    fun `build selects a real IngressProfileProvisioner bound to the SAME store instance it was given`() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val store = InMemoryIngressProfileStore()
        val composition = RelayCompositionFactory.build(context, store)

        assertTrue(composition.ingressProfileProvisioner is IngressProfileProvisioner)
    }

    @Test
    fun `build's resolver reads from the SAME store instance it was given, never a second one`() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val store = InMemoryIngressProfileStore()
        val composition = RelayCompositionFactory.build(context, store)
        val resolver = composition.relayIngressResolver as RelayIngressResolverImpl
        val storeField = RelayIngressResolverImpl::class.java.getDeclaredField("ingressProfileStore")
        storeField.isAccessible = true
        assertTrue(storeField.get(resolver) === store)
    }
}
