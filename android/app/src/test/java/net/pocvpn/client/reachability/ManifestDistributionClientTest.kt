package net.pocvpn.client.reachability

import kotlinx.coroutines.test.runTest
import net.pocvpn.client.transport.TransportKind
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.security.SecureRandom

class ManifestDistributionClientTest {

    @get:Rule val tempFolder = TemporaryFolder()

    private val random = SecureRandom()
    private val priv = Ed25519PrivateKeyParameters(random)
    private val pub = priv.generatePublicKey().encoded
    private val anchors = FixedManifestTrustAnchors(mapOf(TrustedKeyId("key-1") to pub))

    private fun manifest(version: Int) = EndpointManifest(
        manifestVersion = version,
        issuedAtEpochMillis = 1_000L,
        expiresAtEpochMillis = 9_000_000L,
        signingKeyId = "key-1",
        endpoints = listOf(
            EndpointDescriptor(
                EndpointId("gw"), setOf(EndpointRole.GATEWAY), "eu", "acme",
                transports = listOf(EndpointTransportBinding(TransportKind.AMNEZIA_WG, "203.0.113.1", 51820)),
            ),
        ),
    )

    private fun sign(manifest: EndpointManifest, key: Ed25519PrivateKeyParameters = priv): SignedManifest {
        val signer = Ed25519Signer()
        signer.init(true, key)
        val bytes = ManifestCanonicalizer.canonicalBytes(manifest)
        signer.update(bytes, 0, bytes.size)
        return SignedManifest(manifest, signer.generateSignature())
    }

    private fun repository(bootstrapVersion: Int = 1, now: Long = 2_000L) = EndpointManifestRepository(
        verifier = Ed25519ManifestVerifier(),
        trustAnchors = anchors,
        lkgStore = FileLastKnownGoodManifestStore(tempFolder.newFolder()),
        bootstrapManifest = sign(manifest(bootstrapVersion)),
        nowEpochMillis = { now },
    )

    @Test
    fun `a valid live manifest is accepted and becomes the trusted manifest`() = runTest {
        val repo = repository()
        val fetcher = RemoteManifestFetcher { ManifestFetchResult.Fetched(sign(manifest(2))) }
        val client = ManifestDistributionClient(fetcher, repo)

        val result = client.refresh()

        assertTrue(result is ManifestUpdateResult.Accepted)
        assertEquals(2, repo.trusted()!!.manifestVersion)
        assertEquals(ManifestSource.LAST_KNOWN_GOOD, repo.trustedSource())
    }

    @Test
    fun `an invalid signature on a fetched manifest is rejected and LKG is untouched`() = runTest {
        val repo = repository()
        val otherKey = Ed25519PrivateKeyParameters(random)
        val fetcher = RemoteManifestFetcher { ManifestFetchResult.Fetched(sign(manifest(2), otherKey)) }
        val client = ManifestDistributionClient(fetcher, repo)

        val result = client.refresh()

        assertTrue(result is ManifestUpdateResult.Rejected)
        assertEquals(ManifestSource.EMBEDDED_BOOTSTRAP, repo.trustedSource())
    }

    @Test
    fun `a rollback attempt via the live endpoint is rejected`() = runTest {
        val repo = repository()
        val client = ManifestDistributionClient(RemoteManifestFetcher { ManifestFetchResult.Fetched(sign(manifest(5))) }, repo)
        client.refresh() // adopt version 5

        val rollbackClient = ManifestDistributionClient(RemoteManifestFetcher { ManifestFetchResult.Fetched(sign(manifest(3))) }, repo)
        val result = rollbackClient.refresh()

        assertTrue(result is ManifestUpdateResult.Rejected)
        assertEquals(5, repo.trusted()!!.manifestVersion)
    }

    @Test
    fun `a network failure never calls offer - LKG and bootstrap are both untouched`() = runTest {
        val repo = repository()
        val fetcher = RemoteManifestFetcher { ManifestFetchResult.Failed("network error: SocketTimeoutException") }
        val client = ManifestDistributionClient(fetcher, repo)

        val result = client.refresh()

        assertTrue(result is ManifestUpdateResult.Rejected)
        assertEquals(1, repo.trusted()!!.manifestVersion) // still the bootstrap
        assertEquals(ManifestSource.EMBEDDED_BOOTSTRAP, repo.trustedSource())
    }

    @Test
    fun `an unavailable control plane still leaves a valid LKG trusted (fetch failure after a prior successful adoption)`() = runTest {
        val repo = repository()
        ManifestDistributionClient(RemoteManifestFetcher { ManifestFetchResult.Fetched(sign(manifest(4))) }, repo).refresh()
        assertEquals(4, repo.trusted()!!.manifestVersion)

        val failingClient = ManifestDistributionClient(RemoteManifestFetcher { ManifestFetchResult.Failed("timed out") }, repo)
        val result = failingClient.refresh()

        assertTrue(result is ManifestUpdateResult.Rejected)
        assertEquals(4, repo.trusted()!!.manifestVersion) // unchanged, still LKG
        assertEquals(ManifestSource.LAST_KNOWN_GOOD, repo.trustedSource())
    }

    @Test
    fun `an expired live manifest is rejected and does not replace LKG`() = runTest {
        // bootstrap itself must also be valid at this `now` for a clean baseline;
        // use a long-lived bootstrap instead of the default repository() helper.
        val longLivedRepo = EndpointManifestRepository(
            verifier = Ed25519ManifestVerifier(),
            trustAnchors = anchors,
            lkgStore = FileLastKnownGoodManifestStore(tempFolder.newFolder()),
            bootstrapManifest = sign(manifest(1).copy(expiresAtEpochMillis = 100_000_000L)),
            nowEpochMillis = { 20_000_000L },
        )
        val expired = manifest(9).copy(issuedAtEpochMillis = 1_000L, expiresAtEpochMillis = 9_000_000L)
        val client = ManifestDistributionClient(RemoteManifestFetcher { ManifestFetchResult.Fetched(sign(expired)) }, longLivedRepo)

        val result = client.refresh()

        assertTrue(result is ManifestUpdateResult.Rejected)
        assertEquals(1, longLivedRepo.trusted()!!.manifestVersion)
    }
}
