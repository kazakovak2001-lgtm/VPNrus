package net.pocvpn.client.reachability

import kotlinx.coroutines.test.runTest
import net.pocvpn.client.transport.TransportKind
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.security.SecureRandom

/**
 * B20 - multi-origin fetch/failover/trust orchestration. Every scenario here
 * proves the SAME EndpointManifestRepository trust boundary (signature,
 * expiry, rollback) governs candidates regardless of which origin produced
 * them - see MultiOriginManifestDistributionClient's own docs.
 */
class MultiOriginManifestDistributionClientTest {

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

    private val frankfurt = ManifestOrigin("frankfurt", "https://152.70.43.1/v1/manifest")
    private val stockholm = ManifestOrigin("stockholm", "https://16.170.208.231/v1/manifest")

    @Test
    fun `primary origin success is accepted, secondary is not needed but is still tried`() = runTest {
        val repo = repository()
        val client = MultiOriginManifestDistributionClient(
            origins = listOf(frankfurt, stockholm),
            repository = repo,
            fetcherFor = { origin ->
                when (origin.id) {
                    "frankfurt" -> RemoteManifestFetcher { ManifestFetchResult.Fetched(sign(manifest(2))) }
                    else -> RemoteManifestFetcher { ManifestFetchResult.Fetched(sign(manifest(2))) }
                }
            },
        )

        val result = client.refresh()

        assertEquals(2, repo.trusted()!!.manifestVersion)
        assertTrue(result.finalOutcome is ManifestUpdateResult.Accepted)
        assertEquals(ManifestOriginOutcomeKind.ACCEPTED, result.perOrigin[0].outcome.kind)
    }

    @Test
    fun `primary network failure falls through to a secondary that is accepted`() = runTest {
        val repo = repository()
        val client = MultiOriginManifestDistributionClient(
            origins = listOf(frankfurt, stockholm),
            repository = repo,
            fetcherFor = { origin ->
                when (origin.id) {
                    "frankfurt" -> RemoteManifestFetcher { ManifestFetchResult.Failed("network error: SocketTimeoutException") }
                    else -> RemoteManifestFetcher { ManifestFetchResult.Fetched(sign(manifest(2))) }
                }
            },
        )

        val result = client.refresh()

        assertEquals(2, repo.trusted()!!.manifestVersion)
        assertEquals(ManifestOriginOutcomeKind.NETWORK_ERROR, result.perOrigin[0].outcome.kind)
        assertEquals(ManifestOriginOutcomeKind.ACCEPTED, result.perOrigin[1].outcome.kind)
    }

    @Test
    fun `primary TLS and HTTP failures both fall through to an accepted secondary`() = runTest {
        val repo = repository()
        val tlsClient = MultiOriginManifestDistributionClient(
            origins = listOf(frankfurt, stockholm),
            repository = repo,
            fetcherFor = { origin ->
                when (origin.id) {
                    "frankfurt" -> RemoteManifestFetcher { ManifestFetchResult.Failed("TLS error: SSLHandshakeException") }
                    else -> RemoteManifestFetcher { ManifestFetchResult.Fetched(sign(manifest(2))) }
                }
            },
        )
        val tlsResult = tlsClient.refresh()
        assertEquals(ManifestOriginOutcomeKind.TLS_ERROR, tlsResult.perOrigin[0].outcome.kind)
        assertEquals(2, repo.trusted()!!.manifestVersion)

        val repo2 = repository()
        val httpClient = MultiOriginManifestDistributionClient(
            origins = listOf(frankfurt, stockholm),
            repository = repo2,
            fetcherFor = { origin ->
                when (origin.id) {
                    "frankfurt" -> RemoteManifestFetcher { ManifestFetchResult.Failed("unexpected HTTP status 503") }
                    else -> RemoteManifestFetcher { ManifestFetchResult.Fetched(sign(manifest(2))) }
                }
            },
        )
        val httpResult = httpClient.refresh()
        assertEquals(ManifestOriginOutcomeKind.HTTP_ERROR, httpResult.perOrigin[0].outcome.kind)
        assertEquals(2, repo2.trusted()!!.manifestVersion)
    }

    @Test
    fun `primary invalid signature falls through to an accepted valid secondary`() = runTest {
        val repo = repository()
        val otherKey = Ed25519PrivateKeyParameters(random)
        val client = MultiOriginManifestDistributionClient(
            origins = listOf(frankfurt, stockholm),
            repository = repo,
            fetcherFor = { origin ->
                when (origin.id) {
                    "frankfurt" -> RemoteManifestFetcher { ManifestFetchResult.Fetched(sign(manifest(2), otherKey)) }
                    else -> RemoteManifestFetcher { ManifestFetchResult.Fetched(sign(manifest(2))) }
                }
            },
        )

        val result = client.refresh()

        assertEquals(ManifestOriginOutcomeKind.INVALID_SIGNATURE, result.perOrigin[0].outcome.kind)
        assertEquals(ManifestOriginOutcomeKind.ACCEPTED, result.perOrigin[1].outcome.kind)
        assertEquals(2, repo.trusted()!!.manifestVersion)
    }

    @Test
    fun `primary valid v2 and secondary valid v3 converge on v3 - highest valid version wins`() = runTest {
        val repo = repository()
        val client = MultiOriginManifestDistributionClient(
            origins = listOf(frankfurt, stockholm),
            repository = repo,
            fetcherFor = { origin ->
                when (origin.id) {
                    "frankfurt" -> RemoteManifestFetcher { ManifestFetchResult.Fetched(sign(manifest(2))) }
                    else -> RemoteManifestFetcher { ManifestFetchResult.Fetched(sign(manifest(3))) }
                }
            },
        )

        val result = client.refresh()

        assertEquals(3, repo.trusted()!!.manifestVersion)
        assertEquals(ManifestOriginOutcomeKind.ACCEPTED, result.perOrigin[0].outcome.kind)
        assertEquals(ManifestOriginOutcomeKind.ACCEPTED, result.perOrigin[1].outcome.kind)
        assertEquals(3, (result.finalOutcome as ManifestUpdateResult.Accepted).manifest.manifestVersion)
    }

    @Test
    fun `primary valid v3 and secondary valid v2 - v3 stays trusted, v2 is a no-op rollback`() = runTest {
        val repo = repository()
        val client = MultiOriginManifestDistributionClient(
            origins = listOf(frankfurt, stockholm),
            repository = repo,
            fetcherFor = { origin ->
                when (origin.id) {
                    "frankfurt" -> RemoteManifestFetcher { ManifestFetchResult.Fetched(sign(manifest(3))) }
                    else -> RemoteManifestFetcher { ManifestFetchResult.Fetched(sign(manifest(2))) }
                }
            },
        )

        val result = client.refresh()

        assertEquals(3, repo.trusted()!!.manifestVersion)
        assertEquals(ManifestOriginOutcomeKind.ACCEPTED, result.perOrigin[0].outcome.kind)
        assertEquals(ManifestOriginOutcomeKind.ROLLBACK_OR_NOT_NEWER, result.perOrigin[1].outcome.kind)
    }

    @Test
    fun `duplicate origin URLs are deduplicated by ManifestOriginConfig`() {
        val origins = ManifestOriginConfig.parse("https://152.70.43.1/v1/manifest,https://152.70.43.1/v1/manifest,https://16.170.208.231/v1/manifest")
        assertEquals(2, origins.size)
        assertEquals("152.70.43.1", origins[0].id)
        assertEquals("16.170.208.231", origins[1].id)
    }

    @Test
    fun `malformed or blank origin entries are rejected safely, never producing a broken origin`() {
        val origins = ManifestOriginConfig.parse("  ,https://152.70.43.1/v1/manifest, ,not-a-url,http://insecure.example/v1/manifest,")
        assertEquals(1, origins.size)
        assertEquals("152.70.43.1", origins[0].id)
    }

    @Test
    fun `all origins failing leaves the existing LKG completely untouched`() = runTest {
        val repo = repository()
        // establish a real LKG first
        MultiOriginManifestDistributionClient(
            origins = listOf(frankfurt),
            repository = repo,
            fetcherFor = { RemoteManifestFetcher { ManifestFetchResult.Fetched(sign(manifest(4))) } },
        ).refresh()
        assertEquals(4, repo.trusted()!!.manifestVersion)
        assertEquals(ManifestSource.LAST_KNOWN_GOOD, repo.trustedSource())

        val client = MultiOriginManifestDistributionClient(
            origins = listOf(frankfurt, stockholm),
            repository = repo,
            fetcherFor = { RemoteManifestFetcher { ManifestFetchResult.Failed("network error: SocketTimeoutException") } },
        )
        val result = client.refresh()

        assertEquals(4, repo.trusted()!!.manifestVersion)
        assertEquals(ManifestSource.LAST_KNOWN_GOOD, repo.trustedSource())
        assertTrue(result.finalOutcome is ManifestUpdateResult.Rejected)
    }

    @Test
    fun `all origins failing with no prior LKG falls back to the signed embedded bootstrap`() = runTest {
        val repo = repository(bootstrapVersion = 1)
        val client = MultiOriginManifestDistributionClient(
            origins = listOf(frankfurt, stockholm),
            repository = repo,
            fetcherFor = { RemoteManifestFetcher { ManifestFetchResult.Failed("network error: SocketTimeoutException") } },
        )

        client.refresh()

        assertEquals(1, repo.trusted()!!.manifestVersion)
        assertEquals(ManifestSource.EMBEDDED_BOOTSTRAP, repo.trustedSource())
    }

    @Test
    fun `an invalid origin candidate can never poison or erase the LKG`() = runTest {
        val repo = repository()
        MultiOriginManifestDistributionClient(
            origins = listOf(frankfurt),
            repository = repo,
            fetcherFor = { RemoteManifestFetcher { ManifestFetchResult.Fetched(sign(manifest(4))) } },
        ).refresh()
        assertEquals(4, repo.trusted()!!.manifestVersion)

        val otherKey = Ed25519PrivateKeyParameters(random)
        val client = MultiOriginManifestDistributionClient(
            origins = listOf(frankfurt, stockholm),
            repository = repo,
            fetcherFor = { RemoteManifestFetcher { ManifestFetchResult.Fetched(sign(manifest(9), otherKey)) } },
        )
        client.refresh()

        assertEquals(4, repo.trusted()!!.manifestVersion)
        assertEquals(ManifestSource.LAST_KNOWN_GOOD, repo.trustedSource())
    }

    @Test
    fun `an expired candidate from one origin is classified EXPIRED and does not replace LKG`() = runTest {
        val longLivedRepo = EndpointManifestRepository(
            verifier = Ed25519ManifestVerifier(),
            trustAnchors = anchors,
            lkgStore = FileLastKnownGoodManifestStore(tempFolder.newFolder()),
            bootstrapManifest = sign(manifest(1).copy(expiresAtEpochMillis = 100_000_000L)),
            nowEpochMillis = { 20_000_000L },
        )
        val expired = manifest(9).copy(issuedAtEpochMillis = 1_000L, expiresAtEpochMillis = 9_000_000L)
        val client = MultiOriginManifestDistributionClient(
            origins = listOf(frankfurt),
            repository = longLivedRepo,
            fetcherFor = { RemoteManifestFetcher { ManifestFetchResult.Fetched(sign(expired)) } },
        )

        val result = client.refresh()

        assertEquals(ManifestOriginOutcomeKind.EXPIRED, result.perOrigin[0].outcome.kind)
        assertEquals(1, longLivedRepo.trusted()!!.manifestVersion)
    }

    @Test
    fun `zero configured origins yields a null final outcome and an empty per-origin list`() = runTest {
        val repo = repository()
        val client = MultiOriginManifestDistributionClient(origins = emptyList(), repository = repo)

        val result = client.refresh()

        assertNull(result.finalOutcome)
        assertTrue(result.perOrigin.isEmpty())
    }
}
