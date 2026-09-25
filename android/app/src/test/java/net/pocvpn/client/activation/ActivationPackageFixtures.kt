package net.pocvpn.client.activation

import net.pocvpn.client.reachability.Ed25519ManifestVerifier
import net.pocvpn.client.reachability.EndpointDescriptor
import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.reachability.EndpointManifest
import net.pocvpn.client.reachability.EndpointManifestRepository
import net.pocvpn.client.reachability.EndpointRole
import net.pocvpn.client.reachability.EndpointTransportBinding
import net.pocvpn.client.reachability.FileLastKnownGoodManifestStore
import net.pocvpn.client.reachability.FixedManifestTrustAnchors
import net.pocvpn.client.reachability.ManifestCanonicalizer
import net.pocvpn.client.reachability.SignedBootstrapBundleImporter
import net.pocvpn.client.reachability.SignedManifest
import net.pocvpn.client.reachability.SignedManifestCodec
import net.pocvpn.client.reachability.TrustedKeyId
import net.pocvpn.client.transport.TransportKind
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import java.io.File
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * B56-5 test fixtures. EVERY key here is generated fresh per test run -
 * no production private key exists in (or is needed by) this repository.
 * The activation-issuer test key and the manifest test key are distinct
 * keys in distinct trust-anchor types, mirroring production separation.
 */
class ActivationPackageFixtures(lkgDir: File, val now: Long = 1_800_000_000_000L) {
    private val random = SecureRandom()

    val issuerKey = Ed25519PrivateKeyParameters(random)
    val issuerKeyId = ActivationIssuerKeyId("test-activation-issuer")
    val issuerAnchors: ActivationIssuerTrustAnchors =
        FixedActivationIssuerTrustAnchors(mapOf(issuerKeyId to issuerKey.generatePublicKey().encoded))

    val manifestKey = Ed25519PrivateKeyParameters(random)
    val manifestAnchors = FixedManifestTrustAnchors(mapOf(TrustedKeyId("manifest-key") to manifestKey.generatePublicKey().encoded))

    val credential = "Abc_def-123GHIjklMNOpqrSTUvwxYZ0123456789ab"

    val repository = EndpointManifestRepository(
        verifier = Ed25519ManifestVerifier(),
        trustAnchors = manifestAnchors,
        lkgStore = FileLastKnownGoodManifestStore(lkgDir),
        bootstrapManifest = signManifest(manifest(version = 1)),
        nowEpochMillis = { now },
    )

    fun manifest(version: Int, keyId: String = "manifest-key", expiresAt: Long = now + 30L * 86_400_000L) = EndpointManifest(
        manifestVersion = version,
        issuedAtEpochMillis = now - 60_000L,
        expiresAtEpochMillis = expiresAt,
        signingKeyId = keyId,
        endpoints = listOf(
            EndpointDescriptor(
                EndpointId("gw-$version"),
                setOf(EndpointRole.GATEWAY),
                "eu",
                "acme",
                transports = listOf(EndpointTransportBinding(TransportKind.AMNEZIA_WG, "203.0.113.$version", 51820)),
            ),
        ),
    )

    fun signManifest(manifest: EndpointManifest, key: Ed25519PrivateKeyParameters = manifestKey): SignedManifest =
        SignedManifest(manifest, sign(key, ManifestCanonicalizer.canonicalBytes(manifest)))

    fun bundleBytes(version: Int, key: Ed25519PrivateKeyParameters = manifestKey): ByteArray =
        SignedManifestCodec.encode(signManifest(manifest(version), key))

    fun refFor(bundle: ByteArray, version: Int) =
        ActivationBundleRef(version, MessageDigest.getInstance("SHA-256").digest(bundle))

    fun envelope(
        notBefore: Long = now - 60_000L,
        expiresAt: Long = now + 48L * 3_600_000L,
        issuedAt: Long = notBefore,
        bundleRef: ActivationBundleRef? = null,
        nonceSeed: Byte = 7,
        keyId: ActivationIssuerKeyId = issuerKeyId,
        credential: String = this.credential,
    ) = ActivationEnvelope(
        activationId = ActivationId("0123456789abcdef0123456789abcdef"),
        credential = ActivationCredential(credential),
        issuedAtEpochMillis = issuedAt,
        notBeforeEpochMillis = notBefore,
        expiresAtEpochMillis = expiresAt,
        bootstrapBundleRef = bundleRef,
        bootstrapEndpointHints = emptyList(),
        bootstrapCapabilityHint = null,
        nonce = ByteArray(ActivationEnvelope.NONCE_LENGTH) { (nonceSeed + it).toByte() },
        issuerKeyId = keyId,
    )

    fun signEnvelope(envelope: ActivationEnvelope, key: Ed25519PrivateKeyParameters = issuerKey) =
        SignedActivationEnvelope(envelope, sign(key, ActivationEnvelopeCanonicalizer.canonicalBytes(envelope)))

    fun packageText(envelope: ActivationEnvelope = envelope(), bundle: ByteArray? = null, key: Ed25519PrivateKeyParameters = issuerKey): String =
        ActivationPackageParser.encodeText(NovaActivationPackage(signEnvelope(envelope, key), bundle))

    fun importer(replayGuard: ActivationReplayGuard = InMemoryActivationReplayGuard()) =
        ActivationPackageImporter(issuerAnchors, SignedBootstrapBundleImporter(repository), replayGuard)

    private fun sign(key: Ed25519PrivateKeyParameters, bytes: ByteArray): ByteArray {
        val signer = Ed25519Signer()
        signer.init(true, key)
        signer.update(bytes, 0, bytes.size)
        return signer.generateSignature()
    }
}
