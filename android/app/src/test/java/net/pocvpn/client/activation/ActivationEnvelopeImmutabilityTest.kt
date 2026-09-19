package net.pocvpn.client.activation

import net.pocvpn.client.reachability.EndpointId
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.SecureRandom

/**
 * PR #92 blocker 1 - a Kotlin `val ByteArray` only fixes the REFERENCE, not
 * the bytes it points to. Every regression here builds an object from a
 * caller-owned mutable source, mutates that source (or a value obtained
 * from an accessor) AFTER construction, and proves the already-built
 * object's signed data - and, for the full pipeline case, an
 * already-completed signature verification - is unaffected.
 */
class ActivationEnvelopeImmutabilityTest {

    private val random = SecureRandom()

    private fun keypair(): Pair<Ed25519PrivateKeyParameters, ByteArray> {
        val priv = Ed25519PrivateKeyParameters(random)
        return priv to priv.generatePublicKey().encoded
    }

    private fun signBytes(priv: Ed25519PrivateKeyParameters, message: ByteArray): ByteArray {
        val signer = Ed25519Signer()
        signer.init(true, priv)
        signer.update(message, 0, message.size)
        return signer.generateSignature()
    }

    private fun baseNonce(): ByteArray = ByteArray(ActivationEnvelope.NONCE_LENGTH) { it.toByte() }

    private fun envelope(
        nonce: ByteArray = baseNonce(),
        capabilityHint: ByteArray? = ByteArray(8) { it.toByte() },
        hints: List<EndpointId> = listOf(EndpointId("gw-a"), EndpointId("gw-b")),
        bundleRef: ActivationBundleRef? = ActivationBundleRef(1, ByteArray(32) { it.toByte() }),
    ) = ActivationEnvelope(
        activationId = ActivationId("a".repeat(32)),
        credential = ActivationCredential("abcDEF123_-abcDEF123_-abcDEF123456789"),
        issuedAtEpochMillis = 1_000_000L,
        notBeforeEpochMillis = 1_000_000L,
        expiresAtEpochMillis = 2_000_000L,
        bootstrapBundleRef = bundleRef,
        bootstrapEndpointHints = hints,
        bootstrapCapabilityHint = capabilityHint,
        nonce = nonce,
        issuerKeyId = ActivationIssuerKeyId("issuer-key-1"),
    )

    // 1. mutating source nonce after construction does not change envelope
    @Test
    fun `mutating source nonce array after construction does not change the envelope`() {
        val source = baseNonce()
        val envelope = envelope(nonce = source)
        val canonicalBefore = ActivationEnvelopeCanonicalizer.canonicalBytes(envelope)

        source[0] = (source[0] + 1).toByte()

        assertArrayEquals(baseNonce(), envelope.nonce)
        assertArrayEquals(canonicalBefore, ActivationEnvelopeCanonicalizer.canonicalBytes(envelope))
    }

    // 2. mutating source capability array after construction does not change envelope
    @Test
    fun `mutating source capability hint array after construction does not change the envelope`() {
        val source = ByteArray(8) { it.toByte() }
        val original = source.copyOf()
        val envelope = envelope(capabilityHint = source)
        val canonicalBefore = ActivationEnvelopeCanonicalizer.canonicalBytes(envelope)

        source[0] = (source[0] + 1).toByte()

        assertArrayEquals(original, envelope.bootstrapCapabilityHint)
        assertArrayEquals(canonicalBefore, ActivationEnvelopeCanonicalizer.canonicalBytes(envelope))
    }

    // 3. mutating source bundle-hash array after construction does not change bundle ref
    @Test
    fun `mutating source bundle content hash array after construction does not change the bundle ref`() {
        val source = ByteArray(32) { it.toByte() }
        val original = source.copyOf()
        val bundleRef = ActivationBundleRef(1, source)

        source[0] = (source[0] + 1).toByte()

        assertArrayEquals(original, bundleRef.contentHash)
    }

    // 4. mutating source hint MutableList after construction does not change envelope
    @Test
    fun `mutating source mutable hint list after construction does not change the envelope`() {
        val source: MutableList<EndpointId> = mutableListOf(EndpointId("gw-a"), EndpointId("gw-b"))
        val envelope = envelope(hints = source)
        val canonicalBefore = ActivationEnvelopeCanonicalizer.canonicalBytes(envelope)

        source.clear()
        source.add(EndpointId("gw-z"))

        assertEquals(listOf(EndpointId("gw-a"), EndpointId("gw-b")), envelope.bootstrapEndpointHints)
        assertArrayEquals(canonicalBefore, ActivationEnvelopeCanonicalizer.canonicalBytes(envelope))
    }

    // PR #92 second pass, issue 1: the ACCESSOR itself must never hand out a
    // mutable backing list. `List<T>` is only a read-only-view interface -
    // the runtime object behind `.toList()` is normally an `ArrayList`,
    // which an unchecked cast back to `MutableList` can still mutate.
    @Test
    @Suppress("UNCHECKED_CAST")
    fun `mutating the object returned by the bootstrapEndpointHints accessor does not change the envelope`() {
        val envelope = envelope(hints = listOf(EndpointId("gw-a"), EndpointId("gw-b")))
        val canonicalBefore = ActivationEnvelopeCanonicalizer.canonicalBytes(envelope)

        val exposed = envelope.bootstrapEndpointHints
        val mutated = runCatching {
            (exposed as MutableList<EndpointId>).apply {
                clear()
                add(EndpointId("gw-z"))
            }
            true
        }.getOrDefault(false)

        // Whether or not the cast/mutation itself succeeds at runtime is
        // incidental - what matters is that IF it succeeds, it must have
        // mutated only the returned copy, never this envelope's signed state.
        assertEquals(listOf(EndpointId("gw-a"), EndpointId("gw-b")), envelope.bootstrapEndpointHints)
        assertArrayEquals(canonicalBefore, ActivationEnvelopeCanonicalizer.canonicalBytes(envelope))
        assertTrue("test sanity: the cast must actually succeed on this JVM for the assertions above to be meaningful", mutated)
    }

    // 5. mutating source trust-anchor map or public-key byte array after anchor construction does not alter verification behavior
    @Test
    fun `mutating source trust-anchor map after construction does not alter verification behavior`() {
        val (priv, pub) = keypair()
        val envelope = envelope()
        val signature = signBytes(priv, ActivationEnvelopeCanonicalizer.canonicalBytes(envelope))
        val signed = SignedActivationEnvelope(envelope, signature)

        val sourceMap: MutableMap<ActivationIssuerKeyId, ByteArray> = mutableMapOf(ActivationIssuerKeyId("issuer-key-1") to pub)
        val anchors = FixedActivationIssuerTrustAnchors(sourceMap)

        sourceMap.clear()
        sourceMap[ActivationIssuerKeyId("issuer-key-1")] = ByteArray(32)

        val result = Ed25519ActivationEnvelopeVerifier().verify(signed, anchors, nowEpochMillis = 1_500_000L)
        assertTrue("verification must still succeed - the anchor set must not have been affected by mutating the source map afterward", result is ActivationEnvelopeVerificationResult.Valid)
    }

    @Test
    fun `mutating source public-key byte array after anchor construction does not alter verification behavior`() {
        val (priv, pub) = keypair()
        val envelope = envelope()
        val signature = signBytes(priv, ActivationEnvelopeCanonicalizer.canonicalBytes(envelope))
        val signed = SignedActivationEnvelope(envelope, signature)

        val anchors = FixedActivationIssuerTrustAnchors(mapOf(ActivationIssuerKeyId("issuer-key-1") to pub))

        // Mutate the ORIGINAL public-key array the anchor set was built from.
        pub[0] = (pub[0] + 1).toByte()

        val result = Ed25519ActivationEnvelopeVerifier().verify(signed, anchors, nowEpochMillis = 1_500_000L)
        assertTrue("verification must still succeed against the key bytes captured at construction time, not the mutated source array", result is ActivationEnvelopeVerificationResult.Valid)
    }

    // 6. arrays obtained from accessors, if exposed as ByteArray, cannot mutate internal state
    @Test
    fun `mutating an array obtained from the nonce accessor does not affect internal state`() {
        val envelope = envelope()
        val obtained = envelope.nonce
        obtained[0] = (obtained[0] + 1).toByte()
        assertArrayEquals(baseNonce(), envelope.nonce)
    }

    @Test
    fun `mutating an array obtained from the capability hint accessor does not affect internal state`() {
        val original = ByteArray(8) { it.toByte() }
        val envelope = envelope(capabilityHint = original.copyOf())
        val obtained = envelope.bootstrapCapabilityHint!!
        obtained[0] = (obtained[0] + 1).toByte()
        assertArrayEquals(original, envelope.bootstrapCapabilityHint)
    }

    @Test
    fun `mutating an array obtained from the bundle content-hash accessor does not affect internal state`() {
        val original = ByteArray(32) { it.toByte() }
        val bundleRef = ActivationBundleRef(1, original.copyOf())
        val obtained = bundleRef.contentHash
        obtained[0] = (obtained[0] + 1).toByte()
        assertArrayEquals(original, bundleRef.contentHash)
    }

    @Test
    fun `mutating an array obtained from the signature accessor does not affect internal state`() {
        val (priv, _) = keypair()
        val envelope = envelope()
        val signature = signBytes(priv, ActivationEnvelopeCanonicalizer.canonicalBytes(envelope))
        val original = signature.copyOf()
        val signed = SignedActivationEnvelope(envelope, signature)

        val obtained = signed.signature
        obtained[0] = (obtained[0] + 1).toByte()
        assertArrayEquals(original, signed.signature)
    }

    @Test
    fun `mutating an array obtained from publicKeyFor does not affect internal state`() {
        val (_, pub) = keypair()
        val anchors = FixedActivationIssuerTrustAnchors(mapOf(ActivationIssuerKeyId("issuer-key-1") to pub))
        val obtained = anchors.publicKeyFor(ActivationIssuerKeyId("issuer-key-1"))!!
        val original = obtained.copyOf()
        obtained[0] = (obtained[0] + 1).toByte()
        assertArrayEquals(original, anchors.publicKeyFor(ActivationIssuerKeyId("issuer-key-1")))
    }
}
