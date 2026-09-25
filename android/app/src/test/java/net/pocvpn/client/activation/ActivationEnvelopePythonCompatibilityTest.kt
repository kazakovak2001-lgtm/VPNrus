package net.pocvpn.client.activation

import net.pocvpn.client.reachability.EndpointId
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64

/**
 * B56-4A - LOAD-BEARING cross-language proof: gateway/tools/activation_envelope_issuer.py's
 * canonical encoding, Ed25519 signing, and outer [ActivationEnvelopeCodec]
 * container are byte-for-byte compatible with the merged Android B56-1
 * implementation.
 *
 * These artifacts were produced OFFLINE by that Python module using a
 * deterministic TEST-ONLY Ed25519 private key (raw bytes `0x00..0x1f`,
 * i.e. `bytes(range(32))`, from a REPL - see the generation transcript in
 * this PR's description) - never a real/production key, never committed
 * anywhere as a key material file. The corresponding public key
 * ([TEST_ISSUER_PUBLIC_KEY_BASE64]) is test-only fixture data, not a
 * production activation-issuer trust anchor (see
 * [ActivationIssuerTrustAnchors]'s own docs and
 * docs/B56_ACTIVATION_ISSUER_KEY_CEREMONY.md - B56-4A performs NO
 * production ceremony and adds NO production trust anchor).
 *
 * This test uses ONLY the EXISTING, unmodified
 * [ActivationEnvelopeCodec]/[Ed25519ActivationEnvelopeVerifier]/
 * [FixedActivationIssuerTrustAnchors] - no special fixture-only verifier
 * is created here.
 */
class ActivationEnvelopePythonCompatibilityTest {

    private val testIssuerKeyId = ActivationIssuerKeyId("test-activation-issuer-key-1")
    private val testPublicKey = Base64.getDecoder().decode(TEST_ISSUER_PUBLIC_KEY_BASE64)
    private val trustAnchors = FixedActivationIssuerTrustAnchors(mapOf(testIssuerKeyId to testPublicKey))
    private val verifier = Ed25519ActivationEnvelopeVerifier()

    // Both fixtures were issued at 1_700_000_000_000 with a 48h validity
    // window - "now" for verification must fall inside [issuedAt, expiresAt).
    private val fixtureNowEpochMillis = 1_700_000_000_000L + 3600_000L

    @Test
    fun `fixture A (no bundle ref) decodes, verifies, and every field matches what Python encoded`() {
        val bytes = Base64.getDecoder().decode(FIXTURE_A_ARTIFACT_BASE64)

        val decoded = ActivationEnvelopeCodec.decode(bytes)
        assertTrue("expected successful decode, got $decoded", decoded is SignedActivationEnvelopeDecodeResult.Success)
        val signed = (decoded as SignedActivationEnvelopeDecodeResult.Success).signed

        val result = verifier.verify(signed, trustAnchors, fixtureNowEpochMillis)
        assertTrue("expected signature to verify, got $result", result is ActivationEnvelopeVerificationResult.Valid)
        val envelope = (result as ActivationEnvelopeVerificationResult.Valid).envelope

        assertEquals("a1b2c3d4e5f60718293a4b5c6d7e8f90", envelope.activationId.value)
        assertEquals("TESTcredential_urlsafe-0123456789ABCDEFGHIJ", envelope.credential.value)
        assertEquals(1_700_000_000_000L, envelope.issuedAtEpochMillis)
        assertEquals(1_700_000_000_000L, envelope.notBeforeEpochMillis)
        assertEquals(1_700_000_000_000L + 48 * 3600_000L, envelope.expiresAtEpochMillis)
        assertNull(envelope.bootstrapBundleRef)
        // Hint ORDER preserved exactly as Python emitted it - never sorted.
        assertEquals(listOf(EndpointId("frankfurt-gw"), EndpointId("stockholm-gw")), envelope.bootstrapEndpointHints)
        assertNull(envelope.bootstrapCapabilityHint)
        assertArrayEquals((0 until 16).map { it.toByte() }.toByteArray(), envelope.nonce)
        assertEquals(testIssuerKeyId, envelope.issuerKeyId)
    }

    @Test
    fun `fixture B (with bundle ref) decodes, verifies, and bundle version+hash match exactly`() {
        val bytes = Base64.getDecoder().decode(FIXTURE_B_ARTIFACT_BASE64)

        val decoded = ActivationEnvelopeCodec.decode(bytes)
        assertTrue("expected successful decode, got $decoded", decoded is SignedActivationEnvelopeDecodeResult.Success)
        val signed = (decoded as SignedActivationEnvelopeDecodeResult.Success).signed

        val result = verifier.verify(signed, trustAnchors, fixtureNowEpochMillis)
        assertTrue("expected signature to verify, got $result", result is ActivationEnvelopeVerificationResult.Valid)
        val envelope = (result as ActivationEnvelopeVerificationResult.Valid).envelope

        val ref = envelope.bootstrapBundleRef
        assertTrue("expected a bootstrapBundleRef", ref != null)
        assertEquals(7, ref!!.manifestVersion)
        assertArrayEquals(hexToBytes(FIXTURE_B_CONTENT_HASH_HEX), ref.contentHash)
        assertEquals(listOf(EndpointId("frankfurt-gw"), EndpointId("stockholm-gw")), envelope.bootstrapEndpointHints)
        assertNull(envelope.bootstrapCapabilityHint)
    }

    @Test
    fun `canonical bytes produced by Python match ActivationEnvelopeCanonicalizer's own re-encoding exactly`() {
        val bytes = Base64.getDecoder().decode(FIXTURE_A_ARTIFACT_BASE64)
        val decoded = (ActivationEnvelopeCodec.decode(bytes) as SignedActivationEnvelopeDecodeResult.Success).signed
        val recanonicalized = ActivationEnvelopeCanonicalizer.canonicalBytes(decoded.envelope)
        val pythonCanonical = Base64.getDecoder().decode(FIXTURE_A_CANONICAL_BASE64)
        assertArrayEquals(pythonCanonical, recanonicalized)
    }

    @Test
    fun `tampering a single byte of the Python-produced artifact fails signature verification`() {
        val bytes = Base64.getDecoder().decode(FIXTURE_A_ARTIFACT_BASE64)
        val tampered = bytes.copyOf()
        // Flip one byte well inside the canonical section (past the fixed
        // header), not the outer length-prefix framing, so this exercises
        // signature invalidation rather than a decode-level rejection.
        tampered[40] = (tampered[40].toInt() xor 0x01).toByte()

        val decoded = ActivationEnvelopeCodec.decode(tampered)
        // Either the flipped byte corrupts the container enough to fail
        // decode, or it decodes but the signature must then fail - both are
        // acceptable "tampering detected" outcomes; a byte flip must never
        // silently produce a validly-verified envelope.
        when (decoded) {
            is SignedActivationEnvelopeDecodeResult.Failure -> { /* tampering caught at decode - acceptable */ }
            is SignedActivationEnvelopeDecodeResult.Success -> {
                val result = verifier.verify(decoded.signed, trustAnchors, fixtureNowEpochMillis)
                assertTrue("tampered artifact must not verify as Valid", result is ActivationEnvelopeVerificationResult.Invalid)
                assertEquals(ActivationEnvelopeFailureKind.PACKAGE_SIGNATURE_INVALID, (result as ActivationEnvelopeVerificationResult.Invalid).kind)
            }
        }
    }

    @Test
    fun `activation issuer trust anchors are a disjoint type from manifest trust anchors - cross-authority isolation holds for the fixture key too`() {
        // Structural, reflection-based proof, not a behavior test:
        // FixedActivationIssuerTrustAnchors does not implement
        // net.pocvpn.client.reachability.ManifestTrustAnchors at all (Kotlin's
        // own compiler already refuses an `is` check between these two
        // unrelated types, which is itself evidence of the separation) -
        // there is no API surface on which this fixture's test public key
        // could ever be handed to a net.pocvpn.client.reachability.ManifestVerifier
        // call, so this fixture cannot be used to authorize a manifest by
        // construction. See ActivationIssuerTrustAnchorsTest for the
        // canonical version of this proof.
        val manifestTrustAnchorsInterface = Class.forName("net.pocvpn.client.reachability.ManifestTrustAnchors")
        assertFalse(manifestTrustAnchorsInterface.isAssignableFrom(FixedActivationIssuerTrustAnchors::class.java))
    }

    private fun hexToBytes(hex: String): ByteArray =
        ByteArray(hex.length / 2) { i -> ((Character.digit(hex[i * 2], 16) shl 4) + Character.digit(hex[i * 2 + 1], 16)).toByte() }

    @Test
    fun `B56-5 - Python-produced NovaActivationPackage parses, verifies, and re-encodes byte-identically`() {
        val parsed = ActivationPackageParser.parse(ActivationPackageInput.Text(FIXTURE_A_PACKAGE_TEXT))
        assertTrue("expected package parse success, got $parsed", parsed is ActivationPackageParseResult.Success)
        val pkg = (parsed as ActivationPackageParseResult.Success).pkg
        assertNull(pkg.bootstrapBundle)
        val result = verifier.verify(pkg.signedEnvelope, trustAnchors, fixtureNowEpochMillis)
        assertTrue("expected Valid, got $result", result is ActivationEnvelopeVerificationResult.Valid)
        assertEquals("a1b2c3d4e5f60718293a4b5c6d7e8f90", (result as ActivationEnvelopeVerificationResult.Valid).envelope.activationId.value)
        assertEquals(FIXTURE_A_PACKAGE_TEXT, ActivationPackageParser.encodeText(pkg))
    }

    companion object {
        /** B56-5 - fixture A wrapped by Python `activation_envelope_issuer.pack_activation_package` (no bundle). */
        private const val FIXTURE_A_PACKAGE_TEXT =
            "nova-activation:1:AAAAGk5PVkFfQUNUSVZBVElPTl9QQUNLQUdFX1YxAAAAAQAAATQAAAABAAAA6AAAABtOT1ZBX0FDVElWQV" +
            "RJT05fRU5WRUxPUEVfVjEAAAABAAAAIGExYjJjM2Q0ZTVmNjA3MTgyOTNhNGI1YzZkN2U4ZjkwAAAAK1RFU1RjcmVkZW50aWFsX3" +
            "VybHNhZmUtMDEyMzQ1Njc4OUFCQ0RFRkdISUoAAAGLz-VoAAAAAYvP5WgAAAABi9oyIAAAAAAAAgAAAAxmcmFua2Z1cnQtZ3cAAA" +
            "AMc3RvY2tob2xtLWd3AAAAABAAAQIDBAUGBwgJCgsMDQ4PAAAAHHRlc3QtYWN0aXZhdGlvbi1pc3N1ZXIta2V5LTEAAABAxxsay3" +
            "Nq_gQV0ppBjL6JziQPghx2AwlGTIYShLZtDdzNK-j7kPJ99OC0xnZjsxYjwhcPc30sWgCmx9Xb9bQeAwAAAAAAAAAA"

        /**
         * Raw 32-byte Ed25519 public key for the deterministic TEST-ONLY
         * private key `bytes(range(32))` - TEST FIXTURE DATA ONLY, never a
         * production trust anchor. See class docs.
         */
        private const val TEST_ISSUER_PUBLIC_KEY_BASE64 = "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg="

        /** Python-produced ActivationEnvelopeCodec artifact - no bundle ref, 2 ordered hints. */
        private const val FIXTURE_A_ARTIFACT_BASE64 =
            "AAAAAQAAAOgAAAAbTk9WQV9BQ1RJVkFUSU9OX0VOVkVMT1BFX1YxAAAAAQAAACBhMWIyYzNkNGU1ZjYwNzE4MjkzYTRiNWM2ZDdlOGY5MAAAACtURVNUY3JlZGVudGlhbF91cmxzYWZlLTAxMjM0NTY3ODlBQkNERUZHSElKAAABi8/laAAAAAGLz+VoAAAAAYvaMiAAAAAAAAIAAAAMZnJhbmtmdXJ0LWd3AAAADHN0b2NraG9sbS1ndwAAAAAQAAECAwQFBgcICQoLDA0ODwAAABx0ZXN0LWFjdGl2YXRpb24taXNzdWVyLWtleS0xAAAAQMcbGstzav4EFdKaQYy+ic4kD4IcdgMJRkyGEoS2bQ3czSvo+5DyffTgtMZ2Y7MWI8IXD3N9LFoApsfV2/W0HgM="

        /** The canonical (pre-signature-container) bytes Python computed for fixture A - used to prove Python's canonicalizer and Android's produce IDENTICAL bytes for the same logical envelope. */
        private const val FIXTURE_A_CANONICAL_BASE64 =
            "AAAAG05PVkFfQUNUSVZBVElPTl9FTlZFTE9QRV9WMQAAAAEAAAAgYTFiMmMzZDRlNWY2MDcxODI5M2E0YjVjNmQ3ZThmOTAAAAArVEVTVGNyZWRlbnRpYWxfdXJsc2FmZS0wMTIzNDU2Nzg5QUJDREVGR0hJSgAAAYvP5WgAAAABi8/laAAAAAGL2jIgAAAAAAACAAAADGZyYW5rZnVydC1ndwAAAAxzdG9ja2hvbG0tZ3cAAAAAEAABAgMEBQYHCAkKCwwNDg8AAAAcdGVzdC1hY3RpdmF0aW9uLWlzc3Vlci1rZXktMQ=="

        /** Python-produced ActivationEnvelopeCodec artifact - WITH a bundle ref (manifestVersion=7). */
        private const val FIXTURE_B_ARTIFACT_BASE64 =
            "AAAAAQAAARAAAAAbTk9WQV9BQ1RJVkFUSU9OX0VOVkVMT1BFX1YxAAAAAQAAACBhMWIyYzNkNGU1ZjYwNzE4MjkzYTRiNWM2ZDdlOGY5MAAAACtURVNUY3JlZGVudGlhbF91cmxzYWZlLTAxMjM0NTY3ODlBQkNERUZHSElKAAABi8/laAAAAAGLz+VoAAAAAYvaMiAAAQAAAAcAAAAgJY8XHnWRugoAScxvFu50Pgey//mM2nUf0MXjGdWwNsEAAAACAAAADGZyYW5rZnVydC1ndwAAAAxzdG9ja2hvbG0tZ3cAAAAAEBAREhMUFRYXGBkaGxwdHh8AAAAcdGVzdC1hY3RpdmF0aW9uLWlzc3Vlci1rZXktMQAAAEDayl3fyl8Av2L3eN858gTrVnmSsuWNUIqtlKIe/D33YovYMMIZlz+jV5Kf8IGPNZUubU1Q2b2t2oNbXDmUiHUP"

        /** Exact SHA-256 (hex, 64 chars) Python computed over its own fake test manifest-artifact bytes for fixture B's bundleRef.contentHash. */
        private const val FIXTURE_B_CONTENT_HASH_HEX = "258f171e7591ba0a0049cc6f16ee743e07b2fff98cda751fd0c5e319d5b036c1"
    }
}
