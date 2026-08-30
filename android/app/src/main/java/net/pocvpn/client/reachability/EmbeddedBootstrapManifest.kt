package net.pocvpn.client.reachability

import java.util.Base64

/**
 * B11 - the embedded, offline-signed emergency/bootstrap manifest. This is a
 * REAL, cryptographically valid Ed25519-signed manifest (produced by
 * gateway/tools/manifest_signing.py, an offline tool that never touches the
 * production VPS) - never an unsigned or arbitrary fallback blob (see the
 * task's own "bootstrap must also be cryptographically trusted" requirement).
 *
 * The embedded [BOOTSTRAP_PUBLIC_KEY_BASE64] is this slice's placeholder
 * trust root - a real key generated for this PR, not yet backed by a
 * production key-ceremony process. Rotating to a production-grade root
 * requires only replacing this constant (and re-signing with the matching
 * private key) - nothing else in EndpointManifestRepository/ManifestVerifier
 * depends on this specific key's provenance, which is the point of keeping
 * root/signing verification behind the [ManifestTrustAnchors] interface
 * rather than a hardcoded key check.
 *
 * Canonical bytes + signature are embedded as opaque base64 (never
 * reconstructed field-by-field here) so this file can never silently drift
 * out of byte-for-byte agreement with what was actually signed.
 */
object EmbeddedBootstrapManifest {

    const val TRUSTED_KEY_ID = "bootstrap-key-1"

    private const val BOOTSTRAP_PUBLIC_KEY_BASE64 = "vwGdw1NBud8SVQHZxMlIENKJag1CeNYP0Sy5O1nJgL0="

    private const val CANONICAL_BYTES_BASE64 =
        "AAAAAQAAAAEAAAGgUvlL8wAAAa8CW6PzAAAAD2Jvb3RzdHJhcC1rZXktMQAAAAEAAAAJZnJhbmtmdXJ0AAAAAgAAAAEAAAACAAAAE0dlcm1hbnkgLyBGcmFua2Z1cnQAAAAHaGV0em5lcgAAAAAAAAAAAwAAAAAAAAALMTUyLjcwLjQzLjEAAMpsAAAAAAAAAAEAAAALMTUyLjcwLjQzLjEAAAgFAAAAAAAAAAMAAAALMTUyLjcwLjQzLjEAAAgjAAAAAAAAAAAA"

    private const val SIGNATURE_BASE64 =
        "l3kGonyTGrPasKZA/jEB/vt7fwy87M0qThk3Nv8ekSSqU227ILiasYnOFI5ClN4FX6uoLcdLqrBiQcHQU4NBAQ=="

    fun trustAnchors(): ManifestTrustAnchors = FixedManifestTrustAnchors(
        mapOf(TrustedKeyId(TRUSTED_KEY_ID) to Base64.getDecoder().decode(BOOTSTRAP_PUBLIC_KEY_BASE64)),
    )

    fun signedManifest(): SignedManifest {
        val canonicalBytes = Base64.getDecoder().decode(CANONICAL_BYTES_BASE64)
        val signature = Base64.getDecoder().decode(SIGNATURE_BASE64)
        return SignedManifest(ManifestCanonicalizer.decode(canonicalBytes), signature)
    }
}
