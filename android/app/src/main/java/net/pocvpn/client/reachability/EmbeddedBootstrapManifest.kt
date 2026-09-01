package net.pocvpn.client.reachability

import java.util.Base64

/**
 * B11/B17 - the embedded, offline-signed emergency/bootstrap manifest. This
 * is a REAL, cryptographically valid Ed25519-signed manifest (produced by
 * gateway/tools/manifest_signing.py, an offline tool that never touches the
 * production VPS) - never an unsigned or arbitrary fallback blob (see the
 * task's own "bootstrap must also be cryptographically trusted" requirement).
 *
 * **B17 (2026-09-01) - PRODUCTION key ceremony performed.** The embedded
 * [BOOTSTRAP_PUBLIC_KEY_BASE64] is now a real production Ed25519 public key
 * generated in an offline ceremony (see `docs/B12_MANIFEST_KEY_CEREMONY.md`,
 * superseded/updated by that same file's "Production ceremony (B17,
 * completed)" section for the exact procedure actually run). The matching
 * PRIVATE key was generated and used to sign entirely inside one local,
 * offline script invocation - it was never printed, never passed as a CLI
 * argument, never committed, and is stored only in an operator-local file
 * outside this repository (path recorded in that doc, not here). Public key
 * SHA-256 fingerprint:
 * `2c39eddd256115600e3008495ee52b95865ab7a525f102f2fe45aad17b614aa1`
 * (record this fingerprint anywhere the production key's identity must be
 * confirmed out-of-band - never the private key itself).
 *
 * This bootstrap manifest (manifestVersion 1, signingKeyId
 * "prod-manifest-key-2026-09-01") names BOTH real production gateways
 * (Germany/Frankfurt, Sweden/Stockholm) with only immutable public routing
 * facts (id/roles/region/provider/transport host+port) - no per-device
 * secrets, no client tunnel IPs, no Xray/REALITY credentials (see this
 * object's own "what must never be embedded" discipline, unchanged from B11).
 *
 * Canonical bytes + signature are embedded as opaque base64 (never
 * reconstructed field-by-field here) so this file can never silently drift
 * out of byte-for-byte agreement with what was actually signed.
 */
object EmbeddedBootstrapManifest {

    const val TRUSTED_KEY_ID = "prod-manifest-key-2026-09-01"

    private const val BOOTSTRAP_PUBLIC_KEY_BASE64 = "yvxGVezkV5tkkzcQVf975mSDY9xYh72eOLOMwSFy+aw="

    private const val CANONICAL_BYTES_BASE64 =
        "AAAAAQAAAAEAAAGgWf9uWAAAAaP4+B5YAAAAHHByb2QtbWFuaWZlc3Qta2V5LTIwMjYtMDktMDEAAAACAAAACWZyYW5rZnVydAAAAAIAAAABAAAAAgAAABNHZXJtYW55IC8gRnJhbmtmdXJ0AAAADE9yYWNsZSBDbG91ZAAAAAAAAAAAAwAAAAAAAAALMTUyLjcwLjQzLjEAAMpsAAAAAAAAAAEAAAALMTUyLjcwLjQzLjEAAAgFAAAAAAAAAAMAAAALMTUyLjcwLjQzLjEAAAgjAAAAAAAAAAAAAAAACXN0b2NraG9sbQAAAAIAAAABAAAAAgAAABJTd2VkZW4gLyBTdG9ja2hvbG0AAAADQVdTAAAAAAAAAAADAAAAAAAAAA4xNi4xNzAuMjA4LjIzMQAAymwAAAAAAAAAAQAAAA4xNi4xNzAuMjA4LjIzMQAACAUAAAAAAAAAAwAAAA4xNi4xNzAuMjA4LjIzMQAACCMAAAAAAAAAAAA="

    private const val SIGNATURE_BASE64 =
        "dSxFo1//e7N290TWUZg6JOa+MOo5I2aZxQEBMWYGxMVsQshliebHrog2mc4HGROzfv4e7Eo6bO8omA953jVCCw=="

    fun trustAnchors(): ManifestTrustAnchors = FixedManifestTrustAnchors(
        mapOf(TrustedKeyId(TRUSTED_KEY_ID) to Base64.getDecoder().decode(BOOTSTRAP_PUBLIC_KEY_BASE64)),
    )

    fun signedManifest(): SignedManifest {
        val canonicalBytes = Base64.getDecoder().decode(CANONICAL_BYTES_BASE64)
        val signature = Base64.getDecoder().decode(SIGNATURE_BASE64)
        return SignedManifest(ManifestCanonicalizer.decode(canonicalBytes), signature)
    }
}
