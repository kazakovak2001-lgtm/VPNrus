package net.pocvpn.client.debug.b45a

import java.util.Base64
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B45A - SPIKE ONLY. Verifies [SPIKE_FAKE_PSK] (the fake AEAD-2022 test
 * credential [B45ARuntime] passes to real `sslocal`) is in the exact format
 * the pinned shadowsocks-rust v1.25.0 source actually requires - see
 * docs/B45A_SHADOWSOCKS_RUST_SPIKE.md Section 28.1 for the source citation
 * (`crates/shadowsocks/src/config.rs`'s `make_derived_key()`): base64
 * (standard alphabet, `java.util.Base64.getDecoder()` accepts both padded
 * and unpadded, matching upstream's `DecodePaddingMode::Indifferent`) of
 * EXACTLY 32 raw bytes for `2022-blake3-aes-256-gcm` (the AES-256 key
 * size). Round 3's physical test failed specifically because this was not
 * yet true (a plain ASCII password string, not a base64-encoded 32-byte
 * key) - this test exists so that specific regression can never reappear
 * silently.
 */
class B45AFakeKeyFormatTest {

    private val requiredAead2022Aes256GcmKeyBytes = 32 // Aes256Gcm::key_size() - see class doc citation

    @Test
    fun `fake PSK decodes as standard base64`() {
        // Throws IllegalArgumentException if not valid base64 - the same
        // failure category (base64::DecodeError) real sslocal hit in round 3.
        Base64.getDecoder().decode(SPIKE_FAKE_PSK)
    }

    @Test
    fun `fake PSK decodes to exactly the AES-256 key length AEAD-2022 requires`() {
        val decoded = Base64.getDecoder().decode(SPIKE_FAKE_PSK)

        assertEquals(requiredAead2022Aes256GcmKeyBytes, decoded.size)
    }

    @Test
    fun `fake PSK is obviously non-production test material, never a real secret`() {
        val decoded = Base64.getDecoder().decode(SPIKE_FAKE_PSK)
        val decodedText = String(decoded, Charsets.US_ASCII)

        assertTrue(
            "fake key must be readable, clearly-fake ASCII, not opaque/random-looking bytes that could be mistaken for a real key",
            decodedText.contains("FAKE") && decodedText.contains("B45A"),
        )
    }
}
