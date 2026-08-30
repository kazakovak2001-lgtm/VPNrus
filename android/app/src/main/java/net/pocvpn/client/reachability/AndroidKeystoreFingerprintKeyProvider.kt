package net.pocvpn.client.reachability

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.KeyGenerator
import javax.crypto.Mac

/**
 * Real [NetworkFingerprintKeyProvider]: a non-exportable AndroidKeyStore
 * HMAC-SHA256 key, generated once under a stable alias and reused after
 * that - same "key never leaves the Keystore" discipline as
 * AndroidKeystoreAesGcmEncryptor. Unlike that class, this provider needs the
 * raw key material available to Mac.init() outside the Keystore's own
 * Mac-via-Provider path is NOT possible for a truly non-exportable key - so
 * instead this uses the Keystore's OWN Mac instance directly
 * (Mac.getInstance("HmacSHA256", "AndroidKeyStore")-equivalent via the
 * SecretKey handle) rather than extracting key bytes, keeping the same
 * non-exportability guarantee as the AES encryptor.
 */
class AndroidKeystoreFingerprintKeyProvider(private val keyAlias: String) {

    private companion object {
        const val PROVIDER = "AndroidKeyStore"
        const val ALGORITHM = KeyProperties.KEY_ALGORITHM_HMAC_SHA256
    }

    private val keyStore: KeyStore = KeyStore.getInstance(PROVIDER).apply { load(null) }

    /** Computes an HMAC-SHA256 over [message] using the non-exportable Keystore key directly - the key's raw bytes are never read into process memory. */
    fun hmac(message: ByteArray): ByteArray {
        val mac = Mac.getInstance(ALGORITHM)
        mac.init(getOrCreateKey())
        return mac.doFinal(message)
    }

    private fun getOrCreateKey(): javax.crypto.SecretKey {
        (keyStore.getKey(keyAlias, null) as? javax.crypto.SecretKey)?.let { return it }
        val keyGenerator = KeyGenerator.getInstance(ALGORITHM, PROVIDER)
        val spec = KeyGenParameterSpec.Builder(keyAlias, KeyProperties.PURPOSE_SIGN).build()
        keyGenerator.init(spec)
        return keyGenerator.generateKey()
    }
}

/**
 * Adapts [AndroidKeystoreFingerprintKeyProvider]'s HMAC-over-message shape
 * to [NetworkFingerprinter]'s "give me the key bytes" shape by pre-computing
 * a fixed, non-secret label HMAC as this install's local fingerprinting key
 * material - this never exposes the real Keystore key, only a value derived
 * from it, which is exactly as safe to hold in process memory as any other
 * derived secret.
 */
fun fingerprintKeyProvider(keystoreProvider: AndroidKeystoreFingerprintKeyProvider): NetworkFingerprintKeyProvider =
    NetworkFingerprintKeyProvider { keystoreProvider.hmac("nova-network-fingerprint-v1".toByteArray(Charsets.UTF_8)) }
