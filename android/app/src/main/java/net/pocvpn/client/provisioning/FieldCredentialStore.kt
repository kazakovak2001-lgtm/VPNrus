package net.pocvpn.client.provisioning

import net.pocvpn.client.identity.AesGcmKeyEncryptor
import net.pocvpn.client.identity.EncryptedPayload
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.nio.charset.StandardCharsets
import org.json.JSONObject

/**
 * Russia field-test zero-touch enrollment - this device's OWN, auto-issued
 * activation credential (see gateway/api/field_enrollment.py's own docs),
 * persisted so it never needs to be re-obtained after the first successful
 * POST /v1/field-enroll. This is the ONLY place this credential is ever
 * written to disk, and it is written encrypted - the same AndroidKeystoreAesGcmEncryptor
 * discipline [net.pocvpn.client.relay.FileIngressProfileStore] already uses
 * for the (structurally similar) ingress credential, with its own key
 * alias so this credential is never encrypted under key material shared
 * with anything else.
 *
 * A single credential, not endpoint-scoped: the whole point of zero-touch
 * enrollment is ONE device-specific credential that authorizes both its
 * own gateway activation AND (per the same activated-device authority)
 * ingress provisioning - see MainViewModel's own field-enrollment docs.
 */
data class FieldCredential(
    val credential: String,
    /** The endpoint host this credential was minted against - kept only for diagnostics/debugging, never used to decide trust (the credential's own validity, checked server-side on every use, is the only authority). */
    val issuedByEndpointHost: String,
)

interface FieldCredentialStore {
    suspend fun getOrNull(): FieldCredential?
    suspend fun save(credential: FieldCredential)
    suspend fun clear()
}

class FieldCredentialCorruptedException(message: String) : Exception(message)

class FileFieldCredentialStore(
    private val file: File,
    private val encryptor: AesGcmKeyEncryptor,
) : FieldCredentialStore {
    private companion object {
        const val FORMAT_VERSION = 1
        const val MAX_CIPHERTEXT_LEN = 4096
        const val MAX_IV_LEN = 64
    }

    override suspend fun getOrNull(): FieldCredential? {
        if (!file.exists()) return null
        val encrypted = try {
            DataInputStream(file.inputStream().buffered()).use { input ->
                val version = input.readInt()
                if (version != FORMAT_VERSION) throw FieldCredentialCorruptedException("unsupported format version $version")
                val iv = readLengthPrefixed(input, MAX_IV_LEN)
                val ciphertext = readLengthPrefixed(input, MAX_CIPHERTEXT_LEN)
                EncryptedPayload(iv, ciphertext)
            }
        } catch (e: java.io.EOFException) {
            throw FieldCredentialCorruptedException("truncated field credential file")
        } catch (e: java.io.IOException) {
            throw FieldCredentialCorruptedException("unreadable field credential file: ${e.javaClass.simpleName}")
        }
        val plaintext = encryptor.decrypt(encrypted)
        return try {
            val json = JSONObject(String(plaintext, StandardCharsets.UTF_8))
            val credential = json.getString("credential")
            val issuedByEndpointHost = json.optString("issued_by_endpoint_host", "")
            FieldCredential(credential, issuedByEndpointHost)
        } catch (e: org.json.JSONException) {
            throw FieldCredentialCorruptedException(e.message ?: "malformed field credential file")
        }
    }

    override suspend fun save(credential: FieldCredential) {
        file.parentFile?.mkdirs()
        val json = JSONObject()
            .put("credential", credential.credential)
            .put("issued_by_endpoint_host", credential.issuedByEndpointHost)
        val tmp = File(file.parentFile, "${file.name}.tmp")
        val encrypted = encryptor.encrypt(json.toString().toByteArray(StandardCharsets.UTF_8))
        val bytes = ByteArrayOutputStream().also { buffer ->
            DataOutputStream(buffer).use { out ->
                out.writeInt(FORMAT_VERSION)
                writeLengthPrefixed(out, encrypted.iv)
                writeLengthPrefixed(out, encrypted.ciphertext)
            }
        }.toByteArray()
        tmp.writeBytes(bytes)
        // java.io.File.renameTo is platform-dependent when the destination
        // already exists (POSIX rename() replaces it atomically; some other
        // filesystems refuse instead) - deleting any prior file first makes
        // this the same "replace on every platform" behavior everywhere,
        // including this project's own JVM/Windows test runs.
        file.delete()
        if (!tmp.renameTo(file)) {
            tmp.delete()
            throw java.io.IOException("failed to atomically replace field credential file")
        }
    }

    override suspend fun clear() {
        file.delete()
    }

    private fun writeLengthPrefixed(out: DataOutputStream, bytes: ByteArray) {
        out.writeInt(bytes.size)
        out.write(bytes)
    }

    private fun readLengthPrefixed(input: DataInputStream, maxLen: Int): ByteArray {
        val len = input.readInt()
        require(len in 0..maxLen) { "implausible length-prefixed field: $len" }
        val bytes = ByteArray(len)
        input.readFully(bytes)
        return bytes
    }
}

/** In-memory store for tests/unwired defaults - never used in production (see [FileFieldCredentialStore]). */
class InMemoryFieldCredentialStore : FieldCredentialStore {
    private var stored: FieldCredential? = null
    override suspend fun getOrNull(): FieldCredential? = stored
    override suspend fun save(credential: FieldCredential) { stored = credential }
    override suspend fun clear() { stored = null }
}
