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
 * activation credential(s) (see gateway/api/field_enrollment.py's own
 * docs), persisted so they never need to be re-obtained after the first
 * successful POST /v1/field-enroll. This is the ONLY place a field
 * credential is ever written to disk, and it is written encrypted - the
 * same AndroidKeystoreAesGcmEncryptor discipline [net.pocvpn.client.relay.FileIngressProfileStore]
 * already uses for the (structurally similar) ingress credential, with its
 * own key alias so this credential is never encrypted under key material
 * shared with anything else.
 *
 * Cross-host review fix: Germany/Stockholm (a gateway) and the Stockholm
 * ingress role are SEPARATE `pocvpn-api` processes with their OWN,
 * independent activation stores (see gateway/config/ingress.env.example's
 * own "THIS host's own dedicated activation store, never shared with a
 * real gateway" docs) - a credential minted by one is meaningless to the
 * other. This store is therefore keyed BY ENDPOINT HOST, exactly like
 * [net.pocvpn.client.relay.FileIngressProfileStore] is keyed by
 * [net.pocvpn.client.reachability.EndpointId] - a device holds ONE
 * credential per host it has field-enrolled against (typically two: its
 * target gateway, and separately the ingress host when CHAIN_DIRECT is
 * needed - see MainViewModel's own docs), never a single global value.
 */
data class FieldCredential(
    val credential: String,
    /** The endpoint host this credential was minted against and must be presented back to (never any other host's control plane). */
    val issuedByEndpointHost: String,
)

interface FieldCredentialStore {
    suspend fun getOrNull(endpointHost: String): FieldCredential?
    suspend fun save(credential: FieldCredential)
    suspend fun clear(endpointHost: String)
}

class FieldCredentialCorruptedException(message: String) : Exception(message)

class FileFieldCredentialStore(
    private val directory: File,
    private val encryptor: AesGcmKeyEncryptor,
) : FieldCredentialStore {
    private companion object {
        const val FORMAT_VERSION = 1
        const val MAX_CIPHERTEXT_LEN = 4096
        const val MAX_IV_LEN = 64
    }

    // Same "lossy readable prefix + collision-free hash suffix" shape as
    // net.pocvpn.client.identity.sanitizeForFileName (that one is typed to
    // EndpointId, not a raw String, so this is a small local equivalent
    // rather than a misuse of a differently-typed helper).
    private fun fileFor(endpointHost: String): File {
        val lossyPrefix = endpointHost.map { c -> if (c.isLetterOrDigit() || c == '-' || c == '_') c else '_' }.joinToString("")
        val digest = java.security.MessageDigest.getInstance("SHA-256").digest(endpointHost.toByteArray(Charsets.UTF_8))
        val shortHash = digest.joinToString("") { "%02x".format(it) }.take(12)
        return File(directory, "field_credential_$lossyPrefix-$shortHash.bin")
    }

    override suspend fun getOrNull(endpointHost: String): FieldCredential? {
        val file = fileFor(endpointHost)
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
        directory.mkdirs()
        val file = fileFor(credential.issuedByEndpointHost)
        val json = JSONObject()
            .put("credential", credential.credential)
            .put("issued_by_endpoint_host", credential.issuedByEndpointHost)
        val tmp = File(directory, "${file.name}.tmp")
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

    override suspend fun clear(endpointHost: String) {
        fileFor(endpointHost).delete()
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
    private val stored = mutableMapOf<String, FieldCredential>()
    override suspend fun getOrNull(endpointHost: String): FieldCredential? = stored[endpointHost]
    override suspend fun save(credential: FieldCredential) { stored[credential.issuedByEndpointHost] = credential }
    override suspend fun clear(endpointHost: String) { stored.remove(endpointHost) }
}
