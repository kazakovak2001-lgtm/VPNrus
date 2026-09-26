package net.pocvpn.client.identity

import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import net.pocvpn.client.reachability.EndpointId

sealed class Hysteria2CredentialLoadResult {
    object NotFound : Hysteria2CredentialLoadResult()
    data class Found(val encrypted: EncryptedPayload) : Hysteria2CredentialLoadResult()
    data class Corrupted(val reason: String) : Hysteria2CredentialLoadResult()
}

/**
 * B46-4A - plain-file persistence for the encrypted Hysteria2 credential
 * blob. Mirrors [Shadowsocks2022CredentialFileStore] exactly: endpoint-scoped
 * file naming via [sanitizeForFileName] (a credential for endpoint A can
 * never collide with, or be silently read as, endpoint B's file), and the
 * SAME `Files.move`-with-`ATOMIC_MOVE`+`REPLACE_EXISTING` crash-safety
 * guarantee - a failed rotation never destroys the old, still-usable
 * credential.
 */
interface Hysteria2CredentialFileStore {
    fun read(): Hysteria2CredentialLoadResult
    fun write(encrypted: EncryptedPayload)
    fun delete()
}

class FileHysteria2CredentialStore(
    private val directory: File,
    endpointId: EndpointId,
    private val fileName: String = "hysteria2_credential_${sanitizeForFileName(endpointId)}.bin",
) : Hysteria2CredentialFileStore {

    private val file: File get() = File(directory, fileName)

    private companion object {
        const val FORMAT_VERSION = 1
    }

    override fun read(): Hysteria2CredentialLoadResult {
        if (!file.exists()) return Hysteria2CredentialLoadResult.NotFound
        return try {
            DataInputStream(file.inputStream().buffered()).use { input ->
                val version = input.readInt()
                if (version != FORMAT_VERSION) {
                    return Hysteria2CredentialLoadResult.Corrupted("unsupported format version $version")
                }
                val iv = readLengthPrefixed(input, maxLen = 64)
                val ciphertext = readLengthPrefixed(input, maxLen = 1024)
                Hysteria2CredentialLoadResult.Found(EncryptedPayload(iv, ciphertext))
            }
        } catch (e: java.io.EOFException) {
            Hysteria2CredentialLoadResult.Corrupted("truncated credential file")
        } catch (e: java.io.IOException) {
            Hysteria2CredentialLoadResult.Corrupted("unreadable credential file: ${e.javaClass.simpleName}")
        } catch (e: IllegalArgumentException) {
            Hysteria2CredentialLoadResult.Corrupted(e.message ?: "malformed credential file")
        }
    }

    /** Same crash-safety guarantee as [net.pocvpn.client.identity.FileShadowsocks2022CredentialStore.write] - see that method's own doc. */
    override fun write(encrypted: EncryptedPayload) {
        directory.mkdirs()
        val tmp = File(directory, "$fileName.tmp")
        val bytes = ByteArrayOutputStream().also { buffer ->
            DataOutputStream(buffer).use { out ->
                out.writeInt(FORMAT_VERSION)
                writeLengthPrefixed(out, encrypted.iv)
                writeLengthPrefixed(out, encrypted.ciphertext)
            }
        }.toByteArray()
        tmp.writeBytes(bytes)
        try {
            Files.move(tmp.toPath(), file.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
        } catch (e: java.nio.file.FileSystemException) {
            tmp.delete()
            throw java.io.IOException("failed to atomically replace credential file", e)
        }
    }

    override fun delete() {
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

/** Typed, fail-closed outcome of reading a credential - never a nullable/throw pair that could be misused as "absent == corrupt". */
sealed interface Hysteria2CredentialGetResult {
    data object Absent : Hysteria2CredentialGetResult
    data class Present(val credential: Hysteria2Credential) : Hysteria2CredentialGetResult
    data class Corrupted(val reason: String) : Hysteria2CredentialGetResult
}

/**
 * B46-4A - the narrowest repository contract `Hysteria2VpnService` needs:
 * store/replace, get, delete, exists. Mirrors
 * [Shadowsocks2022CredentialRepository] exactly: endpoint scoping is
 * structural (one repository instance is bound to exactly one [EndpointId]
 * at construction), rotation is "store a new valid credential for the same
 * endpoint" (always atomically replaces), and revocation is
 * [deleteCredential] deleting the file entirely.
 */
interface Hysteria2CredentialRepository {
    suspend fun getCredential(): Hysteria2CredentialGetResult
    suspend fun storeCredential(credential: Hysteria2Credential)
    suspend fun deleteCredential()
    suspend fun credentialExists(): Boolean
}

class Hysteria2CredentialCorruptedException(message: String) : Exception(message)

class SecureHysteria2CredentialRepository(
    private val endpointId: EndpointId,
    private val store: Hysteria2CredentialFileStore,
    private val encryptor: AesGcmKeyEncryptor,
) : Hysteria2CredentialRepository {

    override suspend fun getCredential(): Hysteria2CredentialGetResult {
        return when (val result = store.read()) {
            is Hysteria2CredentialLoadResult.NotFound -> Hysteria2CredentialGetResult.Absent
            is Hysteria2CredentialLoadResult.Corrupted -> Hysteria2CredentialGetResult.Corrupted(result.reason)
            is Hysteria2CredentialLoadResult.Found -> {
                val plaintext = try {
                    encryptor.decrypt(result.encrypted)
                } catch (e: IdentityDecryptionFailedException) {
                    return Hysteria2CredentialGetResult.Corrupted(e.message ?: "decryption failed")
                }
                decodeCredentialPayload(plaintext)?.let { Hysteria2CredentialGetResult.Present(it) }
                    ?: Hysteria2CredentialGetResult.Corrupted("malformed decrypted credential payload")
            }
        }
    }

    override suspend fun storeCredential(credential: Hysteria2Credential) {
        require(credential.endpointId == endpointId) {
            "credential endpointId (${credential.endpointId}) does not match this repository's endpoint ($endpointId) - " +
                "never store a credential under the wrong endpoint's scoped file"
        }
        store.write(encryptor.encrypt(encodeCredentialPayload(credential)))
    }

    override suspend fun deleteCredential() {
        store.delete()
    }

    override suspend fun credentialExists(): Boolean = store.read() !is Hysteria2CredentialLoadResult.NotFound

    /**
     * The decrypted payload re-states its own endpointId so a mismatch (e.g.
     * a file somehow relocated onto the wrong endpoint's scoped path) is
     * caught here - defense in depth beyond file-path scoping alone - and
     * reuses [Hysteria2CredentialValidator] so a tampered/corrupted
     * plaintext (blank/oversized secret) fails closed the exact same way
     * fresh untrusted input would, never silently trusted just because it
     * came from local storage.
     */
    private fun decodeCredentialPayload(plaintext: ByteArray): Hysteria2Credential? {
        return try {
            DataInputStream(plaintext.inputStream()).use { input ->
                val version = input.readInt()
                if (version != PAYLOAD_FORMAT_VERSION) return null
                val storedEndpointId = readLengthPrefixedString(input, maxLen = 256)
                val authSecret = readLengthPrefixedString(input, maxLen = 512)
                val hasObfuscationSecret = input.readBoolean()
                val obfuscationSecret = if (hasObfuscationSecret) readLengthPrefixedString(input, maxLen = 512) else null
                if (storedEndpointId != endpointId.value) return null
                val validated = Hysteria2CredentialValidator.validate(endpointId, authSecret, obfuscationSecret)
                (validated as? Hysteria2CredentialValidationResult.Valid)?.credential
            }
        } catch (e: java.io.IOException) {
            null
        } catch (e: IllegalArgumentException) {
            null
        }
    }

    private fun encodeCredentialPayload(credential: Hysteria2Credential): ByteArray {
        val buffer = ByteArrayOutputStream()
        DataOutputStream(buffer).use { out ->
            out.writeInt(PAYLOAD_FORMAT_VERSION)
            writeLengthPrefixedString(out, credential.endpointId.value)
            writeLengthPrefixedString(out, credential.authSecret.value)
            val obfuscation = credential.obfuscationSecret
            out.writeBoolean(obfuscation != null)
            if (obfuscation != null) writeLengthPrefixedString(out, obfuscation.value)
        }
        return buffer.toByteArray()
    }

    private fun writeLengthPrefixedString(out: DataOutputStream, value: String) {
        val bytes = value.toByteArray(StandardCharsets.UTF_8)
        out.writeInt(bytes.size)
        out.write(bytes)
    }

    private fun readLengthPrefixedString(input: DataInputStream, maxLen: Int): String {
        val len = input.readInt()
        require(len in 0..maxLen) { "implausible length-prefixed field: $len" }
        val bytes = ByteArray(len)
        input.readFully(bytes)
        return String(bytes, StandardCharsets.UTF_8)
    }

    private companion object {
        const val PAYLOAD_FORMAT_VERSION = 1
    }
}
