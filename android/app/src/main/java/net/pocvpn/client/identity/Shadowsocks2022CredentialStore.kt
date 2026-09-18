package net.pocvpn.client.identity

import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import net.pocvpn.client.reachability.EndpointId

sealed class Shadowsocks2022CredentialLoadResult {
    object NotFound : Shadowsocks2022CredentialLoadResult()
    data class Found(val encrypted: EncryptedPayload) : Shadowsocks2022CredentialLoadResult()
    data class Corrupted(val reason: String) : Shadowsocks2022CredentialLoadResult()
}

/**
 * B45B-2 - plain-file persistence for the encrypted Shadowsocks 2022
 * credential blob. Endpoint-scoped file naming via [sanitizeForFileName]
 * (the SAME collision-free hashed-suffix scheme XrayProfile already uses -
 * a credential for endpoint A can never collide with, or be silently read
 * as, endpoint B's file). No legacy/unscoped file exists for this transport
 * - there is no B45A production credential format to migrate from (B45A's
 * own `b45a-dataplane.properties` is a debug-only, gitignored spike
 * mechanism, never a production format - see B45B-2's own "no migration"
 * decision).
 *
 * Replace semantics: [write] uses `Files.move` with `ATOMIC_MOVE` +
 * `REPLACE_EXISTING` - the SAME real project convention
 * [net.pocvpn.client.reachability.FileLastKnownGoodManifestStore]/
 * `ConnectionOutcomeStore` already use, not the plain-`File.renameTo()`
 * pattern [FileXrayProfileStore] happens to use (that pattern is NOT safe
 * to reuse here: `File.renameTo()` FAILS - does not replace - when the
 * destination already exists on Windows, and per-filesystem behavior is
 * otherwise unspecified by the Java platform; `Files.move` with
 * `ATOMIC_MOVE` is the JDK's own explicit atomic-replace guarantee where
 * the filesystem supports it, verified working on this exact NTFS dev
 * machine). See [write]'s own doc for the exact crash-safety guarantee this
 * provides and what happens if the filesystem cannot honor it.
 */
interface Shadowsocks2022CredentialFileStore {
    fun read(): Shadowsocks2022CredentialLoadResult
    fun write(encrypted: EncryptedPayload)
    fun delete()
}

class FileShadowsocks2022CredentialStore(
    private val directory: File,
    endpointId: EndpointId,
    private val fileName: String = "shadowsocks2022_credential_${sanitizeForFileName(endpointId)}.bin",
) : Shadowsocks2022CredentialFileStore {

    private val file: File get() = File(directory, fileName)

    private companion object {
        const val FORMAT_VERSION = 1
    }

    override fun read(): Shadowsocks2022CredentialLoadResult {
        if (!file.exists()) return Shadowsocks2022CredentialLoadResult.NotFound
        return try {
            DataInputStream(file.inputStream().buffered()).use { input ->
                val version = input.readInt()
                if (version != FORMAT_VERSION) {
                    return Shadowsocks2022CredentialLoadResult.Corrupted("unsupported format version $version")
                }
                val iv = readLengthPrefixed(input, maxLen = 64)
                val ciphertext = readLengthPrefixed(input, maxLen = 1024)
                Shadowsocks2022CredentialLoadResult.Found(EncryptedPayload(iv, ciphertext))
            }
        } catch (e: java.io.EOFException) {
            Shadowsocks2022CredentialLoadResult.Corrupted("truncated credential file")
        } catch (e: java.io.IOException) {
            Shadowsocks2022CredentialLoadResult.Corrupted("unreadable credential file: ${e.javaClass.simpleName}")
        } catch (e: IllegalArgumentException) {
            Shadowsocks2022CredentialLoadResult.Corrupted(e.message ?: "malformed credential file")
        }
    }

    /**
     * Crash-safety guarantee: the new content is written completely to
     * [tmp] first; only a fully-written temp file is ever moved into place.
     * `Files.move(tmp, file, ATOMIC_MOVE, REPLACE_EXISTING)` then either
     * fully succeeds (readers only ever observe the complete old content or
     * the complete new content - the filesystem guarantees no window where
     * [file] is missing or truncated, unlike a delete-then-rename sequence)
     * or fully fails (throwing, below) - it never partially replaces the
     * destination. If the underlying filesystem cannot honor `ATOMIC_MOVE`
     * (`AtomicMoveNotSupportedException`, a subtype of `FileSystemException`
     * - not expected on the real target platform's typical filesystems, but
     * possible in principle on an unusual one), this method does NOT
     * silently fall back to a weaker delete-then-rename: [tmp] is discarded
     * and an [java.io.IOException] is thrown, leaving the PREVIOUS credential
     * (if any) exactly as it was - a failed rotation never destroys the old,
     * still-usable credential (mirrors
     * [net.pocvpn.client.reachability.FileLastKnownGoodManifestStore]'s own
     * `writeToDisk`'s exact catch/rethrow shape).
     */
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
sealed interface Shadowsocks2022CredentialGetResult {
    data object Absent : Shadowsocks2022CredentialGetResult
    data class Present(val credential: Shadowsocks2022Credential) : Shadowsocks2022CredentialGetResult
    data class Corrupted(val reason: String) : Shadowsocks2022CredentialGetResult
}

/**
 * B45B-2 - the narrowest repository contract B45B-3 needs: store/replace,
 * get, delete, exists. Endpoint scoping is structural (one repository
 * instance is bound to exactly one [EndpointId] at construction, the SAME
 * convention [XrayProfileRepository] already uses via [FileXrayProfileStore])
 * - a credential for endpoint A is physically stored in a different file
 * than endpoint B's, so there is no code path by which one could be returned
 * for the other. Rotation is "store a new valid credential for the same
 * endpoint" - [storeCredential] always atomically replaces whatever was
 * there via the underlying file store's tmp-then-rename write, never a
 * merge/patch. Revocation is [deleteCredential] - deleting the file entirely.
 */
interface Shadowsocks2022CredentialRepository {
    suspend fun getCredential(): Shadowsocks2022CredentialGetResult
    suspend fun storeCredential(credential: Shadowsocks2022Credential)
    suspend fun deleteCredential()
    suspend fun credentialExists(): Boolean
}

class Shadowsocks2022CredentialCorruptedException(message: String) : Exception(message)

class SecureShadowsocks2022CredentialRepository(
    private val endpointId: EndpointId,
    private val store: Shadowsocks2022CredentialFileStore,
    private val encryptor: AesGcmKeyEncryptor,
) : Shadowsocks2022CredentialRepository {

    override suspend fun getCredential(): Shadowsocks2022CredentialGetResult {
        return when (val result = store.read()) {
            is Shadowsocks2022CredentialLoadResult.NotFound -> Shadowsocks2022CredentialGetResult.Absent
            is Shadowsocks2022CredentialLoadResult.Corrupted -> Shadowsocks2022CredentialGetResult.Corrupted(result.reason)
            is Shadowsocks2022CredentialLoadResult.Found -> {
                val plaintext = try {
                    encryptor.decrypt(result.encrypted)
                } catch (e: IdentityDecryptionFailedException) {
                    return Shadowsocks2022CredentialGetResult.Corrupted(e.message ?: "decryption failed")
                }
                decodeCredentialPayload(plaintext)?.let { Shadowsocks2022CredentialGetResult.Present(it) }
                    ?: Shadowsocks2022CredentialGetResult.Corrupted("malformed decrypted credential payload")
            }
        }
    }

    override suspend fun storeCredential(credential: Shadowsocks2022Credential) {
        require(credential.endpointId == endpointId) {
            "credential endpointId (${credential.endpointId}) does not match this repository's endpoint ($endpointId) - " +
                "never store a credential under the wrong endpoint's scoped file"
        }
        store.write(encryptor.encrypt(encodeCredentialPayload(credential)))
    }

    override suspend fun deleteCredential() {
        store.delete()
    }

    override suspend fun credentialExists(): Boolean = store.read() !is Shadowsocks2022CredentialLoadResult.NotFound

    /**
     * The decrypted payload re-states its own endpointId/method so a
     * mismatch (e.g. a file somehow relocated onto the wrong endpoint's
     * scoped path) is caught here - defense in depth beyond file-path
     * scoping alone - and reuses [Shadowsocks2022CredentialValidator] so a
     * tampered/corrupted plaintext (wrong key length, unsupported method)
     * fails closed the exact same way fresh untrusted input would, never
     * silently trusted just because it came from local storage.
     */
    private fun decodeCredentialPayload(plaintext: ByteArray): Shadowsocks2022Credential? {
        return try {
            DataInputStream(plaintext.inputStream()).use { input ->
                val version = input.readInt()
                if (version != PAYLOAD_FORMAT_VERSION) return null
                val storedEndpointId = readLengthPrefixedString(input, maxLen = 256)
                val method = readLengthPrefixedString(input, maxLen = 64)
                val secretBase64 = readLengthPrefixedString(input, maxLen = 128)
                if (storedEndpointId != endpointId.value) return null
                val validated = Shadowsocks2022CredentialValidator.validate(endpointId, method, secretBase64)
                (validated as? Shadowsocks2022CredentialValidationResult.Valid)?.credential
            }
        } catch (e: java.io.IOException) {
            null
        } catch (e: IllegalArgumentException) {
            null
        }
    }

    private fun encodeCredentialPayload(credential: Shadowsocks2022Credential): ByteArray {
        val buffer = ByteArrayOutputStream()
        DataOutputStream(buffer).use { out ->
            out.writeInt(PAYLOAD_FORMAT_VERSION)
            writeLengthPrefixedString(out, credential.endpointId.value)
            writeLengthPrefixedString(out, credential.method)
            writeLengthPrefixedString(out, credential.key.base64)
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
