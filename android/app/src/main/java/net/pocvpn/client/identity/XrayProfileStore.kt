package net.pocvpn.client.identity

import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.nio.charset.StandardCharsets

sealed class XrayProfileLoadResult {
    object NotFound : XrayProfileLoadResult()
    data class Found(val encrypted: EncryptedPayload) : XrayProfileLoadResult()
    data class Corrupted(val reason: String) : XrayProfileLoadResult()
}

/**
 * Plain-file persistence for the encrypted [XrayProfile] JSON blob. Mirrors
 * IdentityFileStore's format/atomic-write/corruption-handling shape exactly,
 * but stores one opaque encrypted blob (the whole profile, including its
 * non-secret fields like server/serverName) rather than a public+private
 * split - nothing in an Xray profile is meant to be shown unencrypted the
 * way AWG's public key is.
 */
interface XrayProfileFileStore {
    fun read(): XrayProfileLoadResult
    fun write(encrypted: EncryptedPayload)
    fun delete()
}

class FileXrayProfileStore(
    private val directory: File,
    private val fileName: String = "xray_profile.bin",
) : XrayProfileFileStore {

    private val file: File get() = File(directory, fileName)

    private companion object {
        const val FORMAT_VERSION = 1
    }

    override fun read(): XrayProfileLoadResult {
        if (!file.exists()) return XrayProfileLoadResult.NotFound
        return try {
            DataInputStream(file.inputStream().buffered()).use { input ->
                val version = input.readInt()
                if (version != FORMAT_VERSION) {
                    return XrayProfileLoadResult.Corrupted("unsupported format version $version")
                }
                val iv = readLengthPrefixed(input, maxLen = 64)
                val ciphertext = readLengthPrefixed(input, maxLen = 8192)
                XrayProfileLoadResult.Found(EncryptedPayload(iv, ciphertext))
            }
        } catch (e: java.io.EOFException) {
            XrayProfileLoadResult.Corrupted("truncated profile file")
        } catch (e: java.io.IOException) {
            XrayProfileLoadResult.Corrupted("unreadable profile file: ${e.javaClass.simpleName}")
        } catch (e: IllegalArgumentException) {
            XrayProfileLoadResult.Corrupted(e.message ?: "malformed profile file")
        }
    }

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
        if (!tmp.renameTo(file)) {
            tmp.delete()
            throw java.io.IOException("failed to atomically replace profile file")
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

class XrayProfileCorruptedException(message: String) : Exception(message)

/**
 * Owns the (possibly absent) Xray VLESS+REALITY profile. Unlike
 * ClientKeyRepository, there is no getOrCreate/generate path here: an Xray
 * profile is provisioned externally (a real server's real credentials), and
 * this B8K1B slice creates none - see NovaXrayDiagnosticsEntryPoint's own
 * "refuse cleanly if absent" behavior, which is exactly what
 * [getProfileOrNull] returning null enables.
 */
interface XrayProfileRepository {
    /** Null if no profile has ever been saved. */
    suspend fun getProfileOrNull(): XrayProfile?
    suspend fun saveProfile(profile: XrayProfile)
    suspend fun clearProfile()
}

class SecureXrayProfileRepository(
    private val store: XrayProfileFileStore,
    private val encryptor: AesGcmKeyEncryptor,
) : XrayProfileRepository {

    override suspend fun getProfileOrNull(): XrayProfile? {
        return when (val result = store.read()) {
            is XrayProfileLoadResult.NotFound -> null
            is XrayProfileLoadResult.Corrupted -> throw XrayProfileCorruptedException(result.reason)
            is XrayProfileLoadResult.Found -> {
                val plaintext = encryptor.decrypt(result.encrypted)
                XrayProfile.fromJson(String(plaintext, StandardCharsets.UTF_8))
            }
        }
    }

    override suspend fun saveProfile(profile: XrayProfile) {
        val plaintext = profile.toJson().toByteArray(StandardCharsets.UTF_8)
        store.write(encryptor.encrypt(plaintext))
    }

    override suspend fun clearProfile() {
        store.delete()
    }
}
