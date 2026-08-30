package net.pocvpn.client.identity

import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.nio.charset.StandardCharsets
import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.smartconnect.ProductionGateway

sealed class XrayTlsProfileLoadResult {
    object NotFound : XrayTlsProfileLoadResult()
    data class Found(val encrypted: EncryptedPayload) : XrayTlsProfileLoadResult()
    data class Corrupted(val reason: String) : XrayTlsProfileLoadResult()
}

/**
 * B8O2 - the TLS/TCP counterpart of [XrayProfileFileStore]/
 * [FileXrayProfileStore]: same plain-file, atomic-write, corruption-handling
 * shape, a DIFFERENT file so a REALITY profile and a TLS profile are two
 * independent, simultaneously-persistable records - never one overwriting
 * the other.
 */
interface XrayTlsProfileFileStore {
    fun read(): XrayTlsProfileLoadResult
    fun write(encrypted: EncryptedPayload)
    fun delete()
}

/**
 * B13 - same endpoint-scoping/migration discipline as [FileXrayProfileStore] -
 * see that class's own docs for [legacyFileName]'s "one designated migration
 * target only" contract.
 */
class FileXrayTlsProfileStore(
    private val directory: File,
    // B13 - see FileXrayProfileStore's own docs for this default's contract.
    endpointId: EndpointId = EndpointId(ProductionGateway.ID),
    private val fileName: String = "xray_tls_profile_${sanitizeForFileName(endpointId)}.bin",
    private val legacyFileName: String? = null,
) : XrayTlsProfileFileStore {

    private val file: File get() = File(directory, fileName)
    private val legacyFile: File? get() = legacyFileName?.let { File(directory, it) }

    private companion object {
        const val FORMAT_VERSION = 1
    }

    private fun migrateLegacyIfNeeded() {
        if (file.exists()) return
        val legacy = legacyFile ?: return
        if (!legacy.exists()) return
        legacy.renameTo(file)
    }

    override fun read(): XrayTlsProfileLoadResult {
        migrateLegacyIfNeeded()
        if (!file.exists()) return XrayTlsProfileLoadResult.NotFound
        return try {
            DataInputStream(file.inputStream().buffered()).use { input ->
                val version = input.readInt()
                if (version != FORMAT_VERSION) {
                    return XrayTlsProfileLoadResult.Corrupted("unsupported format version $version")
                }
                val iv = readLengthPrefixed(input, maxLen = 64)
                val ciphertext = readLengthPrefixed(input, maxLen = 8192)
                XrayTlsProfileLoadResult.Found(EncryptedPayload(iv, ciphertext))
            }
        } catch (e: java.io.EOFException) {
            XrayTlsProfileLoadResult.Corrupted("truncated profile file")
        } catch (e: java.io.IOException) {
            XrayTlsProfileLoadResult.Corrupted("unreadable profile file: ${e.javaClass.simpleName}")
        } catch (e: IllegalArgumentException) {
            XrayTlsProfileLoadResult.Corrupted(e.message ?: "malformed profile file")
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

class XrayTlsProfileCorruptedException(message: String) : Exception(message)

/** The TLS/TCP counterpart of [XrayProfileRepository] - see that interface's own docs. */
interface XrayTlsProfileRepository {
    /** Null if no profile has ever been saved. */
    suspend fun getProfileOrNull(): XrayTlsProfile?
    suspend fun saveProfile(profile: XrayTlsProfile)
    suspend fun clearProfile()
}

class SecureXrayTlsProfileRepository(
    private val store: XrayTlsProfileFileStore,
    private val encryptor: AesGcmKeyEncryptor,
) : XrayTlsProfileRepository {

    override suspend fun getProfileOrNull(): XrayTlsProfile? {
        return when (val result = store.read()) {
            is XrayTlsProfileLoadResult.NotFound -> null
            is XrayTlsProfileLoadResult.Corrupted -> throw XrayTlsProfileCorruptedException(result.reason)
            is XrayTlsProfileLoadResult.Found -> {
                val plaintext = encryptor.decrypt(result.encrypted)
                XrayTlsProfile.fromJson(String(plaintext, StandardCharsets.UTF_8))
            }
        }
    }

    override suspend fun saveProfile(profile: XrayTlsProfile) {
        val plaintext = profile.toJson().toByteArray(StandardCharsets.UTF_8)
        store.write(encryptor.encrypt(plaintext))
    }

    override suspend fun clearProfile() {
        store.delete()
    }
}
