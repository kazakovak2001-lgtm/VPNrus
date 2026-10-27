package net.pocvpn.client.identity

import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.nio.charset.StandardCharsets
import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.smartconnect.ProductionGateway

sealed class XrayRealityXhttpProfileLoadResult {
    object NotFound : XrayRealityXhttpProfileLoadResult()
    data class Found(val encrypted: EncryptedPayload) : XrayRealityXhttpProfileLoadResult()
    data class Corrupted(val reason: String) : XrayRealityXhttpProfileLoadResult()
}

/**
 * The REALITY + XHTTP counterpart of [XrayXhttpProfileFileStore]: same
 * plain-file, atomic-write, corruption-handling shape and endpoint scoping,
 * a DIFFERENT file so it is independent of the REALITY/TLS/XHTTP profiles.
 */
interface XrayRealityXhttpProfileFileStore {
    fun read(): XrayRealityXhttpProfileLoadResult
    fun write(encrypted: EncryptedPayload)
    fun delete()
}

class FileXrayRealityXhttpProfileStore(
    private val directory: File,
    endpointId: EndpointId = EndpointId(ProductionGateway.ID),
    private val fileName: String = "xray_reality_xhttp_profile_${sanitizeForFileName(endpointId)}.bin",
) : XrayRealityXhttpProfileFileStore {

    private val file: File get() = File(directory, fileName)

    private companion object {
        const val FORMAT_VERSION = 1
    }

    override fun read(): XrayRealityXhttpProfileLoadResult {
        if (!file.exists()) return XrayRealityXhttpProfileLoadResult.NotFound
        return try {
            DataInputStream(file.inputStream().buffered()).use { input ->
                val version = input.readInt()
                if (version != FORMAT_VERSION) {
                    return XrayRealityXhttpProfileLoadResult.Corrupted("unsupported format version $version")
                }
                val iv = readLengthPrefixed(input, maxLen = 64)
                val ciphertext = readLengthPrefixed(input, maxLen = 8192)
                XrayRealityXhttpProfileLoadResult.Found(EncryptedPayload(iv, ciphertext))
            }
        } catch (e: java.io.EOFException) {
            XrayRealityXhttpProfileLoadResult.Corrupted("truncated profile file")
        } catch (e: java.io.IOException) {
            XrayRealityXhttpProfileLoadResult.Corrupted("unreadable profile file: ${e.javaClass.simpleName}")
        } catch (e: IllegalArgumentException) {
            XrayRealityXhttpProfileLoadResult.Corrupted(e.message ?: "malformed profile file")
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

class XrayRealityXhttpProfileCorruptedException(message: String) : Exception(message)

/** The REALITY + XHTTP counterpart of [XrayXhttpProfileRepository]. */
interface XrayRealityXhttpProfileRepository {
    /** Null if no profile has ever been saved. */
    suspend fun getProfileOrNull(): XrayRealityXhttpProfile?
    suspend fun saveProfile(profile: XrayRealityXhttpProfile)
    suspend fun clearProfile()
}

class SecureXrayRealityXhttpProfileRepository(
    private val store: XrayRealityXhttpProfileFileStore,
    private val encryptor: AesGcmKeyEncryptor,
) : XrayRealityXhttpProfileRepository {

    override suspend fun getProfileOrNull(): XrayRealityXhttpProfile? {
        return when (val result = store.read()) {
            is XrayRealityXhttpProfileLoadResult.NotFound -> null
            is XrayRealityXhttpProfileLoadResult.Corrupted -> throw XrayRealityXhttpProfileCorruptedException(result.reason)
            is XrayRealityXhttpProfileLoadResult.Found -> {
                val plaintext = encryptor.decrypt(result.encrypted)
                XrayRealityXhttpProfile.fromJson(String(plaintext, StandardCharsets.UTF_8))
            }
        }
    }

    override suspend fun saveProfile(profile: XrayRealityXhttpProfile) {
        val plaintext = profile.toJson().toByteArray(StandardCharsets.UTF_8)
        store.write(encryptor.encrypt(plaintext))
    }

    override suspend fun clearProfile() {
        store.delete()
    }
}
