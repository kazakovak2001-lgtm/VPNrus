package net.pocvpn.client.identity

import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.nio.charset.StandardCharsets
import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.smartconnect.ProductionGateway

sealed class XrayXhttpProfileLoadResult {
    object NotFound : XrayXhttpProfileLoadResult()
    data class Found(val encrypted: EncryptedPayload) : XrayXhttpProfileLoadResult()
    data class Corrupted(val reason: String) : XrayXhttpProfileLoadResult()
}

/**
 * B61 - the XHTTP counterpart of [XrayTlsProfileFileStore]: same plain-file,
 * atomic-write, corruption-handling shape, a DIFFERENT file so an XHTTP
 * profile and a REALITY/TLS profile are independent, simultaneously
 * persistable records.
 */
interface XrayXhttpProfileFileStore {
    fun read(): XrayXhttpProfileLoadResult
    fun write(encrypted: EncryptedPayload)
    fun delete()
}

/** B61 - same endpoint-scoping discipline as [FileXrayTlsProfileStore] - see that class's own docs. */
class FileXrayXhttpProfileStore(
    private val directory: File,
    endpointId: EndpointId = EndpointId(ProductionGateway.ID),
    private val fileName: String = "xray_xhttp_profile_${sanitizeForFileName(endpointId)}.bin",
) : XrayXhttpProfileFileStore {

    private val file: File get() = File(directory, fileName)

    private companion object {
        const val FORMAT_VERSION = 1
    }

    override fun read(): XrayXhttpProfileLoadResult {
        if (!file.exists()) return XrayXhttpProfileLoadResult.NotFound
        return try {
            DataInputStream(file.inputStream().buffered()).use { input ->
                val version = input.readInt()
                if (version != FORMAT_VERSION) {
                    return XrayXhttpProfileLoadResult.Corrupted("unsupported format version $version")
                }
                val iv = readLengthPrefixed(input, maxLen = 64)
                val ciphertext = readLengthPrefixed(input, maxLen = 8192)
                XrayXhttpProfileLoadResult.Found(EncryptedPayload(iv, ciphertext))
            }
        } catch (e: java.io.EOFException) {
            XrayXhttpProfileLoadResult.Corrupted("truncated profile file")
        } catch (e: java.io.IOException) {
            XrayXhttpProfileLoadResult.Corrupted("unreadable profile file: ${e.javaClass.simpleName}")
        } catch (e: IllegalArgumentException) {
            XrayXhttpProfileLoadResult.Corrupted(e.message ?: "malformed profile file")
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

class XrayXhttpProfileCorruptedException(message: String) : Exception(message)

/** The XHTTP counterpart of [XrayTlsProfileRepository] - see that interface's own docs. */
interface XrayXhttpProfileRepository {
    /** Null if no profile has ever been saved. */
    suspend fun getProfileOrNull(): XrayXhttpProfile?
    suspend fun saveProfile(profile: XrayXhttpProfile)
    suspend fun clearProfile()
}

class SecureXrayXhttpProfileRepository(
    private val store: XrayXhttpProfileFileStore,
    private val encryptor: AesGcmKeyEncryptor,
) : XrayXhttpProfileRepository {

    override suspend fun getProfileOrNull(): XrayXhttpProfile? {
        return when (val result = store.read()) {
            is XrayXhttpProfileLoadResult.NotFound -> null
            is XrayXhttpProfileLoadResult.Corrupted -> throw XrayXhttpProfileCorruptedException(result.reason)
            is XrayXhttpProfileLoadResult.Found -> {
                val plaintext = encryptor.decrypt(result.encrypted)
                XrayXhttpProfile.fromJson(String(plaintext, StandardCharsets.UTF_8))
            }
        }
    }

    override suspend fun saveProfile(profile: XrayXhttpProfile) {
        val plaintext = profile.toJson().toByteArray(StandardCharsets.UTF_8)
        store.write(encryptor.encrypt(plaintext))
    }

    override suspend fun clearProfile() {
        store.delete()
    }
}
