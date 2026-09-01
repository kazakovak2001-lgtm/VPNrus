package net.pocvpn.client.identity

import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.nio.charset.StandardCharsets
import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.smartconnect.ProductionGateway

sealed class XrayQuicProfileLoadResult {
    object NotFound : XrayQuicProfileLoadResult()
    data class Found(val encrypted: EncryptedPayload) : XrayQuicProfileLoadResult()
    data class Corrupted(val reason: String) : XrayQuicProfileLoadResult()
}

/** B21 - the QUIC counterpart of [XrayTlsProfileFileStore]: same plain-file, atomic-write, corruption-handling shape, its own file - never overwrites/shares storage with REALITY or TLS_TCP. */
interface XrayQuicProfileFileStore {
    fun read(): XrayQuicProfileLoadResult
    fun write(encrypted: EncryptedPayload)
    fun delete()
}

/** B21 - same endpoint-scoping discipline as [FileXrayTlsProfileStore] - no legacy unscoped file exists for QUIC (it never had a pre-endpoint-scoped era), so there is no migration path to carry. */
class FileXrayQuicProfileStore(
    private val directory: File,
    endpointId: EndpointId = EndpointId(ProductionGateway.ID),
    private val fileName: String = "xray_quic_profile_${sanitizeForFileName(endpointId)}.bin",
) : XrayQuicProfileFileStore {

    private val file: File get() = File(directory, fileName)

    private companion object {
        const val FORMAT_VERSION = 1
    }

    override fun read(): XrayQuicProfileLoadResult {
        if (!file.exists()) return XrayQuicProfileLoadResult.NotFound
        return try {
            DataInputStream(file.inputStream().buffered()).use { input ->
                val version = input.readInt()
                if (version != FORMAT_VERSION) {
                    return XrayQuicProfileLoadResult.Corrupted("unsupported format version $version")
                }
                val iv = readLengthPrefixed(input, maxLen = 64)
                val ciphertext = readLengthPrefixed(input, maxLen = 8192)
                XrayQuicProfileLoadResult.Found(EncryptedPayload(iv, ciphertext))
            }
        } catch (e: java.io.EOFException) {
            XrayQuicProfileLoadResult.Corrupted("truncated profile file")
        } catch (e: java.io.IOException) {
            XrayQuicProfileLoadResult.Corrupted("unreadable profile file: ${e.javaClass.simpleName}")
        } catch (e: IllegalArgumentException) {
            XrayQuicProfileLoadResult.Corrupted(e.message ?: "malformed profile file")
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

class XrayQuicProfileCorruptedException(message: String) : Exception(message)

/** The QUIC counterpart of [XrayTlsProfileRepository] - see that interface's own docs. */
interface XrayQuicProfileRepository {
    suspend fun getProfileOrNull(): XrayQuicProfile?
    suspend fun saveProfile(profile: XrayQuicProfile)
    suspend fun clearProfile()
}

class SecureXrayQuicProfileRepository(
    private val store: XrayQuicProfileFileStore,
    private val encryptor: AesGcmKeyEncryptor,
) : XrayQuicProfileRepository {

    override suspend fun getProfileOrNull(): XrayQuicProfile? {
        return when (val result = store.read()) {
            is XrayQuicProfileLoadResult.NotFound -> null
            is XrayQuicProfileLoadResult.Corrupted -> throw XrayQuicProfileCorruptedException(result.reason)
            is XrayQuicProfileLoadResult.Found -> {
                val plaintext = encryptor.decrypt(result.encrypted)
                XrayQuicProfile.fromJson(String(plaintext, StandardCharsets.UTF_8))
            }
        }
    }

    override suspend fun saveProfile(profile: XrayQuicProfile) {
        val plaintext = profile.toJson().toByteArray(StandardCharsets.UTF_8)
        store.write(encryptor.encrypt(plaintext))
    }

    override suspend fun clearProfile() {
        store.delete()
    }
}
