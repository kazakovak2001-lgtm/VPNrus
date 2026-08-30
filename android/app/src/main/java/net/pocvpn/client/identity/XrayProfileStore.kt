package net.pocvpn.client.identity

import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.nio.charset.StandardCharsets
import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.smartconnect.ProductionGateway

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

/**
 * B13 - endpoint-scoped file name: (endpointId, transport-credential-kind) is
 * the conceptual key the B12 endpoint-identity audit recommended
 * (docs/B12_ENDPOINT_IDENTITY_AUDIT.md, option (a)) - a REALITY credential
 * for endpoint "frankfurt" must never collide with, or be silently read as,
 * one for a future second endpoint. [legacyFileName] is non-null ONLY for
 * the single historical endpoint that had a real profile persisted BEFORE
 * this scoping existed (see [migrateLegacyIfNeeded]) - every other endpoint
 * gets `null` and never touches that file, so two endpoint-scoped stores can
 * never race over the same legacy blob.
 */
class FileXrayProfileStore(
    private val directory: File,
    // B13 - defaults to the one real production endpoint so every pre-B13
    // call site (tests, and any construction that doesn't explicitly pass an
    // endpoint) is unaffected in shape; production code paths that must stay
    // consistent with XrayProfileRepositoryFactory now go through it instead
    // of constructing this class directly (see NovaXrayVpnService/
    // XrayDiagnosticsActivity/VlessRealityTransport).
    endpointId: EndpointId = EndpointId(ProductionGateway.ID),
    private val fileName: String = "xray_profile_${sanitizeForFileName(endpointId)}.bin",
    private val legacyFileName: String? = null,
) : XrayProfileFileStore {

    private val file: File get() = File(directory, fileName)
    private val legacyFile: File? get() = legacyFileName?.let { File(directory, it) }

    private companion object {
        const val FORMAT_VERSION = 1
    }

    /**
     * B13 - one-time, best-effort migration from the pre-endpoint-scoping
     * unscoped file into this endpoint's own scoped slot. A no-op the moment
     * the scoped file already exists (every read after the first) or when
     * this store was never designated the legacy migration target (see class
     * docs). An atomic rename - if it fails (e.g. cross-filesystem), the
     * legacy file is left untouched and this read reports NotFound rather
     * than risking a partially-migrated/duplicated credential.
     */
    private fun migrateLegacyIfNeeded() {
        if (file.exists()) return
        val legacy = legacyFile ?: return
        if (!legacy.exists()) return
        legacy.renameTo(file)
    }

    override fun read(): XrayProfileLoadResult {
        migrateLegacyIfNeeded()
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
 * B13 (audit fix) - EndpointId restricts its charset only by length (see its
 * own validation), never by content: two DISTINCT valid values (e.g.
 * `"a/b"` and `"a.b"`, or `"gw a"` and `"gw_a"`) sanitize to the IDENTICAL
 * lossy prefix under a naive char-replace, which would silently collide two
 * different endpoints' credentials onto the SAME file the moment a second
 * real gateway exists - a real, provable bug, not merely a theoretical one
 * (see SanitizeForFileNameTest). Fixed by appending a short SHA-256 digest of
 * the FULL, non-lossy `endpointId.value` - the lossy prefix stays only for
 * human-readability when browsing app-private storage; COLLISION-FREEDOM
 * comes entirely from the hash suffix, which is deterministic (same
 * EndpointId always produces the same filename) and depends on the whole
 * string, not just the characters the lossy prefix preserves.
 */
internal fun sanitizeForFileName(endpointId: EndpointId): String {
    val lossyPrefix = endpointId.value.map { c -> if (c.isLetterOrDigit() || c == '-' || c == '_') c else '_' }.joinToString("")
    val digest = java.security.MessageDigest.getInstance("SHA-256").digest(endpointId.value.toByteArray(Charsets.UTF_8))
    val shortHash = digest.joinToString("") { "%02x".format(it) }.take(12)
    return "$lossyPrefix-$shortHash"
}

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
