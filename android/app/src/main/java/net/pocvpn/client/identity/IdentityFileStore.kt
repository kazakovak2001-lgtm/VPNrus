package net.pocvpn.client.identity

import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.nio.charset.StandardCharsets

/** What's actually written to disk: encrypted private key + the (non-secret) public key. */
data class PersistedIdentity(val encryptedPrivateKey: EncryptedPayload, val publicKeyBase64: String)

sealed class IdentityLoadResult {
    object NotFound : IdentityLoadResult()
    data class Found(val identity: PersistedIdentity) : IdentityLoadResult()
    data class Corrupted(val reason: String) : IdentityLoadResult()
}

/**
 * Plain-file persistence for the encrypted identity blob. Contains no
 * Android-framework dependency, so it is directly unit-testable on the JVM
 * with a temp directory; on Android it should be pointed at
 * context.noBackupFilesDir so it is excluded from Auto Backup (a restored,
 * still-encrypted blob would be undecryptable on a new device anyway, since
 * the AndroidKeyStore key is device-bound and does not travel with backups).
 */
interface IdentityFileStore {
    fun read(): IdentityLoadResult
    fun write(identity: PersistedIdentity)
    fun delete()
}

class FileIdentityStore(private val directory: File, private val fileName: String = "client_identity.bin") : IdentityFileStore {

    private val file: File get() = File(directory, fileName)

    private companion object {
        const val FORMAT_VERSION = 1
    }

    override fun read(): IdentityLoadResult {
        if (!file.exists()) return IdentityLoadResult.NotFound
        return try {
            DataInputStream(file.inputStream().buffered()).use { input ->
                val version = input.readInt()
                if (version != FORMAT_VERSION) {
                    return IdentityLoadResult.Corrupted("unsupported format version $version")
                }
                val iv = readLengthPrefixed(input, maxLen = 64)
                val ciphertext = readLengthPrefixed(input, maxLen = 4096)
                val publicKeyBytes = readLengthPrefixed(input, maxLen = 256)
                IdentityLoadResult.Found(
                    PersistedIdentity(
                        encryptedPrivateKey = EncryptedPayload(iv, ciphertext),
                        publicKeyBase64 = String(publicKeyBytes, StandardCharsets.UTF_8),
                    ),
                )
            }
        } catch (e: java.io.EOFException) {
            IdentityLoadResult.Corrupted("truncated identity file")
        } catch (e: java.io.IOException) {
            IdentityLoadResult.Corrupted("unreadable identity file: ${e.javaClass.simpleName}")
        } catch (e: IllegalArgumentException) {
            IdentityLoadResult.Corrupted(e.message ?: "malformed identity file")
        }
    }

    override fun write(identity: PersistedIdentity) {
        directory.mkdirs()
        val tmp = File(directory, "$fileName.tmp")
        val bytes = ByteArrayOutputStream().also { buffer ->
            DataOutputStream(buffer).use { out ->
                out.writeInt(FORMAT_VERSION)
                writeLengthPrefixed(out, identity.encryptedPrivateKey.iv)
                writeLengthPrefixed(out, identity.encryptedPrivateKey.ciphertext)
                writeLengthPrefixed(out, identity.publicKeyBase64.toByteArray(StandardCharsets.UTF_8))
            }
        }.toByteArray()
        tmp.writeBytes(bytes)
        if (!tmp.renameTo(file)) {
            tmp.delete()
            throw java.io.IOException("failed to atomically replace identity file")
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
