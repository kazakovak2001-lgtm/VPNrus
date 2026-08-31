package net.pocvpn.client.vpn.config

import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.nio.charset.StandardCharsets

/**
 * B8B3C - non-secret, durable snapshot of a server-issued provisioning
 * result (see net.pocvpn.client.provisioning.ProvisioningResult.Success).
 * Deliberately carries ONLY the five gateway-side fields
 * MutableGatewayConfigSource.apply() accepts - no enrollment bearer token,
 * no private key. The private key remains exclusively in
 * ClientKeyRepository/IdentityFileStore (identity/IdentityFileStore.kt) -
 * this store never reads, writes, or even has a field for it.
 */
data class PersistedProfile(
    val endpointHost: String,
    val endpointPort: Int,
    val gatewayPublicKey: String,
    val clientTunnelIp: String,
    val gatewayTunnelIp: String,
)

sealed class ProfileLoadResult {
    object NotFound : ProfileLoadResult()
    data class Found(val profile: PersistedProfile) : ProfileLoadResult()
    data class Corrupted(val reason: String) : ProfileLoadResult()
}

/**
 * Plain-file persistence for PersistedProfile - the SAME atomic
 * tmp-file-then-rename, length-prefixed, versioned-format pattern as
 * identity/IdentityFileStore.kt (B4), reused deliberately rather than
 * introducing a database/DataStore/new framework for five small,
 * non-secret fields. No Android-framework dependency - directly
 * unit-testable on the JVM with a temp directory; on Android this should
 * be pointed at context.noBackupFilesDir like the identity store (this
 * data is a specific device's assigned tunnel address - a restored copy
 * from another device's backup would be meaningless/wrong here anyway).
 *
 * read() ALWAYS structurally re-validates before ever returning Found -
 * a corrupted, truncated, or hand-edited file can never produce a
 * silently-partial or malformed PersistedProfile; it becomes Corrupted
 * instead, and the caller (MainViewModel) is required to treat that
 * exactly like NotFound (fail closed - see its own startup-restore logic).
 */
interface ProfileStore {
    fun read(): ProfileLoadResult
    fun write(profile: PersistedProfile)
    fun delete()
}

class FileProfileStore(
    private val directory: File,
    private val fileName: String = "provisioned_profile.bin",
) : ProfileStore {

    private val file: File get() = File(directory, fileName)

    private companion object {
        const val FORMAT_VERSION = 1
        const val MAX_STRING_LEN = 512
    }

    override fun read(): ProfileLoadResult {
        if (!file.exists()) return ProfileLoadResult.NotFound
        return try {
            DataInputStream(file.inputStream().buffered()).use { input ->
                val version = input.readInt()
                if (version != FORMAT_VERSION) {
                    return ProfileLoadResult.Corrupted("unsupported format version $version")
                }
                val endpointHost = readString(input)
                val endpointPort = input.readInt()
                val gatewayPublicKey = readString(input)
                val clientTunnelIp = readString(input)
                val gatewayTunnelIp = readString(input)

                val validated = validatePersistedProfile(
                    endpointHost = endpointHost,
                    endpointPort = endpointPort,
                    gatewayPublicKey = gatewayPublicKey,
                    clientTunnelIp = clientTunnelIp,
                    gatewayTunnelIp = gatewayTunnelIp,
                ) ?: return ProfileLoadResult.Corrupted("persisted profile failed structural validation")

                ProfileLoadResult.Found(validated)
            }
        } catch (e: java.io.EOFException) {
            ProfileLoadResult.Corrupted("truncated profile file")
        } catch (e: java.io.IOException) {
            ProfileLoadResult.Corrupted("unreadable profile file: ${e.javaClass.simpleName}")
        } catch (e: IllegalArgumentException) {
            ProfileLoadResult.Corrupted(e.message ?: "malformed profile file")
        }
    }

    override fun write(profile: PersistedProfile) {
        directory.mkdirs()
        val tmp = File(directory, "$fileName.tmp")
        val bytes = ByteArrayOutputStream().also { buffer ->
            DataOutputStream(buffer).use { out ->
                out.writeInt(FORMAT_VERSION)
                writeString(out, profile.endpointHost)
                out.writeInt(profile.endpointPort)
                writeString(out, profile.gatewayPublicKey)
                writeString(out, profile.clientTunnelIp)
                writeString(out, profile.gatewayTunnelIp)
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

    private fun writeString(out: DataOutputStream, s: String) {
        val bytes = s.toByteArray(StandardCharsets.UTF_8)
        out.writeInt(bytes.size)
        out.write(bytes)
    }

    private fun readString(input: DataInputStream): String {
        val len = input.readInt()
        require(len in 0..MAX_STRING_LEN) { "implausible length-prefixed field: $len" }
        val bytes = ByteArray(len)
        input.readFully(bytes)
        return String(bytes, StandardCharsets.UTF_8)
    }
}

// Mirrors ProvisioningClient's own structural checks (IPv4 shape, AmneziaWG/
// WireGuard public-key shape, port range) - `internal`, not private, so it
// is directly unit-testable against hand-built corrupt/partial inputs
// without going through file I/O. IPv4 validity is Ipv4Format.isValid - the
// SAME strict, all-octets-0..255 check GatewayConfigurationRepository/
// ClientTunnelIdentityStore use (a B13 consolidated review fix - the old
// regex-only check here happily accepted "999.999.999.999", which matters
// now that a PersistedProfile is real migration evidence for
// ClientTunnelIdentityStore - see that class's own docs).
private val PROFILE_WG_KEY_REGEX = Regex("^[A-Za-z0-9+/]{43}=$")

internal fun validatePersistedProfile(
    endpointHost: String,
    endpointPort: Int,
    gatewayPublicKey: String,
    clientTunnelIp: String,
    gatewayTunnelIp: String,
): PersistedProfile? {
    if (endpointHost.isBlank()) return null
    if (endpointPort !in 1..65535) return null
    if (!PROFILE_WG_KEY_REGEX.matches(gatewayPublicKey)) return null
    if (!Ipv4Format.isValid(clientTunnelIp)) return null
    if (!Ipv4Format.isValid(gatewayTunnelIp)) return null
    return PersistedProfile(
        endpointHost = endpointHost,
        endpointPort = endpointPort,
        gatewayPublicKey = gatewayPublicKey,
        clientTunnelIp = clientTunnelIp,
        gatewayTunnelIp = gatewayTunnelIp,
    )
}
