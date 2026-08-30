package net.pocvpn.client.vpn.config

import java.io.File
import java.nio.file.Files
import java.nio.file.StandardCopyOption

/**
 * B13 review fix - the one canonical, DEVICE-LOCAL, per-endpoint store for
 * THIS DEVICE'S client tunnel IP on a given production gateway. A B13 final
 * review found that value hardcoded straight into ProductionGatewayCatalog,
 * which is wrong for the same reason the pre-B13 Germany data-plane bug was
 * wrong (see that incident's own notes, formerly on
 * ProductionGatewayCatalog.GERMANY): a gateway's own add-peer.sh-managed
 * peer list assigns each physical device its OWN AllowedIPs value, so this
 * is provisioned per-device identity, not a gateway infrastructure fact -
 * committing one value to source only ever describes ONE physical device.
 *
 * Keyed by [ProductionGatewayId] so Germany and Stockholm carry fully
 * independent assignments for this device, same "device-local preference,
 * never server-issued back" reasoning as SelectedGatewayStore/
 * AppRoutingPolicyStore (see their own docs). read() for an endpoint with
 * no stored entry returns null - callers MUST fail closed on that (see
 * SelectedProductionGatewaySource.clientTunnelIp()), never substitute
 * another endpoint's value or a hardcoded default: a leaked Stockholm IP
 * presented to Germany's peer (or vice versa) would silently misroute
 * packets exactly like the original bug did.
 */
interface ClientTunnelIdentityStore {
    /** The client tunnel IP THIS DEVICE is provisioned with on [id], or null if never set. */
    fun read(id: ProductionGatewayId): String?
    fun write(id: ProductionGatewayId, clientTunnelIp: String)
}

/**
 * The exact two values that were, until this review fix, hardcoded into
 * ProductionGatewayCatalog - i.e. this device's own already-working,
 * physically-verified peer assignment on each gateway. Consulted ONLY by
 * the one-time migration below, never by product code directly - a fresh
 * install/new device gets no seed and correctly starts unprovisioned
 * (read() returns null, DefaultGatewayConfigurationRepository.get()
 * fails closed to Invalid - see ClientTunnelIdentityStore's own docs).
 */
internal object MigratedClientTunnelIdentityDefaults {
    val values: Map<ProductionGatewayId, String> = mapOf(
        ProductionGatewayId.GERMANY to "10.77.0.5",
        ProductionGatewayId.STOCKHOLM to "10.77.0.2",
    )
}

private val IPV4_REGEX = Regex("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$")

class FileClientTunnelIdentityStore(
    private val directory: File,
    private val fileName: String = "client_tunnel_identity.txt",
) : ClientTunnelIdentityStore {

    private val file: File get() = File(directory, fileName)

    override fun read(id: ProductionGatewayId): String? = readAll()[id]

    override fun write(id: ProductionGatewayId, clientTunnelIp: String) {
        require(IPV4_REGEX.matches(clientTunnelIp)) {
            "not a valid IPv4 address: '$clientTunnelIp'"
        }
        val entries = readAll().toMutableMap()
        entries[id] = clientTunnelIp
        writeAll(entries)
    }

    /**
     * Seeds THIS DEVICE'S already-provisioned identity on first run after
     * this fix ships (no file yet) so the physical device this was
     * validated on keeps working - never overwrites an endpoint that
     * already has a stored (possibly different) value. Idempotent and
     * safe to call on every startup.
     */
    fun migrateLegacyDefaultsIfMissing() {
        val entries = readAll().toMutableMap()
        var changed = false
        for ((id, ip) in MigratedClientTunnelIdentityDefaults.values) {
            if (!entries.containsKey(id)) {
                entries[id] = ip
                changed = true
            }
        }
        if (changed) writeAll(entries)
    }

    private fun readAll(): Map<ProductionGatewayId, String> {
        if (!file.exists()) return emptyMap()
        return try {
            file.readLines(Charsets.UTF_8).mapNotNull { line ->
                val parts = line.split("=", limit = 2)
                if (parts.size != 2) return@mapNotNull null
                val id = ProductionGatewayId.entries.firstOrNull { it.name == parts[0] } ?: return@mapNotNull null
                val ip = parts[1].trim()
                if (!IPV4_REGEX.matches(ip)) return@mapNotNull null
                id to ip
            }.toMap()
        } catch (e: java.io.IOException) {
            emptyMap()
        }
    }

    private fun writeAll(entries: Map<ProductionGatewayId, String>) {
        directory.mkdirs()
        val tmp = File(directory, "$fileName.tmp")
        val text = entries.entries.joinToString("\n") { "${it.key.name}=${it.value}" }
        tmp.writeText(text, Charsets.UTF_8)
        // Files.move(..., REPLACE_EXISTING) rather than File.renameTo() -
        // renameTo() does NOT overwrite an existing destination on Windows
        // (same fix FilePathHistoryStore/FileSelectedGatewayStore's own
        // writeToDisk already applies), and this file gets rewritten on
        // every subsequent write() after the first.
        try {
            Files.move(tmp.toPath(), file.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
        } catch (e: java.nio.file.FileSystemException) {
            tmp.delete()
            throw java.io.IOException("failed to atomically replace client tunnel identity file", e)
        }
    }
}
