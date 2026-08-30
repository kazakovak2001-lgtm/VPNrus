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
 *
 * A SECOND, immediately following review found the first fix's own
 * migration was itself wrong: it unconditionally seeded EVERY install
 * (fresh device or not) with the two IP values that used to be hardcoded
 * in ProductionGatewayCatalog - i.e. it re-injected the exact same
 * "one value baked into every install" bug this store exists to remove,
 * just moved one file over. A brand-new device has no business inheriting
 * THIS test device's own peer assignment.
 *
 * [migrateFromLegacyProvisionedProfile] is the real fix: it seeds ONLY
 * from genuine, already-persisted, per-device evidence
 * ([net.pocvpn.client.vpn.config.PersistedProfile], written exclusively
 * from a real POST /v1/activate response or restored from a prior
 * session's copy of one - see [ProvisionedProfileStore]'s own docs) - a
 * fresh install has no such file, so it is left entirely unprovisioned
 * (read() stays null for every endpoint, which
 * DefaultGatewayConfigurationRepository.get() already fails closed to
 * Invalid). No hardcoded IP is ever compiled into this store or a fallback
 * path for any device.
 */
interface ClientTunnelIdentityStore {
    /** The client tunnel IP THIS DEVICE is provisioned with on [id], or null if never set. */
    fun read(id: ProductionGatewayId): String?
    fun write(id: ProductionGatewayId, clientTunnelIp: String)
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
     * One-time, EVIDENCE-BASED migration for GERMANY only - the sole
     * endpoint that could possibly have been provisioned through the
     * legacy pre-B13 activation flow (Stockholm did not exist yet, so no
     * legitimate local evidence for it can ever exist here - per this
     * class's own top-level docs, that is never invented).
     *
     * [legacyProfile] is whatever [ProvisionedProfileStore.read] already
     * found for this device BEFORE this call (the caller - MainViewModel's
     * Factory - passes its own existing read result, this never re-reads
     * anything itself). null (never activated on this device - the fresh-
     * install case) is a no-op: nothing is seeded, [read] stays null for
     * every endpoint.
     *
     * Two extra checks beyond "a profile exists" keep this honestly
     * evidence-based rather than a rubber stamp:
     *  - the persisted profile's own endpointHost must match Germany's
     *    real gateway host - a profile activated against some OTHER host
     *    (a dev/staging server, gateway-dev.properties smoke-testing,
     *    etc.) is not evidence of a real Germany peer assignment and is
     *    silently ignored, never mis-migrated.
     *  - an endpoint that already has a stored value is NEVER overwritten
     *    (idempotent, safe to call on every startup - matches the
     *    previous migration's own idempotency contract).
     */
    fun migrateFromLegacyProvisionedProfile(legacyProfile: PersistedProfile?) {
        if (legacyProfile == null) return
        if (legacyProfile.endpointHost != ProductionGatewayCatalog.GERMANY.awg.endpointHost) return

        val entries = readAll()
        if (entries.containsKey(ProductionGatewayId.GERMANY)) return

        write(ProductionGatewayId.GERMANY, legacyProfile.clientTunnelIp)
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
