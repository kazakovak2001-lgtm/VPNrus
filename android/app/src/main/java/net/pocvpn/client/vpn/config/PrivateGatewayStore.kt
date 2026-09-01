package net.pocvpn.client.vpn.config

import org.json.JSONObject
import java.io.File
import java.nio.file.Files
import java.nio.file.StandardCopyOption

/**
 * B22 - device-local persistence for the single supported [PrivateGatewayConfig]
 * (first-slice scope). Deliberately structurally incapable of holding a
 * client private key - [PrivateGatewayConfig] itself has no such field, so
 * there is nothing for this store to serialize even by mistake (architecture
 * constraint 1: "must not be ... committed"/"placed in diagnostics" - the
 * type system, not caller discipline, is what enforces this).
 *
 * Plain (non-encrypted) storage is correct here: every field
 * [PrivateGatewayConfig] carries is either public by nature (server public
 * key, host/port - the same class of fact [ProductionGatewayCatalog] commits
 * to source in plaintext) or this device's own already-non-secret tunnel
 * address - exactly the same sensitivity level [FileSelectedGatewayStore]/
 * [FileClientTunnelIdentityStore] already persist unencrypted. The genuinely
 * secret material (the client private key) never reaches this class - see
 * [net.pocvpn.client.identity.PrivateGatewayKeyRepositoryFactory].
 */
interface PrivateGatewayStore {
    /** null if never configured (or the persisted file is missing/corrupted - corruption is never treated as "configured with garbage"). */
    fun read(): PrivateGatewayConfig?
    fun write(config: PrivateGatewayConfig)
    fun clear()
}

class FilePrivateGatewayStore(
    private val directory: File,
    private val fileName: String = "private_gateway_config.json",
) : PrivateGatewayStore {

    private val file: File get() = File(directory, fileName)

    override fun read(): PrivateGatewayConfig? {
        if (!file.exists()) return null
        return try {
            val json = JSONObject(file.readText(Charsets.UTF_8))
            val profileJson = json.getJSONObject(KEY_AWG_PROFILE)
            val config = PrivateGatewayConfig(
                id = json.optString(KEY_ID, PrivateGatewayConfig.ID),
                host = json.getString(KEY_HOST),
                port = json.getInt(KEY_PORT),
                serverPublicKeyBase64 = json.getString(KEY_SERVER_PUBLIC_KEY),
                clientTunnelIp = json.getString(KEY_CLIENT_TUNNEL_IP),
                gatewayTunnelIp = json.getString(KEY_GATEWAY_TUNNEL_IP),
                awgProfile = AwgProfile(
                    junkPacketCount = profileJson.optIntOrNull(KEY_JUNK_PACKET_COUNT),
                    junkPacketMinSize = profileJson.optIntOrNull(KEY_JUNK_PACKET_MIN_SIZE),
                    junkPacketMaxSize = profileJson.optIntOrNull(KEY_JUNK_PACKET_MAX_SIZE),
                    initPacketMagicHeader = profileJson.optStringOrNull(KEY_INIT_HEADER),
                    responsePacketMagicHeader = profileJson.optStringOrNull(KEY_RESPONSE_HEADER),
                    underloadPacketMagicHeader = profileJson.optStringOrNull(KEY_UNDERLOAD_HEADER),
                    transportPacketMagicHeader = profileJson.optStringOrNull(KEY_TRANSPORT_HEADER),
                ),
            )
            // Never trust a stored value as "configured" if it is structurally
            // invalid - a corrupted/hand-edited file must fail closed exactly
            // like a never-configured one, never silently connect with a
            // malformed peer (architecture "SECURITY / VALIDATION" requirement).
            when (PrivateGatewayConfigValidator.revalidate(config)) {
                is PrivateGatewayValidationResult.Valid -> config
                is PrivateGatewayValidationResult.Invalid -> null
            }
        } catch (e: org.json.JSONException) {
            null
        } catch (e: java.io.IOException) {
            null
        }
    }

    override fun write(config: PrivateGatewayConfig) {
        val profileJson = JSONObject()
            .putOpt(KEY_JUNK_PACKET_COUNT, config.awgProfile.junkPacketCount)
            .putOpt(KEY_JUNK_PACKET_MIN_SIZE, config.awgProfile.junkPacketMinSize)
            .putOpt(KEY_JUNK_PACKET_MAX_SIZE, config.awgProfile.junkPacketMaxSize)
            .putOpt(KEY_INIT_HEADER, config.awgProfile.initPacketMagicHeader)
            .putOpt(KEY_RESPONSE_HEADER, config.awgProfile.responsePacketMagicHeader)
            .putOpt(KEY_UNDERLOAD_HEADER, config.awgProfile.underloadPacketMagicHeader)
            .putOpt(KEY_TRANSPORT_HEADER, config.awgProfile.transportPacketMagicHeader)
        val json = JSONObject()
            .put(KEY_ID, config.id)
            .put(KEY_HOST, config.host)
            .put(KEY_PORT, config.port)
            .put(KEY_SERVER_PUBLIC_KEY, config.serverPublicKeyBase64)
            .put(KEY_CLIENT_TUNNEL_IP, config.clientTunnelIp)
            .put(KEY_GATEWAY_TUNNEL_IP, config.gatewayTunnelIp)
            .put(KEY_AWG_PROFILE, profileJson)

        directory.mkdirs()
        val tmp = File(directory, "$fileName.tmp")
        tmp.writeText(json.toString(), Charsets.UTF_8)
        try {
            Files.move(tmp.toPath(), file.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
        } catch (e: java.nio.file.FileSystemException) {
            tmp.delete()
            throw java.io.IOException("failed to atomically replace private gateway config file", e)
        }
    }

    override fun clear() {
        file.delete()
    }

    private companion object {
        const val KEY_ID = "id"
        const val KEY_HOST = "host"
        const val KEY_PORT = "port"
        const val KEY_SERVER_PUBLIC_KEY = "serverPublicKey"
        const val KEY_CLIENT_TUNNEL_IP = "clientTunnelIp"
        const val KEY_GATEWAY_TUNNEL_IP = "gatewayTunnelIp"
        const val KEY_AWG_PROFILE = "awgProfile"
        const val KEY_JUNK_PACKET_COUNT = "junkPacketCount"
        const val KEY_JUNK_PACKET_MIN_SIZE = "junkPacketMinSize"
        const val KEY_JUNK_PACKET_MAX_SIZE = "junkPacketMaxSize"
        const val KEY_INIT_HEADER = "initPacketMagicHeader"
        const val KEY_RESPONSE_HEADER = "responsePacketMagicHeader"
        const val KEY_UNDERLOAD_HEADER = "underloadPacketMagicHeader"
        const val KEY_TRANSPORT_HEADER = "transportPacketMagicHeader"
    }
}

private fun JSONObject.optIntOrNull(key: String): Int? = if (has(key) && !isNull(key)) getInt(key) else null
private fun JSONObject.optStringOrNull(key: String): String? = if (has(key) && !isNull(key)) getString(key) else null
