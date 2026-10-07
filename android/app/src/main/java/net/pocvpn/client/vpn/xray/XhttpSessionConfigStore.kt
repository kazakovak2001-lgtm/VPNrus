package net.pocvpn.client.vpn.xray

import net.pocvpn.client.identity.AesGcmKeyEncryptor
import net.pocvpn.client.identity.EncryptedPayload
import org.json.JSONObject
import java.io.File
import java.util.concurrent.ConcurrentHashMap

/**
 * One-shot handoff of a resolved XHTTP config from VlessXhttpTransport (main
 * process) to NovaXrayVpnService for exactly one session. The config holds
 * the VLESS uuid, so it never crosses Intent/Binder extras.
 *
 * Since Xray runs in its own process (`:xray`, see XrayProcessBridge), the
 * handoff is an app-private file encrypted with an Android Keystore
 * AES-GCM key - the same protection the stored Xray profiles use - written
 * atomically by [put] and deleted by [consume] / [remove]. Both processes
 * install the file backing from NovaVpnApplication; without it (JVM unit
 * tests) an in-memory map is used, which only works within one process.
 */
object XhttpSessionConfigStore {
    private val memory = ConcurrentHashMap<Long, XrayVlessXhttpConfig>()

    @Volatile private var files: FileHandoff? = null

    fun installFileHandoff(directory: File, encryptor: AesGcmKeyEncryptor) {
        files = FileHandoff(File(directory, "xhttp-sessions"), encryptor).also { it.deleteStale() }
    }

    fun put(sessionId: Long, config: XrayVlessXhttpConfig) {
        val f = files
        if (f == null) memory[sessionId] = config else f.write(sessionId, encodeXhttpConfig(config))
    }

    fun consume(sessionId: Long): XrayVlessXhttpConfig? {
        val f = files ?: return memory.remove(sessionId)
        return f.readAndDelete(sessionId)?.let(::decodeXhttpConfig)
    }

    fun remove(sessionId: Long) {
        memory.remove(sessionId)
        files?.delete(sessionId)
    }

    internal class FileHandoff(private val dir: File, private val encryptor: AesGcmKeyEncryptor) {
        private fun file(id: Long) = File(dir, "$id.bin")

        fun write(id: Long, plaintext: String) {
            dir.mkdirs()
            val payload = encryptor.encrypt(plaintext.toByteArray(Charsets.UTF_8))
            val tmp = File(dir, "$id.tmp")
            tmp.writeText(b64(payload.iv) + "\n" + b64(payload.ciphertext))
            if (!tmp.renameTo(file(id))) {
                tmp.delete()
                throw java.io.IOException("XHTTP session handoff rename failed")
            }
        }

        fun readAndDelete(id: Long): String? {
            val f = file(id)
            if (!f.exists()) return null
            return try {
                val (iv, ct) = f.readText().split('\n', limit = 2)
                String(encryptor.decrypt(EncryptedPayload(unb64(iv), unb64(ct))), Charsets.UTF_8)
            } catch (e: Exception) {
                null
            } finally {
                f.delete()
            }
        }

        fun delete(id: Long) {
            file(id).delete()
        }

        /** Leftovers of a crashed attempt are never reused. */
        fun deleteStale(maxAgeMs: Long = 10 * 60_000L, now: Long = System.currentTimeMillis()) {
            dir.listFiles()?.filter { now - it.lastModified() > maxAgeMs }?.forEach { it.delete() }
        }

        private fun b64(bytes: ByteArray) = java.util.Base64.getEncoder().encodeToString(bytes)
        private fun unb64(text: String) = java.util.Base64.getDecoder().decode(text)
    }
}

/** Pure, lossless JSON codec for the handoff (never logged). */
internal fun encodeXhttpConfig(c: XrayVlessXhttpConfig): String = JSONObject()
    .put("server", c.server)
    .put("serverPort", c.serverPort)
    .put("uuid", c.uuid)
    .put("tlsServerName", c.tlsServerName)
    .put("fingerprint", c.fingerprint)
    .put("minimumTlsVersion", c.minimumTlsVersion.name)
    .put("alpn", c.alpn)
    .put("xhttpHost", c.xhttpHost)
    .put("xhttpPath", c.xhttpPath)
    .put("queryParameters", JSONObject(c.queryParameters))
    .put("headers", JSONObject(c.headers))
    .put("mode", c.mode.name)
    .put("uplinkHttpMethod", c.uplinkHttpMethod.name)
    .put("maxEachPostBytes", c.maxEachPostBytes)
    .put("paddingPlacement", c.paddingPlacement?.name ?: JSONObject.NULL)
    .put("paddingMinBytes", c.paddingMinBytes ?: JSONObject.NULL)
    .put("paddingMaxBytes", c.paddingMaxBytes ?: JSONObject.NULL)
    .put("mtu", c.mtu)
    .put("dnsServers", org.json.JSONArray(c.dnsServers))
    .put("tunLocalAddressIpv4", c.tunLocalAddressIpv4)
    .put("tunLocalPrefixLengthIpv4", c.tunLocalPrefixLengthIpv4)
    .toString()

internal fun decodeXhttpConfig(text: String): XrayVlessXhttpConfig? = try {
    val o = JSONObject(text)
    fun map(key: String): Map<String, String> = o.getJSONObject(key).let { m -> m.keys().asSequence().associateWith { m.getString(it) } }
    fun optInt(key: String): Int? = if (o.isNull(key)) null else o.getInt(key)
    XrayVlessXhttpConfig(
        server = o.getString("server"),
        serverPort = o.getInt("serverPort"),
        uuid = o.getString("uuid"),
        tlsServerName = o.getString("tlsServerName"),
        fingerprint = o.getString("fingerprint"),
        minimumTlsVersion = XrayXhttpMinimumTlsVersion.valueOf(o.getString("minimumTlsVersion")),
        alpn = o.getString("alpn"),
        xhttpHost = o.getString("xhttpHost"),
        xhttpPath = o.getString("xhttpPath"),
        queryParameters = map("queryParameters"),
        headers = map("headers"),
        mode = XrayXhttpMode.valueOf(o.getString("mode")),
        uplinkHttpMethod = XrayXhttpUplinkHttpMethod.valueOf(o.getString("uplinkHttpMethod")),
        maxEachPostBytes = o.getInt("maxEachPostBytes"),
        paddingPlacement = if (o.isNull("paddingPlacement")) null else XrayXhttpPaddingPlacement.valueOf(o.getString("paddingPlacement")),
        paddingMinBytes = optInt("paddingMinBytes"),
        paddingMaxBytes = optInt("paddingMaxBytes"),
        mtu = o.getInt("mtu"),
        dnsServers = o.getJSONArray("dnsServers").let { a -> (0 until a.length()).map { a.getString(it) } },
        tunLocalAddressIpv4 = o.getString("tunLocalAddressIpv4"),
        tunLocalPrefixLengthIpv4 = o.getInt("tunLocalPrefixLengthIpv4"),
    )
} catch (e: Exception) {
    null
}
