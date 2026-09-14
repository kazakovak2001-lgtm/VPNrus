package net.pocvpn.client.vpn.xray

import java.util.concurrent.ConcurrentHashMap

/**
 * B35 - process-local one-shot handoff for validated XHTTP runtime config.
 *
 * The secret-bearing config never crosses Intent/Binder extras and is never
 * persisted. NovaXrayVpnService runs in the same application process.
 */
object XhttpSessionConfigStore {
    private val configs = ConcurrentHashMap<Long, XrayVlessXhttpConfig>()

    fun put(sessionId: Long, config: XrayVlessXhttpConfig) {
        configs[sessionId] = config
    }

    fun consume(sessionId: Long): XrayVlessXhttpConfig? =
        configs.remove(sessionId)

    fun remove(sessionId: Long) {
        configs.remove(sessionId)
    }
}