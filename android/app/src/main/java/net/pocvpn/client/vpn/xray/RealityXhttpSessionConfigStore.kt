package net.pocvpn.client.vpn.xray

import java.util.concurrent.ConcurrentHashMap

/**
 * B-WL-R6 - process-local hand-off of a validated, secret-bearing (uuid)
 * [XrayVlessRealityXhttpConfig] from VlessRealityXhttpTransport to
 * NovaXrayVpnService, keyed by session id - the same pattern
 * [XhttpSessionConfigStore] uses for B35, so the config never crosses
 * Intent/Binder extras. [consume] removes it: one start per stored config.
 */
object RealityXhttpSessionConfigStore {
    private val configs = ConcurrentHashMap<Long, XrayVlessRealityXhttpConfig>()

    fun put(sessionId: Long, config: XrayVlessRealityXhttpConfig) {
        configs[sessionId] = config
    }

    fun consume(sessionId: Long): XrayVlessRealityXhttpConfig? = configs.remove(sessionId)

    fun remove(sessionId: Long) {
        configs.remove(sessionId)
    }
}
