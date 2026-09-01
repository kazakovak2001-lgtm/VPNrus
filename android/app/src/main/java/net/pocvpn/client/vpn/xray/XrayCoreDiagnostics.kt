package net.pocvpn.client.vpn.xray

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/** One sanitized, bounded xray-core lifecycle/status line - see [XrayCoreDiagnostics]. */
data class XrayDiagnosticEvent(val level: String, val message: String)

/**
 * B21-fix - DEBUG-only, bounded, sanitized record of what xray-core's own
 * CoreCallbackHandler actually reported (startup/shutdown/onEmitStatus) -
 * the channel [XrayCoreRuntime]'s previous NoopCoreCallbackHandler discarded
 * entirely, which is why the QUIC false-positive dial failure produced no
 * client-side evidence at all. Only ever written from
 * [net.pocvpn.client.vpn.xray.LibXrayCoreRuntime]'s callback handler, gated
 * on `BuildConfig.DEBUG` there - this object itself has no build-type
 * awareness, so a release build simply never calls [record].
 *
 * [sanitize] is defense in depth, not the primary control: xray-core's own
 * `loglevel: "warning"` config (see [XrayConfigRenderer]) does not emit
 * credential material at that level in the first place. This additionally
 * strips any long hex/base64-shaped token before a line is ever kept, so a
 * uuid/reality-public-key/short_id-shaped string could not survive here even
 * if a future log line included one.
 */
object XrayCoreDiagnostics {
    private const val MAX_EVENTS = 50
    private const val MAX_MESSAGE_LENGTH = 200

    private val _events = MutableStateFlow<List<XrayDiagnosticEvent>>(emptyList())
    val events: StateFlow<List<XrayDiagnosticEvent>> = _events

    fun record(level: String, rawMessage: String?) {
        val event = XrayDiagnosticEvent(level, sanitize(rawMessage))
        _events.value = (_events.value + event).takeLast(MAX_EVENTS)
    }

    fun clear() {
        _events.value = emptyList()
    }

    internal fun sanitize(raw: String?): String {
        val truncated = (raw ?: "").take(MAX_MESSAGE_LENGTH)
        return SECRET_LIKE_TOKEN.replace(truncated, "[redacted]")
    }

    /** Matches a uuid, a reality public key/short id, or any other long hex/base64-shaped run. */
    private val SECRET_LIKE_TOKEN = Regex(
        "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}" + // uuid
            "|[0-9a-fA-F]{16,}" + // long hex run (short ids, raw key bytes)
            "|[A-Za-z0-9+/]{24,}={0,2}", // long base64 run (reality public key, etc.)
    )
}
