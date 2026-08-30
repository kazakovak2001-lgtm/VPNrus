package net.pocvpn.client.vpn.xray

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/**
 * B8I7 - one real Xray core/tunnel lifecycle event, published ONLY by
 * NovaXrayVpnService (the actual runtime - see its own docs) and consumed
 * ONLY by VlessRealityTransport (the VpnTransport-facing adapter - see its
 * own docs). [sessionId] identifies ONE start attempt (assigned by
 * VlessRealityTransport.connect(), threaded through the ACTION_START Intent
 * as NovaXrayVpnService.EXTRA_SESSION_ID, and echoed back in every event
 * NovaXrayVpnService publishes for that attempt) - a consumer filters on
 * this to reject an event from a session it has already moved on from (see
 * VlessRealityTransport's own docs for exactly how). [reason] on [Failed] is
 * always one of XrayCoreStartOutcome's own non-secret reason strings -
 * never a uuid/reality-public-key/short_id.
 */
sealed class XrayRuntimeEvent {
    abstract val sessionId: Long

    data class Started(override val sessionId: Long) : XrayRuntimeEvent()
    data class Failed(override val sessionId: Long, val reason: String) : XrayRuntimeEvent()
    data class Stopped(override val sessionId: Long) : XrayRuntimeEvent()
}

/**
 * B8I7 - the truthful, in-process signal of the REAL Xray core/tunnel
 * lifecycle. Same shape AlwaysOnVpnState already uses (a process-wide
 * singleton StateFlow one component writes and another reads) - not a new
 * pattern, not polling, not elapsed-time inference. A [StateFlow] (not a
 * one-shot SharedFlow) deliberately: a NEW subscriber (VlessRealityTransport
 * starting a fresh connect() attempt) immediately replays whatever the
 * CURRENT value is, so a publish() that raced ahead of the subscribe() can
 * never be silently missed - the subscriber's own sessionId filter is what
 * then correctly discards a replayed event from a DIFFERENT (older) session
 * as stale, never mistaking it for confirmation of its own attempt.
 */
object XrayRuntimeState {
    private val _events = MutableStateFlow<XrayRuntimeEvent?>(null)
    val events: StateFlow<XrayRuntimeEvent?> = _events

    /** Call ONLY from NovaXrayVpnService's own lifecycle - never fabricated elsewhere. */
    fun publish(event: XrayRuntimeEvent) {
        _events.value = event
    }
}
