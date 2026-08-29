package net.pocvpn.client.vpn

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/**
 * B8G - "Level B" (Android OS Always-on VPN / lockdown) DETECTION only, and
 * even that only partially - this file NEVER enables, requests, or fakes
 * enablement of that system feature. See MainViewModel/VpnController for
 * "Level A" (this app's own session-scoped fail-closed behavior), which is
 * what this app can actually guarantee end to end.
 *
 * The ONLY reliable, non-fabricated signal available to a normal (non-
 * privileged, non-device-owner) app: decompiling the pinned AmneziaWG AAR's
 * org.amnezia.awg.backend.GoBackend$VpnService.onStartCommand() shows it
 * calling GoBackend.alwaysOnCallback?.alwaysOnTriggered() whenever the
 * incoming Intent has no explicit component targeting this app's own
 * package - which only happens when Android's OS itself starts this
 * VpnService directly (exactly what Settings -> VPN -> Always-on VPN does),
 * never from this app's own MainViewModel.connect() flow (which always
 * starts the service via GoBackend's own explicit-component path). Verified
 * against the real bytecode, not assumed from documentation.
 *
 * This is a ONE-DIRECTIONAL signal: observing it fire is confirmed, real
 * proof Always-on is configured for this app. Never observing it fire
 * proves NOTHING either way (the OS may simply not have needed to
 * autostart the service yet, e.g. no reboot/kill has happened since
 * Always-on was turned on) - so this deliberately has no "confirmed
 * disabled" state, only CONFIRMED_ENABLED or UNKNOWN. There is also no
 * public SDK API this app could call instead to ask directly:
 * android.net.VpnService.isLockdownEnabled() (API 29+) is an INSTANCE
 * method on the live VpnService, and GoBackend keeps that instance
 * entirely private - no public getter exists on GoBackend or
 * GoBackend$VpnService (verified via `javap -p` against the full pinned
 * class) - so this callback is the only practical detection point without
 * forking the pinned AAR, which is out of scope for this slice.
 */
enum class AlwaysOnDetectionState { CONFIRMED_ENABLED, UNKNOWN }

object AlwaysOnVpnState {
    private val _state = MutableStateFlow(AlwaysOnDetectionState.UNKNOWN)
    val state: StateFlow<AlwaysOnDetectionState> = _state

    /** Call ONLY from the GoBackend.AlwaysOnCallback registered at process startup (see NovaVpnApplication). */
    fun markConfirmedEnabled() {
        _state.value = AlwaysOnDetectionState.CONFIRMED_ENABLED
    }
}
