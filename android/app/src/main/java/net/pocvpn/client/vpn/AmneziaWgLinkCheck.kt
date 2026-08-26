package net.pocvpn.client.vpn

import org.amnezia.awg.backend.GoBackend
import org.amnezia.awg.backend.Tunnel

/**
 * B2 verification only: proves the app module can resolve and reference
 * classes from the pinned org.amnezia.awg :tunnel AAR at compile time.
 * Full AmneziaWgTransport (B3) is implemented separately.
 */
object AmneziaWgLinkCheck {
    fun backendClassName(): String = GoBackend::class.java.name
    fun tunnelStateEnumValues(): Array<Tunnel.State> = Tunnel.State.values()
}
