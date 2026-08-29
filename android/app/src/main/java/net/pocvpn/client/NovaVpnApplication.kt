package net.pocvpn.client

import android.app.Application
import net.pocvpn.client.vpn.AlwaysOnVpnState
import org.amnezia.awg.backend.GoBackend

/**
 * B8G - registers the ONE detection hook AlwaysOnVpnState can rely on
 * (see that class's own docs) as early as possible in the process
 * lifetime, so it is already in place if Android's OS starts
 * GoBackend$VpnService directly (Always-on VPN) before MainActivity/
 * MainViewModel ever runs. Nothing else lives here - no VPN/backend logic,
 * no eager GoBackend instantiation (AmneziaWgTransport still lazily creates
 * its own GoBackend instance exactly as before; GoBackend.setAlwaysOnCallback
 * is a static registration independent of any particular instance).
 */
class NovaVpnApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        GoBackend.setAlwaysOnCallback { AlwaysOnVpnState.markConfirmedEnabled() }
    }
}
