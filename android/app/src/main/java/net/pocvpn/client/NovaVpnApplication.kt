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
    private companion object {
        const val XHTTP_HANDOFF_KEY_ALIAS = "nova_xhttp_session_handoff_key"
    }


    override fun onCreate() {
        super.onCreate()
        // Records uncaught JVM crashes locally for diagnostics reports (never uploaded).
        net.pocvpn.client.diagnostics.fieldtest.CrashRecorder.install(this)
        // Both processes: the XHTTP session handoff crosses from the main
        // process to `:xray` as an encrypted app-private file.
        net.pocvpn.client.vpn.xray.XhttpSessionConfigStore.installFileHandoff(
            noBackupFilesDir,
            net.pocvpn.client.identity.AndroidKeystoreAesGcmEncryptor(XHTTP_HANDOFF_KEY_ALIAS),
        )
        // `:xray` hosts only NovaXrayVpnService (one Go runtime per process -
        // see XrayProcessBridge); everything else is main-process only.
        if (net.pocvpn.client.vpn.xray.XrayProcessBridge.isXrayProcess(this)) return
        GoBackend.setAlwaysOnCallback { AlwaysOnVpnState.markConfirmedEnabled() }
        net.pocvpn.client.vpn.xray.XrayProcessBridge.installMainProcess(this)
    }
}
