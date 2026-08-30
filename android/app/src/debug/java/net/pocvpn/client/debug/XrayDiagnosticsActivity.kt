package net.pocvpn.client.debug

import android.os.Bundle
import android.view.Gravity
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.launch
import net.pocvpn.client.identity.XrayProfile
import net.pocvpn.client.identity.XrayProfileRepositoryFactory
import net.pocvpn.client.identity.XrayTlsProfile
import net.pocvpn.client.identity.XrayTlsProfileRepositoryFactory
import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.smartconnect.ProductionGateway
import net.pocvpn.client.vpn.VlessRealityTransport
import net.pocvpn.client.vpn.VlessTlsTransport
import net.pocvpn.client.vpn.config.TransportConfig
import net.pocvpn.client.vpn.xray.toXrayVlessRealityConfig
import net.pocvpn.client.vpn.xray.toXrayVlessTlsConfig

/**
 * B8K1B - debug-build-only screen for manually exercising the isolated Xray
 * adapter shell on a physical device. Debug-only via the `debug` Gradle
 * source set's own AndroidManifest.xml (see that file's docs) - never
 * present in a release APK.
 *
 * Uses NO fabricated credentials: if no real profile has been saved via
 * [net.pocvpn.client.identity.XrayProfileRepository.saveProfile] (a future
 * real provisioning flow's job, not this activity's, EXCEPT the one-time
 * manual-save path below), this screen shows a refusal message and does
 * nothing else. There is no UUID/public key/short ID hardcoded anywhere in
 * this file.
 *
 * B13 (2026-08-30, Stockholm physical validation) - endpoint-aware
 * ([EXTRA_ENDPOINT_ID], defaults to the production/Germany endpoint so
 * every pre-B13 launch - including a plain tap from the launcher, with no
 * extras at all - is byte-for-byte unaffected) and REALITY/TLS-aware
 * ([EXTRA_KIND]). Adds a genuine, minimal manual-save path
 * ([EXTRA_SAVE_PROFILE]) for exactly ONE reason: AndroidKeyStore-encrypted
 * profile storage (SecureXrayProfileRepository) cannot be constructed
 * off-device - there is no way to pre-build a valid encrypted profile file
 * and push it in, unlike the plaintext AWG PersistedProfile. A real,
 * operator-provisioned server-side credential (never invented here) is the
 * ONLY thing this path can ever save - it is a save mechanism, not a
 * credential generator.
 */
class XrayDiagnosticsActivity : AppCompatActivity() {

    private lateinit var endpointId: EndpointId
    private lateinit var statusText: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        endpointId = intent.getStringExtra(EXTRA_ENDPOINT_ID)?.takeIf { it.isNotBlank() }
            ?.let { EndpointId(it) } ?: EndpointId(ProductionGateway.ID)
        val kind = intent.getStringExtra(EXTRA_KIND) ?: "reality"

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            setPadding(48, 48, 48, 48)
        }
        statusText = TextView(this).apply { text = "endpoint=${endpointId.value} kind=$kind\nChecking for a saved Xray profile..." }
        root.addView(statusText)

        val startButton = Button(this).apply {
            text = "Start Xray test tunnel"
            isEnabled = false
            setOnClickListener {
                lifecycleScope.launch {
                    if (kind == "tls") {
                        val repository = XrayTlsProfileRepositoryFactory.create(applicationContext, endpointId)
                        val profile = repository.getProfileOrNull()
                        if (profile == null) {
                            statusText.text = "No Xray TLS profile configured for ${endpointId.value} - refusing to start."
                            return@launch
                        }
                        VlessTlsTransport(applicationContext).connect(TransportConfig.XrayTls(profile.toXrayVlessTlsConfig(), endpointId = endpointId))
                    } else {
                        val repository = XrayProfileRepositoryFactory.create(applicationContext, endpointId)
                        val profile = repository.getProfileOrNull()
                        if (profile == null) {
                            statusText.text = "No Xray profile configured for ${endpointId.value} - refusing to start."
                            return@launch
                        }
                        VlessRealityTransport(applicationContext).connect(TransportConfig.Xray(profile.toXrayVlessRealityConfig(), endpointId = endpointId))
                    }
                    statusText.text = "Start requested (endpoint=${endpointId.value}, kind=$kind) - see logcat NovaXrayVpnService for real lifecycle detail."
                }
            }
        }
        root.addView(startButton)

        val stopButton = Button(this).apply {
            text = "Stop Xray test tunnel"
            setOnClickListener {
                lifecycleScope.launch {
                    if (kind == "tls") VlessTlsTransport(applicationContext).disconnect() else VlessRealityTransport(applicationContext).disconnect()
                    statusText.text = "Stop requested - see logcat NovaXrayVpnService for real lifecycle detail."
                }
            }
        }
        root.addView(stopButton)

        setContentView(root)

        if (intent.getBooleanExtra(EXTRA_SAVE_PROFILE, false)) {
            lifecycleScope.launch {
                saveProfileFromIntent(kind)
                refreshStatus(kind, startButton)
            }
        } else {
            lifecycleScope.launch { refreshStatus(kind, startButton) }
        }
    }

    /**
     * B13 - saves EXACTLY the fields the launcher passed as Intent extras -
     * never a default/invented value for any credential field. Requires
     * every field for the requested [kind] to be present; otherwise no-ops
     * (never a partial/corrupt save).
     */
    private suspend fun saveProfileFromIntent(kind: String) {
        if (kind == "tls") {
            val server = intent.getStringExtra("server") ?: return
            val port = intent.getIntExtra("port", -1).takeIf { it > 0 } ?: return
            val uuid = intent.getStringExtra("uuid") ?: return
            val serverName = intent.getStringExtra("serverName") ?: return
            val fingerprint = intent.getStringExtra("fingerprint") ?: return
            XrayTlsProfileRepositoryFactory.create(applicationContext, endpointId).saveProfile(
                XrayTlsProfile(server = server, serverPort = port, uuid = uuid, serverName = serverName, fingerprint = fingerprint),
            )
        } else {
            val server = intent.getStringExtra("server") ?: return
            val port = intent.getIntExtra("port", -1).takeIf { it > 0 } ?: return
            val uuid = intent.getStringExtra("uuid") ?: return
            val flow = intent.getStringExtra("flow") ?: ""
            val serverName = intent.getStringExtra("serverName") ?: return
            val fingerprint = intent.getStringExtra("fingerprint") ?: return
            val realityPublicKey = intent.getStringExtra("realityPublicKey") ?: return
            val shortId = intent.getStringExtra("shortId") ?: return
            XrayProfileRepositoryFactory.create(applicationContext, endpointId).saveProfile(
                XrayProfile(
                    server = server, serverPort = port, uuid = uuid, flow = flow, serverName = serverName,
                    fingerprint = fingerprint, realityPublicKey = realityPublicKey, shortId = shortId,
                ),
            )
        }
    }

    private suspend fun refreshStatus(kind: String, startButton: Button) {
        val hasProfile = try {
            if (kind == "tls") {
                XrayTlsProfileRepositoryFactory.create(applicationContext, endpointId).getProfileOrNull() != null
            } else {
                XrayProfileRepositoryFactory.create(applicationContext, endpointId).getProfileOrNull() != null
            }
        } catch (t: Throwable) {
            false
        }
        statusText.text = "endpoint=${endpointId.value} kind=$kind\n" + if (hasProfile) {
            "Profile found. Ready to start (server/UUID/keys are never shown here)."
        } else {
            "No Xray profile configured - refusing to start. Provision a real profile first."
        }
        startButton.isEnabled = hasProfile
    }

    companion object {
        const val EXTRA_ENDPOINT_ID = "endpointId"
        const val EXTRA_KIND = "kind"
        const val EXTRA_SAVE_PROFILE = "saveProfile"
    }
}
