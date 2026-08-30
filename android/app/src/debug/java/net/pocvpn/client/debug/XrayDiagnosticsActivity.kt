package net.pocvpn.client.debug

import android.os.Bundle
import android.view.Gravity
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.launch
import net.pocvpn.client.identity.XrayProfileRepositoryFactory
import net.pocvpn.client.vpn.VlessRealityTransport
import net.pocvpn.client.vpn.config.TransportConfig
import net.pocvpn.client.vpn.xray.toXrayVlessRealityConfig

/**
 * B8K1B - debug-build-only screen for manually exercising the isolated Xray
 * adapter shell on a physical device. Debug-only via the `debug` Gradle
 * source set's own AndroidManifest.xml (see that file's docs) - never
 * present in a release APK.
 *
 * Uses NO fabricated credentials: if no real profile has been saved via
 * [net.pocvpn.client.identity.XrayProfileRepository.saveProfile] (a future
 * real provisioning flow's job, not this activity's), this screen shows a
 * refusal message and does nothing else. There is no UUID/public key/short
 * ID hardcoded anywhere in this file.
 */
class XrayDiagnosticsActivity : AppCompatActivity() {

    private val transport by lazy { VlessRealityTransport(applicationContext) }

    private lateinit var statusText: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            setPadding(48, 48, 48, 48)
        }
        statusText = TextView(this).apply { text = "Checking for a saved Xray profile..." }
        root.addView(statusText)

        val startButton = Button(this).apply {
            text = "Start Xray test tunnel"
            isEnabled = false
            setOnClickListener {
                lifecycleScope.launch {
                    val repository = XrayProfileRepositoryFactory.create(applicationContext)
                    val profile = repository.getProfileOrNull()
                    if (profile == null) {
                        statusText.text = "No Xray profile configured - refusing to start."
                        return@launch
                    }
                    transport.connect(TransportConfig.Xray(profile.toXrayVlessRealityConfig()))
                    statusText.text = "Start requested - see logcat NovaXrayVpnService for real lifecycle detail."
                }
            }
        }
        root.addView(startButton)

        val stopButton = Button(this).apply {
            text = "Stop Xray test tunnel"
            setOnClickListener {
                lifecycleScope.launch {
                    transport.disconnect()
                    statusText.text = "Stop requested - see logcat NovaXrayVpnService for real lifecycle detail."
                }
            }
        }
        root.addView(stopButton)

        setContentView(root)

        lifecycleScope.launch {
            val repository = XrayProfileRepositoryFactory.create(applicationContext)
            val hasProfile = try {
                repository.getProfileOrNull() != null
            } catch (t: Throwable) {
                false
            }
            statusText.text = if (hasProfile) {
                "Profile found. Ready to start (server/UUID/keys are never shown here)."
            } else {
                "No Xray profile configured - refusing to start. Provision a real profile first."
            }
            startButton.isEnabled = hasProfile
        }
    }
}
