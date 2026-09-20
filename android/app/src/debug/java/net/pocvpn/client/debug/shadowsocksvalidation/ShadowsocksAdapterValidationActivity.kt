package net.pocvpn.client.debug.shadowsocksvalidation

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import java.io.File
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import net.pocvpn.client.identity.Shadowsocks2022CredentialRepositoryFactory
import net.pocvpn.client.identity.Shadowsocks2022CredentialValidationResult
import net.pocvpn.client.identity.Shadowsocks2022CredentialValidator
import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.vpn.TransportState
import net.pocvpn.client.vpn.config.TransportConfig
import net.pocvpn.client.vpn.shadowsocks.ShadowsocksTransport
import org.json.JSONObject

private const val TAG = "ShadowsocksValidation"
private const val STAGING_FILE_NAME = "ss_test_cred_staging.json"
// B45B-4P - pointed at the real Frankfurt endpoint id so this harness's
// "Provision" button stores a credential into the SAME real, endpoint-scoped
// Shadowsocks2022CredentialRepository the main app's own selection pipeline
// (MainViewModel.buildTransportRegistry/isShadowsocksAvailableFor) reads for
// this exact endpoint id - never a second/parallel credential store. This is
// debug-only tooling for physical device testing against the real endpoint;
// it has no effect on any release build.
private const val VALIDATION_ENDPOINT_ID = "frankfurt"

/**
 * B45B-3P - isolated, debug-only PHYSICAL VALIDATION HARNESS for the
 * PRODUCTION Shadowsocks 2022 adapter. Never a second implementation:
 * invokes [ShadowsocksTransport] (production, `src/main`) directly - never
 * B45A's own runtime/service/bridges - and never goes through
 * TransportRegistry/TransportOrchestrator/Smart Connect/AutoGatewaySelector/
 * PathCandidateBuilder (all untouched, unreachable from here).
 *
 * Credential provisioning: reads a staging JSON file from this app's own
 * external-files directory (placed there by `adb push` from outside the
 * app, never typed/logged), stores it into the REAL, production
 * Shadowsocks2022CredentialRepository (B45B-2), then deletes the staging
 * file immediately - the repository's own encrypted file is the only place
 * the credential persists afterward. The credential value itself is never
 * logged, never rendered in any TextView, never included in any exception
 * message this Activity produces.
 */
class ShadowsocksAdapterValidationActivity : AppCompatActivity() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private lateinit var statusView: TextView
    private lateinit var transport: ShadowsocksTransport
    private val endpointId = EndpointId(VALIDATION_ENDPOINT_ID)
    private var pendingConfig: TransportConfig.Shadowsocks? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        transport = ShadowsocksTransport(applicationContext)

        val root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        statusView = TextView(this).apply { text = "idle" }
        val provisionButton = Button(this).apply {
            text = "Provision test credential from staging file"
            setOnClickListener { provisionCredential() }
        }
        val connectButton = Button(this).apply {
            text = "Connect (production adapter)"
            setOnClickListener { connect() }
        }
        val disconnectButton = Button(this).apply {
            text = "Disconnect"
            setOnClickListener { disconnect() }
        }
        root.addView(statusView)
        root.addView(provisionButton)
        root.addView(connectButton)
        root.addView(disconnectButton)
        setContentView(root)

        scope.launch {
            transport.observeState().collect { state ->
                statusView.text = describeState(state)
                Log.i(TAG, "state -> ${state.javaClass.simpleName}")
            }
        }
    }

    /**
     * Reads {endpointId, host, port, method, key} from the staging file,
     * validates via the SAME [Shadowsocks2022CredentialValidator] the
     * production repository itself trusts, stores it, then deletes the
     * staging file - never logs any field value.
     */
    private fun provisionCredential() {
        scope.launch(Dispatchers.IO) {
            // B45B-4P physical validation - internal filesDir instead of the
            // external files dir (never committed): this Android 14 device
            // enforces per-app storage isolation that `adb`/`run-as` cannot
            // bypass even as the app's own UID (a known platform limitation,
            // not a security downgrade - the staging file is still deleted
            // immediately after use, same as before).
            val stagingFile = File(filesDir, STAGING_FILE_NAME)
            if (!stagingFile.exists()) {
                publishStatus("provision failed: staging file not present")
                return@launch
            }
            try {
                val json = JSONObject(stagingFile.readText())
                val host = json.getString("host")
                val port = json.getInt("port")
                val method = json.getString("method")
                val key = json.getString("key")

                val validation = Shadowsocks2022CredentialValidator.validate(endpointId, method, key)
                if (validation !is Shadowsocks2022CredentialValidationResult.Valid) {
                    publishStatus("provision failed: credential invalid (${validation.javaClass.simpleName})")
                    return@launch
                }

                val repository = Shadowsocks2022CredentialRepositoryFactory.create(applicationContext, endpointId)
                repository.storeCredential(validation.credential)

                pendingConfig = TransportConfig.Shadowsocks(endpointId = endpointId, host = host, port = port, method = method)
                publishStatus("credential provisioned into production repository")
            } catch (t: Throwable) {
                publishStatus("provision failed: ${t.javaClass.simpleName}")
            } finally {
                stagingFile.delete()
            }
        }
    }

    private fun connect() {
        val config = pendingConfig
        if (config == null) {
            publishStatus("no config - provision credential first")
            return
        }
        val permissionIntent = transport.preparePermissionIntent()
        if (permissionIntent != null) {
            pendingConfig = config
            startActivityForResult(permissionIntent, REQUEST_VPN_PERMISSION)
            return
        }
        scope.launch { transport.connect(config) }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQUEST_VPN_PERMISSION && resultCode == Activity.RESULT_OK) {
            val config = pendingConfig ?: return
            scope.launch { transport.connect(config) }
        } else if (requestCode == REQUEST_VPN_PERMISSION) {
            publishStatus("VPN permission denied")
        }
    }

    private fun disconnect() {
        scope.launch { transport.disconnect() }
    }

    private fun publishStatus(text: String) {
        runOnUiThread { statusView.text = text }
    }

    private fun describeState(state: TransportState): String = when (state) {
        is TransportState.Disconnected -> "Disconnected"
        is TransportState.Connecting -> "Connecting"
        is TransportState.Connected -> "Connected"
        is TransportState.Disconnecting -> "Disconnecting"
        is TransportState.Reconnecting -> "Reconnecting(${state.attempt})"
        is TransportState.Error -> "Error: ${state.message}"
        is TransportState.HandshakeFailed -> "HandshakeFailed"
    }

    private companion object {
        const val REQUEST_VPN_PERMISSION = 4501
    }
}
