package net.pocvpn.client

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.os.Bundle
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import kotlinx.coroutines.launch
import net.pocvpn.client.vpn.ControllerEvent
import net.pocvpn.client.vpn.TransportState
import net.pocvpn.client.vpn.config.GatewayConfiguration

/**
 * B7A developer screen. Deliberately no visual polish - functional only.
 * Owns no tunnel/connection state itself; everything comes from MainViewModel,
 * which survives Activity recreation.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var viewModel: MainViewModel

    private lateinit var stateView: TextView
    private lateinit var permissionView: TextView
    private lateinit var publicKeyView: TextView
    private lateinit var clientTunnelIpView: TextView
    private lateinit var gatewayView: TextView
    private lateinit var profileView: TextView
    private lateinit var handshakeView: TextView
    private lateinit var rxView: TextView
    private lateinit var txView: TextView
    private lateinit var lastErrorView: TextView

    private val vpnPermissionLauncher =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            viewModel.onVpnPermissionResult(result.resultCode == RESULT_OK)
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        viewModel = ViewModelProvider(this, MainViewModel.Factory(applicationContext))[MainViewModel::class.java]

        setContentView(buildUi())
        observeViewModel()
    }

    private fun buildUi(): LinearLayout {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 48, 48, 48)
        }

        fun label(text: String) = TextView(this).apply { this.text = text }.also { root.addView(it) }

        label("VPN PoC")
        label("Transport: AWG 3.1")
        stateView = label("State: -")
        permissionView = label("VPN permission: -")
        publicKeyView = label("Client public key: (loading...)")
        clientTunnelIpView = label("Client tunnel IP: -")
        gatewayView = label("Gateway: -")
        profileView = label("Transport profile: AWG 3.1 POC")

        label("Diagnostics:")
        handshakeView = label("  Handshake: -")
        rxView = label("  RX: -")
        txView = label("  TX: -")
        lastErrorView = label("  Last error: -")

        root.addView(Button(this).apply {
            text = "CONNECT"
            setOnClickListener { viewModel.connect() }
        })
        root.addView(Button(this).apply {
            text = "DISCONNECT"
            setOnClickListener { viewModel.disconnect() }
        })
        root.addView(Button(this).apply {
            text = "COPY PUBLIC KEY"
            setOnClickListener { copyPublicKey() }
        })

        if (BuildConfig.DEBUG) {
            root.addView(TextView(this).apply { text = "-- debug-only, not a VPN control --" })
            root.addView(Button(this).apply {
                text = "Regenerate identity (debug only)"
                setOnClickListener { viewModel.regenerateIdentity() }
            })
        }

        return root
    }

    private fun observeViewModel() {
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                launch {
                    viewModel.transportState.collect { state ->
                        stateView.text = "State: ${state.toDisplayString()}"
                        if (state is TransportState.Error) {
                            lastErrorView.text = "  Last error: ${state.message}"
                        }
                    }
                }
                launch {
                    viewModel.publicKey.collect { key ->
                        publicKeyView.text = "Client public key: ${key ?: "(loading...)"}"
                    }
                }
                launch {
                    viewModel.diagnostics.collect { snapshot ->
                        permissionView.text =
                            "VPN permission: ${if (snapshot.permissionGranted) "GRANTED" else "REQUIRED"}"
                        handshakeView.text = "  Handshake: -"
                        rxView.text = "  RX: -"
                        txView.text = "  TX: -"
                        snapshot.lastError?.let { lastErrorView.text = "  Last error: ${it.displayText()}" }
                    }
                }
                launch {
                    updateGatewayDisplay()
                }
                launch {
                    viewModel.events.collect { event ->
                        when (event) {
                            is ControllerEvent.RequestVpnPermission -> requestVpnPermission(event.intent)
                        }
                    }
                }
            }
        }
    }

    private fun updateGatewayDisplay() {
        when (val gateway = viewModel.gatewayStatus()) {
            is GatewayConfiguration.Missing -> {
                clientTunnelIpView.text = "Client tunnel IP: NOT CONFIGURED"
                gatewayView.text = "Gateway: NOT CONFIGURED"
            }
            is GatewayConfiguration.Invalid -> {
                clientTunnelIpView.text = "Client tunnel IP: NOT CONFIGURED"
                gatewayView.text = "Gateway: INVALID (${gateway.reason})"
            }
            is GatewayConfiguration.Configured -> {
                clientTunnelIpView.text = "Client tunnel IP: ${gateway.clientTunnelIp}"
                gatewayView.text = "Gateway: ${gateway.endpointHost}:${gateway.endpointPort}"
            }
        }
    }

    private fun requestVpnPermission(intent: Intent) {
        vpnPermissionLauncher.launch(intent)
    }

    private fun copyPublicKey() {
        val key = viewModel.publicKey.value ?: return
        val clipboard = getSystemService(ClipboardManager::class.java)
        clipboard.setPrimaryClip(ClipData.newPlainText("AWG public key", key))
        Toast.makeText(this, "Public key copied", Toast.LENGTH_SHORT).show()
    }
}

private fun TransportState.toDisplayString(): String = when (this) {
    is TransportState.Disconnected -> "DISCONNECTED"
    is TransportState.Connecting -> "CONNECTING"
    is TransportState.Connected -> "CONNECTED"
    is TransportState.Disconnecting -> "DISCONNECTING"
    is TransportState.Reconnecting -> "RECONNECTING (attempt $attempt)"
    is TransportState.Error -> "ERROR"
}
