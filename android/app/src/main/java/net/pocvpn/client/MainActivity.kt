package net.pocvpn.client

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.os.Bundle
import android.text.InputType
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import kotlinx.coroutines.launch
import net.pocvpn.client.provisioning.ProvisioningUiState
import net.pocvpn.client.vpn.config.ProfileSource
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

    // B8B3A - debug-only live provisioning UI. tokenInputView deliberately
    // has isSaveEnabled = false and autofill disabled below (see buildUi) -
    // the pasted token must never end up in a saved instance state Bundle
    // or an autofill store. Nothing here is retained by MainActivity itself
    // beyond the current EditText widget; MainViewModel doesn't persist it
    // either - see MainViewModel.activateDevice's own comment.
    private lateinit var tokenInputView: EditText
    private lateinit var provisioningStatusView: TextView
    private lateinit var effectiveConfigView: TextView
    private lateinit var profileSourceView: TextView

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

    // B8B3A scroll fix - single ScrollView wrapping the one existing
    // vertical content container, nothing nested inside it scrolls on its
    // own (no inner ScrollView/RecyclerView), so there is exactly one
    // scrolling container for the whole screen.
    private fun buildUi(): ScrollView {
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

            // B8C2 - one-time live activation against the real production
            // endpoint. The activation credential is pasted here, held only
            // in memory (see MainViewModel.activateDevice), never written
            // to source/BuildConfig/resources/git/logs.
            root.addView(TextView(this).apply { text = "-- B8C2: device activation (debug only) --" })
            tokenInputView = EditText(this).apply {
                hint = "Activation credential"
                inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
                isSaveEnabled = false
                importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO
            }
            root.addView(tokenInputView)
            root.addView(Button(this).apply {
                text = "ACTIVATE DEVICE"
                setOnClickListener { viewModel.activateDevice(tokenInputView.text.toString()) }
            })
            provisioningStatusView = label("Provisioning: -")

            // B8B3B handshake investigation - debug-only, non-secret
            // effective-config dump: exactly the fields that reach
            // AwgConfigMapper (see VpnController.buildTransportConfig),
            // read fresh from viewModel.gatewayStatus() so it reflects
            // whatever apply() has (or hasn't) done. Never includes the
            // private key (not part of GatewayConfiguration at all - see
            // that class's own doc) or the enrollment bearer token (not
            // part of it either).
            root.addView(TextView(this).apply { text = "-- B8B3B: effective config (debug only) --" })
            root.addView(Button(this).apply {
                text = "Show effective config"
                setOnClickListener { effectiveConfigView.text = buildEffectiveConfigDump() }
            })
            effectiveConfigView = label("Effective config: (tap button above)")
            profileSourceView = label("Profile source: -")
        }

        return ScrollView(this).apply {
            isFillViewport = true
            addView(root)
        }
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
                        // B8B3D - real values from VpnTransport.stats(), non-secret
                        // (byte counters + a handshake timestamp only).
                        handshakeView.text = "  Handshake: ${snapshot.lastHandshakeEpochMillis?.let { "${System.currentTimeMillis() - it}ms ago" } ?: "-"}"
                        rxView.text = "  RX: ${snapshot.bytesReceived ?: "-"}"
                        txView.text = "  TX: ${snapshot.bytesSent ?: "-"}"
                        snapshot.lastError?.let { lastErrorView.text = "  Last error: ${it.displayText()}" }
                    }
                }
                launch {
                    updateGatewayDisplay()
                }
                if (BuildConfig.DEBUG) {
                    launch {
                        viewModel.provisioningState.collect { state ->
                            provisioningStatusView.text = state.toDisplayString()
                        }
                    }
                    launch {
                        viewModel.profileSource.collect { source ->
                            profileSourceView.text = "Profile source: ${source.toDisplayString()}"
                        }
                    }
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

    /**
     * B8B3B - non-secret effective-config snapshot for on-device diagnosis.
     * Deliberately never touches ClientKeyRepository/private-key material or
     * the enrollment bearer token - only fields already present on
     * GatewayConfiguration.Configured (itself never a secret - see that
     * class's own doc comment) plus the AWG obfuscation profile attached to it.
     */
    private fun buildEffectiveConfigDump(): String {
        return when (val config = viewModel.gatewayStatus()) {
            is GatewayConfiguration.Missing -> "Effective config: MISSING (not configured)"
            is GatewayConfiguration.Invalid -> "Effective config: INVALID (${config.reason})"
            is GatewayConfiguration.Configured -> {
                val p = config.profile
                buildString {
                    appendLine("Effective config:")
                    appendLine("  endpointHost=${config.endpointHost}")
                    appendLine("  endpointPort=${config.endpointPort}")
                    appendLine("  serverPublicKey=${config.serverPublicKeyBase64}")
                    appendLine("  clientTunnelIp=${config.clientTunnelIp}/32")
                    appendLine("  gatewayTunnelIp=${config.gatewayTunnelIp}")
                    appendLine("  allowedIps=${config.allowedIps}")
                    appendLine("  dnsServers=${config.dnsServers}")
                    appendLine("  persistentKeepaliveSeconds=${config.persistentKeepaliveSeconds}")
                    appendLine("  Jc=${p.junkPacketCount} Jmin=${p.junkPacketMinSize} Jmax=${p.junkPacketMaxSize}")
                    appendLine("  S1=${p.initPacketJunkSize} S2=${p.responsePacketJunkSize} S3=${p.cookieReplyPacketJunkSize} S4=${p.transportPacketJunkSize}")
                    appendLine("  H1=${p.initPacketMagicHeader} H2=${p.responsePacketMagicHeader} H3=${p.underloadPacketMagicHeader} H4=${p.transportPacketMagicHeader}")
                    append("  (client public key shown above; private key never read/shown here)")
                }
            }
        }
    }

    private fun copyPublicKey() {
        val key = viewModel.publicKey.value ?: return
        val clipboard = getSystemService(ClipboardManager::class.java)
        clipboard.setPrimaryClip(ClipData.newPlainText("AWG public key", key))
        Toast.makeText(this, "Public key copied", Toast.LENGTH_SHORT).show()
    }
}

private fun TransportState.toDisplayString(): String = when (this) {
    is TransportState.Disconnected -> "Disconnected"
    is TransportState.Connecting -> "Connecting…"
    // B8B3D - reaching this branch means a REAL handshake was already
    // observed for the current attempt (see VpnController.awaitFreshHandshake) -
    // interface-up/TX>0 alone can never produce this text.
    is TransportState.Connected -> "Connected"
    is TransportState.Disconnecting -> "Disconnecting…"
    is TransportState.Reconnecting -> "Reconnecting (attempt $attempt)…"
    is TransportState.Error -> "Connection failed: $message"
    is TransportState.HandshakeFailed -> "Connection failed: no VPN handshake"
}

private fun ProvisioningUiState.toDisplayString(): String = when (this) {
    is ProvisioningUiState.Idle -> "Provisioning: -"
    is ProvisioningUiState.Provisioning -> "Provisioning: in progress..."
    is ProvisioningUiState.Unauthorized -> "Provisioning: INVALID ACTIVATION"
    is ProvisioningUiState.Revoked -> "Provisioning: ACTIVATION REVOKED"
    is ProvisioningUiState.Expired -> "Provisioning: ACTIVATION EXPIRED"
    is ProvisioningUiState.DeviceLimitReached -> "Provisioning: DEVICE LIMIT REACHED"
    is ProvisioningUiState.Error -> "Provisioning: ERROR - $message"
    is ProvisioningUiState.Success -> {
        val r = result
        // B8B3B - applying the validated result to the runtime gateway
        // config source already happened synchronously in
        // MainViewModel.provisionDevice before this state was ever
        // published, so reaching this branch IS the "profile applied" signal.
        "Provisioned - profile applied\nTunnel IP: ${r.clientTunnelIp}\nEndpoint: ${r.endpointHost}:${r.endpointPort}\nTap CONNECT to use it"
    }
}

private fun ProfileSource.toDisplayString(): String = when (this) {
    ProfileSource.PROVISIONED_LIVE -> "provisioned-live"
    ProfileSource.RESTORED_PERSISTED -> "restored-persisted"
    ProfileSource.DEV_FALLBACK -> "dev fallback"
}
