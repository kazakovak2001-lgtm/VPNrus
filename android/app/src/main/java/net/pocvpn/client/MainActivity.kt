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
import net.pocvpn.client.ui.AppScreen
import net.pocvpn.client.ui.isConnectedOrConnecting
import net.pocvpn.client.ui.screenFor
import net.pocvpn.client.ui.shouldClearCredentialInput
import net.pocvpn.client.ui.shouldShowDiagnostics
import net.pocvpn.client.ui.toActivationErrorText
import net.pocvpn.client.ui.toHomeStatusText
import net.pocvpn.client.vpn.config.ProfileSource
import net.pocvpn.client.vpn.ControllerEvent
import net.pocvpn.client.vpn.TransportState
import net.pocvpn.client.vpn.config.GatewayConfiguration

/**
 * B8D - first-run Activation screen vs normal Home screen, chosen purely by
 * net.pocvpn.client.ui.screenFor(viewModel.profileSource.value) (see that
 * file's own docs). Deliberately no visual polish yet - functional product-
 * flow structure only. Owns no tunnel/connection/profile state itself;
 * everything comes from MainViewModel, which survives Activity recreation.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var viewModel: MainViewModel

    // --- screen containers - exactly one of activationScreen/homeScreen is
    // visible at a time, driven by observeViewModel()'s profileSource collector ---
    private lateinit var activationScreen: LinearLayout
    private lateinit var homeScreen: LinearLayout
    private lateinit var diagnosticsScreen: LinearLayout

    // --- Activation screen (release-facing - only shown pre-activation) ---
    // credentialInput deliberately has isSaveEnabled = false and autofill
    // disabled below (see buildActivationScreen) - the pasted credential must
    // never end up in a saved instance state Bundle or an autofill store.
    // Nothing here is retained by MainActivity itself beyond the current
    // EditText widget; MainViewModel doesn't persist it either (see
    // MainViewModel.activateDevice's own comment). Cleared explicitly on
    // success (see observeViewModel's provisioningState collector).
    private lateinit var credentialInput: EditText
    private lateinit var activationErrorView: TextView

    // --- Home screen (release-facing - only shown once a profile exists) ---
    private lateinit var homeStatusView: TextView
    private lateinit var primaryButton: Button

    // --- Diagnostics (debug builds only, collapsed by default) ---
    private lateinit var diagnosticsToggle: Button
    private lateinit var stateView: TextView
    private lateinit var permissionView: TextView
    private lateinit var publicKeyView: TextView
    private lateinit var clientTunnelIpView: TextView
    private lateinit var gatewayView: TextView
    private lateinit var handshakeView: TextView
    private lateinit var rxView: TextView
    private lateinit var txView: TextView
    private lateinit var lastErrorView: TextView
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

    // B8B3A scroll fix, kept - single ScrollView wrapping the one existing
    // vertical content container, nothing nested inside it scrolls on its
    // own (no inner ScrollView/RecyclerView), so there is exactly one
    // scrolling container for the whole screen.
    private fun buildUi(): ScrollView {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 48, 48, 48)
        }

        root.addView(buildActivationScreen())
        root.addView(buildHomeScreen())
        if (shouldShowDiagnostics(BuildConfig.DEBUG)) {
            root.addView(buildDiagnosticsToggle())
            root.addView(buildDiagnosticsScreen())
        }

        return ScrollView(this).apply {
            isFillViewport = true
            addView(root)
        }
    }

    /** B8D - "ACTIVATION SCREEN": only ever shown when no provisioned profile exists. */
    private fun buildActivationScreen(): LinearLayout {
        activationScreen = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }

        fun label(text: String) = TextView(this).apply { this.text = text }.also { activationScreen.addView(it) }

        label("Activate VPN")
        credentialInput = EditText(this).apply {
            hint = "Activation credential"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
            isSaveEnabled = false
            importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO
        }
        activationScreen.addView(credentialInput)
        activationScreen.addView(Button(this).apply {
            text = "ACTIVATE"
            setOnClickListener { viewModel.activateDevice(credentialInput.text.toString()) }
        })
        activationErrorView = label("")

        return activationScreen
    }

    /** B8D - "NORMAL HOME SCREEN": minimal, no technical values (see this file's own top doc). */
    private fun buildHomeScreen(): LinearLayout {
        homeScreen = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }

        homeStatusView = TextView(this).apply { text = "Disconnected" }.also { homeScreen.addView(it) }
        primaryButton = Button(this).apply {
            text = "CONNECT"
            setOnClickListener {
                if (viewModel.transportState.value.isConnectedOrConnecting()) viewModel.disconnect() else viewModel.connect()
            }
        }.also { homeScreen.addView(it) }
        // Placeholder single-gateway label - update if this deployment's
        // gateway location changes; there is no per-gateway location field
        // in GatewayConfiguration yet (only one gateway exists today).
        homeScreen.addView(TextView(this).apply { text = "Germany · Frankfurt" })

        return homeScreen
    }

    private fun buildDiagnosticsToggle(): Button {
        diagnosticsToggle = Button(this).apply {
            text = "Diagnostics"
            setOnClickListener {
                diagnosticsScreen.visibility = if (diagnosticsScreen.visibility == View.VISIBLE) View.GONE else View.VISIBLE
            }
        }
        return diagnosticsToggle
    }

    /**
     * B8D "DEBUG / DIAGNOSTICS" - debug builds only, collapsed (View.GONE)
     * until diagnosticsToggle is tapped. Never shows the device private key,
     * activation credential, enrollment bearer token, or server private key
     * - only values GatewayConfiguration.Configured/DiagnosticsSnapshot
     * already treat as non-secret (see their own docs).
     */
    private fun buildDiagnosticsScreen(): LinearLayout {
        diagnosticsScreen = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            visibility = View.GONE
        }

        fun label(text: String) = TextView(this).apply { this.text = text }.also { diagnosticsScreen.addView(it) }

        stateView = label("State: -")
        permissionView = label("VPN permission: -")
        publicKeyView = label("Client public key: (loading...)")
        clientTunnelIpView = label("Client tunnel IP: -")
        gatewayView = label("Gateway: -")
        provisioningStatusView = label("Provisioning: -")
        profileSourceView = label("Profile source: -")
        handshakeView = label("  Handshake: -")
        rxView = label("  RX: -")
        txView = label("  TX: -")
        lastErrorView = label("  Last error: -")

        diagnosticsScreen.addView(Button(this).apply {
            text = "COPY PUBLIC KEY"
            setOnClickListener { copyPublicKey() }
        })
        diagnosticsScreen.addView(Button(this).apply {
            text = "Regenerate identity (debug only)"
            setOnClickListener { viewModel.regenerateIdentity() }
        })
        diagnosticsScreen.addView(Button(this).apply {
            text = "Show effective config"
            setOnClickListener { effectiveConfigView.text = buildEffectiveConfigDump() }
        })
        effectiveConfigView = label("Effective config: (tap button above)")

        return diagnosticsScreen
    }

    private fun showScreen(screen: AppScreen) {
        activationScreen.visibility = if (screen == AppScreen.ACTIVATION) View.VISIBLE else View.GONE
        homeScreen.visibility = if (screen == AppScreen.HOME) View.VISIBLE else View.GONE
    }

    private fun observeViewModel() {
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                launch {
                    viewModel.profileSource.collect { source -> showScreen(screenFor(source)) }
                }
                launch {
                    viewModel.transportState.collect { state ->
                        homeStatusView.text = state.toHomeStatusText()
                        primaryButton.text = if (state.isConnectedOrConnecting()) "DISCONNECT" else "CONNECT"
                        if (shouldShowDiagnostics(BuildConfig.DEBUG)) {
                            stateView.text = "State: ${state.toDisplayString()}"
                            if (state is TransportState.Error) {
                                lastErrorView.text = "  Last error: ${state.message}"
                            }
                        }
                    }
                }
                launch {
                    viewModel.provisioningState.collect { state ->
                        activationErrorView.text = state.toActivationErrorText() ?: ""
                        // B8D requirement 4: clear the credential from UI
                        // memory as soon as activation succeeds - the
                        // profileSource collector above independently
                        // transitions the screen to Home in the same tick.
                        if (shouldClearCredentialInput(state)) {
                            credentialInput.setText("")
                        }
                        if (shouldShowDiagnostics(BuildConfig.DEBUG)) {
                            provisioningStatusView.text = state.toDisplayString()
                        }
                    }
                }
                if (shouldShowDiagnostics(BuildConfig.DEBUG)) {
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
                    launch { updateGatewayDisplay() }
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

/** Diagnostics-only, more technical wording than net.pocvpn.client.ui.toHomeStatusText(). */
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
        // MainViewModel.activateDevice before this state was ever
        // published, so reaching this branch IS the "profile applied" signal.
        "Provisioned - profile applied\nTunnel IP: ${r.clientTunnelIp}\nEndpoint: ${r.endpointHost}:${r.endpointPort}\nTap CONNECT to use it"
    }
}

private fun ProfileSource.toDisplayString(): String = when (this) {
    ProfileSource.PROVISIONED_LIVE -> "provisioned-live"
    ProfileSource.RESTORED_PERSISTED -> "restored-persisted"
    ProfileSource.DEV_FALLBACK -> "dev fallback"
}
