package net.pocvpn.client.ui

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import net.pocvpn.client.MainViewModel
import net.pocvpn.client.diagnostics.DiagnosticsSnapshot
import net.pocvpn.client.provisioning.ProvisioningUiState
import net.pocvpn.client.ui.screens.ActivationScreen
import net.pocvpn.client.ui.screens.DiagnosticsDialog
import net.pocvpn.client.ui.screens.HomeScreen
import net.pocvpn.client.vpn.ControllerEvent
import net.pocvpn.client.vpn.TransportState
import net.pocvpn.client.vpn.config.GatewayConfiguration
import net.pocvpn.client.vpn.config.Ipv6LeakPolicy
import net.pocvpn.client.vpn.config.ProfileSource
import net.pocvpn.client.vpn.config.VpnIpv6Policy

/**
 * B8E - single Compose entry point for MainActivity. Owns no VPN/profile
 * state itself - every value comes from MainViewModel's existing StateFlows
 * (see B8D's "STATE SOURCE" requirement, still honored here); this file
 * only decides WHICH screen to render and formats plain display strings.
 */
@Composable
fun AppRoot(
    viewModel: MainViewModel,
    isDebugBuild: Boolean,
    onRequestVpnPermission: (android.content.Intent) -> Unit,
) {
    val profileSource by viewModel.profileSource.collectAsStateWithLifecycle()
    val transportState by viewModel.transportState.collectAsStateWithLifecycle()
    val provisioningState by viewModel.provisioningState.collectAsStateWithLifecycle()
    val publicKey by viewModel.publicKey.collectAsStateWithLifecycle()
    val diagnosticsSnapshot by viewModel.diagnostics.collectAsStateWithLifecycle()

    var credential by remember { mutableStateOf("") }
    var showDiagnostics by remember { mutableStateOf(false) }

    LaunchedEffect(provisioningState) {
        if (shouldClearCredentialInput(provisioningState)) credential = ""
    }
    LaunchedEffect(viewModel) {
        viewModel.events.collect { event ->
            when (event) {
                is ControllerEvent.RequestVpnPermission -> onRequestVpnPermission(event.intent)
            }
        }
    }

    Surface(modifier = Modifier.fillMaxSize()) {
        Box(modifier = Modifier.fillMaxSize()) {
            when (screenFor(profileSource)) {
                AppScreen.ACTIVATION -> ActivationScreen(
                    credential = credential,
                    onCredentialChange = { credential = it },
                    onActivateClick = { viewModel.activateDevice(credential) },
                    errorText = provisioningState.toActivationErrorText(),
                    isSubmitting = provisioningState is ProvisioningUiState.Provisioning,
                )
                AppScreen.HOME -> HomeScreen(
                    visualState = transportState.toHomeVisualState(),
                    statusHeadline = transportState.toHomeStatusText(),
                    onPowerButtonClick = {
                        if (transportState.isConnectedOrConnecting()) viewModel.disconnect() else viewModel.connect()
                    },
                    showDiagnosticsEntry = isDebugBuild,
                    onDiagnosticsClick = { showDiagnostics = true },
                )
            }
        }
    }

    if (isDebugBuild && showDiagnostics) {
        val clipboard = LocalClipboardManager.current
        val context = LocalContext.current
        DiagnosticsDialog(
            lines = buildDiagnosticsLines(viewModel, publicKey, diagnosticsSnapshot, provisioningState, profileSource),
            onCopyPublicKey = {
                publicKey?.let {
                    clipboard.setText(AnnotatedString(it))
                    android.widget.Toast.makeText(context, "Public key copied", android.widget.Toast.LENGTH_SHORT).show()
                }
            },
            onRegenerateIdentity = { viewModel.regenerateIdentity() },
            onDismiss = { showDiagnostics = false },
        )
    }
}

private fun buildDiagnosticsLines(
    viewModel: MainViewModel,
    publicKey: String?,
    diagnostics: DiagnosticsSnapshot,
    provisioningState: ProvisioningUiState,
    profileSource: ProfileSource,
): List<String> {
    val gateway = viewModel.gatewayStatus()
    val gatewayLine = when (gateway) {
        is GatewayConfiguration.Missing -> "Gateway: NOT CONFIGURED"
        is GatewayConfiguration.Invalid -> "Gateway: INVALID (${gateway.reason})"
        is GatewayConfiguration.Configured -> "Gateway: ${gateway.endpointHost}:${gateway.endpointPort}"
    }
    val tunnelIpLine = when (gateway) {
        is GatewayConfiguration.Configured -> "Client tunnel IP: ${gateway.clientTunnelIp}"
        else -> "Client tunnel IP: NOT CONFIGURED"
    }
    // B8F - the ACTUAL effective values (read off gatewayStatus(), the same
    // GatewayConfiguration VpnController.buildTransportConfig uses), not
    // just the VpnDnsPolicy/VpnIpv6Policy constants restated - this proves
    // what is really wired for THIS session, not merely what the policy says.
    val dnsLine = when (gateway) {
        is GatewayConfiguration.Configured -> "DNS servers: ${gateway.dnsServers.ifEmpty { listOf("NONE") }.joinToString()}"
        else -> "DNS servers: NOT CONFIGURED"
    }
    val allowedIpsLine = when (gateway) {
        is GatewayConfiguration.Configured -> "AllowedIPs: ${gateway.allowedIps.joinToString()}"
        else -> "AllowedIPs: NOT CONFIGURED"
    }
    val ipv6PolicyLine = "IPv6 policy: ${ipv6PolicyDisplayText(VpnIpv6Policy.current)}"

    return listOf(
        "State: ${transportDisplayText(diagnostics.transportState)}",
        "VPN permission: ${if (diagnostics.permissionGranted) "GRANTED" else "REQUIRED"}",
        "Client public key: ${publicKey ?: "(loading...)"}",
        tunnelIpLine,
        gatewayLine,
        allowedIpsLine,
        dnsLine,
        ipv6PolicyLine,
        "Provisioning: ${provisioningDisplayText(provisioningState)}",
        "Profile source: ${profileSourceDisplayText(profileSource)}",
        "Handshake: ${diagnostics.lastHandshakeEpochMillis?.let { "${System.currentTimeMillis() - it}ms ago" } ?: "-"}",
        "RX: ${diagnostics.bytesReceived ?: "-"}",
        "TX: ${diagnostics.bytesSent ?: "-"}",
        "Last error: ${diagnostics.lastError?.displayText() ?: "-"}",
    )
}

private fun ipv6PolicyDisplayText(policy: Ipv6LeakPolicy): String = when (policy) {
    Ipv6LeakPolicy.TUNNELED -> "tunneled"
    Ipv6LeakPolicy.FAIL_CLOSED -> "blocked/fail-closed"
}

/** Diagnostics-only, more technical wording than toHomeStatusText() - unchanged from the original View-based Diagnostics section. */
private fun transportDisplayText(state: TransportState): String = when (state) {
    is TransportState.Disconnected -> "Disconnected"
    is TransportState.Connecting -> "Connecting…"
    is TransportState.Connected -> "Connected"
    is TransportState.Disconnecting -> "Disconnecting…"
    is TransportState.Reconnecting -> "Reconnecting (attempt ${state.attempt})…"
    is TransportState.Error -> "Connection failed: ${state.message}"
    is TransportState.HandshakeFailed -> "Connection failed: no VPN handshake"
}

private fun provisioningDisplayText(state: ProvisioningUiState): String = when (state) {
    is ProvisioningUiState.Idle -> "-"
    is ProvisioningUiState.Provisioning -> "in progress..."
    is ProvisioningUiState.Unauthorized -> "INVALID ACTIVATION"
    is ProvisioningUiState.Revoked -> "ACTIVATION REVOKED"
    is ProvisioningUiState.Expired -> "ACTIVATION EXPIRED"
    is ProvisioningUiState.DeviceLimitReached -> "DEVICE LIMIT REACHED"
    is ProvisioningUiState.Error -> "ERROR - ${state.message}"
    is ProvisioningUiState.Success -> {
        val r = state.result
        "profile applied - tunnel IP ${r.clientTunnelIp}, endpoint ${r.endpointHost}:${r.endpointPort}"
    }
}

private fun profileSourceDisplayText(source: ProfileSource): String = when (source) {
    ProfileSource.PROVISIONED_LIVE -> "provisioned-live"
    ProfileSource.RESTORED_PERSISTED -> "restored-persisted"
    ProfileSource.DEV_FALLBACK -> "dev fallback"
}
