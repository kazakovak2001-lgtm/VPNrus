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
import net.pocvpn.client.apps.PackageManagerInstalledAppRepository
import net.pocvpn.client.diagnostics.DiagnosticsSnapshot
import net.pocvpn.client.network.NetworkProfile
import net.pocvpn.client.provisioning.ProvisioningUiState
import net.pocvpn.client.smartconnect.ConnectionOutcome
import net.pocvpn.client.smartconnect.ConnectionOutcomeResult
import net.pocvpn.client.smartconnect.SmartConnectDecision
import net.pocvpn.client.ui.screens.ActivationScreen
import net.pocvpn.client.ui.screens.AppSelectorScreen
import net.pocvpn.client.ui.screens.DiagnosticsDialog
import net.pocvpn.client.ui.screens.HomeScreen
import net.pocvpn.client.ui.screens.SettingsScreen
import net.pocvpn.client.vpn.AlwaysOnDetectionState
import net.pocvpn.client.vpn.AlwaysOnVpnState
import net.pocvpn.client.vpn.ControllerEvent
import net.pocvpn.client.vpn.TransportState
import net.pocvpn.client.vpn.config.GatewayConfiguration
import net.pocvpn.client.vpn.config.Ipv6LeakPolicy
import net.pocvpn.client.vpn.config.ProfileSource
import net.pocvpn.client.vpn.config.VpnIpv6Policy
import net.pocvpn.client.vpn.policy.AppRoutingMode
import net.pocvpn.client.vpn.policy.AppRoutingPolicy

/**
 * B8H - lightweight in-file navigation for Settings/AppSelector, sitting
 * "on top of" AppScreen.HOME (see the `when` inside AppRoot below) - no
 * navigation-compose dependency added for two screens, consistent with
 * DiagnosticsDialog's existing plain-boolean-toggle approach.
 */
private enum class SettingsRoute { Settings, AppSelector }

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
    val alwaysOnState by AlwaysOnVpnState.state.collectAsStateWithLifecycle()
    val savedRoutingPolicy by viewModel.savedAppRoutingPolicy.collectAsStateWithLifecycle()
    val appliedRoutingPolicy by viewModel.appliedAppRoutingPolicy.collectAsStateWithLifecycle()
    val networkProfile by viewModel.networkProfile.collectAsStateWithLifecycle()

    var credential by remember { mutableStateOf("") }
    var showDiagnostics by remember { mutableStateOf(false) }
    var settingsRoute by remember { mutableStateOf<SettingsRoute?>(null) }
    val context = LocalContext.current
    val installedApps = remember { PackageManagerInstalledAppRepository(context).listLaunchableApps() }

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
            when {
                screenFor(profileSource) == AppScreen.ACTIVATION -> ActivationScreen(
                    credential = credential,
                    onCredentialChange = { credential = it },
                    onActivateClick = { viewModel.activateDevice(credential) },
                    errorText = provisioningState.toActivationErrorText(),
                    isSubmitting = provisioningState is ProvisioningUiState.Provisioning,
                )
                // B8H - "Select apps" screen, reached only from Settings.
                settingsRoute == SettingsRoute.AppSelector -> AppSelectorScreen(
                    apps = installedApps,
                    selectedPackageNames = savedRoutingPolicy.selectedPackageNames,
                    onToggle = { packageName, checked ->
                        val updated = if (checked) {
                            savedRoutingPolicy.selectedPackageNames + packageName
                        } else {
                            savedRoutingPolicy.selectedPackageNames - packageName
                        }
                        viewModel.updateAppRoutingPolicy(savedRoutingPolicy.copy(selectedPackageNames = updated))
                    },
                    onBack = { settingsRoute = SettingsRoute.Settings },
                )
                // B8H - "Settings -> Split tunneling". Saving here NEVER
                // touches the transport/tunnel (see MainViewModel
                // .updateAppRoutingPolicy's own docs) - showReconnectNotice
                // is purely informational.
                settingsRoute == SettingsRoute.Settings -> SettingsScreen(
                    mode = savedRoutingPolicy.mode,
                    selectedAppCount = savedRoutingPolicy.selectedPackageNames.size,
                    showReconnectNotice = hasPendingRoutingPolicyChange(appliedRoutingPolicy, savedRoutingPolicy),
                    onModeSelected = { mode -> viewModel.updateAppRoutingPolicy(savedRoutingPolicy.copy(mode = mode)) },
                    onSelectAppsClick = { settingsRoute = SettingsRoute.AppSelector },
                    onBack = { settingsRoute = null },
                )
                else -> HomeScreen(
                    visualState = transportState.toHomeVisualState(),
                    statusHeadline = transportState.toHomeStatusText(),
                    onPowerButtonClick = {
                        if (transportState.isConnectedOrConnecting()) viewModel.disconnect() else viewModel.connect()
                    },
                    onSettingsClick = { settingsRoute = SettingsRoute.Settings },
                    showDiagnosticsEntry = isDebugBuild,
                    onDiagnosticsClick = { showDiagnostics = true },
                    showKillSwitchNotice = transportState.showsKillSwitchNotice(),
                    // B8H1 - the APPLIED policy's mode, never savedRoutingPolicy's -
                    // see homeConnectedSubtitle's own docs for why.
                    appliedRoutingMode = appliedRoutingPolicy?.mode ?: AppRoutingMode.ALL_APPS,
                )
            }
        }
    }

    if (isDebugBuild && showDiagnostics) {
        val clipboard = LocalClipboardManager.current
        DiagnosticsDialog(
            lines = buildDiagnosticsLines(
                viewModel, publicKey, diagnosticsSnapshot, provisioningState, profileSource,
                transportState, alwaysOnState, savedRoutingPolicy, appliedRoutingPolicy, networkProfile,
            ),
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
    transportState: TransportState,
    alwaysOnState: AlwaysOnDetectionState,
    savedRoutingPolicy: AppRoutingPolicy,
    appliedRoutingPolicy: AppRoutingPolicy?,
    networkProfile: NetworkProfile,
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
    // B8G - see ProductFlowPresentation.isSessionActive/AlwaysOnVpnState's
    // own docs. Android lockdown NEVER reports a fabricated "NOT ENABLED" -
    // only a confirmed-positive signal, or UNKNOWN.
    val killSwitchAppSessionLine = "Kill switch - App session: ${if (transportState.isSessionActive()) "ACTIVE" else "INACTIVE"}"
    val killSwitchLockdownLine = "Kill switch - Android lockdown: ${when (alwaysOnState) {
        AlwaysOnDetectionState.CONFIRMED_ENABLED -> "ENABLED (auto-detected)"
        AlwaysOnDetectionState.UNKNOWN -> "UNKNOWN"
    }}"

    // B8H - saved (MainViewModel.savedAppRoutingPolicy) vs applied
    // (VpnController.appliedRoutingPolicy, via the SAME
    // hasPendingRoutingPolicyChange the Settings screen itself uses - never
    // a second/different comparison here) - see those classes' own docs.
    val routingModeLine = "Routing mode: ${savedRoutingPolicy.mode}"
    val selectedAppsCountLine = "Selected apps count: ${savedRoutingPolicy.selectedPackageNames.size}"
    val appliedRoutingLine = "Applied routing policy: ${appliedRoutingPolicy?.let { "${it.mode} (${it.selectedPackageNames.size} apps)" } ?: "NONE (no active session)"}"
    val savedRoutingLine = "Saved routing policy: ${savedRoutingPolicy.mode} (${savedRoutingPolicy.selectedPackageNames.size} apps)"
    val pendingReconnectLine = "Pending reconnect: ${if (hasPendingRoutingPolicyChange(appliedRoutingPolicy, savedRoutingPolicy)) "YES" else "NO"}"

    // B8I - CURRENT network facts (NetworkProfiler, real ConnectivityManager
    // callbacks - see that class's own docs), never inferred/estimated.
    val networkTypeLine = "Network type: ${networkProfile.type}"
    val validatedLine = "Validated: ${networkProfile.validatedInternet}"
    val meteredLine = "Metered: ${networkProfile.metered}"
    val ipv4AvailableLine = "IPv4 available: ${networkProfile.ipv4Available}"
    val ipv6AvailableLine = "IPv6 available: ${networkProfile.ipv6Available}"

    val smartConnectDecision = viewModel.smartConnectDecision()
    val currentTransportLine = "Current transport: ${when (smartConnectDecision) {
        is SmartConnectDecision.Selected -> smartConnectDecision.score.candidate.transport.kind
        SmartConnectDecision.NoCandidateAvailable -> "NONE"
    }}"
    val smartConnectGatewayLine = "Gateway: ${when (smartConnectDecision) {
        is SmartConnectDecision.Selected -> smartConnectDecision.score.candidate.gateway.region
        SmartConnectDecision.NoCandidateAvailable -> "NONE"
    }}"
    val smartConnectReasonLine = "Smart Connect decision reason: ${when (smartConnectDecision) {
        is SmartConnectDecision.Selected -> smartConnectDecision.score.reason
        SmartConnectDecision.NoCandidateAvailable -> "NO_CANDIDATE_AVAILABLE"
    }}"

    // B8I - HISTORICAL outcomes (see ConnectionOutcomeStore's own docs);
    // only ever the LAST recorded one is surfaced here - no raw endpoint/IP,
    // just the technical result/duration/category ConnectionOutcome models.
    val lastOutcome = viewModel.recentConnectionOutcomes().lastOrNull()
    val lastHandshakeDurationLine = "Last handshake duration: ${lastOutcome?.handshakeDurationMs?.let { "${it}ms" } ?: "-"}"
    val lastOutcomeLine = "Last connection outcome: ${lastOutcome?.let {
        if (it.result == ConnectionOutcomeResult.SUCCESS) "SUCCESS" else "FAILURE (${it.errorCategory})"
    } ?: "-"}"

    // B8J - the ONLY place a RestrictionClass is computed (see
    // RestrictionClassifier's own docs) - never a second interpretation here.
    val restrictionClassLine = "Restriction class: ${viewModel.restrictionClass()}"

    return listOf(
        "State: ${transportDisplayText(diagnostics.transportState)}",
        "VPN permission: ${if (diagnostics.permissionGranted) "GRANTED" else "REQUIRED"}",
        "Client public key: ${publicKey ?: "(loading...)"}",
        tunnelIpLine,
        gatewayLine,
        allowedIpsLine,
        dnsLine,
        ipv6PolicyLine,
        killSwitchAppSessionLine,
        killSwitchLockdownLine,
        routingModeLine,
        selectedAppsCountLine,
        appliedRoutingLine,
        savedRoutingLine,
        pendingReconnectLine,
        networkTypeLine,
        validatedLine,
        meteredLine,
        ipv4AvailableLine,
        ipv6AvailableLine,
        currentTransportLine,
        smartConnectGatewayLine,
        lastHandshakeDurationLine,
        lastOutcomeLine,
        smartConnectReasonLine,
        restrictionClassLine,
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
