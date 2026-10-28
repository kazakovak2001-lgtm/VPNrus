package net.pocvpn.client.debug.homepreview

import android.os.Bundle
import android.os.SystemClock
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import net.pocvpn.client.ui.NavDestination
import net.pocvpn.client.ui.SessionTraffic
import net.pocvpn.client.ui.bottomNavDestinations
import net.pocvpn.client.ui.components.WithBottomNav
import net.pocvpn.client.ui.screens.HomeScreen
import net.pocvpn.client.ui.screens.DiagnosticsDialog
import net.pocvpn.client.ui.screens.ServersScreen
import net.pocvpn.client.ui.screens.SettingsScreen
import net.pocvpn.client.vpn.policy.AppRoutingMode
import net.pocvpn.client.vpn.policy.RoutingMode
import net.pocvpn.client.vpn.config.ProductionGatewayCatalog
import net.pocvpn.client.ui.theme.NovaVpnTheme
import net.pocvpn.client.ui.toHomeStatusText
import net.pocvpn.client.ui.toHomeVisualState
import net.pocvpn.client.vpn.VpnSessionHealth
import net.pocvpn.client.vpn.traffic.TrafficRate

/**
 * DEBUG-ONLY, TEMPORARY visual preview of the Secure Orbit Home screen with
 * FICTIONAL data, so the layout can be inspected without an activation
 * credential. Lives in the `debug` source set and is declared only in
 * src/debug/AndroidManifest.xml - absent from release builds.
 *
 * Touches NO ViewModel, VpnController, network, storage or credential. The
 * status text/visual state come from the production mappings applied to real
 * [VpnSessionHealth] values; every number below is made up and the screen
 * says so. Light/dark follows the system setting.
 */
class HomePreviewActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            NovaVpnTheme {
                var scenario by remember { mutableStateOf(Scenario.PROTECTED) }
                var killSwitch by remember { mutableStateOf(false) }
                var otherProfiles by remember { mutableStateOf(false) }
                var serversScreen by remember { mutableStateOf(false) }
                var blocked by remember { mutableStateOf(false) }
                var settingsScreen by remember { mutableStateOf(false) }
                var diagnosticsDialog by remember { mutableStateOf(false) }
                // Fixed once per selection so the displayed timer actually ticks.
                val startedAt = remember(scenario) { SystemClock.elapsedRealtime() - (24 * 60 + 18) * 1_000L }
                val health = scenario.health
                val protectedWithStats = scenario == Scenario.PROTECTED
                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .background(MaterialTheme.colorScheme.background)
                        .statusBarsPadding(),
                ) {
                    Text(
                        text = "DEBUG PREVIEW - fictional data, not a real connection",
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.error,
                        modifier = Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 6.dp),
                    )
                    Row(modifier = Modifier.horizontalScroll(rememberScrollState()).padding(horizontal = 12.dp)) {
                        Scenario.values().forEach { s ->
                            FilterChip(
                                selected = s == scenario,
                                onClick = { scenario = s },
                                label = { Text(s.label) },
                                modifier = Modifier.padding(horizontal = 4.dp),
                            )
                        }
                    }
                    Row(modifier = Modifier.horizontalScroll(rememberScrollState()).padding(horizontal = 12.dp)) {
                        FilterChip(
                            selected = settingsScreen,
                            onClick = { settingsScreen = !settingsScreen },
                            label = { Text("Settings screen") },
                            modifier = Modifier.padding(horizontal = 4.dp),
                        )
                        FilterChip(
                            selected = diagnosticsDialog,
                            onClick = { diagnosticsDialog = !diagnosticsDialog },
                            label = { Text("Diagnostics dialog") },
                            modifier = Modifier.padding(horizontal = 4.dp),
                        )
                        FilterChip(
                            selected = serversScreen,
                            onClick = { serversScreen = !serversScreen },
                            label = { Text("Servers screen") },
                            modifier = Modifier.padding(horizontal = 4.dp),
                        )
                        FilterChip(
                            selected = blocked,
                            onClick = { blocked = !blocked },
                            label = { Text("Selection blocked") },
                            modifier = Modifier.padding(horizontal = 4.dp),
                        )
                        FilterChip(
                            selected = killSwitch,
                            onClick = { killSwitch = !killSwitch },
                            label = { Text("Kill-switch notice") },
                            modifier = Modifier.padding(horizontal = 4.dp),
                        )
                        FilterChip(
                            selected = otherProfiles,
                            onClick = { otherProfiles = !otherProfiles },
                            label = { Text("Other-profile notice") },
                            modifier = Modifier.padding(horizontal = 4.dp),
                        )
                    }
                    if (diagnosticsDialog) {
                        DiagnosticsDialog(
                            lines = listOf("Preview line 1", "Preview line 2"),
                            onCopyPublicKey = {},
                            onRegenerateIdentity = {},
                            transportForce = null,
                            onSetTransportForce = {},
                            onSimulateAwgFailure = {},
                            onSimulateAwgSuccess = {},
                            onReactivateGermany = {},
                            onReactivateStockholm = {},
                            onRefreshManifest = {},
                            onSaveDiagnosticsLocally = {},
                            saveLocallyStatus = null,
                            onOpenFieldTest = {},
                            onDismiss = { diagnosticsDialog = false },
                        )
                    }
                    if (settingsScreen) WithBottomNav(
                        selected = NavDestination.SETTINGS,
                        destinations = bottomNavDestinations(isDebugBuild = true),
                        onSelect = {},
                    ) {
                        SettingsScreen(
                            routingMode = RoutingMode.FULL_VPN,
                            onRoutingModeSelected = {},
                            mode = AppRoutingMode.ALL_APPS,
                            selectedAppCount = 0,
                            showReconnectNotice = false,
                            onModeSelected = {},
                            onSelectAppsClick = {},
                            onBack = {},
                            lastConnectionResult = "Preview result",
                            onExportDiagnosticsClick = {},
                            onClearDiagnosticsClick = {},
                            onAdvancedDiagnosticsClick = { diagnosticsDialog = true },
                        )
                    } else if (serversScreen) WithBottomNav(
                        selected = NavDestination.SERVERS,
                        destinations = bottomNavDestinations(isDebugBuild = true),
                        onSelect = {},
                    ) {
                        val all = ProductionGatewayCatalog.all
                        ServersScreen(
                            current = all.first().id,
                            autoMode = false,
                            options = all,
                            // Last gateway shown as not activated, to preview the Activate action.
                            provisionedGatewayIds = all.dropLast(1).map { it.id }.toSet(),
                            selectionBlocked = blocked,
                            onSelect = {},
                            onSelectAuto = {},
                            onActivate = {},
                            privateMode = false,
                            privateConfigured = false,
                            onSelectPrivate = {},
                            onConfigurePrivate = {},
                        )
                    } else WithBottomNav(
                        selected = NavDestination.VPN,
                        destinations = bottomNavDestinations(isDebugBuild = true),
                        onSelect = {},
                    ) { HomeScreen(
                        visualState = health.toHomeVisualState(),
                        statusHeadline = health.toHomeStatusText(),
                        onPowerButtonClick = {},
                        onSettingsClick = {},
                        showDiagnosticsEntry = false,
                        onDiagnosticsClick = {},
                        showKillSwitchNotice = killSwitch,
                        showOtherProfileNotice = otherProfiles,
                        locationCountry = "Preview country",
                        locationCity = "Preview city",
                        onLocationClick = {},
                        protocolLabel = if (health is VpnSessionHealth.Idle) null else "Preview protocol",
                        sessionStartedAtMillis = if (protectedWithStats || scenario == Scenario.PROTECTED_NO_STATS) startedAt else null,
                        sessionTraffic = if (protectedWithStats) {
                            SessionTraffic(
                                bytesReceived = 134_623_846L,
                                bytesSent = 19_608_371L,
                                rate = TrafficRate.Rate(2_202_009L, 314_573L),
                            )
                        } else {
                            null
                        },
                    ) }
                }
            }
        }
    }

    private enum class Scenario(val label: String, val health: VpnSessionHealth) {
        DISCONNECTED("Disconnected", VpnSessionHealth.Idle),
        CONNECTING("Connecting", VpnSessionHealth.InProgress),
        VERIFYING("Verifying", VpnSessionHealth.DataPlaneVerifying),
        RECONNECTING("Reconnecting", VpnSessionHealth.Reconnecting),
        PROTECTED("Protected", VpnSessionHealth.DirectProtected),
        PROTECTED_NO_STATS("Protected, no stats", VpnSessionHealth.DirectProtected),
        FAILED("Failed", VpnSessionHealth.Failed("preview")),
    }
}
