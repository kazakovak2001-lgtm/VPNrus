package net.pocvpn.client.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import net.pocvpn.client.R
import net.pocvpn.client.ui.components.ChevronRightGlyph
import net.pocvpn.client.vpn.policy.AppRoutingMode
import net.pocvpn.client.vpn.policy.RoutingMode

/**
 * B8H/B18 - "Settings -> Split tunneling" plus the top-level B18 routing
 * mode picker. No raw package-name text field (see this feature's own UI
 * requirements) - app selection is always via AppSelectorScreen, reached
 * through the "Select apps" row below, never typed. showReconnectNotice is
 * purely display-only - selecting a mode here ONLY saves the policy (see
 * MainViewModel.updateAppRoutingPolicy/updateRoutingMode); it never itself
 * reconnects or rebuilds the active tunnel. [routingMode] and [mode] are
 * orthogonal (see RoutingDecisionEngine's own precedence-rule docs) - the
 * split-tunneling section below always applies, independent of which
 * top-level routing mode is selected.
 */
@Composable
fun SettingsScreen(
    routingMode: RoutingMode,
    onRoutingModeSelected: (RoutingMode) -> Unit,
    mode: AppRoutingMode,
    selectedAppCount: Int,
    showReconnectNotice: Boolean,
    onModeSelected: (AppRoutingMode) -> Unit,
    onSelectAppsClick: () -> Unit,
    onBack: () -> Unit,
    // B29 (task I) - the ONE simple, human-readable sentence
    // MainViewModel.lastConnectionResultSummary() already produces - never
    // technical detail (that stays behind onExportDiagnosticsClick, task I's
    // own "detailed technical data remains behind the diagnostic action").
    lastConnectionResult: String,
    onExportDiagnosticsClick: () -> Unit,
    onClearDiagnosticsClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    // B30A - physical-validation fix: this Column has no bound on its
    // content height, so on real devices (especially at larger display/font
    // scale - see this fix's own PR docs) the Smart Connect and B29
    // Diagnostics sections below were composed but pushed entirely past the
    // bottom of the viewport, with no way to scroll to them. verticalScroll
    // is the plain idiomatic fix - no LazyColumn needed since this is a
    // short, fully-known, non-recycled list of sections.
    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 24.dp),
    ) {
        Spacer(modifier = Modifier.height(24.dp))

        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
            val backDescription = stringResource(R.string.settings_back_content_description)
            IconButton(
                onClick = onBack,
                modifier = Modifier.semantics { contentDescription = backDescription },
            ) {
                ChevronRightGlyph(
                    tint = MaterialTheme.colorScheme.onBackground,
                    modifier = Modifier.size(20.dp).graphicsLayer(rotationZ = 180f),
                )
            }
            Spacer(modifier = Modifier.width(4.dp))
            Text(
                text = stringResource(R.string.settings_title),
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.onBackground,
            )
        }

        Spacer(modifier = Modifier.height(28.dp))

        Text(
            text = stringResource(R.string.settings_routing_mode_title),
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.SemiBold,
            color = MaterialTheme.colorScheme.onBackground,
        )
        Spacer(modifier = Modifier.height(4.dp))
        Text(
            text = stringResource(R.string.settings_routing_mode_helper),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        Spacer(modifier = Modifier.height(16.dp))

        RoutingModeRow(
            label = stringResource(R.string.settings_routing_mode_full_vpn),
            helper = stringResource(R.string.settings_routing_mode_full_vpn_helper),
            selected = routingMode == RoutingMode.FULL_VPN,
            onClick = { onRoutingModeSelected(RoutingMode.FULL_VPN) },
        )
        RoutingModeRow(
            label = stringResource(R.string.settings_routing_mode_adaptive),
            helper = stringResource(R.string.settings_routing_mode_adaptive_helper),
            selected = routingMode == RoutingMode.ADAPTIVE,
            onClick = { onRoutingModeSelected(RoutingMode.ADAPTIVE) },
        )
        RoutingModeRow(
            label = stringResource(R.string.settings_routing_mode_apps),
            helper = stringResource(R.string.settings_routing_mode_apps_helper),
            selected = routingMode == RoutingMode.APPS,
            onClick = { onRoutingModeSelected(RoutingMode.APPS) },
        )

        Spacer(modifier = Modifier.height(28.dp))

        Text(
            text = stringResource(R.string.settings_split_tunneling_title),
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.SemiBold,
            color = MaterialTheme.colorScheme.onBackground,
        )
        Spacer(modifier = Modifier.height(4.dp))
        Text(
            text = stringResource(R.string.settings_split_tunneling_helper),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        Spacer(modifier = Modifier.height(16.dp))

        RoutingModeRow(
            label = stringResource(R.string.settings_mode_all_apps),
            selected = mode == AppRoutingMode.ALL_APPS,
            onClick = { onModeSelected(AppRoutingMode.ALL_APPS) },
        )
        RoutingModeRow(
            label = stringResource(R.string.settings_mode_bypass_selected),
            selected = mode == AppRoutingMode.BYPASS_SELECTED,
            onClick = { onModeSelected(AppRoutingMode.BYPASS_SELECTED) },
        )
        RoutingModeRow(
            label = stringResource(R.string.settings_mode_vpn_only_selected),
            selected = mode == AppRoutingMode.VPN_ONLY_SELECTED,
            onClick = { onModeSelected(AppRoutingMode.VPN_ONLY_SELECTED) },
        )

        if (mode != AppRoutingMode.ALL_APPS) {
            Spacer(modifier = Modifier.height(12.dp))
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .background(MaterialTheme.colorScheme.surfaceVariant, RoundedCornerShape(16.dp))
                    .clickable(onClick = onSelectAppsClick)
                    .padding(horizontal = 20.dp, vertical = 16.dp),
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = stringResource(R.string.settings_select_apps),
                        style = MaterialTheme.typography.bodyLarge,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                    Text(
                        text = stringResource(R.string.settings_select_apps_count, selectedAppCount),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                ChevronRightGlyph(tint = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.size(18.dp))
            }
        }

        if (showReconnectNotice) {
            Spacer(modifier = Modifier.height(16.dp))
            Text(
                text = stringResource(R.string.settings_reconnect_to_apply),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.error,
            )
        }

        Spacer(modifier = Modifier.height(28.dp))

        // B8I - Smart Connect only ever picks a TRANSPORT within whichever
        // gateway is already manually selected (see
        // SmartConnectCandidateSelector's own docs and the real gateway
        // picker on Home/LocationCard for gateway choice) - automatic
        // multi-gateway selection/failover does not exist yet (see
        // docs/ROADMAP.md's own "automatic gateway failover" row). This is
        // deliberately a plain informational row, never a fake toggle with
        // choices that don't actually exist yet.
        Text(
            text = stringResource(R.string.settings_smart_connect_title),
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.SemiBold,
            color = MaterialTheme.colorScheme.onBackground,
        )
        Spacer(modifier = Modifier.height(4.dp))
        Text(
            text = stringResource(R.string.settings_smart_connect_status),
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onSurface,
        )
        Spacer(modifier = Modifier.height(4.dp))
        Text(
            text = stringResource(R.string.settings_smart_connect_explanation),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        Spacer(modifier = Modifier.height(28.dp))

        // B29 (task I) - the field-diagnostics/support-bundle surface: the
        // normal screen shows only a simple, human-readable last result;
        // exporting/clearing is one explicit tap away (task J - no export
        // ever happens without this exact user action), and nothing here
        // renders a credential/endpoint/technical id.
        Text(
            text = stringResource(R.string.settings_diagnostics_title),
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.SemiBold,
            color = MaterialTheme.colorScheme.onBackground,
        )
        Spacer(modifier = Modifier.height(4.dp))
        Text(
            text = stringResource(R.string.settings_diagnostics_explanation),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(modifier = Modifier.height(12.dp))
        Text(
            text = stringResource(R.string.settings_diagnostics_last_result_label),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(
            text = lastConnectionResult,
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onSurface,
        )
        Spacer(modifier = Modifier.height(12.dp))
        androidx.compose.material3.TextButton(onClick = onExportDiagnosticsClick, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.settings_diagnostics_export))
        }
        androidx.compose.material3.TextButton(onClick = onClearDiagnosticsClick, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.settings_diagnostics_clear))
        }
        Spacer(modifier = Modifier.height(24.dp))
    }
}

@Composable
private fun RoutingModeRow(label: String, selected: Boolean, onClick: () -> Unit, helper: String? = null) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(vertical = 10.dp),
    ) {
        RadioButton(selected = selected, onClick = onClick)
        Spacer(modifier = Modifier.width(4.dp))
        Column {
            Text(text = label, style = MaterialTheme.typography.bodyLarge, color = MaterialTheme.colorScheme.onBackground)
            if (helper != null) {
                Text(text = helper, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}
