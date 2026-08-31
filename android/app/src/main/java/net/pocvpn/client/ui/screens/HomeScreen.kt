package net.pocvpn.client.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import net.pocvpn.client.R
import net.pocvpn.client.ui.HomeConnectedSubtitle
import net.pocvpn.client.ui.HomeVisualState
import net.pocvpn.client.ui.components.LocationCard
import net.pocvpn.client.ui.components.SettingsGlyph
import net.pocvpn.client.ui.components.VpnPowerButton
import net.pocvpn.client.ui.homeConnectedSubtitle
import net.pocvpn.client.vpn.policy.AppRoutingMode

/**
 * B8E - the normal, release-facing Home screen. No technical values here -
 * see this screen's own callers (AppRoot) for how Diagnostics is kept
 * strictly debug-only and off this composable entirely when not debug.
 */
@Composable
fun HomeScreen(
    visualState: HomeVisualState,
    statusHeadline: String,
    onPowerButtonClick: () -> Unit,
    onSettingsClick: () -> Unit,
    showDiagnosticsEntry: Boolean,
    onDiagnosticsClick: () -> Unit,
    // B8G - true while the app-session kill switch is holding traffic
    // blocked (see net.pocvpn.client.ui.showsKillSwitchNotice). A small,
    // truthful extra line only - no technical clutter, no redesign.
    showKillSwitchNotice: Boolean = false,
    // B8H1 - the APPLIED routing policy's mode (VpnController
    // .appliedRoutingPolicy.mode), NEVER the merely-saved one - see
    // homeConnectedSubtitle's own docs. Only read while visualState ==
    // CONNECTED; the default is otherwise unreachable/irrelevant.
    appliedRoutingMode: AppRoutingMode = AppRoutingMode.ALL_APPS,
    // B13 - the ACTUALLY selected gateway's display text, never a static
    // placeholder (see LocationCard's own docs).
    locationCountry: String,
    locationCity: String,
    onLocationClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val statusSubtitle = when (visualState) {
        HomeVisualState.CONNECTED -> when (homeConnectedSubtitle(appliedRoutingMode)) {
            HomeConnectedSubtitle.ALL_APPS_SECURE -> stringResource(R.string.home_status_subtitle_connected)
            HomeConnectedSubtitle.BYPASS_SELECTED_APPS -> stringResource(R.string.home_status_subtitle_connected_bypass_selected)
            HomeConnectedSubtitle.VPN_ONLY_SELECTED_APPS -> stringResource(R.string.home_status_subtitle_connected_vpn_only_selected)
        }
        HomeVisualState.DISCONNECTED -> stringResource(R.string.home_status_subtitle_disconnected)
        HomeVisualState.IN_PROGRESS -> stringResource(R.string.home_status_subtitle_connecting)
        HomeVisualState.FAILED -> stringResource(R.string.home_status_subtitle_failed)
    }

    Column(modifier = modifier.fillMaxSize().padding(horizontal = 28.dp)) {
        Spacer(modifier = Modifier.height(24.dp))

        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(
                text = stringResource(R.string.app_name),
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.onBackground,
                modifier = Modifier.weight(1f),
            )
            val settingsDescription = stringResource(R.string.home_settings_content_description)
            IconButton(onClick = onSettingsClick, modifier = Modifier.semantics { contentDescription = settingsDescription }) {
                SettingsGlyph(tint = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.size(22.dp))
            }
        }

        Box(modifier = Modifier.weight(1f).fillMaxWidth(), contentAlignment = Alignment.Center) {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                val powerButtonDescription = if (visualState == HomeVisualState.CONNECTED || visualState == HomeVisualState.IN_PROGRESS) {
                    stringResource(R.string.home_power_button_content_description_disconnect)
                } else {
                    stringResource(R.string.home_power_button_content_description_connect)
                }
                VpnPowerButton(
                    state = visualState,
                    onClick = onPowerButtonClick,
                    contentDescription = powerButtonDescription,
                )
                Spacer(modifier = Modifier.height(28.dp))
                Text(
                    text = statusHeadline,
                    style = MaterialTheme.typography.headlineSmall,
                    fontWeight = FontWeight.SemiBold,
                    color = MaterialTheme.colorScheme.onBackground,
                )
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = statusSubtitle,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                if (showKillSwitchNotice) {
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = stringResource(R.string.home_kill_switch_notice),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }

        LocationCard(country = locationCountry, city = locationCity, onClick = onLocationClick)

        Spacer(modifier = Modifier.height(12.dp))

        if (showDiagnosticsEntry) {
            TextButton(onClick = onDiagnosticsClick, modifier = Modifier.fillMaxWidth()) {
                Text(
                    text = stringResource(R.string.home_diagnostics_entry),
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        } else {
            Spacer(modifier = Modifier.height(20.dp))
        }
    }
}
