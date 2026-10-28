package net.pocvpn.client.ui.components

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.size
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LocalContentColor
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import net.pocvpn.client.R
import net.pocvpn.client.ui.NavDestination

/**
 * Secure Orbit - the bottom navigation: [content] fills the space above a
 * [NavigationBar] listing [destinations]. Pure presentation: [onSelect] is
 * wired by AppRoot to the EXISTING actions (Home route, gateway picker,
 * debug diagnostics dialog, Settings route); this bar owns no navigation
 * state of its own. [selected] only highlights the screen currently shown.
 */
@Composable
fun WithBottomNav(
    selected: NavDestination,
    destinations: List<NavDestination>,
    onSelect: (NavDestination) -> Unit,
    modifier: Modifier = Modifier,
    content: @Composable () -> Unit,
) {
    Column(modifier = modifier.fillMaxSize()) {
        Box(modifier = Modifier.weight(1f).fillMaxWidth()) { content() }
        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
        NavigationBar(
            containerColor = MaterialTheme.colorScheme.surface,
            tonalElevation = 0.dp,
        ) {
            destinations.forEach { destination ->
                val label = stringResource(destination.labelRes())
                NavigationBarItem(
                    selected = destination == selected,
                    onClick = { onSelect(destination) },
                    icon = { NavGlyph(destination, modifier = Modifier.size(24.dp)) },
                    label = { Text(label, maxLines = 1) },
                    colors = NavigationBarItemDefaults.colors(
                        selectedIconColor = MaterialTheme.colorScheme.primary,
                        selectedTextColor = MaterialTheme.colorScheme.primary,
                        unselectedIconColor = MaterialTheme.colorScheme.onSurfaceVariant,
                        unselectedTextColor = MaterialTheme.colorScheme.onSurfaceVariant,
                        indicatorColor = MaterialTheme.colorScheme.primary.copy(alpha = 0.16f),
                    ),
                )
            }
        }
    }
}

@Composable
private fun NavGlyph(destination: NavDestination, modifier: Modifier) {
    val tint = LocalContentColor.current
    when (destination) {
        NavDestination.VPN -> ShieldGlyph(tint, modifier)
        NavDestination.SERVERS -> ServersGlyph(tint, modifier)
        NavDestination.DIAGNOSTICS -> PulseGlyph(tint, modifier)
        NavDestination.SETTINGS -> SettingsGlyph(tint, modifier)
    }
}

private fun NavDestination.labelRes(): Int = when (this) {
    NavDestination.VPN -> R.string.nav_vpn
    NavDestination.SERVERS -> R.string.nav_servers
    NavDestination.DIAGNOSTICS -> R.string.nav_diagnostics
    NavDestination.SETTINGS -> R.string.nav_settings
}
