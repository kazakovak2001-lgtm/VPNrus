package net.pocvpn.client.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import net.pocvpn.client.R
import net.pocvpn.client.ui.components.LocationPinGlyph
import net.pocvpn.client.vpn.config.ProductionGatewayDescriptor
import net.pocvpn.client.vpn.config.ProductionGatewayId

/**
 * Secure Orbit - the full-screen Servers tab. Same data and same actions as
 * [GatewayPickerDialog] (real catalog only: no fictional locations, latency,
 * load or favorites), laid out as cards. [selectionBlocked] mirrors
 * TransportState.blocksGatewaySelection: while a session exists the rows are
 * shown but inert, with an explanation - AppRoot and MainViewModel.selectGateway
 * enforce the same rule, this screen only reflects it.
 */
@Composable
fun ServersScreen(
    current: ProductionGatewayId,
    autoMode: Boolean,
    options: List<ProductionGatewayDescriptor>,
    provisionedGatewayIds: Set<ProductionGatewayId>,
    selectionBlocked: Boolean,
    onSelect: (ProductionGatewayId) -> Unit,
    onSelectAuto: () -> Unit,
    onActivate: (ProductionGatewayId) -> Unit,
    privateMode: Boolean,
    privateConfigured: Boolean,
    onSelectPrivate: () -> Unit,
    onConfigurePrivate: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(modifier = modifier.fillMaxSize().padding(horizontal = 20.dp)) {
        Spacer(modifier = Modifier.height(24.dp))
        Text(
            text = stringResource(R.string.servers_title),
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.SemiBold,
            color = MaterialTheme.colorScheme.onBackground,
        )
        if (selectionBlocked) {
            Spacer(modifier = Modifier.height(6.dp))
            Text(
                text = stringResource(R.string.servers_blocked_notice),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Spacer(modifier = Modifier.height(16.dp))

        Column(
            verticalArrangement = Arrangement.spacedBy(10.dp),
            modifier = Modifier.weight(1f).fillMaxWidth().verticalScroll(rememberScrollState()),
        ) {
            ServerCard(
                title = stringResource(R.string.gateway_picker_auto_title),
                subtitle = stringResource(R.string.gateway_picker_auto_subtitle),
                selected = autoMode,
                enabled = !selectionBlocked,
                onClick = onSelectAuto,
            )
            options.forEach { descriptor ->
                // While Auto is engaged no manual row is "selected" (see GatewayPickerDialog).
                val provisioned = descriptor.id in provisionedGatewayIds
                ServerCard(
                    // Geographic labels only - never provider/ASN/infrastructure names.
                    title = descriptor.displayCountry,
                    subtitle = if (provisioned) descriptor.displayCity else stringResource(R.string.gateway_picker_unavailable),
                    selected = !autoMode && !privateMode && descriptor.id == current,
                    enabled = provisioned && !selectionBlocked,
                    onClick = { onSelect(descriptor.id) },
                    trailing = if (!provisioned) {
                        {
                            TextButton(onClick = { onActivate(descriptor.id) }) {
                                Text(stringResource(R.string.gateway_picker_activate))
                            }
                        }
                    } else {
                        null
                    },
                )
            }
            ServerCard(
                title = stringResource(R.string.gateway_picker_private_title),
                subtitle = stringResource(
                    if (privateConfigured) R.string.gateway_picker_private_subtitle_configured else R.string.gateway_picker_private_subtitle_unconfigured,
                ),
                selected = privateMode,
                enabled = !selectionBlocked,
                onClick = onSelectPrivate,
                trailing = {
                    TextButton(onClick = onConfigurePrivate) {
                        Text(stringResource(R.string.gateway_picker_private_configure))
                    }
                },
            )
            Spacer(modifier = Modifier.height(8.dp))
        }
    }
}

@Composable
private fun ServerCard(
    title: String,
    subtitle: String,
    selected: Boolean,
    enabled: Boolean,
    onClick: () -> Unit,
    trailing: (@Composable () -> Unit)? = null,
) {
    val colors = MaterialTheme.colorScheme
    val shape = RoundedCornerShape(20.dp)
    Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(14.dp),
        modifier = Modifier
            .fillMaxWidth()
            .background(colors.surfaceVariant, shape)
            .border(if (selected) 2.dp else 1.dp, if (selected) colors.primary else colors.outlineVariant, shape)
            .let { if (enabled) it.clickable(onClick = onClick) else it }
            .padding(horizontal = 16.dp, vertical = 14.dp)
            .alpha(if (enabled || selected) 1f else 0.6f),
    ) {
        Box(
            contentAlignment = Alignment.Center,
            modifier = Modifier.size(40.dp).background(colors.primary.copy(alpha = 0.18f), CircleShape),
        ) {
            LocationPinGlyph(tint = colors.primary, modifier = Modifier.size(22.dp))
        }
        Column(modifier = Modifier.weight(1f)) {
            Text(text = title, style = MaterialTheme.typography.titleMedium, color = colors.onSurface)
            Text(text = subtitle, style = MaterialTheme.typography.bodyMedium, color = colors.onSurfaceVariant)
        }
        trailing?.invoke()
        RadioButton(selected = selected, onClick = if (enabled) onClick else null, enabled = enabled)
    }
}
