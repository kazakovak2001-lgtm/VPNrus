package net.pocvpn.client.ui.screens

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import net.pocvpn.client.R
import net.pocvpn.client.vpn.config.ProductionGatewayDescriptor
import net.pocvpn.client.vpn.config.ProductionGatewayId

/**
 * B13 - the real gateway picker: lists EVERY [ProductionGatewayDescriptor]
 * in [options] (today Germany and Stockholm) - the catalog stays fully
 * visible regardless of readiness - radio-selected against [current], and
 * calls [onSelect] with a DETERMINISTIC choice - the tapped row's own id,
 * never inferred/derived. Selection alone does not reconnect/touch the
 * tunnel (see MainViewModel.selectGateway's own docs) - this dialog is
 * purely the input surface.
 *
 * B13 review fix - [provisionedGatewayIds] is THIS DEVICE'S actual
 * readiness (MainViewModel.provisionedGatewayIds, itself sourced from
 * ClientTunnelIdentityStore - see that class's own docs for why this is
 * per-device, not a gateway/catalog fact). A gateway NOT in that set has no
 * client tunnel identity on this device and is rendered disabled - its row
 * is not clickable, its RadioButton is disabled, and its city label is
 * replaced with an explicit "unavailable" string - neither the row's
 * `clickable` modifier nor the RadioButton's `onClick` invoke [onSelect]
 * for it. A provisioned gateway is completely unaffected - normal tap
 * target, normal label, normal onSelect.
 *
 * B15 - before this, an unprovisioned gateway's row was a dead end: the ONLY
 * way to reach ActivationScreen was net.pocvpn.client.ui.screenFor, which
 * only ever fires when NO gateway has ever been provisioned at all - so once
 * a device had activated its first gateway, there was no UI path left to
 * activate an ADDITIONAL one (see docs/ROADMAP.md's B15 update). [onActivate]
 * closes that gap: an unprovisioned row now also shows a small "Activate"
 * action that requests activation for THAT gateway id specifically, leaving
 * the row's own clickable/RadioButton [onSelect] wiring (connection
 * selection) untouched.
 */
@Composable
fun GatewayPickerDialog(
    current: ProductionGatewayId,
    options: List<ProductionGatewayDescriptor>,
    provisionedGatewayIds: Set<ProductionGatewayId>,
    onSelect: (ProductionGatewayId) -> Unit,
    onActivate: (ProductionGatewayId) -> Unit,
    onDismiss: () -> Unit,
) {
    Dialog(onDismissRequest = onDismiss) {
        Surface(
            shape = MaterialTheme.shapes.extraLarge,
            color = MaterialTheme.colorScheme.surface,
        ) {
            Column(modifier = Modifier.padding(24.dp)) {
                Text(
                    text = stringResource(R.string.gateway_picker_title),
                    style = MaterialTheme.typography.titleLarge,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                Spacer(modifier = Modifier.height(16.dp))

                options.forEach { descriptor ->
                    val selected = descriptor.id == current
                    val provisioned = descriptor.id in provisionedGatewayIds
                    val rowModifier = Modifier
                        .fillMaxWidth()
                        .let { base -> if (provisioned) base.clickable { onSelect(descriptor.id) } else base }
                        .padding(vertical = 8.dp)
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(12.dp),
                        modifier = rowModifier,
                    ) {
                        RadioButton(
                            selected = selected,
                            enabled = provisioned,
                            onClick = { if (provisioned) onSelect(descriptor.id) },
                        )
                        Column {
                            // B13 - geographic labels only in normal
                            // user-facing UI: NO provider/ASN/infrastructure
                            // names here (descriptor.provider deliberately
                            // unused) - see ProductionGatewayCatalog's own
                            // docs for where that metadata still lives
                            // (internal fields, diagnostics-only surfaces).
                            Text(
                                text = descriptor.displayCountry,
                                style = MaterialTheme.typography.bodyLarge,
                                color = if (provisioned) MaterialTheme.colorScheme.onSurface else MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                            Text(
                                text = if (provisioned) descriptor.displayCity else stringResource(R.string.gateway_picker_unavailable),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                        if (!provisioned) {
                            TextButton(onClick = { onActivate(descriptor.id) }) {
                                Text(stringResource(R.string.gateway_picker_activate))
                            }
                        }
                    }
                }

                Spacer(modifier = Modifier.height(8.dp))
                TextButton(onClick = onDismiss, modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(R.string.gateway_picker_close))
                }
            }
        }
    }
}
