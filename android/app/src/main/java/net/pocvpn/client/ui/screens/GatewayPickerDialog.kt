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
 *
 * B16 - a leading "Auto" row lets the user hand gateway choice to Smart
 * Connect (task requirement 9's minimal UI: "Auto / Smart Connect, Germany,
 * Stockholm"). Selected when [autoMode] is true - in that state none of the
 * manual [ProductionGatewayId] rows show as selected, even if [current]
 * still names one (it remains the manual fallback/last pick, never
 * fabricated). Tapping a manual row still calls [onSelect] exactly as
 * before AND is what turns Auto back off (see MainViewModel.selectGateway's
 * own docs) - this dialog itself has no separate "turn auto off" concept.
 */
@Composable
fun GatewayPickerDialog(
    current: ProductionGatewayId,
    autoMode: Boolean,
    options: List<ProductionGatewayDescriptor>,
    provisionedGatewayIds: Set<ProductionGatewayId>,
    onSelect: (ProductionGatewayId) -> Unit,
    onSelectAuto: () -> Unit,
    onActivate: (ProductionGatewayId) -> Unit,
    onDismiss: () -> Unit,
    // B22 - additive, all defaulted so this dialog's one existing call site
    // compiles/behaves unchanged unless AppRoot explicitly wires them (which
    // it does - see that file's own docs). [privateMode] mirrors [autoMode]'s
    // own shape: true only when GatewaySelectionMode.PRIVATE is the current
    // selection - see that enum's own docs for why this is a THIRD,
    // disjoint state, never overloading [current]/[autoMode].
    privateMode: Boolean = false,
    privateConfigured: Boolean = false,
    onSelectPrivate: () -> Unit = {},
    onConfigurePrivate: () -> Unit = {},
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

                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable(onClick = onSelectAuto)
                        .padding(vertical = 8.dp),
                ) {
                    RadioButton(selected = autoMode, onClick = onSelectAuto)
                    Column {
                        Text(
                            text = stringResource(R.string.gateway_picker_auto_title),
                            style = MaterialTheme.typography.bodyLarge,
                            color = MaterialTheme.colorScheme.onSurface,
                        )
                        Text(
                            text = stringResource(R.string.gateway_picker_auto_subtitle),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }

                options.forEach { descriptor ->
                    // B16 - while Auto is engaged, no manual row shows as
                    // selected, even though [current] still names the last
                    // manual pick (the fallback GatewayConfigurationRepository
                    // would resolve to if Auto were ever turned off) - never
                    // a false "you picked this one" claim.
                    val selected = !autoMode && descriptor.id == current
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

                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable(onClick = onSelectPrivate)
                        .padding(vertical = 8.dp),
                ) {
                    RadioButton(selected = privateMode, onClick = onSelectPrivate)
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = stringResource(R.string.gateway_picker_private_title),
                            style = MaterialTheme.typography.bodyLarge,
                            color = MaterialTheme.colorScheme.onSurface,
                        )
                        Text(
                            text = stringResource(
                                if (privateConfigured) R.string.gateway_picker_private_subtitle_configured else R.string.gateway_picker_private_subtitle_unconfigured,
                            ),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    TextButton(onClick = onConfigurePrivate) {
                        Text(stringResource(R.string.gateway_picker_private_configure))
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
