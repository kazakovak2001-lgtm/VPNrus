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
 * B13 - the real gateway picker: lists every [ProductionGatewayDescriptor]
 * in [options] (today Germany and Stockholm), radio-selected against
 * [current], and calls [onSelect] with a DETERMINISTIC choice - the tapped
 * row's own id, never inferred/derived. Selection alone does not
 * reconnect/touch the tunnel (see MainViewModel.selectGateway's own docs) -
 * this dialog is purely the input surface.
 */
@Composable
fun GatewayPickerDialog(
    current: ProductionGatewayId,
    options: List<ProductionGatewayDescriptor>,
    onSelect: (ProductionGatewayId) -> Unit,
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
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(12.dp),
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { onSelect(descriptor.id) }
                            .padding(vertical = 8.dp),
                    ) {
                        RadioButton(selected = selected, onClick = { onSelect(descriptor.id) })
                        Column {
                            Text(
                                text = "${descriptor.displayCountry} · ${descriptor.displayCity}",
                                style = MaterialTheme.typography.bodyLarge,
                                color = MaterialTheme.colorScheme.onSurface,
                            )
                            Text(
                                text = descriptor.provider,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
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
