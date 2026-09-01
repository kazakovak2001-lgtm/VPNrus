package net.pocvpn.client.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import net.pocvpn.client.R
import net.pocvpn.client.vpn.config.PrivateGatewayConfig
import net.pocvpn.client.vpn.config.PrivateGatewayConfigFailureReason

/**
 * B22 - the real (not debug-only) add/edit UI for the single supported
 * [PrivateGatewayConfig] (FIRST SLICE UX). Every field here is hoisted -
 * this Composable owns no persistence itself (mirrors [ActivationScreen]/
 * [GatewayPickerDialog]'s own convention) - the caller (AppRoot) reads/
 * writes through [net.pocvpn.client.MainViewModel.savePrivateGatewayConfig]/
 * [net.pocvpn.client.MainViewModel.removePrivateGatewayConfig]/
 * [net.pocvpn.client.MainViewModel.privateGatewayClientPublicKey].
 *
 * The client PRIVATE key is never a field, never displayed, never
 * requested - [clientPublicKey] is the ONLY key material this dialog ever
 * shows, explicitly labeled as the value to paste into the user's own VPS
 * (architecture "FIRST SLICE UX": "expose/copy only the client PUBLIC key").
 */
@Composable
fun PrivateGatewayDialog(
    existing: PrivateGatewayConfig?,
    clientPublicKey: String?,
    onCopyPublicKey: () -> Unit,
    onSave: (
        host: String,
        port: String,
        serverPublicKey: String,
        clientTunnelIp: String,
        gatewayTunnelIp: String,
        initHeader: String,
        responseHeader: String,
        underloadHeader: String,
        transportHeader: String,
    ) -> Unit,
    validationError: PrivateGatewayConfigFailureReason?,
    onRemove: () -> Unit,
    onDismiss: () -> Unit,
) {
    var host by remember { mutableStateOf(existing?.host.orEmpty()) }
    var port by remember { mutableStateOf(existing?.port?.toString().orEmpty()) }
    var serverPublicKey by remember { mutableStateOf(existing?.serverPublicKeyBase64.orEmpty()) }
    var clientTunnelIp by remember { mutableStateOf(existing?.clientTunnelIp.orEmpty()) }
    var gatewayTunnelIp by remember { mutableStateOf(existing?.gatewayTunnelIp.orEmpty()) }
    var initHeader by remember { mutableStateOf(existing?.awgProfile?.initPacketMagicHeader.orEmpty()) }
    var responseHeader by remember { mutableStateOf(existing?.awgProfile?.responsePacketMagicHeader.orEmpty()) }
    var underloadHeader by remember { mutableStateOf(existing?.awgProfile?.underloadPacketMagicHeader.orEmpty()) }
    var transportHeader by remember { mutableStateOf(existing?.awgProfile?.transportPacketMagicHeader.orEmpty()) }

    Dialog(onDismissRequest = onDismiss) {
        Surface(shape = MaterialTheme.shapes.extraLarge, color = MaterialTheme.colorScheme.surface) {
            Column(
                modifier = Modifier
                    .padding(24.dp)
                    .heightIn(max = 560.dp)
                    .verticalScroll(rememberScrollState()),
            ) {
                Text(
                    text = androidx.compose.ui.res.stringResource(R.string.private_gateway_title),
                    style = MaterialTheme.typography.titleLarge,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = androidx.compose.ui.res.stringResource(R.string.private_gateway_helper),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(modifier = Modifier.height(16.dp))

                Field(androidx.compose.ui.res.stringResource(R.string.private_gateway_field_host), host) { host = it }
                Field(androidx.compose.ui.res.stringResource(R.string.private_gateway_field_port), port, KeyboardType.Number) { port = it }
                Field(androidx.compose.ui.res.stringResource(R.string.private_gateway_field_server_key), serverPublicKey) { serverPublicKey = it }
                Field(androidx.compose.ui.res.stringResource(R.string.private_gateway_field_client_ip), clientTunnelIp) { clientTunnelIp = it }
                Field(androidx.compose.ui.res.stringResource(R.string.private_gateway_field_gateway_ip), gatewayTunnelIp) { gatewayTunnelIp = it }

                Spacer(modifier = Modifier.height(12.dp))
                Text(
                    text = androidx.compose.ui.res.stringResource(R.string.private_gateway_obfuscation_title),
                    style = MaterialTheme.typography.titleSmall,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                Field(androidx.compose.ui.res.stringResource(R.string.private_gateway_field_h1), initHeader, KeyboardType.Number) { initHeader = it }
                Field(androidx.compose.ui.res.stringResource(R.string.private_gateway_field_h2), responseHeader, KeyboardType.Number) { responseHeader = it }
                Field(androidx.compose.ui.res.stringResource(R.string.private_gateway_field_h3), underloadHeader, KeyboardType.Number) { underloadHeader = it }
                Field(androidx.compose.ui.res.stringResource(R.string.private_gateway_field_h4), transportHeader, KeyboardType.Number) { transportHeader = it }

                if (validationError != null) {
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = androidx.compose.ui.res.stringResource(R.string.private_gateway_invalid_prefix, validationError.name),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                    )
                }

                Spacer(modifier = Modifier.height(16.dp))
                Text(
                    text = androidx.compose.ui.res.stringResource(R.string.private_gateway_public_key_title),
                    style = MaterialTheme.typography.titleSmall,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                Text(
                    text = clientPublicKey ?: androidx.compose.ui.res.stringResource(R.string.private_gateway_public_key_unavailable),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                if (clientPublicKey != null) {
                    TextButton(onClick = onCopyPublicKey) {
                        Text(androidx.compose.ui.res.stringResource(R.string.private_gateway_copy_public_key))
                    }
                }

                Spacer(modifier = Modifier.height(16.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                    TextButton(onClick = onDismiss) {
                        Text(androidx.compose.ui.res.stringResource(R.string.private_gateway_close))
                    }
                    if (existing != null) {
                        TextButton(onClick = onRemove) {
                            Text(androidx.compose.ui.res.stringResource(R.string.private_gateway_remove))
                        }
                    }
                    TextButton(
                        onClick = {
                            onSave(host, port, serverPublicKey, clientTunnelIp, gatewayTunnelIp, initHeader, responseHeader, underloadHeader, transportHeader)
                        },
                    ) {
                        Text(androidx.compose.ui.res.stringResource(R.string.private_gateway_save))
                    }
                }
            }
        }
    }
}

@Composable
private fun Field(label: String, value: String, keyboardType: KeyboardType = KeyboardType.Text, onValueChange: (String) -> Unit) {
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        label = { Text(label) },
        singleLine = true,
        keyboardOptions = KeyboardOptions(keyboardType = keyboardType),
        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
    )
}
