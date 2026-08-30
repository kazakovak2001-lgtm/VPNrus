package net.pocvpn.client.ui.screens

import androidx.compose.foundation.layout.Column
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
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import net.pocvpn.client.R

/**
 * B8D/B8E - debug-only technical detail, unchanged in meaning from the
 * original View-based Diagnostics section - only ever constructed from a
 * debug build (see AppRoot/MainActivity). Never shows the device private
 * key, activation credential, enrollment bearer token, or server private
 * key - every line here is a value the pre-existing diagnostics UI already
 * treated as non-secret (see MainViewModel/DiagnosticsSnapshot/
 * GatewayConfiguration's own docs).
 *
 * B8E1 - a plain Compose Dialog + Surface, NOT AlertDialog: AlertDialog's
 * own `text` slot gives its content unbounded height, so
 * Modifier.verticalScroll on a Column inside it has nothing to scroll
 * within - the dialog just grows (and clips against the screen edge on a
 * real device) instead of scrolling. Here the Surface is explicitly capped
 * to 85% of screen height, the title and the action buttons keep their
 * natural (unweighted) height, and ONLY the middle content Column is
 * `weight(1f)` + `verticalScroll` - so it, and only it, absorbs whatever
 * height remains and becomes finger-scrollable while the header and
 * actions stay pinned and always reachable.
 */
@Composable
fun DiagnosticsDialog(
    lines: List<String>,
    onCopyPublicKey: () -> Unit,
    onRegenerateIdentity: () -> Unit,
    onDismiss: () -> Unit,
    // B8O2-ops - additive, defaults so the widely-used call shape above
    // (onCopyPublicKey/onRegenerateIdentity/onDismiss only) stays valid:
    // a minimal standalone TLS-profile-fetch action for a device that is
    // ALREADY activated and therefore has no reachable ActivationScreen -
    // see MainViewModel.provisionTlsProfile's own docs for why this exists
    // instead of reusing that screen. Never touches AWG/REALITY identity or
    // activation state - the credential typed here exists only for the
    // duration of one onProvisionTlsProfile(credential) call, the same
    // "never stored" discipline ActivationScreen's own credential field uses.
    tlsCredential: String = "",
    onTlsCredentialChange: (String) -> Unit = {},
    onProvisionTlsProfile: (String) -> Unit = {},
    tlsProvisioningResultText: String? = null,
    // B8O2-ops - additive, defaults so the widely-used call shape stays
    // valid. No product UI exposes transport selection yet (Smart Connect
    // Auto is the only wired preference - see MainViewModel's own docs) -
    // this is a debug-only way to reach the EXISTING, already-safe
    // UserTransportPreference.Manual(TLS_TCP) path for physical-device
    // verification, never a new automatic selection/failover rule.
    transportPreferenceOverrideText: String = "Auto",
    onForceManualTlsTcp: () -> Unit = {},
    onForceManualReality: () -> Unit = {},
    onClearTransportPreferenceOverride: () -> Unit = {},
) {
    val maxDialogHeight = LocalConfiguration.current.screenHeightDp.dp * 0.85f

    Dialog(onDismissRequest = onDismiss) {
        Surface(
            shape = MaterialTheme.shapes.extraLarge,
            color = MaterialTheme.colorScheme.surface,
            modifier = Modifier.heightIn(max = maxDialogHeight),
        ) {
            Column(modifier = Modifier.padding(24.dp)) {
                Text(
                    text = stringResource(R.string.diagnostics_title),
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.SemiBold,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                Spacer(modifier = Modifier.height(16.dp))

                // The only scrollable region - bounded by the Surface's
                // heightIn(max=...) above, which is what makes weight(1f)
                // (and therefore verticalScroll) actually have something
                // finite to scroll within instead of growing unbounded.
                Column(
                    modifier = Modifier
                        .weight(weight = 1f, fill = false)
                        .verticalScroll(rememberScrollState()),
                ) {
                    lines.forEach { line ->
                        Text(
                            text = line,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurface,
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                    }
                }

                Spacer(modifier = Modifier.height(8.dp))

                TextButton(onClick = onCopyPublicKey, modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(R.string.diagnostics_copy_public_key))
                }
                TextButton(onClick = onRegenerateIdentity, modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(R.string.diagnostics_regenerate_identity))
                }

                Spacer(modifier = Modifier.height(8.dp))
                OutlinedTextField(
                    value = tlsCredential,
                    onValueChange = onTlsCredentialChange,
                    label = { Text(stringResource(R.string.diagnostics_tls_credential_label)) },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.None),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = MaterialTheme.colorScheme.primary,
                        cursorColor = MaterialTheme.colorScheme.primary,
                    ),
                    modifier = Modifier.fillMaxWidth(),
                )
                tlsProvisioningResultText?.let {
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(text = it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                TextButton(
                    onClick = { onProvisionTlsProfile(tlsCredential) },
                    enabled = tlsCredential.isNotBlank(),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(stringResource(R.string.diagnostics_provision_tls_button))
                }

                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = "Transport preference override: $transportPreferenceOverrideText",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                TextButton(onClick = onForceManualTlsTcp, modifier = Modifier.fillMaxWidth()) {
                    Text("Force Manual TLS_TCP (debug only)")
                }
                TextButton(onClick = onForceManualReality, modifier = Modifier.fillMaxWidth()) {
                    Text("Force Manual XRAY_REALITY (debug only)")
                }
                TextButton(onClick = onClearTransportPreferenceOverride, modifier = Modifier.fillMaxWidth()) {
                    Text("Clear override - use Auto (debug only)")
                }

                TextButton(onClick = onDismiss, modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(R.string.diagnostics_close))
                }
            }
        }
    }
}
