package net.pocvpn.client.ui.screens

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
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
    // B18-2 - debug-only: pins UserTransportPreference.Manual(XRAY_REALITY)
    // for the NEXT connect() (same "saved, applied on next connect"
    // discipline as every other setting here) so the real VpnController/
    // Smart Connect path can be exercised with Xray for adaptive-route
    // consistency testing - see MainViewModel.debugSetTransportPreference's
    // own docs. Never itself reconnects.
    onForceXrayTest: () -> Unit,
    // B19 physical-validation follow-up - debug-only: writes a REAL
    // FAILURE/SUCCESS ConnectionOutcome + PathHistory entry for Frankfurt
    // AWG into the SAME stores the real Auto ranking pipeline reads - see
    // MainViewModel.debugRecordConnectionFailure/Success's own docs. Never
    // itself starts/reconnects anything.
    onSimulateAwgFailure: () -> Unit,
    onSimulateAwgSuccess: () -> Unit,
    // B18 physical-validation follow-up - debug-only: opens the REAL
    // ActivationScreen for an ALREADY-provisioned gateway (AppRoot's own
    // `activatingGatewayId` state - the SAME mechanism B15 built for an
    // unprovisioned ADDITIONAL gateway, see GatewayPickerDialog's own docs -
    // this just reaches it for a gateway this device already has a, possibly
    // stale, identity for). Never a second activation path: the resulting
    // screen calls the SAME MainViewModel.activateDevice(credential,
    // targetGatewayId) every other activation flow uses.
    onReactivateGermany: () -> Unit,
    onDismiss: () -> Unit,
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
                TextButton(onClick = onForceXrayTest, modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(R.string.diagnostics_force_xray_test))
                }
                TextButton(onClick = onSimulateAwgFailure, modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(R.string.diagnostics_simulate_awg_failure))
                }
                TextButton(onClick = onSimulateAwgSuccess, modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(R.string.diagnostics_simulate_awg_success))
                }
                TextButton(onClick = onReactivateGermany, modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(R.string.diagnostics_reactivate_germany))
                }
                TextButton(onClick = onDismiss, modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(R.string.diagnostics_close))
                }
            }
        }
    }
}
