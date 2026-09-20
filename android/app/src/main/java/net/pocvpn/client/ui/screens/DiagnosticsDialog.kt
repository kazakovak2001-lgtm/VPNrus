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
import net.pocvpn.client.transport.TransportKind

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
 * to 85% of screen height and only the title stays pinned/unweighted -
 * the `lines` detail list AND every action button below it share ONE
 * `weight(1f)` + `verticalScroll` region (SG-002 evidence-closure fix:
 * originally only `lines` scrolled while the button block stayed fixed-
 * height, which silently squeezed the last buttons to ~0dp once this
 * dialog grew enough debug-only actions that the button block alone could
 * exceed maxDialogHeight while connected - see that fix's own inline docs
 * below) - so every action, Close included, is always reachable by
 * scrolling regardless of how many `lines`/buttons exist.
 */
@Composable
fun DiagnosticsDialog(
    lines: List<String>,
    onCopyPublicKey: () -> Unit,
    onRegenerateIdentity: () -> Unit,
    // Stabilization gate - debug-only: pins a requested transport
    // for the NEXT connect() (same "saved, applied on next connect"
    // discipline as every other setting here) so the real VpnController/
    // Smart Connect path can be exercised with Xray for adaptive-route
    // physical testing - see MainViewModel.debugSetTransportPreference's
    // own docs. Never itself reconnects.
    transportForce: TransportKind?,
    onSetTransportForce: (TransportKind?) -> Unit,
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
    // B20 - debug-only: manually triggers the SAME real
    // MainViewModel.refreshManifest() -> MultiOriginManifestDistributionClient
    // path the ViewModel init-time startup refresh already uses (never a
    // parallel/fake test client) - see MainViewModel.debugRefreshManifest's
    // own docs. Exists for deterministic physical validation without
    // force-stopping the app between fault-injection steps.
    onRefreshManifest: () -> Unit,
    // SG-002 evidence-closure - debug-only: writes the EXACT SAME JSON
    // [onExportDiagnosticsClick] (SettingsScreen's real "Export diagnostics"
    // button) already produces to app-private storage instead of the
    // share sheet - see MainViewModel.exportSupportBundleJson/
    // net.pocvpn.client.diagnostics.support.LocalDiagnosticsExporter's own
    // docs (a build-type-scoped symbol: a real writer only in the debug
    // source set, a no-op stub in release). Never shares/uploads anything.
    onSaveDiagnosticsLocally: () -> Unit,
    saveLocallyStatus: String?,
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

                // SG-002 evidence-closure fix - the ONLY scrollable region,
                // bounded by the Surface's heightIn(max=...) above (same
                // "weight(1f) needs a finite parent to scroll within"
                // reasoning as before). Originally wrapped only the
                // technical-detail `lines` list, keeping every action
                // button pinned below it at ALWAYS-full, unweighted height -
                // that assumption broke the day this dialog grew enough
                // debug-only buttons (12, after adding "Save diagnostics
                // locally") that the button block ALONE could exceed
                // maxDialogHeight while connected (more `lines` content
                // than disconnected): Compose then squeezes the LAST
                // buttons (observed: the new button and Close) to a
                // degenerate ~0dp size - present in the tree, genuinely
                // untappable. Now the buttons scroll together with the
                // lines in ONE region, so every action (Close included)
                // stays reachable regardless of line/button count - no
                // regression for the empty-lines case, since an empty list
                // just means the scrollable region starts at the buttons.
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

                    Spacer(modifier = Modifier.height(8.dp))

                    TextButton(onClick = onCopyPublicKey, modifier = Modifier.fillMaxWidth()) {
                        Text(stringResource(R.string.diagnostics_copy_public_key))
                    }
                    TextButton(onClick = onRegenerateIdentity, modifier = Modifier.fillMaxWidth()) {
                        Text(stringResource(R.string.diagnostics_regenerate_identity))
                    }
                    Text(
                        text = stringResource(
                            R.string.diagnostics_transport_force_status,
                            transportForce?.name ?: "AUTO",
                        ),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                    TextButton(onClick = { onSetTransportForce(null) }, modifier = Modifier.fillMaxWidth()) {
                        Text(stringResource(R.string.diagnostics_force_auto))
                    }
                    TextButton(onClick = { onSetTransportForce(TransportKind.AMNEZIA_WG) }, modifier = Modifier.fillMaxWidth()) {
                        Text(stringResource(R.string.diagnostics_force_awg))
                    }
                    TextButton(onClick = { onSetTransportForce(TransportKind.XRAY_REALITY) }, modifier = Modifier.fillMaxWidth()) {
                        Text(stringResource(R.string.diagnostics_force_reality))
                    }
                    TextButton(onClick = { onSetTransportForce(TransportKind.TLS_TCP) }, modifier = Modifier.fillMaxWidth()) {
                        Text(stringResource(R.string.diagnostics_force_tls))
                    }
                    TextButton(onClick = { onSetTransportForce(TransportKind.XRAY_XHTTP) }, modifier = Modifier.fillMaxWidth()) {
                        Text(stringResource(R.string.diagnostics_force_xhttp))
                    }
                    // B45B-4P - physical validation only: SHADOWSOCKS_2022 has no
                    // production UI entry point yet (Smart Connect never
                    // auto-selects it before every other transport is
                    // exhausted - see PREFERRED_ORDER). This reuses the exact
                    // same generic onSetTransportForce/debugSetTransportPreference
                    // plumbing every other button above already uses - never a
                    // second selection mechanism - and is gated by the same
                    // isDebugBuild condition the whole dialog already requires.
                    TextButton(onClick = { onSetTransportForce(TransportKind.SHADOWSOCKS_2022) }, modifier = Modifier.fillMaxWidth()) {
                        Text(stringResource(R.string.diagnostics_force_shadowsocks))
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
                    TextButton(onClick = onRefreshManifest, modifier = Modifier.fillMaxWidth()) {
                        Text(stringResource(R.string.diagnostics_refresh_manifest))
                    }
                    TextButton(onClick = onSaveDiagnosticsLocally, modifier = Modifier.fillMaxWidth()) {
                        Text(stringResource(R.string.diagnostics_save_locally))
                    }
                    saveLocallyStatus?.let {
                        Text(
                            text = stringResource(R.string.diagnostics_save_locally_status, it),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurface,
                        )
                    }
                    TextButton(onClick = onDismiss, modifier = Modifier.fillMaxWidth()) {
                        Text(stringResource(R.string.diagnostics_close))
                    }
                }
            }
        }
    }
}
