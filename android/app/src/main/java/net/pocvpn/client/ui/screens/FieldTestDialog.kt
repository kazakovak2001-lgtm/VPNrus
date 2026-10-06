package net.pocvpn.client.ui.screens

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import net.pocvpn.client.R
import net.pocvpn.client.diagnostics.fieldtest.FieldTestMode
import net.pocvpn.client.diagnostics.fieldtest.FieldTestProgress

/**
 * Field test - debug-only (opened from the isDebugBuild-gated Diagnostics
 * dialog). Shows the live log of [net.pocvpn.client.diagnostics.fieldtest
 * .FieldTestRunner] and, once a report exists, lets the tester share it
 * (share sheet, chosen by the tester) or keep a local copy. Never uploads
 * anything by itself. Same single-scroll-region layout as DiagnosticsDialog.
 */
@Composable
fun FieldTestDialog(
    progress: FieldTestProgress?,
    /** Debug build: full test + monitor modes; release: the quick network check only. */
    allModes: Boolean,
    onStart: (FieldTestMode, Int) -> Unit,
    onCancel: () -> Unit,
    onShareJson: () -> Unit,
    onShareSummary: () -> Unit,
    onSaveLocally: () -> Unit,
    saveStatus: String?,
    onDismiss: () -> Unit,
) {
    val maxDialogHeight = LocalConfiguration.current.screenHeightDp.dp * 0.9f
    val running = progress?.running == true
    val hasReport = progress?.report != null
    val scroll = rememberScrollState()
    LaunchedEffect(progress?.log?.size) { scroll.animateScrollTo(scroll.maxValue) }
    // Long runs (full test, monitor) must not be cut short by the screen
    // turning off and the activity going away - keep it on while running.
    val view = androidx.compose.ui.platform.LocalView.current
    androidx.compose.runtime.DisposableEffect(running) {
        view.keepScreenOn = running
        onDispose { view.keepScreenOn = false }
    }

    Dialog(onDismissRequest = { if (!running) onDismiss() }) {
        Surface(
            shape = MaterialTheme.shapes.extraLarge,
            color = MaterialTheme.colorScheme.surface,
            modifier = Modifier.heightIn(max = maxDialogHeight),
        ) {
            Column(modifier = Modifier.padding(20.dp)) {
                Text(
                    text = stringResource(R.string.field_test_title),
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.SemiBold,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                Spacer(modifier = Modifier.height(8.dp))
                progress?.let { p ->
                    Text(
                        text = stringResource(R.string.field_test_progress, p.phase, p.step, p.totalSteps),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                    if (p.totalSteps > 0) {
                        LinearProgressIndicator(
                            progress = { p.step.toFloat() / p.totalSteps },
                            modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp),
                        )
                    }
                }
                Column(
                    modifier = Modifier
                        .weight(weight = 1f, fill = false)
                        .verticalScroll(scroll),
                ) {
                    if (progress == null) {
                        Text(
                            text = stringResource(if (allModes) R.string.field_test_intro else R.string.field_test_intro_quick),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurface,
                        )
                    }
                    progress?.log?.forEach { line ->
                        Text(
                            text = line,
                            style = MaterialTheme.typography.bodySmall,
                            fontFamily = FontFamily.Monospace,
                            color = MaterialTheme.colorScheme.onSurface,
                        )
                    }
                    Spacer(modifier = Modifier.height(8.dp))
                    if (running) {
                        TextButton(onClick = onCancel, modifier = Modifier.fillMaxWidth()) {
                            Text(stringResource(R.string.field_test_cancel))
                        }
                    } else {
                        if (allModes) {
                            TextButton(onClick = { onStart(FieldTestMode.FULL, 0) }, modifier = Modifier.fillMaxWidth()) {
                                Text(stringResource(R.string.field_test_start))
                            }
                        }
                        TextButton(onClick = { onStart(FieldTestMode.QUICK, 0) }, modifier = Modifier.fillMaxWidth()) {
                            Text(stringResource(R.string.field_test_start_quick))
                        }
                        if (allModes) {
                            TextButton(onClick = { onStart(FieldTestMode.MONITOR, 30) }, modifier = Modifier.fillMaxWidth()) {
                                Text(stringResource(R.string.field_test_start_monitor, 30))
                            }
                            TextButton(onClick = { onStart(FieldTestMode.MONITOR, 120) }, modifier = Modifier.fillMaxWidth()) {
                                Text(stringResource(R.string.field_test_start_monitor, 120))
                            }
                        }
                    }
                    if (hasReport && !running) {
                        TextButton(onClick = onShareJson, modifier = Modifier.fillMaxWidth()) {
                            Text(stringResource(R.string.field_test_share))
                        }
                        TextButton(onClick = onShareSummary, modifier = Modifier.fillMaxWidth()) {
                            Text(stringResource(R.string.field_test_share_summary))
                        }
                        if (allModes) {
                            TextButton(onClick = onSaveLocally, modifier = Modifier.fillMaxWidth()) {
                                Text(stringResource(R.string.field_test_save))
                            }
                        }
                        saveStatus?.let {
                            Text(text = it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurface)
                        }
                    }
                    if (!running) {
                        TextButton(onClick = onDismiss, modifier = Modifier.fillMaxWidth()) {
                            Text(stringResource(R.string.diagnostics_close))
                        }
                    }
                }
            }
        }
    }
}
