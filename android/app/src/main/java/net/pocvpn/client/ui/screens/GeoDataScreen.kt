package net.pocvpn.client.ui.screens

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import net.pocvpn.client.R
import net.pocvpn.client.geodata.GeoDataPresentation
import net.pocvpn.client.geodata.GeoDataUiState
import net.pocvpn.client.geodata.GeoOperationState
import net.pocvpn.client.geodata.GeoUpdateResult
import net.pocvpn.client.ui.components.ChevronRightGlyph

/**
 * Settings -> GeoData. Shows which `geoip.dat` / `geosite.dat` are in use, one separate https:// address field per
 * file, Save, a manual "Download and update" with progress/cancel, and a way back to the built-in databases.
 * Every dynamic sentence comes from [GeoDataPresentation] (unit-tested); this composable only lays it out.
 */
@Composable
fun GeoDataScreen(
    state: GeoDataUiState,
    onGeoipChanged: (String) -> Unit,
    onGeositeChanged: (String) -> Unit,
    onSave: () -> Unit,
    onUpdate: () -> Unit,
    onCancel: () -> Unit,
    onUseBundled: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 24.dp),
    ) {
        Spacer(modifier = Modifier.height(24.dp))
        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
            val backDescription = stringResource(R.string.settings_back_content_description)
            IconButton(onClick = onBack, modifier = Modifier.semantics { contentDescription = backDescription }) {
                ChevronRightGlyph(
                    tint = MaterialTheme.colorScheme.onBackground,
                    modifier = Modifier.size(20.dp).graphicsLayer(rotationZ = 180f),
                )
            }
            Spacer(modifier = Modifier.width(4.dp))
            Text(
                text = stringResource(R.string.geodata_title),
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.onBackground,
            )
        }

        Spacer(modifier = Modifier.height(16.dp))
        Text(
            text = stringResource(R.string.geodata_explanation),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(modifier = Modifier.height(4.dp))
        Text(
            text = GeoDataPresentation.USAGE_NOTICE,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        // ---- status ----
        Spacer(modifier = Modifier.height(24.dp))
        SectionTitle(stringResource(R.string.geodata_status_title))
        Spacer(modifier = Modifier.height(4.dp))
        val status = state.status
        if (status == null) {
            Text(
                text = stringResource(R.string.geodata_status_loading),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        } else {
            Text(
                text = GeoDataPresentation.describeOrigin(status),
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurface,
            )
            status.files.forEach { file ->
                Text(
                    text = GeoDataPresentation.describeFile(file),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            GeoDataPresentation.describeCoreUsage(status)?.let { line ->
                Spacer(modifier = Modifier.height(4.dp))
                Text(text = line, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }

        // ---- addresses ----
        Spacer(modifier = Modifier.height(24.dp))
        SectionTitle(stringResource(R.string.geodata_urls_title))
        Spacer(modifier = Modifier.height(4.dp))
        Text(
            text = stringResource(R.string.geodata_urls_helper),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(modifier = Modifier.height(4.dp))
        Text(
            text = GeoDataPresentation.OUTSIDE_VPN_NOTICE,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(modifier = Modifier.height(12.dp))
        UrlField(
            label = stringResource(R.string.geodata_geoip_url_label),
            value = state.geoipInput,
            problem = state.geoipProblem?.let { GeoDataPresentation.describeUrlProblem(it) },
            enabled = !state.isRunning,
            onChange = onGeoipChanged,
        )
        Spacer(modifier = Modifier.height(12.dp))
        UrlField(
            label = stringResource(R.string.geodata_geosite_url_label),
            value = state.geositeInput,
            problem = state.geositeProblem?.let { GeoDataPresentation.describeUrlProblem(it) },
            enabled = !state.isRunning,
            onChange = onGeositeChanged,
        )
        if (state.saveFailed) {
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                text = stringResource(R.string.geodata_save_failed),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error,
            )
        }
        Spacer(modifier = Modifier.height(8.dp))
        OutlinedButton(
            onClick = onSave,
            enabled = !state.isRunning && state.hasUnsavedChanges,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(stringResource(R.string.geodata_save))
        }

        // ---- update ----
        Spacer(modifier = Modifier.height(24.dp))
        SectionTitle(stringResource(R.string.geodata_update_title))
        Spacer(modifier = Modifier.height(8.dp))
        val running = state.operation as? GeoOperationState.Running
        if (running == null) {
            Button(onClick = onUpdate, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.geodata_update_button))
            }
        } else {
            val progress = running.progress
            Text(
                text = if (running.cancelRequested) {
                    stringResource(R.string.geodata_cancelling)
                } else {
                    progress?.let { GeoDataPresentation.describeProgress(it) } ?: stringResource(R.string.geodata_starting)
                },
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurface,
            )
            Spacer(modifier = Modifier.height(8.dp))
            val fraction = progress?.let { GeoDataPresentation.progressFraction(it) }
            if (fraction != null) {
                LinearProgressIndicator(progress = { fraction }, modifier = Modifier.fillMaxWidth())
            } else {
                LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
            }
            Spacer(modifier = Modifier.height(8.dp))
            OutlinedButton(onClick = onCancel, enabled = !running.cancelRequested, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.geodata_cancel))
            }
        }

        when (val op = state.operation) {
            is GeoOperationState.Finished -> {
                Spacer(modifier = Modifier.height(12.dp))
                val failed = op.result is GeoUpdateResult.Failed
                Text(
                    text = GeoDataPresentation.describeSuccess(op.result),
                    style = MaterialTheme.typography.bodyMedium,
                    color = if (failed) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface,
                )
            }
            is GeoOperationState.Info -> {
                Spacer(modifier = Modifier.height(12.dp))
                Text(text = op.message, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurface)
            }
            else -> Unit
        }

        Spacer(modifier = Modifier.height(8.dp))
        Text(
            text = GeoDataPresentation.RESTART_NOTICE,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        // ---- built-in ----
        Spacer(modifier = Modifier.height(16.dp))
        TextButton(onClick = onUseBundled, enabled = !state.isRunning, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.geodata_use_bundled))
        }
        Spacer(modifier = Modifier.height(24.dp))
    }
}

@Composable
private fun SectionTitle(text: String) {
    Text(
        text = text,
        style = MaterialTheme.typography.titleMedium,
        fontWeight = FontWeight.SemiBold,
        color = MaterialTheme.colorScheme.onBackground,
    )
}

@Composable
private fun UrlField(label: String, value: String, problem: String?, enabled: Boolean, onChange: (String) -> Unit) {
    OutlinedTextField(
        value = value,
        onValueChange = onChange,
        label = { Text(label) },
        placeholder = { Text("https://") },
        singleLine = true,
        enabled = enabled,
        isError = problem != null,
        supportingText = problem?.let { { Text(it) } },
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
        modifier = Modifier.fillMaxWidth(),
    )
}
