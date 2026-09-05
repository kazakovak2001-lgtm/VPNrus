package net.pocvpn.client.fieldtest

import android.content.Intent
import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.lifecycle.ViewModelProvider

/**
 * The field test's ONE screen (task's required UX, verbatim):
 *
 *   Nova VPN
 *   [ Connect ]
 *   Connecting… / Protected / Connection failed
 *
 * No activation screen, no activation code, no provisioning, no
 * registration, no account creation, no bootstrap API, no profile
 * download, no technical setup screen - the tester installs, opens, and
 * presses Connect. This is the ONLY launcher activity for this build type
 * (see src/fieldTest/AndroidManifest.xml - MainActivity is not launchable
 * here at all).
 */
class FieldTestActivity : AppCompatActivity() {

    private lateinit var viewModel: FieldTestViewModel

    private val vpnPermissionLauncher =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
            // Field-test connect() already fails this candidate closed when
            // preparePermissionIntent() returns non-null (see
            // FieldTestTunnelController) - a denied permission simply means
            // the NEXT candidate (or Failed) is reached on the tester's next
            // Connect tap, same as the normal app's own permission flow.
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        viewModel = ViewModelProvider(this, FieldTestViewModel.Factory(application))[FieldTestViewModel::class.java]

        setContent {
            MaterialTheme {
                FieldTestScreen(
                    viewModel = viewModel,
                    onRequestVpnPermission = { intent: Intent -> vpnPermissionLauncher.launch(intent) },
                    onShareReport = { json -> shareReport(json) },
                )
            }
        }
    }

    /**
     * The manual export/share fallback (task requirement 4's own "preserve
     * the existing export/share mechanism") - the EXACT same
     * `Intent.ACTION_SEND` / `text/json` pattern
     * [net.pocvpn.client.ui.AppRoot]'s own "Export diagnostics" button
     * already uses, never a second/different sharing mechanism.
     */
    private fun shareReport(json: String) {
        val sendIntent = Intent(Intent.ACTION_SEND).apply {
            type = "application/json"
            putExtra(Intent.EXTRA_TEXT, json)
        }
        startActivity(Intent.createChooser(sendIntent, "Share field test report"))
    }
}

@Composable
private fun FieldTestScreen(
    viewModel: FieldTestViewModel,
    onRequestVpnPermission: (Intent) -> Unit,
    onShareReport: (String) -> Unit,
) {
    val uiState by viewModel.uiState.collectAsState()
    val report by viewModel.lastReport.collectAsState()

    Surface(modifier = Modifier.fillMaxSize()) {
        Column(
            modifier = Modifier.fillMaxSize().padding(24.dp),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Text(text = "Nova VPN", style = MaterialTheme.typography.headlineMedium)
            Text(text = "Field Test", style = MaterialTheme.typography.labelMedium)

            androidx.compose.foundation.layout.Spacer(modifier = Modifier.padding(16.dp))

            Button(
                onClick = { if (uiState is FieldTestUiState.Failed) viewModel.retry() else viewModel.connect() },
                enabled = uiState is FieldTestUiState.Idle || uiState is FieldTestUiState.Failed,
            ) {
                Text(text = if (uiState is FieldTestUiState.Failed) "Retry" else "Connect")
            }

            androidx.compose.foundation.layout.Spacer(modifier = Modifier.padding(8.dp))

            Text(
                text = when (uiState) {
                    FieldTestUiState.Idle -> ""
                    FieldTestUiState.Connecting -> "Connecting…"
                    FieldTestUiState.Protected -> "Protected"
                    FieldTestUiState.Failed -> "Connection failed"
                },
            )

            if (report != null) {
                androidx.compose.foundation.layout.Spacer(modifier = Modifier.padding(8.dp))
                Button(onClick = { onShareReport(report!!.toJson()) }) {
                    Text(text = "Share report")
                }
            }
        }
    }
}
