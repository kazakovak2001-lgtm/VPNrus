package net.pocvpn.client

import android.content.Intent
import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.ViewModelProvider
import net.pocvpn.client.ui.AppRoot
import net.pocvpn.client.ui.theme.NovaVpnTheme

/**
 * B8E - thin Compose host only. All screen structure/decisions live in
 * net.pocvpn.client.ui.AppRoot and the composables it calls; this class
 * owns nothing beyond the ViewModel instance and the one Android-framework
 * callback (VPN permission) Compose can't issue itself. Everything comes
 * from MainViewModel, which survives Activity recreation.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var viewModel: MainViewModel

    private val vpnPermissionLauncher =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            viewModel.onVpnPermissionResult(result.resultCode == RESULT_OK)
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        viewModel = ViewModelProvider(this, MainViewModel.Factory(applicationContext))[MainViewModel::class.java]

        setContent {
            NovaVpnTheme {
                AppRoot(
                    viewModel = viewModel,
                    isDebugBuild = BuildConfig.DEBUG,
                    onRequestVpnPermission = { intent: Intent -> vpnPermissionLauncher.launch(intent) },
                )
            }
        }
    }
}
