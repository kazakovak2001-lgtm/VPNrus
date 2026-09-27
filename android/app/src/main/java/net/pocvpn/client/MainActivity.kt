package net.pocvpn.client

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.ViewModelProvider
import net.pocvpn.client.activation.ActivationInput
import net.pocvpn.client.activation.ActivationInputResolver
import net.pocvpn.client.ui.AppRoot
import net.pocvpn.client.ui.theme.NovaVpnTheme

/**
 * B8E - thin Compose host only. All screen structure/decisions live in
 * net.pocvpn.client.ui.AppRoot and the composables it calls; this class
 * owns nothing beyond the ViewModel instance and the Android-framework
 * callbacks (VPN permission, SAF file picker, incoming App Link intent)
 * Compose can't issue/receive itself. Everything comes from MainViewModel,
 * which survives Activity recreation.
 *
 * B-ACT-IMPORT - this class NEVER performs cryptographic validation of an
 * activation package/link; it only turns an Android-framework event (a
 * picked file's Uri, an incoming ACTION_VIEW Intent) into a plain
 * [ActivationInput], resolved via [ActivationInputResolver] (pure JVM, see
 * that object's own docs), and hands the result to the SAME
 * `MainViewModel.submitActivationInput` every other adapter uses - the
 * EXISTING [net.pocvpn.client.activation.ActivationPackageImporter]/
 * [net.pocvpn.client.activation.ActivationPackageRedeemer] pipeline decides
 * everything about trust, unchanged.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var viewModel: MainViewModel

    private val vpnPermissionLauncher =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            viewModel.onVpnPermissionResult(result.resultCode == RESULT_OK)
        }

    /**
     * B-ACT-IMPORT - Storage Access Framework document picker. No MIME type
     * restriction is hardcoded here (SAF's own `ACTION_OPEN_DOCUMENT` contract) -
     * see [AppRoot]'s file-picker launch site for the preferred/fallback MIME
     * types it actually requests. On pick, reads the file's exact UTF-8 text
     * (no trim/normalization beyond what decoding bytes as a String already
     * is) and hands it to [ActivationInputResolver.resolveFile] - the ONLY
     * place that decides whether that text is usable at all. Deliberately
     * never calls `takePersistableUriPermission` - this Uri is read exactly
     * once, right here, so the one-time grant Android already provides for
     * the launching call is sufficient and nothing needs to be explicitly
     * released afterward.
     */
    private val activationFileLauncher =
        registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri: Uri? ->
            if (uri == null) return@registerForActivityResult
            val content = try {
                contentResolver.openInputStream(uri)?.bufferedReader(Charsets.UTF_8)?.use { it.readText() }
            } catch (e: java.io.IOException) {
                null
            } catch (e: SecurityException) {
                null
            }
            val resolution = if (content == null) {
                ActivationInputResolver.resolveFile("")
            } else {
                ActivationInputResolver.resolve(ActivationInput.File(content))
            }
            viewModel.submitActivationInput(resolution)
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        viewModel = ViewModelProvider(this, MainViewModel.Factory(applicationContext))[MainViewModel::class.java]
        handleActivationAppLinkIntent(intent)

        setContent {
            NovaVpnTheme {
                AppRoot(
                    viewModel = viewModel,
                    isDebugBuild = BuildConfig.DEBUG,
                    onRequestVpnPermission = { intent: Intent -> vpnPermissionLauncher.launch(intent) },
                    isZeroTouchEnrollmentBuild = BuildConfig.FIELD_ENROLLMENT_ENABLED,
                    onLaunchActivationFilePicker = { mimeTypes -> activationFileLauncher.launch(mimeTypes) },
                )
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleActivationAppLinkIntent(intent)
    }

    /**
     * B-ACT-IMPORT - the ONLY place an incoming `ACTION_VIEW` Intent is
     * handled. Only `ACTION_VIEW` with a non-null `data` Uri is considered at
     * all; anything else is ignored (never treated as an implicit
     * activation attempt). The Uri's own string form is handed to
     * [ActivationInputResolver.resolveAppLinkUrl] unchanged - scheme/host/
     * path allow-listing happens entirely there, never here.
     */
    private fun handleActivationAppLinkIntent(intent: Intent) {
        if (intent.action != Intent.ACTION_VIEW) return
        val uri = intent.data ?: return
        val resolution = ActivationInputResolver.resolveAppLinkUrl(uri.toString())
        viewModel.submitActivationInput(resolution)
    }
}
