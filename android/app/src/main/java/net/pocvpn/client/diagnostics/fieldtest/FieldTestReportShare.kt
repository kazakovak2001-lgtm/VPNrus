package net.pocvpn.client.diagnostics.fieldtest

import android.content.ClipData
import android.content.Context
import android.content.Intent
import androidx.core.content.FileProvider
import java.io.File

/**
 * Field test - shares the JSON report as a FILE, not as Intent text. A full
 * report (with the app's log buffer) is larger than the ~1 MB binder limit,
 * so EXTRA_TEXT failed with TransactionTooLargeException on testers'
 * devices. The file lives in an app-private cache directory exposed only
 * through this app's non-exported FileProvider, with a one-shot read grant
 * for the app the user picks in the share sheet.
 */
object FieldTestReportShare {
    const val DIR = "field-test-share"
    private const val AUTHORITY_SUFFIX = ".fieldtestshare"

    /** Writes [json] to a fresh `cacheDir/field-test-share/` file; older shared reports are removed. */
    fun writeReportFile(cacheDir: File, epochMillis: Long, json: String): File {
        val dir = File(cacheDir, DIR)
        dir.mkdirs()
        dir.listFiles()?.forEach { it.delete() }
        return File(dir, fileName(epochMillis)).apply { writeText(json) }
    }

    fun fileName(epochMillis: Long): String = "nova-field-test-$epochMillis.json"

    fun shareIntent(context: Context, json: String, chooserTitle: String): Intent {
        val file = writeReportFile(context.cacheDir, System.currentTimeMillis(), json)
        val uri = FileProvider.getUriForFile(context, context.packageName + AUTHORITY_SUFFIX, file)
        val send = Intent(Intent.ACTION_SEND).apply {
            type = "application/json"
            putExtra(Intent.EXTRA_STREAM, uri)
            putExtra(Intent.EXTRA_SUBJECT, file.name)
            clipData = ClipData.newRawUri(file.name, uri)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        return Intent.createChooser(send, chooserTitle).addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
    }
}
