package net.pocvpn.client.geodata

import net.pocvpn.client.vpn.xray.GeoDataOrigin
import net.pocvpn.client.vpn.xray.GeoFileInfo
import java.text.DateFormat
import java.util.Date

/**
 * Plain-string presentation for Settings -> GeoData, kept free of Android types so the exact wording (and which
 * situation produces which message) is unit-tested. No message ever contains a URL: addresses are shown only in
 * their own input fields and never copied into status, error or diagnostic text.
 */
object GeoDataPresentation {

    const val RESTART_NOTICE =
        "New databases are picked up when the VPN core starts next (the next Xray connection). " +
            "A connection that is already running keeps using the databases it started with."

    const val USAGE_NOTICE =
        "Routing rules do not use these databases yet; they are stored and kept ready for the core."

    fun describeUrlProblem(problem: GeoUrlProblem): String = when (problem) {
        GeoUrlProblem.TOO_LONG -> "The address is too long."
        GeoUrlProblem.MALFORMED -> "This is not a valid web address."
        GeoUrlProblem.NOT_HTTPS -> "Only secure https:// addresses are allowed."
        GeoUrlProblem.NO_HOST -> "The address has no host name."
        GeoUrlProblem.HAS_CREDENTIALS -> "Remove the user name and password from the address."
    }

    fun describeProgress(progress: GeoProgress): String = when (progress.phase) {
        GeoUpdatePhase.DOWNLOADING -> {
            val name = progress.file?.label ?: "database"
            if (progress.bytesDone <= 0L) {
                "Downloading $name..."
            } else if (progress.bytesTotal > 0L) {
                "Downloading $name: ${formatBytes(progress.bytesDone)} of ${formatBytes(progress.bytesTotal)}"
            } else {
                "Downloading $name: ${formatBytes(progress.bytesDone)}"
            }
        }
        GeoUpdatePhase.STAGING -> "Checking and preparing the new databases..."
        GeoUpdatePhase.ACTIVATING -> "Activating the new databases..."
    }

    /** 0..1 for a determinate bar, or null when the size is unknown / not downloading. */
    fun progressFraction(progress: GeoProgress): Float? =
        if (progress.phase == GeoUpdatePhase.DOWNLOADING && progress.bytesTotal > 0L) {
            (progress.bytesDone.toFloat() / progress.bytesTotal.toFloat()).coerceIn(0f, 1f)
        } else {
            null
        }

    fun describeFailure(failure: GeoUpdateResult.Failed): String {
        val file = failure.file?.label
        val prefix = if (file != null) "$file: " else ""
        val reason = when (failure.kind) {
            GeoUpdateFailureKind.NOT_CONFIGURED -> return "Enter at least one address first."
            GeoUpdateFailureKind.INVALID_URL -> return prefix + "the address is not a valid https:// address."
            GeoUpdateFailureKind.BUSY -> return "Another update is already running."
            GeoUpdateFailureKind.CANCELLED -> return "The update was cancelled. The previous databases are unchanged."
            GeoUpdateFailureKind.STAGING_FAILED -> failure.detail.ifBlank { "The new databases could not be prepared." }
            GeoUpdateFailureKind.ACTIVATION_FAILED -> failure.detail.ifBlank { "The new databases could not be activated." }
            GeoUpdateFailureKind.DOWNLOAD_FAILED -> describeDownload(failure)
        }
        return prefix + reason + " The previous databases are unchanged."
    }

    private fun describeDownload(failure: GeoUpdateResult.Failed): String = when (failure.download) {
        GeoDownloadFailure.INVALID_URL -> "the address is not valid."
        GeoDownloadFailure.NETWORK -> "the server could not be reached. Check the connection and the address."
        GeoDownloadFailure.TIMEOUT -> "the server did not respond in time."
        GeoDownloadFailure.TLS -> "a secure connection could not be established."
        GeoDownloadFailure.HTTP_ERROR -> "the server answered with HTTP ${failure.httpStatus ?: "error"}."
        GeoDownloadFailure.TOO_MANY_REDIRECTS -> "too many redirects."
        GeoDownloadFailure.REDIRECT_NOT_HTTPS -> "the server redirected to a non-https address, which is refused."
        GeoDownloadFailure.TOO_LARGE -> "the file is larger than allowed."
        GeoDownloadFailure.INSUFFICIENT_SPACE -> "not enough free storage space."
        GeoDownloadFailure.INTERRUPTED -> "the download was interrupted."
        GeoDownloadFailure.EMPTY -> "the server returned an empty file."
        GeoDownloadFailure.NOT_A_DATABASE -> when (failure.invalidReason) {
            GeoInvalidReason.LOOKS_LIKE_HTML -> "the address returned a web page instead of a database."
            GeoInvalidReason.WRONG_KIND -> "the file looks like the other database (geoip/geosite swapped)."
            GeoInvalidReason.EMPTY -> "the file is empty."
            GeoInvalidReason.NO_ENTRIES -> "the file contains no entries."
            else -> "the file is not a valid database."
        }
        GeoDownloadFailure.CANCELLED -> "cancelled."
        null -> failure.detail.ifBlank { "the download failed." }
    }

    fun describeSuccess(result: GeoUpdateResult): String = when (result) {
        is GeoUpdateResult.Updated -> {
            val names = result.changed.joinToString(" and ") { it.label }
            "Updated $names. $RESTART_NOTICE"
        }
        is GeoUpdateResult.AlreadyCurrent -> "The downloaded databases are identical to the ones already in use. Nothing changed."
        is GeoUpdateResult.Failed -> describeFailure(result)
    }

    /** One line per database, e.g. `geoip.dat - 17.7 MB - 78061159`. */
    fun describeFile(info: GeoFileInfo): String = "${info.name} - ${formatBytes(info.size)} - ${info.sha256.take(8)}"

    fun describeOrigin(status: GeoDataStatus): String = when (status.origin) {
        GeoDataOrigin.DOWNLOADED -> "Downloaded databases" +
            (status.activatedAtMillis?.takeIf { it > 0 }?.let { " (activated ${formatDate(it)})" } ?: "")
        GeoDataOrigin.BUNDLED -> if (status.activePointerBroken) {
            "Built-in databases (the downloaded ones were not usable)"
        } else {
            "Built-in databases"
        }
        GeoDataOrigin.NONE -> "No databases available"
    }

    /** Whether the running VPN core process has the databases that are currently active. */
    fun describeCoreUsage(status: GeoDataStatus): String? {
        val active = status.datasetId ?: return null
        val core = status.coreDatasetId ?: return "Not used by the VPN core yet - it picks them up at the next Xray connection."
        return if (core == active) "In use by the VPN core." else "The VPN core is still on the previous databases; it switches at the next Xray connection."
    }

    fun formatBytes(bytes: Long): String = when {
        bytes < 1024L -> "$bytes B"
        bytes < 1024L * 1024L -> String.format(java.util.Locale.ROOT, "%.1f KB", bytes / 1024.0)
        else -> String.format(java.util.Locale.ROOT, "%.1f MB", bytes / (1024.0 * 1024.0))
    }

    private fun formatDate(millis: Long): String =
        DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT).format(Date(millis))
}
