package net.pocvpn.client.geodata

import java.io.Closeable
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream
import java.net.MalformedURLException
import java.net.SocketTimeoutException
import java.net.URL
import java.security.MessageDigest
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLException

/** One HTTP response, already past the headers. Redirects are NOT followed by the transport. */
class GeoHttpResponse(
    val status: Int,
    val location: String?,
    val contentType: String?,
    /** -1 when unknown. */
    val contentLength: Long,
    val body: InputStream,
    private val onClose: () -> Unit = {},
) : Closeable {
    override fun close() {
        try {
            body.close()
        } catch (ignored: IOException) {
        }
        onClose()
    }
}

fun interface GeoHttp {
    @Throws(IOException::class)
    fun get(url: URL): GeoHttpResponse
}

/**
 * The real transport: platform HTTPS with the platform trust store only (no custom TrustManager, no hostname
 * verifier override, no cleartext). Redirects are left to [GeoDatabaseDownloader] so every hop is checked to
 * still be HTTPS. `Accept-Encoding: identity` keeps the byte count and `Content-Length` honest (no transparent gzip).
 */
class HttpsGeoHttp(
    private val connectTimeoutMs: Int = 15_000,
    private val readTimeoutMs: Int = 30_000,
) : GeoHttp {
    override fun get(url: URL): GeoHttpResponse {
        if (!url.protocol.equals("https", ignoreCase = true)) throw MalformedURLException("not https")
        val connection = url.openConnection() as HttpsURLConnection
        connection.instanceFollowRedirects = false
        connection.connectTimeout = connectTimeoutMs
        connection.readTimeout = readTimeoutMs
        connection.requestMethod = "GET"
        connection.useCaches = false
        connection.setRequestProperty("Accept-Encoding", "identity")
        connection.setRequestProperty("User-Agent", "NovaVPN-GeoData")
        try {
            val status = connection.responseCode
            val stream = if (status in 200..299) connection.inputStream else (connection.errorStream ?: java.io.ByteArrayInputStream(ByteArray(0)))
            return GeoHttpResponse(
                status = status,
                location = connection.getHeaderField("Location"),
                contentType = connection.contentType,
                contentLength = connection.contentLengthLong,
                body = stream,
                onClose = { connection.disconnect() },
            )
        } catch (e: IOException) {
            connection.disconnect()
            throw e
        }
    }
}

enum class GeoDownloadFailure {
    INVALID_URL,
    NETWORK,
    TIMEOUT,
    TLS,
    HTTP_ERROR,
    TOO_MANY_REDIRECTS,
    REDIRECT_NOT_HTTPS,
    TOO_LARGE,
    INSUFFICIENT_SPACE,
    INTERRUPTED,
    EMPTY,
    NOT_A_DATABASE,
    CANCELLED,
}

sealed class GeoDownloadResult {
    data class Success(val file: File, val sizeBytes: Long, val sha256: String, val entries: Int) : GeoDownloadResult()

    /** [detail] is a short human-readable line without the URL; [httpStatus] is set for [GeoDownloadFailure.HTTP_ERROR]. */
    data class Failure(
        val kind: GeoDownloadFailure,
        val detail: String,
        val httpStatus: Int? = null,
        val invalidReason: GeoInvalidReason? = null,
    ) : GeoDownloadResult()
}

/**
 * Downloads one database into [dest] (a temporary file chosen by the caller) and validates it, or fails
 * without leaving a file behind. It only ever writes [dest]; the databases in use are never touched here.
 *
 * Limits: at most [maxRedirects] hops, each of which must be HTTPS (an HTTPS -> HTTP downgrade is refused);
 * at most [maxBytes] bytes; enough free space is required before writing ([usableSpace]).
 */
class GeoDatabaseDownloader(
    private val http: GeoHttp,
    private val maxBytes: Long = MAX_DATABASE_BYTES,
    private val maxRedirects: Int = 5,
    private val usableSpace: (File) -> Long = { it.usableSpace },
) {

    fun download(
        rawUrl: String,
        kind: GeoDatabaseKind,
        dest: File,
        isCancelled: () -> Boolean = { false },
        onProgress: (bytesDone: Long, bytesTotal: Long) -> Unit = { _, _ -> },
    ): GeoDownloadResult {
        val result = try {
            downloadInternal(rawUrl, kind, dest, isCancelled, onProgress)
        } catch (t: Throwable) {
            dest.delete()
            throw t
        }
        if (result is GeoDownloadResult.Failure) dest.delete()
        return result
    }

    private fun downloadInternal(
        rawUrl: String,
        kind: GeoDatabaseKind,
        dest: File,
        isCancelled: () -> Boolean,
        onProgress: (Long, Long) -> Unit,
    ): GeoDownloadResult {
        val first = when (val v = GeoUrlValidator.validate(rawUrl)) {
            is GeoUrlValidation.Valid -> v.url
            else -> return GeoDownloadResult.Failure(GeoDownloadFailure.INVALID_URL, "The URL is not a valid HTTPS URL.")
        }
        var url = try {
            URL(first)
        } catch (e: MalformedURLException) {
            return GeoDownloadResult.Failure(GeoDownloadFailure.INVALID_URL, "The URL is not a valid HTTPS URL.")
        }

        var redirects = 0
        while (true) {
            if (isCancelled()) return GeoDownloadResult.Failure(GeoDownloadFailure.CANCELLED, "Cancelled.")
            val response = try {
                http.get(url)
            } catch (e: SocketTimeoutException) {
                return GeoDownloadResult.Failure(GeoDownloadFailure.TIMEOUT, "The server did not respond in time.")
            } catch (e: SSLException) {
                return GeoDownloadResult.Failure(GeoDownloadFailure.TLS, "A secure (TLS) connection could not be established.")
            } catch (e: IOException) {
                return GeoDownloadResult.Failure(GeoDownloadFailure.NETWORK, "The server could not be reached.")
            }
            response.use { r ->
                when (r.status) {
                    200 -> return receive(r, kind, dest, isCancelled, onProgress)
                    301, 302, 303, 307, 308 -> {
                        val location = r.location
                            ?: return GeoDownloadResult.Failure(GeoDownloadFailure.HTTP_ERROR, "The server sent a redirect without a target.", r.status)
                        if (++redirects > maxRedirects) {
                            return GeoDownloadResult.Failure(GeoDownloadFailure.TOO_MANY_REDIRECTS, "Too many redirects.")
                        }
                        val next = try {
                            URL(url, location)
                        } catch (e: MalformedURLException) {
                            return GeoDownloadResult.Failure(GeoDownloadFailure.INVALID_URL, "The server sent an invalid redirect.")
                        }
                        if (!next.protocol.equals("https", ignoreCase = true)) {
                            return GeoDownloadResult.Failure(GeoDownloadFailure.REDIRECT_NOT_HTTPS, "The server redirected to a non-HTTPS address; refused.")
                        }
                        url = next
                    }
                    else -> return GeoDownloadResult.Failure(GeoDownloadFailure.HTTP_ERROR, "The server answered with HTTP ${r.status}.", r.status)
                }
            }
        }
    }

    private fun receive(
        response: GeoHttpResponse,
        kind: GeoDatabaseKind,
        dest: File,
        isCancelled: () -> Boolean,
        onProgress: (Long, Long) -> Unit,
    ): GeoDownloadResult {
        if (response.contentType?.contains("text/html", ignoreCase = true) == true) {
            return GeoDownloadResult.Failure(
                GeoDownloadFailure.NOT_A_DATABASE,
                "The server returned a web page, not a database.",
                invalidReason = GeoInvalidReason.LOOKS_LIKE_HTML,
            )
        }
        val declared = response.contentLength
        if (declared > maxBytes) return GeoDownloadResult.Failure(GeoDownloadFailure.TOO_LARGE, "The file is larger than the allowed ${maxBytes / (1024 * 1024)} MB.")
        val parent = dest.absoluteFile.parentFile
        if (parent != null) {
            parent.mkdirs()
            // download + a second copy while publishing the dataset, plus a little slack
            val needed = (if (declared > 0) declared else MIN_UNKNOWN_SIZE_SPACE) * 2 + SLACK_BYTES
            if (usableSpace(parent) < needed) {
                return GeoDownloadResult.Failure(GeoDownloadFailure.INSUFFICIENT_SPACE, "Not enough free storage space.")
            }
        }
        dest.delete()

        val md = MessageDigest.getInstance("SHA-256")
        var total = 0L
        try {
            FileOutputStream(dest).use { out ->
                val buffer = ByteArray(64 * 1024)
                while (true) {
                    if (isCancelled()) return GeoDownloadResult.Failure(GeoDownloadFailure.CANCELLED, "Cancelled.")
                    val n = response.body.read(buffer)
                    if (n < 0) break
                    total += n
                    if (total > maxBytes) return GeoDownloadResult.Failure(GeoDownloadFailure.TOO_LARGE, "The file is larger than the allowed ${maxBytes / (1024 * 1024)} MB.")
                    md.update(buffer, 0, n)
                    out.write(buffer, 0, n)
                    onProgress(total, declared)
                }
                out.flush()
                out.fd.sync()
            }
        } catch (e: SocketTimeoutException) {
            return GeoDownloadResult.Failure(GeoDownloadFailure.TIMEOUT, "The connection stalled while downloading.")
        } catch (e: IOException) {
            return if (isOutOfSpace(e)) {
                GeoDownloadResult.Failure(GeoDownloadFailure.INSUFFICIENT_SPACE, "Not enough free storage space.")
            } else {
                GeoDownloadResult.Failure(GeoDownloadFailure.INTERRUPTED, "The download was interrupted.")
            }
        }
        if (total == 0L) return GeoDownloadResult.Failure(GeoDownloadFailure.EMPTY, "The server returned an empty file.")
        if (declared > 0 && total != declared) {
            return GeoDownloadResult.Failure(GeoDownloadFailure.INTERRUPTED, "The download ended early ($total of $declared bytes).")
        }
        return when (val v = GeoDatabaseValidator.validate(dest, kind)) {
            is GeoValidation.Invalid -> GeoDownloadResult.Failure(
                GeoDownloadFailure.NOT_A_DATABASE,
                "The downloaded file is not a valid ${kind.label} database.",
                invalidReason = v.reason,
            )
            is GeoValidation.Ok ->
                GeoDownloadResult.Success(dest, total, md.digest().joinToString("") { "%02x".format(it) }, v.entries)
        }
    }

    private fun isOutOfSpace(e: IOException): Boolean {
        val text = (e.message ?: "") + (e.cause?.message ?: "")
        return text.contains("ENOSPC", ignoreCase = true) || text.contains("No space left", ignoreCase = true)
    }

    companion object {
        /** Real databases are ~18 MB and ~9 MB; this is a generous ceiling against a runaway or hostile response. */
        const val MAX_DATABASE_BYTES: Long = 128L * 1024 * 1024
        private const val MIN_UNKNOWN_SIZE_SPACE: Long = 64L * 1024 * 1024
        private const val SLACK_BYTES: Long = 8L * 1024 * 1024
    }
}
