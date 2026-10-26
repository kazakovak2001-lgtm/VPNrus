package net.pocvpn.client.geodata

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.ByteArrayInputStream
import java.io.File
import java.io.IOException
import java.net.SocketTimeoutException
import javax.net.ssl.SSLHandshakeException

class GeoDatabaseValidatorAndDownloaderTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private fun file(bytes: ByteArray): File = File(tmp.root, "f${System.nanoTime()}.bin").also { it.writeBytes(bytes) }

    private fun reason(result: GeoValidation) = (result as GeoValidation.Invalid).reason

    // ---- validator ----

    @Test
    fun `a real-shaped geoip and geosite are accepted`() {
        assertEquals(GeoValidation.Ok(3), GeoDatabaseValidator.validate(file(GeoTestData.geoipV1), GeoDatabaseKind.GEOIP))
        assertEquals(GeoValidation.Ok(2), GeoDatabaseValidator.validate(file(GeoTestData.geositeV1), GeoDatabaseKind.GEOSITE))
    }

    @Test
    fun `an empty file is rejected`() {
        assertEquals(GeoInvalidReason.EMPTY, reason(GeoDatabaseValidator.validate(file(ByteArray(0)), GeoDatabaseKind.GEOIP)))
    }

    @Test
    fun `an html error page served as a database is rejected`() {
        val html = "<!DOCTYPE html><html><head><title>404 Not Found</title></head><body>Not here</body></html>"
        assertEquals(GeoInvalidReason.LOOKS_LIKE_HTML, reason(GeoDatabaseValidator.validate(file(html.toByteArray()), GeoDatabaseKind.GEOSITE)))
        val withBomAndSpace = byteArrayOf(0xEF.toByte(), 0xBB.toByte(), 0xBF.toByte(), '\r'.code.toByte(), '\n'.code.toByte()) + "  <html>login</html>".toByteArray()
        assertEquals(GeoInvalidReason.LOOKS_LIKE_HTML, reason(GeoDatabaseValidator.validate(file(withBomAndSpace), GeoDatabaseKind.GEOIP)))
    }

    @Test
    fun `random bytes and json are rejected as not a database`() {
        assertEquals(GeoInvalidReason.NOT_A_DATABASE, reason(GeoDatabaseValidator.validate(file(ByteArray(4096) { (it * 31 + 7).toByte() }), GeoDatabaseKind.GEOIP)))
        assertEquals(GeoInvalidReason.NOT_A_DATABASE, reason(GeoDatabaseValidator.validate(file("{\"error\":\"denied\"}".toByteArray()), GeoDatabaseKind.GEOSITE)))
    }

    @Test
    fun `a truncated database is rejected`() {
        val whole = GeoTestData.geoipV2
        // A cut exactly between two entries is itself a well-formed (shorter) file; the structural check cannot
        // see that. The downloader catches it through Content-Length (see the "shorter than announced" test).
        for (cut in listOf(whole.size - 1, whole.size - 7, 5, 1)) {
            val result = GeoDatabaseValidator.validate(file(whole.copyOf(cut)), GeoDatabaseKind.GEOIP)
            assertTrue("cut at $cut was $result", result is GeoValidation.Invalid)
        }
    }

    @Test
    fun `trailing garbage after the entries is rejected`() {
        val result = GeoDatabaseValidator.validate(file(GeoTestData.geositeV1 + byteArrayOf(0x7F, 0x01, 0x02)), GeoDatabaseKind.GEOSITE)
        assertTrue(result is GeoValidation.Invalid)
    }

    @Test
    fun `geosite offered as geoip and the other way round is rejected as the wrong kind`() {
        assertEquals(GeoInvalidReason.WRONG_KIND, reason(GeoDatabaseValidator.validate(file(GeoTestData.geositeV1), GeoDatabaseKind.GEOIP)))
        assertEquals(GeoInvalidReason.WRONG_KIND, reason(GeoDatabaseValidator.validate(file(GeoTestData.geoipV1), GeoDatabaseKind.GEOSITE)))
    }

    // ---- downloader ----

    private val geoipUrl = "https://example.org/geoip.dat"
    private fun dest() = File(tmp.newFolder("work${System.nanoTime()}"), "geoip.dat.download")

    private fun download(
        http: FakeHttp,
        url: String = geoipUrl,
        dest: File = dest(),
        kind: GeoDatabaseKind = GeoDatabaseKind.GEOIP,
        isCancelled: () -> Boolean = { false },
        downloader: GeoDatabaseDownloader = GeoDatabaseDownloader(http),
    ): Pair<GeoDownloadResult, File> = downloader.download(url, kind, dest, isCancelled) to dest

    private fun failure(result: GeoDownloadResult): GeoDownloadResult.Failure {
        assertTrue("expected failure but was $result", result is GeoDownloadResult.Failure)
        return result as GeoDownloadResult.Failure
    }

    @Test
    fun `a successful download is stored validated and hashed`() {
        val http = FakeHttp().apply { serve(geoipUrl, GeoTestData.geoipV1) }
        val (result, dest) = download(http)
        val ok = result as GeoDownloadResult.Success
        assertEquals(GeoTestData.geoipV1.size.toLong(), ok.sizeBytes)
        assertEquals(3, ok.entries)
        assertArrayEquals(GeoTestData.geoipV1, dest.readBytes())
        assertEquals(java.security.MessageDigest.getInstance("SHA-256").digest(GeoTestData.geoipV1).joinToString("") { "%02x".format(it) }, ok.sha256)
    }

    @Test
    fun `an unknown content length is fine`() {
        val http = FakeHttp().apply { serve(geoipUrl, GeoTestData.geoipV1, declareLength = false) }
        assertTrue(download(http).first is GeoDownloadResult.Success)
    }

    @Test
    fun `a redirect chain over https is followed including relative targets`() {
        val http = FakeHttp().apply {
            status(geoipUrl, 302, "https://cdn.example.org/a")
            status("https://cdn.example.org/a", 301, "/b/geoip.dat")
            serve("https://cdn.example.org/b/geoip.dat", GeoTestData.geoipV1)
        }
        assertTrue(download(http).first is GeoDownloadResult.Success)
        assertEquals(listOf(geoipUrl, "https://cdn.example.org/a", "https://cdn.example.org/b/geoip.dat"), http.requested)
    }

    @Test
    fun `a redirect to http is refused and nothing is fetched over it`() {
        val http = FakeHttp().apply { status(geoipUrl, 302, "http://example.org/geoip.dat") }
        val (result, dest) = download(http)
        assertEquals(GeoDownloadFailure.REDIRECT_NOT_HTTPS, failure(result).kind)
        assertEquals(listOf(geoipUrl), http.requested)
        assertFalse(dest.exists())
    }

    @Test
    fun `a redirect loop ends with too many redirects`() {
        val http = FakeHttp().apply { status(geoipUrl, 302, geoipUrl) }
        assertEquals(GeoDownloadFailure.TOO_MANY_REDIRECTS, failure(download(http).first).kind)
        assertEquals(6, http.requested.size)
    }

    @Test
    fun `a redirect without target is an http error`() {
        val http = FakeHttp().apply { status(geoipUrl, 302, null) }
        assertEquals(GeoDownloadFailure.HTTP_ERROR, failure(download(http).first).kind)
    }

    @Test
    fun `http error statuses are reported with the status code`() {
        for (code in listOf(204, 304, 401, 403, 404, 429, 500, 503)) {
            val http = FakeHttp().apply { status(geoipUrl, code) }
            val (result, dest) = download(http)
            val f = failure(result)
            assertEquals("status $code", GeoDownloadFailure.HTTP_ERROR, f.kind)
            assertEquals(code, f.httpStatus)
            assertFalse(dest.exists())
        }
    }

    @Test
    fun `an invalid or non-https url never reaches the network`() {
        val http = FakeHttp()
        assertEquals(GeoDownloadFailure.INVALID_URL, failure(download(http, url = "http://example.org/geoip.dat").first).kind)
        assertEquals(GeoDownloadFailure.INVALID_URL, failure(download(http, url = "not a url").first).kind)
        assertEquals(GeoDownloadFailure.INVALID_URL, failure(download(http, url = "").first).kind)
        assertTrue(http.requested.isEmpty())
    }

    @Test
    fun `an empty body is rejected`() {
        val http = FakeHttp().apply { serve(geoipUrl, ByteArray(0)) }
        assertEquals(GeoDownloadFailure.EMPTY, failure(download(http).first).kind)
    }

    @Test
    fun `an html page is rejected by content type before any data is stored`() {
        val http = FakeHttp().apply { serve(geoipUrl, "<html>hi</html>".toByteArray(), contentType = "text/html; charset=utf-8") }
        val (result, dest) = download(http)
        val f = failure(result)
        assertEquals(GeoDownloadFailure.NOT_A_DATABASE, f.kind)
        assertEquals(GeoInvalidReason.LOOKS_LIKE_HTML, f.invalidReason)
        assertFalse(dest.exists())
    }

    @Test
    fun `an html page without a telling content type is caught by content`() {
        val http = FakeHttp().apply { serve(geoipUrl, "<!doctype html><html>Sign in</html>".toByteArray(), contentType = "application/octet-stream") }
        val (result, dest) = download(http)
        assertEquals(GeoInvalidReason.LOOKS_LIKE_HTML, failure(result).invalidReason)
        assertFalse("a rejected file must not be left behind", dest.exists())
    }

    @Test
    fun `a swapped database is rejected`() {
        val http = FakeHttp().apply { serve(geoipUrl, GeoTestData.geositeV1) }
        val f = failure(download(http).first)
        assertEquals(GeoDownloadFailure.NOT_A_DATABASE, f.kind)
        assertEquals(GeoInvalidReason.WRONG_KIND, f.invalidReason)
    }

    @Test
    fun `an interrupted download leaves no partial file`() {
        val http = FakeHttp().apply { breakMidway(geoipUrl, GeoTestData.geoipV1, afterBytes = 40) }
        val (result, dest) = download(http)
        assertEquals(GeoDownloadFailure.INTERRUPTED, failure(result).kind)
        assertFalse(dest.exists())
    }

    @Test
    fun `a body shorter than the announced length is an interrupted download`() {
        val http = FakeHttp().apply {
            handlers[geoipUrl] = { GeoHttpResponse(200, null, null, GeoTestData.geoipV1.size + 100L, ByteArrayInputStream(GeoTestData.geoipV1)) }
        }
        assertEquals(GeoDownloadFailure.INTERRUPTED, failure(download(http).first).kind)
    }

    @Test
    fun `network timeout and tls failures are told apart`() {
        val http = FakeHttp()
        http.fail(geoipUrl, SocketTimeoutException("slow"))
        assertEquals(GeoDownloadFailure.TIMEOUT, failure(download(http).first).kind)
        http.fail(geoipUrl, SSLHandshakeException("bad cert"))
        assertEquals(GeoDownloadFailure.TLS, failure(download(http).first).kind)
        http.fail(geoipUrl, IOException("unreachable"))
        assertEquals(GeoDownloadFailure.NETWORK, failure(download(http).first).kind)
    }

    @Test
    fun `an oversized file is refused by announced and by actual size`() {
        val big = GeoTestData.geoipV1
        val http = FakeHttp().apply { serve(geoipUrl, big) }
        val small = GeoDatabaseDownloader(http, maxBytes = (big.size - 1).toLong())
        assertEquals(GeoDownloadFailure.TOO_LARGE, failure(download(http, downloader = small).first).kind)
        http.serve(geoipUrl, big, declareLength = false)
        assertEquals(GeoDownloadFailure.TOO_LARGE, failure(download(http, downloader = small).first).kind)
    }

    @Test
    fun `not enough free space is reported before writing`() {
        val http = FakeHttp().apply { serve(geoipUrl, GeoTestData.geoipV1) }
        val noSpace = GeoDatabaseDownloader(http, usableSpace = { 1024L })
        val (result, dest) = download(http, downloader = noSpace)
        assertEquals(GeoDownloadFailure.INSUFFICIENT_SPACE, failure(result).kind)
        assertFalse(dest.exists())
    }

    @Test
    fun `a write that runs out of space is reported as insufficient space`() {
        val http = FakeHttp().apply {
            handlers[geoipUrl] = {
                GeoHttpResponse(200, null, null, -1L, object : java.io.InputStream() {
                    override fun read(): Int = throw IOException("write failed: ENOSPC (No space left on device)")
                    override fun read(b: ByteArray, off: Int, len: Int): Int = throw IOException("write failed: ENOSPC (No space left on device)")
                })
            }
        }
        assertEquals(GeoDownloadFailure.INSUFFICIENT_SPACE, failure(download(http).first).kind)
    }

    @Test
    fun `cancellation stops the download and removes the partial file`() {
        val http = FakeHttp().apply { serve(geoipUrl, GeoTestData.geoip(*Array(400) { "C$it" }, cidrsPerEntry = 20)) }
        var polls = 0
        val (result, dest) = download(http, isCancelled = { ++polls > 2 })
        assertEquals(GeoDownloadFailure.CANCELLED, failure(result).kind)
        assertFalse(dest.exists())
    }
}
