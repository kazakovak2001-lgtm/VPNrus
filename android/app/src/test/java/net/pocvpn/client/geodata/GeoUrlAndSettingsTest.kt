package net.pocvpn.client.geodata

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

class GeoUrlAndSettingsTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private fun problem(raw: String): GeoUrlProblem =
        (GeoUrlValidator.validate(raw) as GeoUrlValidation.Invalid).problem

    // ---- URL validation ----

    @Test
    fun `a plain https address is accepted and trimmed`() {
        val v = GeoUrlValidator.validate("  https://example.org/files/geoip.dat  ")
        assertEquals(GeoUrlValidation.Valid("https://example.org/files/geoip.dat"), v)
    }

    @Test
    fun `query strings and ports are accepted`() {
        assertTrue(GeoUrlValidator.validate("https://cdn.example.org:8443/g.dat?v=2&x=y") is GeoUrlValidation.Valid)
    }

    @Test
    fun `blank input means not configured`() {
        assertEquals(GeoUrlValidation.Empty, GeoUrlValidator.validate(""))
        assertEquals(GeoUrlValidation.Empty, GeoUrlValidator.validate("   \n"))
    }

    @Test
    fun `http is refused - there is no approved cleartext exception`() {
        assertEquals(GeoUrlProblem.NOT_HTTPS, problem("http://example.org/geoip.dat"))
        assertEquals(GeoUrlProblem.NOT_HTTPS, problem("ftp://example.org/geoip.dat"))
        assertEquals(GeoUrlProblem.NOT_HTTPS, problem("file:///sdcard/geoip.dat"))
    }

    @Test
    fun `scheme-less and malformed addresses are refused`() {
        assertEquals(GeoUrlProblem.MALFORMED, problem("example.org/geoip.dat"))
        assertEquals(GeoUrlProblem.MALFORMED, problem("https://exa mple.org/geoip.dat"))
        assertEquals(GeoUrlProblem.MALFORMED, problem("https://example.org/a b"))
    }

    @Test
    fun `an address without host is refused`() {
        assertEquals(GeoUrlProblem.NO_HOST, problem("https:///geoip.dat"))
    }

    @Test
    fun `credentials in the address are refused`() {
        assertEquals(GeoUrlProblem.HAS_CREDENTIALS, problem("https://user:secret@example.org/geoip.dat"))
        assertEquals(GeoUrlProblem.HAS_CREDENTIALS, problem("https://user@example.org/geoip.dat"))
    }

    @Test
    fun `overlong addresses are refused`() {
        assertEquals(GeoUrlProblem.TOO_LONG, problem("https://example.org/" + "a".repeat(GeoUrlValidator.MAX_LENGTH)))
    }

    // ---- settings persistence ----

    @Test
    fun `settings round-trip and the two urls are independent`() {
        val store = FileGeoDataSettingsStore(tmp.newFolder("nobackup"))
        store.write(GeoDataSettings("https://a.example/geoip.dat", "https://b.other.example/sub/geosite.dat"))
        val read = FileGeoDataSettingsStore(File(tmp.root, "nobackup")).read()
        assertEquals("https://a.example/geoip.dat", read.geoipUrl)
        assertEquals("https://b.other.example/sub/geosite.dat", read.geositeUrl)
    }

    @Test
    fun `writing only one url leaves the other empty`() {
        val store = FileGeoDataSettingsStore(tmp.newFolder("nobackup"))
        store.write(GeoDataSettings(geoipUrl = "https://a.example/geoip.dat"))
        val read = store.read()
        assertEquals("https://a.example/geoip.dat", read.urlFor(GeoDatabaseKind.GEOIP))
        assertEquals("", read.urlFor(GeoDatabaseKind.GEOSITE))
        assertTrue(read.hasAnyUrl)
    }

    @Test
    fun `missing or corrupt settings read as nothing configured and never throw`() {
        val dir = tmp.newFolder("nobackup")
        val store = FileGeoDataSettingsStore(dir)
        assertEquals(GeoDataSettings(), store.read())
        File(dir, "geodata_settings.json").writeText("{ this is not json")
        assertEquals(GeoDataSettings(), store.read())
        assertFalse(store.read().hasAnyUrl)
    }

    @Test
    fun `overwriting leaves no temp file behind`() {
        val dir = tmp.newFolder("nobackup")
        val store = FileGeoDataSettingsStore(dir)
        store.write(GeoDataSettings("https://a.example/1", ""))
        store.write(GeoDataSettings("https://a.example/2", "https://b.example/2"))
        assertEquals(listOf("geodata_settings.json"), dir.list()!!.toList())
        assertEquals("https://a.example/2", store.read().geoipUrl)
    }
}
