package net.pocvpn.client.geodata

import org.json.JSONObject
import java.io.File
import java.io.IOException
import java.net.URI
import java.net.URISyntaxException
import java.nio.file.Files
import java.nio.file.StandardCopyOption

/** The two databases, each with its own download URL. An empty URL means "not configured" for that file. */
data class GeoDataSettings(val geoipUrl: String = "", val geositeUrl: String = "") {
    fun urlFor(kind: GeoDatabaseKind): String = when (kind) {
        GeoDatabaseKind.GEOIP -> geoipUrl
        GeoDatabaseKind.GEOSITE -> geositeUrl
    }

    val hasAnyUrl: Boolean get() = geoipUrl.isNotBlank() || geositeUrl.isNotBlank()
}

enum class GeoDatabaseKind(val fileName: String, val label: String) {
    GEOIP("geoip.dat", "geoip.dat"),
    GEOSITE("geosite.dat", "geosite.dat"),
}

enum class GeoUrlProblem {
    TOO_LONG,
    MALFORMED,
    NOT_HTTPS,
    NO_HOST,
    HAS_CREDENTIALS,
}

sealed class GeoUrlValidation {
    /** Blank input: the file is simply not configured. */
    object Empty : GeoUrlValidation()

    /** [url] is the trimmed, normalized absolute HTTPS URL. */
    data class Valid(val url: String) : GeoUrlValidation()

    data class Invalid(val problem: GeoUrlProblem) : GeoUrlValidation()
}

/**
 * HTTPS only - the project has no approved cleartext exception for downloads, so `http://` is rejected
 * outright (it would also let anyone on the path replace a database). User info in the URL
 * (`https://user:pass@host/...`) is rejected so credentials are never stored in settings or shown in the UI.
 */
object GeoUrlValidator {
    const val MAX_LENGTH = 2048

    fun validate(raw: String): GeoUrlValidation {
        val text = raw.trim()
        if (text.isEmpty()) return GeoUrlValidation.Empty
        if (text.length > MAX_LENGTH) return GeoUrlValidation.Invalid(GeoUrlProblem.TOO_LONG)
        val uri = try {
            URI(text)
        } catch (e: URISyntaxException) {
            return GeoUrlValidation.Invalid(GeoUrlProblem.MALFORMED)
        }
        val scheme = uri.scheme ?: return GeoUrlValidation.Invalid(GeoUrlProblem.MALFORMED)
        if (!scheme.equals("https", ignoreCase = true)) return GeoUrlValidation.Invalid(GeoUrlProblem.NOT_HTTPS)
        if (uri.userInfo != null) return GeoUrlValidation.Invalid(GeoUrlProblem.HAS_CREDENTIALS)
        val host = uri.host
        if (host.isNullOrBlank()) return GeoUrlValidation.Invalid(GeoUrlProblem.NO_HOST)
        return GeoUrlValidation.Valid(uri.toString())
    }
}

interface GeoDataSettingsStore {
    fun read(): GeoDataSettings

    @Throws(IOException::class)
    fun write(settings: GeoDataSettings)
}

/**
 * Device-local, in the same style as the other policy stores (see `FileRoutingModeStore`): a small file in
 * the no-backup directory, replaced atomically. A missing or corrupt file reads as "nothing configured" and
 * never throws, so a broken settings file cannot affect VPN startup (the core does not read these URLs at all).
 */
class FileGeoDataSettingsStore(
    private val directory: File,
    private val fileName: String = "geodata_settings.json",
) : GeoDataSettingsStore {

    private val file: File get() = File(directory, fileName)

    override fun read(): GeoDataSettings {
        if (!file.isFile) return GeoDataSettings()
        return try {
            val json = JSONObject(file.readText(Charsets.UTF_8))
            GeoDataSettings(json.optString("geoipUrl"), json.optString("geositeUrl"))
        } catch (e: Exception) {
            GeoDataSettings()
        }
    }

    override fun write(settings: GeoDataSettings) {
        directory.mkdirs()
        val tmp = File(directory, "$fileName.tmp")
        val json = JSONObject().put("geoipUrl", settings.geoipUrl).put("geositeUrl", settings.geositeUrl)
        tmp.writeText(json.toString(), Charsets.UTF_8)
        try {
            Files.move(tmp.toPath(), file.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
        } catch (e: IOException) {
            tmp.delete()
            throw IOException("failed to atomically replace geo data settings", e)
        }
    }
}

/** In-memory store for tests and previews. */
class InMemoryGeoDataSettingsStore(private var value: GeoDataSettings = GeoDataSettings()) : GeoDataSettingsStore {
    override fun read(): GeoDataSettings = value
    override fun write(settings: GeoDataSettings) {
        value = settings
    }
}
