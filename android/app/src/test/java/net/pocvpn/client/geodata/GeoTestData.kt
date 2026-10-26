package net.pocvpn.client.geodata

import net.pocvpn.client.vpn.xray.GeoAssetSource
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.FileNotFoundException
import java.io.IOException
import java.io.InputStream
import java.net.URL

/** Builders for tiny but structurally real V2Ray `geoip.dat` / `geosite.dat` files (router.proto wire format). */
object GeoTestData {

    fun varint(value: Long): ByteArray {
        val out = ByteArrayOutputStream()
        var v = value
        while (v >= 0x80) {
            out.write(((v and 0x7f) or 0x80).toInt())
            v = v ushr 7
        }
        out.write(v.toInt())
        return out.toByteArray()
    }

    /** field with wire type 2 (length-delimited) */
    fun lenField(field: Int, payload: ByteArray): ByteArray =
        varint(((field shl 3) or 2).toLong()) + varint(payload.size.toLong()) + payload

    fun varintField(field: Int, value: Long): ByteArray = varint((field shl 3).toLong()) + varint(value)

    /** CIDR { ip = 1 (bytes), prefix = 2 (varint) } - first tag byte is 0x0A */
    private fun cidr(seed: Int): ByteArray =
        lenField(1, byteArrayOf(10, seed.toByte(), 0, 0)) + varintField(2, 16)

    /** Domain { type = 1 (varint, omitted when 0), value = 2 (string) } - first tag byte is 0x08 or 0x12, never 0x0A */
    private fun domain(name: String, withType: Boolean): ByteArray =
        (if (withType) varintField(1, 2) else ByteArray(0)) + lenField(2, name.toByteArray())

    fun geoip(vararg codes: String, cidrsPerEntry: Int = 3): ByteArray {
        val out = ByteArrayOutputStream()
        for (code in codes) {
            val entry = ByteArrayOutputStream()
            entry.write(lenField(1, code.toByteArray()))
            for (i in 0 until cidrsPerEntry) entry.write(lenField(2, cidr(i)))
            out.write(lenField(1, entry.toByteArray()))
        }
        return out.toByteArray()
    }

    fun geosite(vararg codes: String, domainsPerEntry: Int = 3): ByteArray {
        val out = ByteArrayOutputStream()
        for (code in codes) {
            val entry = ByteArrayOutputStream()
            entry.write(lenField(1, code.toByteArray()))
            for (i in 0 until domainsPerEntry) entry.write(lenField(2, domain("host$i.$code.example", withType = i % 2 == 0)))
            out.write(lenField(1, entry.toByteArray()))
        }
        return out.toByteArray()
    }

    val geoipV1: ByteArray = geoip("CN", "RU", "US")
    val geoipV2: ByteArray = geoip("CN", "RU", "US", "DE")
    val geositeV1: ByteArray = geosite("GOOGLE", "YANDEX")
    val geositeV2: ByteArray = geosite("GOOGLE", "YANDEX", "CN")
}

/** Bundled-asset stand-in. */
class FakeBundled(
    private val geoip: ByteArray = GeoTestData.geoipV1,
    private val geosite: ByteArray = GeoTestData.geositeV1,
) : GeoAssetSource {
    override fun open(name: String): InputStream = when (name) {
        "geoip.dat" -> ByteArrayInputStream(geoip)
        "geosite.dat" -> ByteArrayInputStream(geosite)
        else -> throw FileNotFoundException(name)
    }
}

/** Scriptable HTTP transport: one handler per URL string. Records every requested URL. */
class FakeHttp : GeoHttp {
    val handlers = mutableMapOf<String, () -> GeoHttpResponse>()
    val requested = mutableListOf<String>()

    fun serve(url: String, body: ByteArray, contentType: String? = "application/octet-stream", declareLength: Boolean = true) {
        handlers[url] = { GeoHttpResponse(200, null, contentType, if (declareLength) body.size.toLong() else -1L, ByteArrayInputStream(body)) }
    }

    fun status(url: String, code: Int, location: String? = null) {
        handlers[url] = { GeoHttpResponse(code, location, null, 0L, ByteArrayInputStream(ByteArray(0))) }
    }

    fun fail(url: String, error: IOException) {
        handlers[url] = { throw error }
    }

    /** Serves [body] but the stream breaks with an IOException after [afterBytes] bytes. */
    fun breakMidway(url: String, body: ByteArray, afterBytes: Int) {
        handlers[url] = {
            GeoHttpResponse(200, null, null, body.size.toLong(), object : InputStream() {
                private var pos = 0
                override fun read(): Int {
                    val one = ByteArray(1)
                    return if (read(one, 0, 1) < 0) -1 else one[0].toInt() and 0xff
                }

                override fun read(b: ByteArray, off: Int, len: Int): Int {
                    if (pos >= afterBytes) throw IOException("connection reset")
                    val n = minOf(len, afterBytes - pos, body.size - pos)
                    System.arraycopy(body, pos, b, off, n)
                    pos += n
                    return n
                }
            })
        }
    }

    override fun get(url: URL): GeoHttpResponse {
        requested += url.toString()
        val handler = handlers[url.toString()] ?: throw IOException("no handler for ${url.host}")
        return handler()
    }
}
