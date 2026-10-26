package net.pocvpn.client.geodata

import java.io.BufferedInputStream
import java.io.EOFException
import java.io.File
import java.io.IOException
import java.io.InputStream

enum class GeoInvalidReason {
    EMPTY,
    LOOKS_LIKE_HTML,
    NOT_A_DATABASE,
    NO_ENTRIES,
    WRONG_KIND,
}

sealed class GeoValidation {
    data class Ok(val entries: Int) : GeoValidation()
    data class Invalid(val reason: GeoInvalidReason) : GeoValidation()
}

/**
 * Structural check that a downloaded file really is a V2Ray-style `geoip.dat` / `geosite.dat`, done before
 * anything is activated. It is not a semantic check (it cannot know whether the lists are the ones the user
 * wanted) - it rejects the usual wrong answers: an empty body, an HTML error/login page served with status
 * 200, a truncated or random file, and one database offered where the other is expected.
 *
 * Format used (public V2Ray/Xray `router.proto`, the same wire format both databases use):
 *
 * - top level: repeated field 1 (length-delimited) = one `GeoIP` / `GeoSite` entry;
 * - each entry starts with field 1 = the code string (`CN`, `GOOGLE`, ...), then more fields; field 2 holds the
 *   repeated sub-messages: `CIDR` for geoip (whose first field is always `ip`, field 1 bytes -> tag `0x0A`)
 *   or `Domain` for geosite (whose first written field is `type` (tag `0x08`) or `value` (tag `0x12`) - never `0x0A`).
 *
 * The whole file is walked to its end (lengths must add up exactly), so a truncated download fails.
 */
object GeoDatabaseValidator {

    private const val MAX_ENTRY_BYTES = 256L * 1024 * 1024
    private const val MAX_CODE_LENGTH = 128
    private const val SNIFF_BYTES = 512

    fun validate(file: File, kind: GeoDatabaseKind): GeoValidation {
        val length = file.length()
        if (length <= 0L) return GeoValidation.Invalid(GeoInvalidReason.EMPTY)
        return try {
            file.inputStream().use { raw ->
                val input = BufferedInputStream(raw, 64 * 1024)
                input.mark(SNIFF_BYTES + 8)
                val head = ByteArray(SNIFF_BYTES)
                val n = input.read(head)
                input.reset()
                if (looksLikeHtml(head, maxOf(n, 0))) return GeoValidation.Invalid(GeoInvalidReason.LOOKS_LIKE_HTML)
                walk(input, length, kind)
            }
        } catch (e: IOException) {
            GeoValidation.Invalid(GeoInvalidReason.NOT_A_DATABASE)
        }
    }

    private fun looksLikeHtml(head: ByteArray, n: Int): Boolean {
        var i = 0
        // optional UTF-8 BOM, then whitespace
        if (n >= 3 && head[0] == 0xEF.toByte() && head[1] == 0xBB.toByte() && head[2] == 0xBF.toByte()) i = 3
        while (i < n && (head[i] == ' '.code.toByte() || head[i] == '\t'.code.toByte() || head[i] == '\r'.code.toByte() || head[i] == '\n'.code.toByte())) i++
        return i < n && head[i] == '<'.code.toByte()
    }

    private class Reader(private val input: InputStream) {
        var position = 0L
            private set

        fun readByte(): Int {
            val b = input.read()
            if (b < 0) throw EOFException()
            position++
            return b
        }

        /** -1 when the stream ends before the first byte; EOFException when it ends inside the value. */
        fun readVarintOrEof(): Long {
            val first = input.read()
            if (first < 0) return -1
            position++
            var result = (first and 0x7f).toLong()
            if (first < 0x80) return result
            var shift = 7
            while (true) {
                if (shift > 63) throw IOException("varint too long")
                val b = readByte()
                result = result or ((b and 0x7f).toLong() shl shift)
                if (b < 0x80) return result
                shift += 7
            }
        }

        fun readVarint(): Long = readVarintOrEof().also { if (it < 0) throw EOFException() }

        fun skip(count: Long) {
            var left = count
            val buffer = ByteArray(minOf(8192L, maxOf(count, 1L)).toInt())
            while (left > 0) {
                val got = input.read(buffer, 0, minOf(left, buffer.size.toLong()).toInt())
                if (got < 0) throw EOFException()
                left -= got
                position += got
            }
        }

        fun readBytes(count: Int): ByteArray {
            val out = ByteArray(count)
            var done = 0
            while (done < count) {
                val got = input.read(out, done, count - done)
                if (got < 0) throw EOFException()
                done += got
            }
            position += count
            return out
        }
    }

    private fun walk(input: InputStream, fileLength: Long, kind: GeoDatabaseKind): GeoValidation {
        val reader = Reader(input)
        var entries = 0
        try {
            while (true) {
                val tag = reader.readVarintOrEof()
                if (tag < 0) break
                if (tag != 0x0AL) return GeoValidation.Invalid(GeoInvalidReason.NOT_A_DATABASE)
                val length = reader.readVarint()
                if (length <= 0L || length > MAX_ENTRY_BYTES || reader.position + length > fileLength) {
                    return GeoValidation.Invalid(GeoInvalidReason.NOT_A_DATABASE)
                }
                val verdict = walkEntry(reader, length, kind)
                if (verdict != null) return GeoValidation.Invalid(verdict)
                entries++
            }
        } catch (e: IOException) {
            return GeoValidation.Invalid(GeoInvalidReason.NOT_A_DATABASE)
        }
        return if (entries == 0) GeoValidation.Invalid(GeoInvalidReason.NO_ENTRIES) else GeoValidation.Ok(entries)
    }

    /** Returns null when the entry is well-formed, otherwise the reason it is not. */
    private fun walkEntry(reader: Reader, length: Long, kind: GeoDatabaseKind): GeoInvalidReason? {
        val end = reader.position + length
        // first field: the code string
        if (reader.readVarint() != 0x0AL) return GeoInvalidReason.NOT_A_DATABASE
        val codeLength = reader.readVarint()
        if (codeLength < 1 || codeLength > MAX_CODE_LENGTH || reader.position + codeLength > end) return GeoInvalidReason.NOT_A_DATABASE
        val code = reader.readBytes(codeLength.toInt())
        if (code.any { it < 0x20 || it > 0x7E }) return GeoInvalidReason.NOT_A_DATABASE

        while (reader.position < end) {
            val tag = reader.readVarint()
            val field = tag ushr 3
            when ((tag and 7L).toInt()) {
                0 -> reader.readVarint()
                1 -> reader.skip(8)
                5 -> reader.skip(4)
                2 -> {
                    val len = reader.readVarint()
                    if (len < 0 || reader.position + len > end) return GeoInvalidReason.NOT_A_DATABASE
                    if (field == 2L && len > 0) {
                        val first = reader.readByte()
                        val looksLikeCidr = first == 0x0A
                        if (kind == GeoDatabaseKind.GEOIP && !looksLikeCidr) return GeoInvalidReason.WRONG_KIND
                        if (kind == GeoDatabaseKind.GEOSITE && looksLikeCidr) return GeoInvalidReason.WRONG_KIND
                        reader.skip(len - 1)
                    } else {
                        reader.skip(len)
                    }
                }
                else -> return GeoInvalidReason.NOT_A_DATABASE
            }
        }
        return if (reader.position == end) null else GeoInvalidReason.NOT_A_DATABASE
    }
}
