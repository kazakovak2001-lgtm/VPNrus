package net.pocvpn.client.debug.geoexp

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The error strings below follow the format derived from the pinned Xray-core
 * sources: Error() joins message and inner error with " > " (outermost first);
 * geodata wraps with "failed to open <file>" / "failed to check|load code
 * <CODE> from <file>" and the inner cause (a stat error, or io.EOF = "EOF").
 * They are modelled on the source, not observed on a device.
 */
class GeoExperimentSpecTest {

    private val statMissing = "stat /data/user/0/net.pocvpn.client/no_backup/xray-assets/%s: no such file or directory"
    private fun openAbsent(file: String, rule: String = "geoip:PRIVATE") =
        "illegal ip rule: $rule > geodata: failed to open $file > ${statMissing.format(file)}"

    private fun codeAbsent(file: String, code: String = "NOSUCHCODE", cause: String = "EOF", verb: String = "check") =
        "illegal ip rule: geoip:$code > geodata: failed to $verb code $code from $file > $cause"

    private fun judge(case: GeoCase, mode: Mode, o: GeoExperimentSpec.Observation) = GeoExperimentSpec.judge(case, mode, o)
    private fun failed(message: String) = GeoExperimentSpec.Observation(errorMessage = message)
    private val started = GeoExperimentSpec.Observation(startedOk = true, runningAfterStart = true)

    // ---- config ----

    @Test
    fun `every config is blackhole only with no inbound dns or freedom`() {
        for (case in GeoCase.entries) {
            val text = GeoExperimentSpec.config(case) ?: continue
            val root = JSONObject(text)
            val outbounds = root.getJSONArray("outbounds")
            assertEquals(1, outbounds.length())
            assertEquals("blackhole", outbounds.getJSONObject(0).getString("protocol"))
            assertFalse(root.has("inbounds"))
            assertFalse(root.has("dns"))
            assertFalse(root.has("api"))
            assertFalse(text.contains("freedom"))
            assertTrue(root.has("stats"))
            if (root.has("routing")) {
                val rules = root.getJSONObject("routing").getJSONArray("rules")
                assertEquals(1, rules.length())
                assertEquals(GeoExperimentSpec.OUTBOUND_TAG, rules.getJSONObject(0).getString("outboundTag"))
            }
        }
    }

    @Test
    fun `E0 has no config and E1 has no routing`() {
        assertNull(GeoExperimentSpec.config(GeoCase.E0))
        assertFalse(JSONObject(GeoExperimentSpec.config(GeoCase.E1)!!).has("routing"))
    }

    @Test
    fun `rules reference the expected database entries`() {
        fun first(case: GeoCase, key: String, override: String? = null) =
            JSONObject(GeoExperimentSpec.config(case, override)!!).getJSONObject("routing")
                .getJSONArray("rules").getJSONObject(0).getJSONArray(key).getString(0)
        assertEquals("geoip:private", first(GeoCase.E2, "ip"))
        assertEquals("geosite:google", first(GeoCase.E3, "domain"))
        assertEquals("geoip:cn", first(GeoCase.E2, "ip", "cn"))
        assertEquals("geoip:NOSUCHCODE", first(GeoCase.E4, "ip"))
        assertEquals("geosite:NOSUCHCODE", first(GeoCase.E5, "domain"))
        assertEquals("ext:nosuchfile.dat:private", first(GeoCase.E6, "ip"))
    }

    @Test
    fun `sanitizeCode accepts a restricted alphabet only`() {
        assertEquals("CN", GeoExperimentSpec.sanitizeCode("CN"))
        assertNull(GeoExperimentSpec.sanitizeCode("cn;rm"))
        assertNull(GeoExperimentSpec.sanitizeCode("a b"))
        assertNull(GeoExperimentSpec.sanitizeCode(""))
        assertNull(GeoExperimentSpec.sanitizeCode(null))
        assertNull(GeoExperimentSpec.sanitizeCode("x".repeat(41)))
    }

    // ---- parsing / classification ----

    @Test
    fun `classify lets damage markers win over the code wrapper`() {
        assertEquals(GeoErrorClass.NONE, GeoExperimentSpec.classify(null))
        assertEquals(GeoErrorClass.OPEN_FAILED, GeoExperimentSpec.classify(openAbsent("geoip.dat")))
        assertEquals(GeoErrorClass.CODE_NOT_FOUND, GeoExperimentSpec.classify(codeAbsent("geoip.dat")))
        for (cause in listOf("unexpected EOF", "varint overflow", "invalid body length: 0")) {
            assertEquals(cause, GeoErrorClass.DATA_CORRUPT, GeoExperimentSpec.classify(codeAbsent("geoip.dat", cause = cause)))
            assertEquals(cause, GeoErrorClass.DATA_CORRUPT, GeoExperimentSpec.classify(codeAbsent("geoip.dat", cause = cause, verb = "load")))
        }
        assertEquals(
            GeoErrorClass.DATA_CORRUPT,
            GeoExperimentSpec.classify("geodata: error unmarshal IP in geoip.dat:PRIVATE > proto: cannot parse invalid wire-format data"),
        )
        assertEquals(GeoErrorClass.SYNTAX, GeoExperimentSpec.classify("illegal ip rule: ext:geoip.dat > syntax error"))
        assertEquals(GeoErrorClass.OTHER, GeoExperimentSpec.classify("boom"))
    }

    @Test
    fun `parseCodeNotFound requires a single clean EOF cause`() {
        val clean = GeoExperimentSpec.parseCodeNotFound(codeAbsent("geoip.dat"))!!
        assertEquals("NOSUCHCODE", clean.code)
        assertEquals("geoip.dat", clean.file)
        assertTrue(clean.cleanEof)
        assertFalse(clean.corrupt)
        assertFalse(GeoExperimentSpec.parseCodeNotFound(codeAbsent("geoip.dat", cause = "unexpected EOF"))!!.cleanEof)
        assertTrue(GeoExperimentSpec.parseCodeNotFound(codeAbsent("geoip.dat", cause = "unexpected EOF"))!!.corrupt)
        assertFalse(GeoExperimentSpec.parseCodeNotFound(codeAbsent("geoip.dat", cause = "EOF > something else"))!!.cleanEof)
        assertFalse(GeoExperimentSpec.parseCodeNotFound(codeAbsent("geoip.dat", cause = "read error"))!!.cleanEof)
        assertNull(GeoExperimentSpec.parseCodeNotFound("illegal ip rule: geoip:NOSUCHCODE > boom"))
        assertNull(GeoExperimentSpec.parseCodeNotFound(null))
    }

    @Test
    fun `parseOpenFailure separates an absent file from other open failures`() {
        val absent = GeoExperimentSpec.parseOpenFailure(openAbsent("geoip.dat"))!!
        assertEquals("geoip.dat", absent.file)
        assertTrue(absent.absent)
        val denied = GeoExperimentSpec.parseOpenFailure("geodata: failed to open geoip.dat > open /x/geoip.dat: permission denied")!!
        assertFalse(denied.absent)
        assertFalse(GeoExperimentSpec.parseOpenFailure("geodata: failed to open geoip.dat")!!.absent)
        assertNull(GeoExperimentSpec.parseOpenFailure(codeAbsent("geoip.dat")))
    }

    // ---- NEGATIVE_CONTROL ----

    @Test
    fun `negative control passes only for an absent-file open failure naming the right database`() {
        assertEquals(Verdict.PASS, judge(GeoCase.E2, Mode.NEGATIVE_CONTROL, failed(openAbsent("geoip.dat"))).verdict)
        assertEquals(Verdict.PASS, judge(GeoCase.E4, Mode.NEGATIVE_CONTROL, failed(openAbsent("geoip.dat", "geoip:NOSUCHCODE"))).verdict)
        assertEquals(Verdict.PASS, judge(GeoCase.E3, Mode.NEGATIVE_CONTROL, failed(openAbsent("geosite.dat", "geosite:GOOGLE"))).verdict)
        assertEquals(Verdict.PASS, judge(GeoCase.E5, Mode.NEGATIVE_CONTROL, failed(openAbsent("geosite.dat"))).verdict)
        // wrong database named
        assertEquals(Verdict.FAIL, judge(GeoCase.E3, Mode.NEGATIVE_CONTROL, failed(openAbsent("geoip.dat"))).verdict)
        // not an absence error (permission denied / no cause at all)
        val denied = "geodata: failed to open geoip.dat > open /x/geoip.dat: permission denied"
        assertEquals(Verdict.FAIL, judge(GeoCase.E2, Mode.NEGATIVE_CONTROL, failed(denied)).verdict)
        assertEquals(Verdict.FAIL, judge(GeoCase.E2, Mode.NEGATIVE_CONTROL, failed("geodata: failed to open geoip.dat")).verdict)
        // the open succeeded and the code was not found: the files were NOT absent
        assertEquals(Verdict.FAIL, judge(GeoCase.E4, Mode.NEGATIVE_CONTROL, failed(codeAbsent("geoip.dat"))).verdict)
    }

    @Test
    fun `negative control success is inconclusive and never evidence of mobasset`() {
        for (case in listOf(GeoCase.E2, GeoCase.E3, GeoCase.E4, GeoCase.E5)) {
            val j = judge(case, Mode.NEGATIVE_CONTROL, started)
            assertEquals(Verdict.INCONCLUSIVE, j.verdict)
            assertTrue(j.reason.contains("NOT evidence of mobasset"))
        }
    }

    // ---- COPIED_ASSETS: valid codes (E2/E3) ----

    @Test
    fun `copied assets valid codes are never a plain PASS`() {
        for (case in listOf(GeoCase.E2, GeoCase.E3)) {
            val j = judge(case, Mode.COPIED_ASSETS, started)
            assertEquals(Verdict.INCONCLUSIVE, j.verdict)
            assertTrue(j.reason.contains("not distinguishable"))
            assertEquals(Verdict.FAIL, judge(case, Mode.COPIED_ASSETS, failed(openAbsent(case.databaseFile!!))).verdict)
            assertEquals(Verdict.FAIL, judge(case, Mode.COPIED_ASSETS, failed(codeAbsent(case.databaseFile!!, code = "PRIVATE"))).verdict)
            assertEquals(Verdict.FAIL, judge(case, Mode.COPIED_ASSETS, failed("boom")).verdict)
        }
    }

    @Test
    fun `a started core that is not cleanly stopped is described truthfully`() {
        val stillRunning = started.copy(runningAfterStop = true)
        val j = judge(GeoCase.E2, Mode.COPIED_ASSETS, stillRunning)
        assertEquals(Verdict.FAIL, j.verdict)
        assertFalse(j.reason.contains("start failed"))
        assertTrue(j.reason.contains("stopLoop"))
        assertTrue(j.reason.contains("runningAfterStop=true"))
        val stopThrew = judge(GeoCase.E3, Mode.COPIED_ASSETS, started.copy(stopFailed = true))
        assertEquals(Verdict.FAIL, stopThrew.verdict)
        assertTrue(stopThrew.reason.contains("stopLoopThrew=true"))
        val notRunning = judge(GeoCase.E2, Mode.COPIED_ASSETS, GeoExperimentSpec.Observation(startedOk = true, runningAfterStart = false))
        assertEquals(Verdict.FAIL, notRunning.verdict)
        assertTrue(notRunning.reason.contains("not running"))
        assertEquals(Verdict.FAIL, judge(GeoCase.E1, Mode.NEGATIVE_CONTROL, stillRunning).verdict)
        assertEquals(Verdict.FAIL, judge(GeoCase.E1, Mode.NEGATIVE_CONTROL, started.copy(stopFailed = true)).verdict)
    }

    // ---- COPIED_ASSETS: unknown codes (E4/E5) ----

    @Test
    fun `unknown code passes only for a clean EOF code-not-found naming the code and the right file`() {
        assertEquals(Verdict.PASS, judge(GeoCase.E4, Mode.COPIED_ASSETS, failed(codeAbsent("geoip.dat"))).verdict)
        assertEquals(Verdict.PASS, judge(GeoCase.E4, Mode.COPIED_ASSETS, failed(codeAbsent("geoip.dat", verb = "load"))).verdict)
        assertEquals(Verdict.PASS, judge(GeoCase.E5, Mode.COPIED_ASSETS, failed(codeAbsent("geosite.dat"))).verdict)
        // the code may be reported in either case
        assertEquals(Verdict.PASS, judge(GeoCase.E4, Mode.COPIED_ASSETS, failed(codeAbsent("geoip.dat", code = "nosuchcode"))).verdict)
    }

    @Test
    fun `unknown code never passes on damage markers`() {
        for (cause in listOf("unexpected EOF", "varint overflow", "invalid body length: 0", "EOF > unexpected EOF")) {
            for (verb in listOf("check", "load")) {
                val msg = codeAbsent("geoip.dat", cause = cause, verb = verb)
                assertNotEquals("$verb/$cause", Verdict.PASS, judge(GeoCase.E4, Mode.COPIED_ASSETS, failed(msg)).verdict)
            }
        }
        val unmarshal = "illegal ip rule: geoip:NOSUCHCODE > geodata: failed to load code NOSUCHCODE from geoip.dat > geodata: error unmarshal IP in geoip.dat:NOSUCHCODE > proto: truncated"
        assertEquals(Verdict.FAIL, judge(GeoCase.E4, Mode.COPIED_ASSETS, failed(unmarshal)).verdict)
        // the marker anywhere in the chain (even before the code phrase) disqualifies PASS
        val markerFirst = "varint overflow > geodata: failed to check code NOSUCHCODE from geoip.dat > EOF"
        assertEquals(Verdict.FAIL, judge(GeoCase.E4, Mode.COPIED_ASSETS, failed(markerFirst)).verdict)
    }

    @Test
    fun `unknown code does not pass on a wrong code a wrong file or a non-eof cause`() {
        assertEquals(Verdict.FAIL, judge(GeoCase.E4, Mode.COPIED_ASSETS, failed(codeAbsent("geoip.dat", code = "OTHERCODE"))).verdict)
        assertEquals(Verdict.FAIL, judge(GeoCase.E4, Mode.COPIED_ASSETS, failed(codeAbsent("geosite.dat"))).verdict)
        assertEquals(Verdict.FAIL, judge(GeoCase.E5, Mode.COPIED_ASSETS, failed(codeAbsent("geoip.dat"))).verdict)
        assertEquals(Verdict.FAIL, judge(GeoCase.E4, Mode.COPIED_ASSETS, failed(codeAbsent("geoip.dat", cause = "read tcp: reset"))).verdict)
        // the rule echo alone (which contains the code) is not evidence
        assertEquals(Verdict.FAIL, judge(GeoCase.E4, Mode.COPIED_ASSETS, failed("illegal ip rule: geoip:NOSUCHCODE > boom")).verdict)
        assertEquals(Verdict.FAIL, judge(GeoCase.E4, Mode.COPIED_ASSETS, failed("failed to check code NOSUCHCODE")).verdict)
        // the copy was not effective
        assertEquals(Verdict.FAIL, judge(GeoCase.E4, Mode.COPIED_ASSETS, failed(openAbsent("geoip.dat"))).verdict)
        // silently accepted
        assertEquals(Verdict.FAIL, judge(GeoCase.E5, Mode.COPIED_ASSETS, started).verdict)
    }

    // ---- E0 / E1 / E6 ----

    @Test
    fun `E1 E6 and E0 judgements`() {
        val ok = started
        assertEquals(Verdict.PASS, judge(GeoCase.E1, Mode.NEGATIVE_CONTROL, ok).verdict)
        assertEquals(Verdict.FAIL, judge(GeoCase.E1, Mode.NEGATIVE_CONTROL, failed("boom")).verdict)
        for (mode in Mode.entries) {
            assertEquals(Verdict.PASS, judge(GeoCase.E6, mode, failed(openAbsent("nosuchfile.dat", "ext:nosuchfile.dat:private"))).verdict)
            assertEquals(Verdict.FAIL, judge(GeoCase.E6, mode, ok).verdict)
            assertEquals(Verdict.FAIL, judge(GeoCase.E6, mode, failed(openAbsent("geoip.dat"))).verdict)
            assertEquals(Verdict.PASS, judge(GeoCase.E0, mode, GeoExperimentSpec.Observation()).verdict)
        }
    }

    // ---- nothing generic ever passes ----

    @Test
    fun `a generic error or no observation never passes in any case or mode`() {
        for (case in GeoCase.entries.filter { it != GeoCase.E0 }) {
            for (mode in Mode.entries) {
                for (msg in listOf("boom", "config error", "geodata: failed to open", "failed to check code", "EOF", "")) {
                    assertNotEquals("$case/$mode/'$msg'", Verdict.PASS, judge(case, mode, failed(msg)).verdict)
                }
                assertNotEquals("$case/$mode empty", Verdict.PASS, judge(case, mode, GeoExperimentSpec.Observation()).verdict)
            }
        }
    }

    // ---- precedence of non-Xray outcomes ----

    @Test
    fun `refusal preparation and harness errors are never an Xray verdict`() {
        val refused = judge(GeoCase.E2, Mode.COPIED_ASSETS, GeoExperimentSpec.Observation(refusedReason = "vpn active", startedOk = true))
        assertEquals(Verdict.REFUSED, refused.verdict)
        val prep = judge(GeoCase.E2, Mode.COPIED_ASSETS, GeoExperimentSpec.Observation(prepError = "ownership unknown", startedOk = true))
        assertEquals(Verdict.PREP_ERROR, prep.verdict)
        assertNotNull(prep.expectation)
        val harness = judge(GeoCase.E4, Mode.COPIED_ASSETS, GeoExperimentSpec.Observation(harnessError = "core env init failed", errorMessage = codeAbsent("geoip.dat")))
        assertEquals(Verdict.HARNESS_ERROR, harness.verdict)
        // refusal outranks preparation, which outranks a harness error
        assertEquals(Verdict.REFUSED, judge(GeoCase.E1, Mode.NEGATIVE_CONTROL, GeoExperimentSpec.Observation(refusedReason = "x", prepError = "y", harnessError = "z")).verdict)
        assertEquals(Verdict.PREP_ERROR, judge(GeoCase.E1, Mode.NEGATIVE_CONTROL, GeoExperimentSpec.Observation(prepError = "y", harnessError = "z")).verdict)
    }

    @Test
    fun `needsDatabases and databaseFile line up`() {
        assertEquals("geoip.dat", GeoCase.E2.databaseFile)
        assertEquals("geosite.dat", GeoCase.E5.databaseFile)
        assertNull(GeoCase.E1.databaseFile)
        assertNull(GeoCase.E6.databaseFile)
        assertFalse(GeoExperimentSpec.needsDatabases(GeoCase.E0))
        assertTrue(GeoExperimentSpec.needsDatabases(GeoCase.E3))
    }
}
