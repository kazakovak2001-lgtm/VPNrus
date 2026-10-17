package net.pocvpn.client.diagnostics.fieldtest

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** B54 Scope A - a failed or missing measurement is never reported as "no leak". */
class LeakCheckResultTest {

    private val baseline = listOf("93.153.117.24")

    private fun lookup(vararg addresses: String) = DnsProbeResult(LeakChecks.RESOLVER_WHOAMI, true, addresses.toList(), 5, null)

    private fun failedLookup(kind: ProbeFailureKind) =
        DnsProbeResult(LeakChecks.RESOLVER_WHOAMI, false, emptyList(), 5, "${kind.name}Exception", kind)

    private fun http(status: Int?, kind: ProbeFailureKind? = null) =
        HttpProbeResult("IPv6", LeakChecks.IPV6_ONLY_URL, status != null, status, 5, null, 0, null, status != null, kind?.name, failureKind = kind)

    // --- DNS ---

    @Test fun `dns - VPN-side resolver equal to the direct one is a leak`() {
        assertEquals(LeakCheck(LeakCheckResult.LEAK_DETECTED, null), LeakChecks.classifyDns(true, lookup("93.153.117.24"), baseline))
    }

    @Test fun `dns - a different resolver with a baseline is no leak detected`() {
        assertEquals(LeakCheck(LeakCheckResult.NO_LEAK_DETECTED, null), LeakChecks.classifyDns(true, lookup("104.23.222.38"), baseline))
    }

    @Test fun `dns - timeout is inconclusive`() {
        assertEquals(LeakCheck(LeakCheckResult.INCONCLUSIVE, LeakCheckReason.TIMEOUT), LeakChecks.classifyDns(true, failedLookup(ProbeFailureKind.TIMEOUT), baseline))
    }

    @Test fun `dns - unknown host and other failures are inconclusive`() {
        assertEquals(LeakCheck(LeakCheckResult.INCONCLUSIVE, LeakCheckReason.LOOKUP_FAILED), LeakChecks.classifyDns(true, failedLookup(ProbeFailureKind.UNKNOWN_HOST), baseline))
        assertEquals(LeakCheck(LeakCheckResult.INCONCLUSIVE, LeakCheckReason.REQUEST_FAILED), LeakChecks.classifyDns(true, failedLookup(ProbeFailureKind.OTHER), baseline))
    }

    @Test fun `dns - an empty answer is inconclusive`() {
        assertEquals(LeakCheck(LeakCheckResult.INCONCLUSIVE, LeakCheckReason.LOOKUP_FAILED), LeakChecks.classifyDns(true, lookup(), baseline))
    }

    @Test fun `dns - no direct baseline is inconclusive`() {
        assertEquals(LeakCheck(LeakCheckResult.INCONCLUSIVE, LeakCheckReason.NO_BASELINE), LeakChecks.classifyDns(true, lookup("104.23.222.38"), emptyList()))
    }

    @Test fun `dns - a lookup without a VPN network is inconclusive even when it matches nothing`() {
        assertEquals(LeakCheck(LeakCheckResult.INCONCLUSIVE, LeakCheckReason.NO_VPN_NETWORK), LeakChecks.classifyDns(false, lookup("104.23.222.38"), baseline))
    }

    // --- IPv6 ---

    @Test fun `ipv6 - no global IPv6 on the baseline network is not run`() {
        assertEquals(LeakCheck(LeakCheckResult.NOT_RUN, LeakCheckReason.NO_IPV6_ON_NETWORK), LeakChecks.classifyIpv6(false, null))
    }

    @Test fun `ipv6 - unknown host is inconclusive`() {
        assertEquals(LeakCheck(LeakCheckResult.INCONCLUSIVE, LeakCheckReason.LOOKUP_FAILED), LeakChecks.classifyIpv6(true, http(null, ProbeFailureKind.UNKNOWN_HOST)))
    }

    @Test fun `ipv6 - timeout is inconclusive`() {
        assertEquals(LeakCheck(LeakCheckResult.INCONCLUSIVE, LeakCheckReason.TIMEOUT), LeakChecks.classifyIpv6(null, http(null, ProbeFailureKind.TIMEOUT)))
    }

    @Test fun `ipv6 - an HTTP answer without a checked address is inconclusive, not a leak`() {
        assertEquals(LeakCheck(LeakCheckResult.INCONCLUSIVE, LeakCheckReason.EGRESS_NOT_VERIFIED), LeakChecks.classifyIpv6(true, http(200)))
    }

    @Test fun `ipv6 - no input ever yields no leak detected`() {
        val inputs = listOf<Pair<Boolean?, HttpProbeResult?>>(
            false to null, true to null, null to null,
            true to http(200), true to http(null, ProbeFailureKind.UNKNOWN_HOST),
            null to http(null, ProbeFailureKind.TIMEOUT), true to http(null, ProbeFailureKind.OTHER), true to http(null),
        )
        inputs.forEach { (v6, probe) -> assertNotEquals(LeakCheckResult.NO_LEAK_DETECTED, LeakChecks.classifyIpv6(v6, probe).result) }
    }

    // --- report JSON and compatibility ---

    @Test fun `historical keys keep their meaning while the new keys mark the failure`() {
        val o = LeakChecks.report(true, failedLookup(ProbeFailureKind.UNKNOWN_HOST), baseline, true, http(null, ProbeFailureKind.UNKNOWN_HOST))
        assertFalse(o.getBoolean("dnsLeakSuspected"))
        assertFalse(o.getBoolean("ipv6EgressWhileConnected"))
        assertEquals("NO_LEAK_OBSERVED", o.getString("verdict"))
        assertEquals("INCONCLUSIVE", o.getString("dnsResult"))
        assertEquals("LOOKUP_FAILED", o.getString("dnsReason"))
        assertEquals("INCONCLUSIVE", o.getString("ipv6Result"))
        assertEquals("LOOKUP_FAILED", o.getString("ipv6Reason"))
    }

    @Test fun `a detected DNS leak keeps the historical verdict and adds the typed result`() {
        val o = LeakChecks.report(true, lookup("93.153.117.24"), baseline, false, null)
        assertTrue(o.getBoolean("dnsLeakSuspected"))
        assertEquals("DNS_LEAK_SUSPECTED", o.getString("verdict"))
        assertEquals("LEAK_DETECTED", o.getString("dnsResult"))
        assertTrue(o.isNull("dnsReason"))
        assertEquals(LeakChecks.DNS_EVIDENCE_SOCKET_BINDING, o.getString("dnsEvidence"))
        assertEquals("NOT_RUN", o.getString("ipv6Result"))
        assertEquals("NO_IPV6_ON_NETWORK", o.getString("ipv6Reason"))
        assertTrue(o.isNull("ipv6Error"))
    }

    @Test fun `new values round-trip through JSON text`() {
        val o = JSONObject(LeakChecks.report(true, lookup("104.23.222.38"), baseline, true, http(200)).toString())
        assertEquals(LeakCheckResult.NO_LEAK_DETECTED, LeakChecks.storedResult(o, "dnsResult"))
        assertEquals(LeakCheckResult.INCONCLUSIVE, LeakChecks.storedResult(o, "ipv6Result"))
    }

    @Test fun `a report without the new keys reads as unknown, never as no leak`() {
        val old = JSONObject().put("dnsLeakSuspected", false).put("ipv6EgressWhileConnected", false).put("verdict", "NO_LEAK_OBSERVED")
        assertNull(LeakChecks.storedResult(old, "dnsResult"))
        assertNull(LeakChecks.storedResult(old, "ipv6Result"))
        assertNull(LeakChecks.storedResult(null, "dnsResult"))
        assertNull(LeakChecks.storedResult(JSONObject().put("dnsResult", "SOMETHING_NEW"), "dnsResult"))
        assertEquals("NO_LEAK_OBSERVED", LeakChecks.summaryText(old))
    }

    @Test fun `summary shows the typed results next to the historical verdict`() {
        val o = LeakChecks.report(true, failedLookup(ProbeFailureKind.TIMEOUT), baseline, false, null)
        assertEquals("NO_LEAK_OBSERVED (DNS INCONCLUSIVE/TIMEOUT, IPv6 NOT_RUN/NO_IPV6_ON_NETWORK)", LeakChecks.summaryText(o))
    }

    @Test fun `failure kind comes from the exception type, not its text`() {
        assertEquals(ProbeFailureKind.TIMEOUT, failureKindOf(java.net.SocketTimeoutException("UnknownHostException")))
        assertEquals(ProbeFailureKind.UNKNOWN_HOST, failureKindOf(java.net.UnknownHostException("timeout")))
        assertEquals(ProbeFailureKind.OTHER, failureKindOf(java.io.IOException("SocketTimeoutException")))
    }

    private fun active(globalIpv6: Boolean, vararg transports: String, notVpn: Boolean = "VPN" !in transports) =
        JSONObject().put("activeNetwork", JSONObject().put("transports", org.json.JSONArray(transports.toList())).put("notVpn", notVpn).put("hasGlobalIpv6", globalIpv6))

    @Test fun `baseline IPv6 comes only from an ordinary network and is unknown otherwise`() {
        assertEquals(false, baselineHasGlobalIpv6(active(false, "CELLULAR")))
        assertEquals(true, baselineHasGlobalIpv6(active(true, "WIFI")))
        // A VPN as the active network says nothing about the network underneath.
        assertNull(baselineHasGlobalIpv6(active(false, "WIFI", "VPN")))
        assertNull(baselineHasGlobalIpv6(active(false, "WIFI", notVpn = false)))
        assertNull(baselineHasGlobalIpv6(JSONObject().put("activeNetwork", JSONObject().put("notVpn", true).put("transports", org.json.JSONArray(listOf("WIFI"))))))
        assertNull(baselineHasGlobalIpv6(JSONObject().put("activeNetwork", JSONObject().put("notVpn", true).put("hasGlobalIpv6", false))))
        assertNull(baselineHasGlobalIpv6(JSONObject().put("activeNetwork", JSONObject.NULL)))
        assertNull(baselineHasGlobalIpv6(JSONObject()))
    }

    @Test fun `a session change makes every check that ran inconclusive and leaves NOT_RUN and history alone`() {
        val original = LeakChecks.report(true, lookup("104.23.222.38"), baseline, false, null)
        val o = LeakChecks.invalidatedBySessionChange(original)
        assertEquals("INCONCLUSIVE", o.getString("dnsResult"))
        assertEquals("SESSION_CHANGED", o.getString("dnsReason"))
        assertEquals("NOT_RUN", o.getString("ipv6Result"))
        assertEquals("NO_IPV6_ON_NETWORK", o.getString("ipv6Reason"))
        assertEquals(original.getString("verdict"), o.getString("verdict"))
        assertEquals(original.getBoolean("dnsLeakSuspected"), o.getBoolean("dnsLeakSuspected"))
        // The original object is not modified.
        assertEquals("NO_LEAK_DETECTED", original.getString("dnsResult"))
    }
}
