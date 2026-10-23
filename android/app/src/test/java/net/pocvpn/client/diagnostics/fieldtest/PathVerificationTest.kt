package net.pocvpn.client.diagnostics.fieldtest

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * R1-S2 - reachability, tunnel path and egress are three separate verdicts.
 * A successful HTTPS answer never stands in for a verified egress, and a
 * missing or unreliable physical reference is INCONCLUSIVE, never PASS.
 */
class PathVerificationTest {

    private val physical = "198.51.100.7"
    private val exit = "152.70.43.1"
    private val now = 1_000_000L

    private fun reference(ip: String = physical, ageMs: Long = 60_000L) = PhysicalReference(ip, now - ageMs)

    private fun probe(status: Int? = 200, kind: ProbeFailureKind? = null) =
        HttpProbeResult("trace", FieldTestTargets.CLOUDFLARE_TRACE, status != null, status, 10, 5, 100, null, status != null, kind?.name, failureKind = kind)

    private fun input(
        probe: HttpProbeResult? = probe(),
        observed: String? = exit,
        reference: PhysicalReference? = reference(),
        session: SessionValidity = SessionValidity.STABLE,
        via: ReachabilityVia = ReachabilityVia.VPN_BOUND_SOCKET,
        appExcluded: Boolean = false,
        coreAnyOk: Boolean? = null,
    ) = PathInput(via, probe, coreAnyOk, appExcluded, observed, reference, now, session)

    private fun eval(i: PathInput = input()) = PathVerification.evaluate(i)

    // --- the one fully verified case ---

    @Test fun `bound socket plus a public address that differs from the physical one confirms the path`() {
        val v = eval()
        assertEquals(ReachabilityResult.REACHABLE, v.reachability)
        assertEquals(TunnelPathResult.CONFIRMED, v.tunnelPath)
        assertEquals(EgressResult.DIFFERS_FROM_PHYSICAL, v.egress)
        assertEquals(PathEvidence.SOCKET_BOUND_AND_EGRESS_DIFFERS, v.evidence)
        assertEquals(null, v.egressReason)
    }

    @Test fun `the same public address as the physical one is a violation, not a pass`() {
        val v = eval(input(observed = physical))
        assertEquals(ReachabilityResult.REACHABLE, v.reachability)
        assertEquals(TunnelPathResult.VIOLATED, v.tunnelPath)
        assertEquals(EgressResult.SAME_AS_PHYSICAL, v.egress)
        assertEquals(PathEvidence.EGRESS_SAME_AS_PHYSICAL, v.evidence)
    }

    // --- HTTPS working is not a verified egress ---

    @Test fun `without an independent reference HTTPS reachability stays separate and egress is inconclusive`() {
        val v = eval(input(reference = null))
        assertEquals(ReachabilityResult.REACHABLE, v.reachability)
        assertEquals(TunnelPathResult.INCONCLUSIVE, v.tunnelPath)
        assertEquals(PathReason.NO_REFERENCE, v.tunnelReason)
        assertEquals(EgressResult.INCONCLUSIVE, v.egress)
        assertEquals(PathReason.NO_REFERENCE, v.egressReason)
        assertEquals(PathEvidence.SOCKET_BOUND_ONLY, v.evidence)
    }

    @Test fun `a reference that is too old or from the future is stale`() {
        val old = eval(input(reference = reference(ageMs = PathVerification.MAX_REFERENCE_AGE_MS + 1)))
        assertEquals(PathReason.REFERENCE_STALE, old.egressReason)
        assertEquals(EgressResult.INCONCLUSIVE, old.egress)
        val future = eval(input(reference = reference(ageMs = -5)))
        assertEquals(PathReason.REFERENCE_STALE, future.egressReason)
        // exactly at the limit still counts
        assertEquals(EgressResult.DIFFERS_FROM_PHYSICAL, eval(input(reference = reference(ageMs = PathVerification.MAX_REFERENCE_AGE_MS))).egress)
    }

    @Test fun `an unusable reference or observed address is invalid, never compared`() {
        listOf("192.168.0.148", "10.1.2.3", "100.64.3.4", "127.0.0.1", "169.254.1.1", "172.20.1.1", "0.0.0.0", "224.0.0.1", "300.1.1.1", "garbage", "").forEach { bad ->
            val ref = eval(input(reference = reference(bad)))
            assertEquals("reference $bad", PathReason.REFERENCE_INVALID, ref.egressReason)
            val obs = eval(input(observed = bad))
            assertEquals("observed $bad", PathReason.OBSERVED_INVALID, obs.egressReason)
            assertEquals(EgressResult.INCONCLUSIVE, obs.egress)
        }
    }

    @Test fun `an IPv6 reference cannot be compared with an IPv4 observation`() {
        val v = eval(input(reference = reference("2a02:8308:10e:8400:d4b5:2f7f:1f9c:5d65")))
        assertEquals(PathReason.FAMILY_MISMATCH, v.egressReason)
        assertEquals(EgressResult.INCONCLUSIVE, v.egress)
        assertEquals(TunnelPathResult.INCONCLUSIVE, v.tunnelPath)
        // and the other way round
        assertEquals(PathReason.FAMILY_MISMATCH, eval(input(observed = "2606:4700:4700::1111")).egressReason)
    }

    @Test fun `a missing observed address is inconclusive`() {
        val v = eval(input(observed = null))
        assertEquals(ReachabilityResult.REACHABLE, v.reachability)
        assertEquals(PathReason.NO_OBSERVED_IP, v.egressReason)
        assertEquals(EgressResult.INCONCLUSIVE, v.egress)
    }

    // --- the session must still be the one that was measured ---

    @Test fun `a changed session voids every verdict even when the addresses differ`() {
        val v = eval(input(session = SessionValidity.CHANGED))
        assertEquals(ReachabilityResult.INCONCLUSIVE, v.reachability)
        assertEquals(TunnelPathResult.INCONCLUSIVE, v.tunnelPath)
        assertEquals(EgressResult.INCONCLUSIVE, v.egress)
        assertEquals(PathReason.SESSION_CHANGED, v.reachabilityReason)
        assertEquals(PathReason.SESSION_CHANGED, v.tunnelReason)
        assertEquals(PathReason.SESSION_CHANGED, v.egressReason)
        assertEquals(PathEvidence.NONE, v.evidence)
        assertEquals(SessionValidity.CHANGED, v.session)
    }

    // --- reachability: only positive evidence is UNREACHABLE ---

    @Test fun `only an OS no-route errno is unreachable - timeout, lookup, TLS and other failures are inconclusive`() {
        val cases = listOf(
            ProbeFailureKind.NO_ROUTE to (ReachabilityResult.UNREACHABLE to PathReason.NO_ROUTE),
            ProbeFailureKind.TIMEOUT to (ReachabilityResult.INCONCLUSIVE to PathReason.TIMEOUT),
            ProbeFailureKind.UNKNOWN_HOST to (ReachabilityResult.INCONCLUSIVE to PathReason.LOOKUP_FAILED),
            ProbeFailureKind.TLS to (ReachabilityResult.INCONCLUSIVE to PathReason.TLS_FAILED),
            ProbeFailureKind.OTHER to (ReachabilityResult.INCONCLUSIVE to PathReason.REQUEST_FAILED),
        )
        cases.forEach { (kind, expected) ->
            val v = eval(input(probe = probe(null, kind), observed = null))
            assertEquals(kind.name, expected.first, v.reachability)
            assertEquals(kind.name, expected.second, v.reachabilityReason)
            // A failed request never proves the tunnel path either way.
            assertEquals(TunnelPathResult.INCONCLUSIVE, v.tunnelPath)
            assertEquals(EgressResult.INCONCLUSIVE, v.egress)
            assertNotEquals(TunnelPathResult.VIOLATED, v.tunnelPath)
        }
    }

    @Test fun `any HTTP status counts as an answer`() {
        listOf(200, 204, 404, 503).forEach { assertEquals(ReachabilityResult.REACHABLE, eval(input(probe = probe(it))).reachability) }
    }

    @Test fun `no probe at all is inconclusive`() {
        val v = eval(input(probe = null))
        assertEquals(PathReason.NO_PROBE, v.reachabilityReason)
        assertEquals(ReachabilityResult.INCONCLUSIVE, v.reachability)
    }

    // --- where the measurement was made ---

    @Test fun `an app excluded from the VPN cannot measure its own path`() {
        val v = eval(input(appExcluded = true, via = ReachabilityVia.NONE))
        assertEquals(PathReason.APP_EXCLUDED, v.reachabilityReason)
        assertEquals(PathReason.APP_EXCLUDED, v.tunnelReason)
        assertEquals(PathReason.APP_EXCLUDED, v.egressReason)
        assertEquals(PathEvidence.NONE, v.evidence)
    }

    @Test fun `an Xray core measurement shows reachability only, never the tunnel path or egress`() {
        val ok = eval(input(via = ReachabilityVia.XRAY_CORE_OUTBOUND, probe = null, observed = null, coreAnyOk = true))
        assertEquals(ReachabilityResult.REACHABLE, ok.reachability)
        assertEquals(ReachabilityVia.XRAY_CORE_OUTBOUND, ok.reachabilityVia)
        assertEquals(TunnelPathResult.INCONCLUSIVE, ok.tunnelPath)
        assertEquals(PathReason.CORE_MEASUREMENT_ONLY, ok.tunnelReason)
        assertEquals(EgressResult.INCONCLUSIVE, ok.egress)
        assertEquals(PathReason.CORE_MEASUREMENT_ONLY, ok.egressReason)
        val failed = eval(input(via = ReachabilityVia.XRAY_CORE_OUTBOUND, probe = null, observed = null, coreAnyOk = false))
        assertEquals(ReachabilityResult.INCONCLUSIVE, failed.reachability)
        assertEquals(TunnelPathResult.INCONCLUSIVE, failed.tunnelPath)
    }

    @Test fun `a probe that was not VPN-bound counts for nothing`() {
        val v = eval(input(via = ReachabilityVia.NONE))
        assertEquals(PathReason.NOT_VPN_BOUND, v.reachabilityReason)
        assertEquals(ReachabilityResult.INCONCLUSIVE, v.reachability)
        assertEquals(TunnelPathResult.INCONCLUSIVE, v.tunnelPath)
        assertEquals(EgressResult.INCONCLUSIVE, v.egress)
    }

    // --- nothing identifying is stored ---

    @Test fun `the verdict JSON holds names only - never an address`() {
        val text = eval().toJson().toString() + eval(input(observed = physical)).toJson().toString()
        assertFalse(text.contains(physical))
        assertFalse(text.contains(exit))
        assertTrue(text.contains("DIFFERS_FROM_PHYSICAL"))
        assertFalse(reference().toString().contains(physical))
    }

    @Test fun `summary text names the three verdicts`() {
        assertEquals("reach REACHABLE, tunnel CONFIRMED, egress DIFFERS_FROM_PHYSICAL", eval().summaryText())
        assertEquals(
            "reach REACHABLE, tunnel INCONCLUSIVE/NO_REFERENCE, egress INCONCLUSIVE/NO_REFERENCE",
            eval(input(reference = null)).summaryText(),
        )
    }

    // --- failure kinds come from types and errnos, never from text ---

    private class FakeErrno(val errno: Int) : Exception("errno")

    private val errnoOf: (Throwable) -> Int? = { (it as? FakeErrno)?.errno }
    private val noRoute = { setOf(101, 113) } // ENETUNREACH, EHOSTUNREACH on Linux

    @Test fun `a no-route errno in the cause chain is NO_ROUTE`() {
        val e = java.net.ConnectException("connect failed").apply { initCause(FakeErrno(101)) }
        assertEquals(ProbeFailureKind.NO_ROUTE, failureKindOf(e, errnoOf, noRoute))
        val host = java.io.IOException("outer", java.net.ConnectException("mid").apply { initCause(FakeErrno(113)) })
        assertEquals(ProbeFailureKind.NO_ROUTE, failureKindOf(host, errnoOf, noRoute))
    }

    @Test fun `message text alone never means no route`() {
        val e = java.net.ConnectException("isConnected failed: ENETUNREACH (Network is unreachable)")
        assertEquals(ProbeFailureKind.OTHER, failureKindOf(e, errnoOf, noRoute))
    }

    @Test fun `a different errno such as connection refused is not no route`() {
        val e = java.net.ConnectException("refused").apply { initCause(FakeErrno(111)) }
        assertEquals(ProbeFailureKind.OTHER, failureKindOf(e, errnoOf, noRoute))
    }

    @Test fun `a timeout stays a timeout even when an errno is attached`() {
        val e = java.net.SocketTimeoutException("t").apply { initCause(FakeErrno(101)) }
        assertEquals(ProbeFailureKind.TIMEOUT, failureKindOf(e, errnoOf, noRoute))
    }

    @Test fun `TLS failures are their own kind`() {
        assertEquals(ProbeFailureKind.TLS, failureKindOf(javax.net.ssl.SSLHandshakeException("bad cert")))
        assertEquals(ProbeFailureKind.TLS, failureKindOf(java.io.IOException("wrapped", javax.net.ssl.SSLPeerUnverifiedException("x"))))
    }

    @Test fun `a cyclic cause chain terminates`() {
        val a = java.io.IOException("a")
        val b = java.io.IOException("b", a)
        a.initCause(b)
        assertEquals(ProbeFailureKind.OTHER, failureKindOf(a, errnoOf, noRoute))
    }

    // --- IPv6 is judged separately, and "blocked locally" needs the errno ---

    private fun v6(kind: ProbeFailureKind?) =
        HttpProbeResult("IPv6", LeakChecks.IPV6_ONLY_URL, false, null, 5, null, 0, null, false, kind?.name, failureKind = kind)

    @Test fun `ipv6 no-route on a network with global IPv6 is concrete local blocking`() {
        assertEquals(LeakCheck(LeakCheckResult.NO_LEAK_DETECTED, LeakCheckReason.ROUTE_UNREACHABLE), LeakChecks.classifyIpv6(true, v6(ProbeFailureKind.NO_ROUTE)))
    }

    @Test fun `ipv6 no-route without a known baseline is inconclusive`() {
        assertEquals(LeakCheck(LeakCheckResult.INCONCLUSIVE, LeakCheckReason.ROUTE_UNREACHABLE), LeakChecks.classifyIpv6(null, v6(ProbeFailureKind.NO_ROUTE)))
    }

    @Test fun `ipv6 timeout, TLS failure and a plain refusal never count as blocked`() {
        assertEquals(LeakCheck(LeakCheckResult.INCONCLUSIVE, LeakCheckReason.TIMEOUT), LeakChecks.classifyIpv6(true, v6(ProbeFailureKind.TIMEOUT)))
        assertEquals(LeakCheck(LeakCheckResult.INCONCLUSIVE, LeakCheckReason.REQUEST_FAILED), LeakChecks.classifyIpv6(true, v6(ProbeFailureKind.TLS)))
        assertEquals(LeakCheck(LeakCheckResult.INCONCLUSIVE, LeakCheckReason.REQUEST_FAILED), LeakChecks.classifyIpv6(true, v6(ProbeFailureKind.OTHER)))
    }

    @Test fun `ipv6 no-route on a network without IPv6 is not run, not a blocked verdict`() {
        assertEquals(LeakCheck(LeakCheckResult.NOT_RUN, LeakCheckReason.NO_IPV6_ON_NETWORK), LeakChecks.classifyIpv6(false, v6(ProbeFailureKind.NO_ROUTE)))
    }

    @Test fun `an IPv6 answer is still never reported as no leak`() {
        val answered = HttpProbeResult("IPv6", LeakChecks.IPV6_ONLY_URL, true, 200, 5, null, 10, null, true, null)
        assertEquals(LeakCheckResult.INCONCLUSIVE, LeakChecks.classifyIpv6(true, answered).result)
    }

    // --- canonicalization: the same address must never be reported as a difference ---

    @Test fun `two textually different IPv6 forms of the same address are not a difference`() {
        val full = "2a02:8308:010e:8400:d4b5:2f7f:019c:5d65"
        val compressed = "2a02:8308:10e:8400:d4b5:2f7f:19c:5d65"
        val upper = "2A02:8308:10E:8400:D4B5:2F7F:19C:5D65"
        val v1 = eval(input(reference = reference(full), observed = full))
        assertEquals(EgressResult.SAME_AS_PHYSICAL, v1.egress)
        assertEquals(TunnelPathResult.VIOLATED, v1.tunnelPath)
        val v2 = eval(input(reference = reference(compressed), observed = upper))
        assertEquals(EgressResult.SAME_AS_PHYSICAL, v2.egress)
        assertEquals(TunnelPathResult.VIOLATED, v2.tunnelPath)
        val v3 = eval(input(reference = reference(full), observed = compressed))
        assertEquals(EgressResult.SAME_AS_PHYSICAL, v3.egress)
    }

    @Test fun `two genuinely different public IPv6 addresses are a difference`() {
        val a = "2a02:8308:10e:8400:d4b5:2f7f:19c:5d65"
        val b = "2606:4700:4700:1111::1111"
        val v = eval(input(reference = reference(a), observed = b))
        assertEquals(EgressResult.DIFFERS_FROM_PHYSICAL, v.egress)
        assertEquals(TunnelPathResult.CONFIRMED, v.tunnelPath)
    }

    @Test fun `mixed-case IPv6 forms compare by content, not text`() {
        val v = eval(input(reference = reference("2A02:8308:10E:8400:D4B5:2F7F:19C:5D65"), observed = "2a02:8308:10e:8400:d4b5:2f7f:19c:5d65"))
        assertEquals(EgressResult.SAME_AS_PHYSICAL, v.egress)
        assertEquals(TunnelPathResult.VIOLATED, v.tunnelPath)
    }

    @Test fun `an IPv4-mapped IPv6 tail compares by content`() {
        val mapped = "::ffff:198.51.100.7"
        val v = eval(input(reference = reference(mapped), observed = "0:0:0:0:0:ffff:c633:6407"))
        assertEquals(EgressResult.SAME_AS_PHYSICAL, v.egress)
        assertEquals(TunnelPathResult.VIOLATED, v.tunnelPath)
    }

    // --- invalid and ambiguous literals are never silently accepted ---

    @Test fun `an invalid IPv6 literal is invalid, never compared`() {
        listOf(
            "2a02:8308:10e:8400:d4b5:2f7f:19c:5d65:1",
            "2a02:8308:10e:::8400",
            "2a02:8308:10e:8400:d4b5:2f7f:19c:5d65g",
            "2a02:8308:10e:8400:d4b5:2f7f:19c:5d65:1:2",
            ":::",
            "2a02:8308:10e:8400:d4b5:2f7f:19c:5d65::",
        ).forEach { bad ->
            val ref = eval(input(reference = reference(bad)))
            assertEquals("reference $bad", PathReason.REFERENCE_INVALID, ref.egressReason)
            assertEquals(EgressResult.INCONCLUSIVE, ref.egress)
            val obs = eval(input(observed = bad))
            assertEquals("observed $bad", PathReason.OBSERVED_INVALID, obs.egressReason)
            assertEquals(EgressResult.INCONCLUSIVE, obs.egress)
        }
    }

    @Test fun `an IPv4 literal with leading zeros is invalid, never silently compared`() {
        listOf("0192.168.1.1", "192.168.001.1", "192.168.1.00", "00.0.0.1", "10.0.0.01").forEach { bad ->
            val ref = eval(input(reference = reference(bad)))
            assertEquals("reference $bad", PathReason.REFERENCE_INVALID, ref.egressReason)
            val obs = eval(input(observed = bad))
            assertEquals("observed $bad", PathReason.OBSERVED_INVALID, obs.egressReason)
        }
    }

    @Test fun `an out-of-range IPv4 octet is invalid`() {
        listOf("256.1.1.1", "1.300.1.1", "1.1.1.255.1").forEach { bad ->
            val ref = eval(input(reference = reference(bad)))
            assertEquals("reference $bad", PathReason.REFERENCE_INVALID, ref.egressReason)
        }
    }

    @Test fun `link-local, multicast and loopback IPv6 are reserved`() {
        listOf("fe80::1", "ff00::1", "::1").forEach { bad ->
            val ref = eval(input(reference = reference(bad)))
            assertEquals("reference $bad", PathReason.REFERENCE_INVALID, ref.egressReason)
        }
    }

    // --- reserved ranges caught on byte content, not on one written form ---

    @Test fun `unspecified IPv6 is reserved in every written form`() {
        listOf("::", "0:0:0:0:0:0:0:0:0", "::0", "0::0").forEach { bad ->
            val ref = eval(input(reference = reference(bad)))
            assertEquals("reference $bad", PathReason.REFERENCE_INVALID, ref.egressReason)
            assertEquals(EgressResult.INCONCLUSIVE, ref.egress)
            val obs = eval(input(observed = bad))
            assertEquals("observed $bad", PathReason.OBSERVED_INVALID, obs.egressReason)
            assertEquals(EgressResult.INCONCLUSIVE, obs.egress)
        }
    }

    @Test fun `an IPv4-mapped IPv6 tail with a reserved IPv4 is invalid`() {
        listOf("::ffff:10.0.0.1", "::ffff:127.0.0.1", "::ffff:0.0.0.0", "::ffff:192.168.1.1").forEach { bad ->
            val ref = eval(input(reference = reference(bad)))
            assertEquals("reference $bad", PathReason.REFERENCE_INVALID, ref.egressReason)
            assertEquals(EgressResult.INCONCLUSIVE, ref.egress)
            val obs = eval(input(observed = bad))
            assertEquals("observed $bad", PathReason.OBSERVED_INVALID, obs.egressReason)
            assertEquals(EgressResult.INCONCLUSIVE, obs.egress)
        }
    }

    @Test fun `a public IPv4-mapped IPv6 tail is still accepted`() {
        val mapped = "::ffff:198.51.100.7"
        val v = eval(input(reference = reference(mapped), observed = "0:0:0:0:0:ffff:c633:6407"))
        assertEquals(EgressResult.SAME_AS_PHYSICAL, v.egress)
        assertEquals(TunnelPathResult.VIOLATED, v.tunnelPath)
    }

    @Test fun `a normal IPv4 match and difference still work`() {
        val same = eval(input(reference = reference("198.51.100.7"), observed = "198.51.100.7"))
        assertEquals(EgressResult.SAME_AS_PHYSICAL, same.egress)
        assertEquals(TunnelPathResult.VIOLATED, same.tunnelPath)
        val diff = eval(input(reference = reference("198.51.100.7"), observed = "152.70.43.1"))
        assertEquals(EgressResult.DIFFERS_FROM_PHYSICAL, diff.egress)
        assertEquals(TunnelPathResult.CONFIRMED, diff.tunnelPath)
    }
}
