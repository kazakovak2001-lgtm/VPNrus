package net.pocvpn.client.smartconnect

import net.pocvpn.client.transport.TransportKind
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * B66.18 - proof of the ONE new decision
 * [AwgXrayFailoverPolicy.selectXrayFailoverTarget] adds: WHICH Xray kind an
 * already-eligible AWG failover targets. Deliberately does not re-test
 * [AwgXrayFailoverPolicy.isEligibleForXrayFallback] itself (unchanged, see
 * AwgXrayFailoverPolicyTest) - this class only proves the new function's own
 * contract.
 */
class AwgXrayFailoverTargetSelectionTest {

    private fun target(
        restrictionClass: RestrictionClass = RestrictionClass.POSSIBLE_UDP_OR_AWG_FILTERING,
        quality: RestrictionEvidenceQuality = RestrictionEvidenceQuality.MEDIUM,
        directXhttpAvailable: Boolean = true,
    ): TransportKind = AwgXrayFailoverPolicy.selectXrayFailoverTarget(restrictionClass, quality, directXhttpAvailable)

    @Test
    fun `filtering evidence plus MEDIUM quality plus available Direct XHTTP selects XHTTP`() {
        assertEquals(
            TransportKind.XRAY_XHTTP,
            target(quality = RestrictionEvidenceQuality.MEDIUM, directXhttpAvailable = true),
        )
    }

    @Test
    fun `filtering evidence plus HIGH quality plus available Direct XHTTP selects XHTTP`() {
        assertEquals(
            TransportKind.XRAY_XHTTP,
            target(quality = RestrictionEvidenceQuality.HIGH, directXhttpAvailable = true),
        )
    }

    @Test
    fun `LOW quality never selects XHTTP even with filtering evidence and an available profile`() {
        assertEquals(
            TransportKind.XRAY_REALITY,
            target(quality = RestrictionEvidenceQuality.LOW, directXhttpAvailable = true),
        )
    }

    @Test
    fun `INSUFFICIENT quality never selects XHTTP even with filtering evidence and an available profile`() {
        assertEquals(
            TransportKind.XRAY_REALITY,
            target(quality = RestrictionEvidenceQuality.INSUFFICIENT, directXhttpAvailable = true),
        )
    }

    @Test
    fun `a different restriction classification never selects XHTTP regardless of quality or availability`() {
        for (restrictionClass in RestrictionClass.entries) {
            if (restrictionClass == RestrictionClass.POSSIBLE_UDP_OR_AWG_FILTERING) continue
            assertEquals(
                "unexpected XHTTP selection for $restrictionClass",
                TransportKind.XRAY_REALITY,
                target(restrictionClass = restrictionClass, quality = RestrictionEvidenceQuality.HIGH, directXhttpAvailable = true),
            )
        }
    }

    @Test
    fun `Direct XHTTP unavailable for this endpoint falls back to REALITY even with sufficient filtering evidence`() {
        assertEquals(
            TransportKind.XRAY_REALITY,
            target(directXhttpAvailable = false),
        )
    }

    @Test
    fun `directXhttpAvailable=false represents CDN-only or unwired XHTTP, which never qualifies as Direct XHTTP fallback`() {
        // The caller is responsible for computing directXhttpAvailable from the
        // per-endpoint TransportRegistry descriptor (Direct EXIT semantics,
        // never cdnRuntimeCapabilities.isPinnedXhttpExecutable() alone) - this
        // test proves that when that signal is false (e.g. only CDN capability
        // exists, with no Direct EXIT profile), REALITY is selected instead of
        // XHTTP, regardless of how strong the filtering evidence is.
        assertEquals(
            TransportKind.XRAY_REALITY,
            target(
                restrictionClass = RestrictionClass.POSSIBLE_UDP_OR_AWG_FILTERING,
                quality = RestrictionEvidenceQuality.HIGH,
                directXhttpAvailable = false,
            ),
        )
    }
}
