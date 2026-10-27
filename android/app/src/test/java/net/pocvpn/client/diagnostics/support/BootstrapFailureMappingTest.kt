package net.pocvpn.client.diagnostics.support

import net.pocvpn.client.controlplane.ControlPlaneFailureReason
import net.pocvpn.client.reachability.ManifestSource
import net.pocvpn.client.relay.RelayFailureCategory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * ROADMAP "Alternative Control Routing" diagnostics criterion: a bootstrap /
 * control-plane failure must stay distinguishable from a VPN transport
 * failure, using the existing CONTROL_PLANE_* / MANIFEST_UNAVAILABLE labels.
 */
class BootstrapFailureMappingTest {

    private val bootstrapReasons = DiagnosticFailureReason.values()
        .filter { it.name.startsWith("CONTROL_PLANE_") || it == DiagnosticFailureReason.MANIFEST_UNAVAILABLE }
        .toSet()

    @Test
    fun `a client-side relay capability gap is not labelled as a control-plane failure`() {
        assertEquals(
            DiagnosticFailureReason.INTERNAL_ERROR,
            mapRelayFailureCategoryToFailureReason(RelayFailureCategory.EXECUTION_NOT_IMPLEMENTED),
        )
    }

    @Test
    fun `no relay failure category maps onto a bootstrap label`() {
        RelayFailureCategory.values().forEach { category ->
            assertTrue(
                "$category must not claim a bootstrap/control-plane cause",
                mapRelayFailureCategoryToFailureReason(category) !in bootstrapReasons,
            )
        }
    }

    @Test
    fun `every control-plane failure reason maps onto a CONTROL_PLANE label`() {
        ControlPlaneFailureReason.values().forEach { reason ->
            assertTrue(
                "$reason must stay a control-plane label",
                mapControlPlaneFailureReasonToFailureReason(reason).name.startsWith("CONTROL_PLANE_"),
            )
        }
    }

    @Test
    fun `no candidate without any trusted manifest is MANIFEST_UNAVAILABLE`() {
        assertEquals(
            DiagnosticFailureReason.MANIFEST_UNAVAILABLE,
            mapNoCandidateToFailureReason(manifestRepositoryWired = true, trustedSource = null),
        )
    }

    @Test
    fun `no candidate with a trusted manifest stays NO_CANDIDATE`() {
        ManifestSource.values().forEach { source ->
            assertEquals(
                DiagnosticFailureReason.NO_CANDIDATE,
                mapNoCandidateToFailureReason(manifestRepositoryWired = true, trustedSource = source),
            )
        }
    }

    @Test
    fun `no candidate without a wired manifest repository claims nothing about the manifest`() {
        assertEquals(
            DiagnosticFailureReason.NO_CANDIDATE,
            mapNoCandidateToFailureReason(manifestRepositoryWired = false, trustedSource = null),
        )
    }
}
