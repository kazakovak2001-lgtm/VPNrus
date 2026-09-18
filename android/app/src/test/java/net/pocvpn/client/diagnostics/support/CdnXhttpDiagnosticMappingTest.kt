package net.pocvpn.client.diagnostics.support

import net.pocvpn.client.relay.RelayFailureCategory
import net.pocvpn.client.relay.RelayProbeFailureKind
import net.pocvpn.client.smartconnect.AutoGatewayFailoverPolicy
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.vpn.TransportFailureKind
import net.pocvpn.client.vpn.TransportState
import net.pocvpn.client.diagnostics.VpnError
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class CdnXhttpDiagnosticMappingTest {
    private val unavailableCdnOriginReasons = setOf(
        DiagnosticFailureReason.CDN_DNS_FAILURE,
        DiagnosticFailureReason.CDN_TLS_FAILURE,
        DiagnosticFailureReason.CDN_METHOD_REJECTED,
        DiagnosticFailureReason.CDN_RATE_LIMITED,
        DiagnosticFailureReason.CDN_TIMEOUT,
        DiagnosticFailureReason.CDN_ORIGIN_UNREACHABLE,
        DiagnosticFailureReason.ORIGIN_TLS_FAILURE,
        DiagnosticFailureReason.ORIGIN_PROXY_FAILURE,
    )

    @Test fun `typed ingress handshake maps only for CDN XHTTP`() {
        assertEquals(DiagnosticFailureReason.XHTTP_HANDSHAKE_FAILURE,
            mapRelayFailureForPath(RelayFailureCategory.INGRESS_HANDSHAKE_FAILED, PathKind.CHAIN_CDN, TransportKind.XRAY_XHTTP))
        assertEquals(DiagnosticFailureReason.PROTOCOL_OR_TRANSPORT_BLOCKED,
            mapRelayFailureForPath(RelayFailureCategory.INGRESS_HANDSHAKE_FAILED, PathKind.CHAIN_DIRECT, TransportKind.XRAY_REALITY))
    }

    @Test fun `out of band relay proof is distinct from native data plane confirmation`() {
        assertEquals(DiagnosticFailureReason.RELAY_PROOF_FAILURE,
            mapRelayFailureForPath(RelayFailureCategory.END_TO_END_DATA_PLANE_FAILED, PathKind.CHAIN_CDN, TransportKind.XRAY_XHTTP))
        assertEquals(DiagnosticFailureReason.DATA_PLANE_PROOF_FAILURE,
            mapTransportFailureForPath(TransportFailureKind.REMOTE_UNCONFIRMED, PathKind.CHAIN_CDN, TransportKind.XRAY_XHTTP))
        assertEquals(DiagnosticFailureReason.DATA_PLANE_PROOF_FAILURE,
            mapTransportFailureForPath(TransportFailureKind.RELAY_DATA_PLANE_LOST, PathKind.CHAIN_CDN, TransportKind.XRAY_XHTTP))
        assertNull(mapTransportFailureForPath(TransportFailureKind.REMOTE_UNCONFIRMED, PathKind.DIRECT, TransportKind.XRAY_REALITY))
        assertNull(mapTransportFailureForPath(TransportFailureKind.RELAY_DATA_PLANE_LOST, PathKind.CHAIN_DIRECT, TransportKind.XRAY_REALITY))
        assertNull(mapTransportFailureForPath(TransportFailureKind.RELAY_DATA_PLANE_LOST, PathKind.CHAIN_CDN, TransportKind.TLS_TCP))
        assertNull(mapTransportFailureForPath(null, PathKind.CHAIN_CDN, TransportKind.XRAY_XHTTP))
    }

    @Test fun `unrelated relay failures keep B29 reasons`() {
        for (category in RelayFailureCategory.entries - setOf(
            RelayFailureCategory.INGRESS_HANDSHAKE_FAILED,
            RelayFailureCategory.END_TO_END_DATA_PLANE_FAILED,
        )) {
            assertEquals(mapRelayFailureCategoryToFailureReason(category),
                mapRelayFailureForPath(category, PathKind.CHAIN_CDN, TransportKind.XRAY_XHTTP))
        }
        for (kind in listOf(TransportKind.AMNEZIA_WG, TransportKind.XRAY_REALITY, TransportKind.TLS_TCP)) {
            assertEquals(mapRelayFailureCategoryToFailureReason(RelayFailureCategory.END_TO_END_DATA_PLANE_FAILED),
                mapRelayFailureForPath(RelayFailureCategory.END_TO_END_DATA_PLANE_FAILED, PathKind.CHAIN_DIRECT, kind))
        }
    }

    @Test fun `all CDN vocabulary values are closed and safe for B29 export`() {
        val reasons = listOf(
            DiagnosticFailureReason.CDN_DNS_FAILURE,
            DiagnosticFailureReason.CDN_TLS_FAILURE,
            DiagnosticFailureReason.CDN_METHOD_REJECTED,
            DiagnosticFailureReason.CDN_RATE_LIMITED,
            DiagnosticFailureReason.CDN_TIMEOUT,
            DiagnosticFailureReason.CDN_ORIGIN_UNREACHABLE,
            DiagnosticFailureReason.ORIGIN_TLS_FAILURE,
            DiagnosticFailureReason.ORIGIN_PROXY_FAILURE,
            DiagnosticFailureReason.XHTTP_HANDSHAKE_FAILURE,
            DiagnosticFailureReason.RELAY_PROOF_FAILURE,
            DiagnosticFailureReason.DATA_PLANE_PROOF_FAILURE,
        )
        reasons.forEach { assertTrue(DiagnosticSanitizer.isSafeValue(it.name)) }
    }

    @Test fun `reserved CDN and unknowable origin reasons are unreachable from every current structured mapping input`() {
        val emitted = mutableSetOf<DiagnosticFailureReason>()
        for (path in PathKind.entries) {
            for (transport in TransportKind.entries) {
                for (category in RelayFailureCategory.entries) {
                    emitted += mapRelayFailureForPath(category, path, transport)
                    emitted += mapRelayProbeFailureForPath(category, null, path, transport)
                    for (probeKind in RelayProbeFailureKind.entries) {
                        emitted += mapRelayProbeFailureForPath(category, probeKind, path, transport)
                    }
                }
                for (failure in TransportFailureKind.entries) {
                    mapTransportFailureForPath(failure, path, transport)?.let(emitted::add)
                }
            }
        }
        assertTrue("unexpected runtime producer for ${unavailableCdnOriginReasons.intersect(emitted)}",
            unavailableCdnOriginReasons.intersect(emitted).isEmpty())
    }

    @Test fun `diagnostic mapping cannot change Auto failover eligibility or candidate sequence`() {
        val state = TransportState.Error("opaque failure", failureKind = TransportFailureKind.REMOTE_UNCONFIRMED)
        val error = VpnError.BackendStartFailure("typed runtime failure")
        fun candidateSequence() = if (AutoGatewayFailoverPolicy.isEligibleForNextCandidate(state, error)) {
            listOf("candidate-a", "candidate-b")
        } else {
            listOf("candidate-a")
        }

        val before = candidateSequence()
        assertEquals(DiagnosticFailureReason.DATA_PLANE_PROOF_FAILURE,
            mapTransportFailureForPath(state.failureKind, PathKind.CHAIN_CDN, TransportKind.XRAY_XHTTP))
        val after = candidateSequence()

        assertEquals(listOf("candidate-a", "candidate-b"), before)
        assertEquals(before, after)
    }
}
