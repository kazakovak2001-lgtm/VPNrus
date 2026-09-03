package net.pocvpn.client.controlplane

import net.pocvpn.client.diagnostics.support.DiagnosticEventType
import net.pocvpn.client.diagnostics.support.InMemoryDiagnosticSessionStore
import net.pocvpn.client.diagnostics.support.SupportDiagnosticsRecorder
import net.pocvpn.client.provisioning.ProvisioningResult
import net.pocvpn.client.vpn.config.ProductionGatewayId
import net.pocvpn.client.vpn.policy.RoutingMode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ActivationResilienceCoordinatorTest {

    private fun success(host: String) = ProvisioningResult.Success(
        clientTunnelIp = "10.77.0.5",
        gatewayPublicKey = "pk",
        gatewayTunnelIp = "10.77.0.1",
        endpointHost = host,
        endpointPort = 51820,
    )

    private val origins = listOf(
        ControlPlaneOrigin(ProductionGatewayId.GERMANY, "origin-a"),
        ControlPlaneOrigin(ProductionGatewayId.GERMANY, "origin-b"),
    )

    @Test
    fun `primary origin fails, secondary succeeds - activation still succeeds`() {
        val coordinator = ActivationResilienceCoordinator()
        val outcome = coordinator.activate(
            gatewayId = ProductionGatewayId.GERMANY,
            publicKey = "pk",
            activationCredential = "cred",
            hasValidLocalActivation = { false },
            callActivate = { origin, _, _ ->
                if (origin.host == "origin-a") ProvisioningResult.NetworkError("SocketTimeoutException: t") else success(origin.host)
            },
            origins = origins,
        )
        assertTrue(outcome is ActivationResilienceCoordinator.Outcome.Success)
        assertEquals(1, (outcome as ActivationResilienceCoordinator.Outcome.Success).originIndex)
    }

    @Test
    fun `all origins fail yields an explicit typed exhaustion outcome`() {
        val coordinator = ActivationResilienceCoordinator()
        val outcome = coordinator.activate(
            gatewayId = ProductionGatewayId.GERMANY,
            publicKey = "pk",
            activationCredential = "cred",
            hasValidLocalActivation = { false },
            callActivate = { _, _, _ -> ProvisioningResult.ServiceUnavailable },
            origins = origins,
        )
        assertTrue(outcome is ActivationResilienceCoordinator.Outcome.AllOriginsExhausted)
        assertEquals(2, (outcome as ActivationResilienceCoordinator.Outcome.AllOriginsExhausted).failures.size)
    }

    @Test
    fun `an authorization rejection is terminal - never tried against a second origin, never disguised as exhaustion`() {
        var attempts = 0
        val coordinator = ActivationResilienceCoordinator()
        val outcome = coordinator.activate(
            gatewayId = ProductionGatewayId.GERMANY,
            publicKey = "pk",
            activationCredential = "wrong-cred",
            hasValidLocalActivation = { false },
            callActivate = { _, _, _ -> attempts++; ProvisioningResult.Revoked },
            origins = origins,
        )
        assertEquals(1, attempts)
        assertTrue(outcome is ActivationResilienceCoordinator.Outcome.Rejected)
        assertEquals(ProvisioningResult.Revoked, (outcome as ActivationResilienceCoordinator.Outcome.Rejected).result)
    }

    @Test
    fun `already-valid local activation short-circuits - zero network calls`() {
        var networkCalls = 0
        val coordinator = ActivationResilienceCoordinator()
        val outcome = coordinator.activate(
            gatewayId = ProductionGatewayId.GERMANY,
            publicKey = "pk",
            activationCredential = "cred",
            hasValidLocalActivation = { true },
            callActivate = { _, _, _ -> networkCalls++; success("origin-a") },
            origins = origins,
        )
        assertEquals(0, networkCalls)
        assertTrue(outcome is ActivationResilienceCoordinator.Outcome.AlreadyValidLocally)
    }

    @Test
    fun `retry after a first attempt reuses the SAME public key and credential - never a new logical activation identity`() {
        val seenKeys = mutableListOf<String>()
        val seenCredentials = mutableListOf<String>()
        val coordinator = ActivationResilienceCoordinator()
        val callActivate: (ControlPlaneOrigin, String, String) -> ProvisioningResult = { origin, key, cred ->
            seenKeys += key
            seenCredentials += cred
            success(origin.host)
        }

        coordinator.activate(ProductionGatewayId.GERMANY, "device-key-1", "cred-1", { false }, callActivate, origins)
        // A second, independent Retry call (e.g. app restart, user tapping Retry) -
        // the caller always passes the SAME already-get-or-created public key.
        coordinator.activate(ProductionGatewayId.GERMANY, "device-key-1", "cred-1", { false }, callActivate, origins)

        assertEquals(listOf("device-key-1"), seenKeys.distinct())
        assertEquals(listOf("cred-1"), seenCredentials.distinct())
    }

    @Test
    fun `diagnostics record typed origin attempts and results but never a host, IP, URL, credential, or UUID`() {
        val store = InMemoryDiagnosticSessionStore()
        val recorder = SupportDiagnosticsRecorder(store, appVersionName = "1.0", appVersionCode = 1L)
        recorder.startSession(
            SupportDiagnosticsRecorder.StartContext(
                networkType = net.pocvpn.client.network.NetworkType.WIFI,
                networkValidatedInternet = true,
                networkCaptivePortal = false,
                networkIpv4Available = true,
                networkIpv6Available = false,
                networkFingerprintId = null,
                rawRestrictionClass = net.pocvpn.client.smartconnect.RestrictionClass.UNKNOWN,
                stabilizedRestrictionClass = net.pocvpn.client.smartconnect.RestrictionClass.UNKNOWN,
                routingMode = RoutingMode.FULL_VPN,
                gatewaySelectionMode = net.pocvpn.client.vpn.config.GatewaySelectionMode.AUTO,
            ),
        )
        val coordinator = ActivationResilienceCoordinator(recorder)
        coordinator.activate(
            gatewayId = ProductionGatewayId.GERMANY,
            publicKey = "super-secret-device-public-key-should-never-appear",
            activationCredential = "super-secret-credential-should-never-appear",
            hasValidLocalActivation = { false },
            callActivate = { origin, _, _ ->
                if (origin.host == "origin-a") ProvisioningResult.NetworkError("SocketTimeoutException: t") else success(origin.host)
            },
            origins = origins,
        )
        recorder.finishProtected()
        val session = store.recent().single()

        assertTrue(session.events.any { it.type == DiagnosticEventType.ACTIVATION_STARTED })
        assertTrue(session.events.any { it.type == DiagnosticEventType.CONTROL_ORIGIN_ATTEMPT })
        assertTrue(session.events.any { it.type == DiagnosticEventType.CONTROL_ORIGIN_FAILED })
        assertTrue(session.events.any { it.type == DiagnosticEventType.CONTROL_ORIGIN_SUCCEEDED })
        assertTrue(session.events.any { it.type == DiagnosticEventType.ACTIVATION_SUCCEEDED })

        val allTagValues = session.events.flatMap { it.tags.values }
        allTagValues.forEach { value ->
            assertFalse("must never carry a host/IP/URL-shaped value: $value", value.contains("origin-a") || value.contains("origin-b"))
            assertFalse("must never carry the credential: $value", value.contains("super-secret"))
            assertFalse("must never look like a URL: $value", value.contains("://"))
        }
    }
}
