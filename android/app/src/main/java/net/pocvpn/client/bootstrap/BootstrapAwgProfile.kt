package net.pocvpn.client.bootstrap

import net.pocvpn.client.vpn.config.AwgConfig
import net.pocvpn.client.vpn.config.AwgPeer
import net.pocvpn.client.vpn.config.ProductionGatewayDescriptor

/**
 * B36 - pure construction of the restricted bootstrap [AwgConfig] for one
 * gateway candidate. Pure/no Android dependency so this is unit-testable on
 * the JVM exactly like [net.pocvpn.client.vpn.xray.buildXrayVpnPlan] already
 * is (see that file's own docs for the same "computed as a pure function"
 * rationale) - the routing-safety proof this task requires (requirement 7/
 * test H) is a property of THIS function, provable without a real
 * VpnService/Builder.
 *
 * Restriction (task requirement 4): [AwgPeer.allowedIps] is narrowed to
 * EXACTLY [controlPlaneHost]/32 - the gateway's own public control-plane
 * address, the ONE destination this bootstrap identity is ever meant to
 * reach - never the normal profile's `0.0.0.0/0`/`::/0`. This is a
 * CLIENT-side routing decision only: it decides which packets THIS DEVICE
 * sends into the bootstrap tunnel, and is NOT itself a security boundary (a
 * patched APK could ignore it) - the real enforcement is server-side (see
 * [BootstrapIdentity]'s own docs and the plan document). Restricting it
 * here anyway is still correct: it keeps this device's own other traffic
 * (DNS, any other app, Nova's own later normal connection) from ever being
 * captured by the bootstrap interface even by accident, and it is the
 * client-side half of defense in depth.
 *
 * No app-exclusion (task requirement 7): unlike
 * [net.pocvpn.client.vpn.xray.buildXrayVpnPlan] (which always disallows
 * Nova's own package - see that file's own "recursion prevention" docs,
 * because the pinned Xray-core AAR exposes no protect-fd hook of its own),
 * this config's [AwgConfig.includedApplications]/[AwgConfig.excludedApplications]
 * are BOTH left empty - i.e. ALL apps, including Nova's own process, are
 * captured by this interface. This is deliberate and is what makes the
 * bootstrap tunnel usable for [net.pocvpn.client.provisioning.ProvisioningClient]'s
 * own in-process HTTPS calls at all: AmneziaWG's `GoBackend` protects only
 * its OWN outbound WireGuard UDP socket internally (the same reason
 * [net.pocvpn.client.vpn.AmneziaWgTransport] never calls
 * `addDisallowedApplication` either, for the NORMAL AWG tunnel) - see
 * docs/B36_BOOTSTRAP_PRE_ACTIVATION_TUNNEL.md's "why AWG, not Xray" section
 * for the full audit trail. [bootstrapControlPlaneHost] is exactly the host
 * [net.pocvpn.client.controlplane.ControlPlaneOriginSetBuilder]/
 * [net.pocvpn.client.provisioning.ProvisioningClient.activate] would already
 * dial for this SAME [gateway] - reusing that exact value (never a second,
 * separately-maintained host literal) is what proves the existing,
 * unmodified activation call genuinely routes into this tunnel: the
 * destination it already dials is a member of [AwgPeer.allowedIps] by
 * construction.
 */
fun bootstrapControlPlaneHost(gateway: ProductionGatewayDescriptor): String = gateway.awg.endpointHost

fun buildBootstrapAwgConfig(gateway: ProductionGatewayDescriptor): AwgConfig {
    val controlPlaneHost = bootstrapControlPlaneHost(gateway)
    return AwgConfig(
        privateKeyBase64 = BootstrapIdentity.PLACEHOLDER_PRIVATE_KEY_BASE64,
        localAddresses = listOf(BootstrapIdentity.CLIENT_TUNNEL_ADDRESS_CIDR),
        dnsServers = listOf("1.1.1.1", "1.0.0.1"),
        listenPort = null,
        mtu = null,
        profile = gateway.awgProfile,
        peer = AwgPeer(
            publicKeyBase64 = gateway.awg.serverPublicKeyBase64,
            endpointHost = gateway.awg.endpointHost,
            endpointPort = gateway.awg.endpointPort,
            allowedIps = listOf("$controlPlaneHost/32"),
        ),
        includedApplications = emptySet(),
        excludedApplications = emptySet(),
    )
}
