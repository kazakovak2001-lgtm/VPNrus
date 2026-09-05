package net.pocvpn.client.fieldtest

import net.pocvpn.client.vpn.config.AwgConfig
import net.pocvpn.client.vpn.config.AwgPeer
import net.pocvpn.client.vpn.config.ProductionGatewayDescriptor

/**
 * Pure construction of the field-test [AwgConfig] for one gateway candidate.
 * Pure/no Android dependency, unit-testable on the JVM - same discipline as
 * [net.pocvpn.client.bootstrap.buildBootstrapAwgConfig].
 *
 * Unlike the B36 bootstrap profile, this is a NORMAL, full-tunnel config
 * ([AwgPeer.allowedIps] defaults to `0.0.0.0/0`/`::/0`) - this build exists
 * specifically to test whether the real data plane can carry general
 * Internet traffic, not merely reach one control-plane host. No B36
 * restricted-bootstrap semantics are created or reused here.
 */
fun buildFieldTestAwgConfig(gateway: ProductionGatewayDescriptor): AwgConfig =
    AwgConfig(
        privateKeyBase64 = FieldTestIdentity.FIELD_TEST_PRIVATE_KEY_BASE64,
        localAddresses = listOf(FieldTestIdentity.CLIENT_TUNNEL_ADDRESS_CIDR),
        dnsServers = listOf("1.1.1.1", "1.0.0.1"),
        listenPort = null,
        mtu = null,
        profile = gateway.awgProfile,
        peer = AwgPeer(
            publicKeyBase64 = gateway.awg.serverPublicKeyBase64,
            endpointHost = gateway.awg.endpointHost,
            endpointPort = gateway.awg.endpointPort,
            // Default AwgPeer.allowedIps (0.0.0.0/0, ::/0) - deliberate:
            // this is a real, full-tunnel VPN data-plane test, not a
            // restricted control-plane-only path.
        ),
        includedApplications = emptySet(),
        excludedApplications = emptySet(),
    )
