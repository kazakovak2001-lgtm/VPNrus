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
 *
 * B37 - [gateway] is now always resolved from
 * [FieldTestAwg31GatewayCatalog], never [net.pocvpn.client.vpn.config.ProductionGatewayCatalog]
 * (see [FieldTestTunnelController]'s `gatewayLookup` wiring in
 * [FieldTestViewModel]) - so the identity used here must be
 * [FieldTestAwg31Identity] (provisioned on the isolated `awg-ft31`
 * interface/subnet), never the legacy [FieldTestIdentity] (provisioned, if
 * ever, on the shared production `awg0` subnet - a mismatched identity
 * would silently be assigned the wrong subnet's tunnel address).
 */
fun buildFieldTestAwgConfig(gateway: ProductionGatewayDescriptor): AwgConfig =
    AwgConfig(
        privateKeyBase64 = FieldTestAwg31Identity.FIELD_TEST_AWG31_PRIVATE_KEY_BASE64,
        localAddresses = listOf(FieldTestAwg31Identity.CLIENT_TUNNEL_ADDRESS_CIDR),
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
