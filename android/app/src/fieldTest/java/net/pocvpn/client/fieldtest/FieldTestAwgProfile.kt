package net.pocvpn.client.fieldtest

import net.pocvpn.client.vpn.config.AwgConfig
import net.pocvpn.client.vpn.config.AwgPeer
import net.pocvpn.client.vpn.config.ProductionGatewayDescriptor

/**
 * Pure construction of the field-test [AwgConfig] for one gateway candidate.
 * Pure/no Android dependency, unit-testable on the JVM - same discipline as
 * [net.pocvpn.client.bootstrap.buildBootstrapAwgConfig].
 *
 * Unlike the B36 bootstrap profile, this is a NORMAL, full-tunnel config -
 * this build exists specifically to test whether the real data plane can
 * carry general Internet traffic, not merely reach one control-plane host.
 * No B36 restricted-bootstrap semantics are created or reused here.
 *
 * B37 senior-review pass (task E2) - [AwgPeer.allowedIps] is set explicitly
 * to `0.0.0.0/0` ONLY (never the shared default's `::/0` IPv6 route too):
 * the B37 server side (provision-ft31.sh / pocvpn-ft31.nft.template) is
 * IPv4-only (NAT/masquerade rules are IPv4-only, no IPv6 server path exists
 * or has been validated), so routing the field-test client's IPv6 traffic
 * into this tunnel would silently blackhole it - never claim IPv6
 * full-tunnel support this build does not actually provide.
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
            // IPv4-only (task E2) - see this file's own top-level docs: the
            // B37 server side has no IPv6 NAT/forwarding path, so the
            // shared AwgPeer default of also routing ::/0 into this tunnel
            // would silently blackhole the field-test device's IPv6
            // traffic. Still a real, full-tunnel test of general IPv4
            // Internet traffic, not a restricted control-plane-only path.
            allowedIps = listOf("0.0.0.0/0"),
        ),
        includedApplications = emptySet(),
        excludedApplications = emptySet(),
    )
