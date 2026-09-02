package net.pocvpn.client.provisioning

import net.pocvpn.client.identity.XrayQuicProfile

/** B21 - the QUIC counterpart of XrayTlsProfileResultMapper: a validated [XrayQuicProfileResult.Success] becomes the persistable [XrayQuicProfile]. */
fun XrayQuicProfileResult.Success.toXrayQuicProfile(): XrayQuicProfile = XrayQuicProfile(
    server = serverAddress,
    serverPort = serverPort,
    uuid = uuid,
    serverName = serverName,
    fingerprint = fingerprint,
    path = path,
)
