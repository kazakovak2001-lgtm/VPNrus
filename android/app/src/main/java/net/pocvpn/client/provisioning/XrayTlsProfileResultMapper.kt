package net.pocvpn.client.provisioning

import net.pocvpn.client.identity.XrayTlsProfile

/** B8O2 - the TLS/TCP counterpart of XrayProfileResultMapper: a validated [XrayTlsProfileResult.Success] becomes the persistable [XrayTlsProfile]. */
fun XrayTlsProfileResult.Success.toXrayTlsProfile(): XrayTlsProfile = XrayTlsProfile(
    server = serverAddress,
    serverPort = serverPort,
    uuid = uuid,
    serverName = serverName,
    fingerprint = fingerprint,
)
