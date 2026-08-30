package net.pocvpn.client.vpn.xray

import net.pocvpn.client.identity.XrayProfile
import net.pocvpn.client.identity.XrayTlsProfile

/** The one place a stored [XrayProfile] becomes a renderer/service-ready [XrayVlessRealityConfig]. */
fun XrayProfile.toXrayVlessRealityConfig(): XrayVlessRealityConfig = XrayVlessRealityConfig(
    server = server,
    serverPort = serverPort,
    uuid = uuid,
    flow = flow,
    serverName = serverName,
    fingerprint = fingerprint,
    realityPublicKey = realityPublicKey,
    shortId = shortId,
)

/** B8O2 - the TLS/TCP counterpart: a stored [XrayTlsProfile] becomes a renderer/service-ready [XrayVlessTlsConfig]. */
fun XrayTlsProfile.toXrayVlessTlsConfig(): XrayVlessTlsConfig = XrayVlessTlsConfig(
    server = server,
    serverPort = serverPort,
    uuid = uuid,
    serverName = serverName,
    fingerprint = fingerprint,
)
