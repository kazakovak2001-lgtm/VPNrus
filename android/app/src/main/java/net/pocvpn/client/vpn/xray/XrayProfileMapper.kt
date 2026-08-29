package net.pocvpn.client.vpn.xray

import net.pocvpn.client.identity.XrayProfile

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
