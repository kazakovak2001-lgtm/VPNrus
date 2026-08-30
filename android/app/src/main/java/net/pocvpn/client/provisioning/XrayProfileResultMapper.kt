package net.pocvpn.client.provisioning

import net.pocvpn.client.identity.XrayProfile

/**
 * B8K4A - the one place a validated [XrayProfileResult.Success] becomes the
 * persistable [XrayProfile]. Not wired to any repository/store yet - see
 * B8K4A's scope note in ProvisioningClient.
 */
fun XrayProfileResult.Success.toXrayProfile(): XrayProfile = XrayProfile(
    server = serverAddress,
    serverPort = serverPort,
    uuid = uuid,
    flow = flow,
    serverName = serverName,
    fingerprint = fingerprint,
    realityPublicKey = realityPublicKey,
    shortId = shortId,
)
