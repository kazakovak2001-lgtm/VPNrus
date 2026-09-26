package net.pocvpn.client.provisioning

import net.pocvpn.client.identity.XrayXhttpProfile

/** B64 - the Direct/EXIT XHTTP counterpart of [XrayTlsProfileResult.Success.toXrayTlsProfile]: a validated [XrayXhttpProfileResult.Success] becomes the persistable [XrayXhttpProfile]. */
fun XrayXhttpProfileResult.Success.toXrayXhttpProfile(): XrayXhttpProfile = XrayXhttpProfile(
    server = serverAddress,
    serverPort = serverPort,
    uuid = uuid,
    xhttpHost = xhttpHost,
    xhttpPath = xhttpPath,
    mode = mode,
    uplinkHttpMethod = uplinkHttpMethod,
    fingerprint = fingerprint,
)
