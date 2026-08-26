package net.pocvpn.client.identity

/**
 * Public-facing view of the client's AmneziaWG identity. Deliberately holds
 * only the public key - never the private key - so it is safe to log, show
 * in UI, or hand to code that provisions the gateway (B5/B6).
 */
data class ClientIdentity(val publicKeyBase64: String)
