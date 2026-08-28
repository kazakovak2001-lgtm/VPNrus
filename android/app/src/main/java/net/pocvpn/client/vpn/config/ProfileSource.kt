package net.pocvpn.client.vpn.config

/** B8B3C - debug-only visibility into where the currently-effective gateway profile came from. */
enum class ProfileSource {
    /** Freshly applied from a live POST /v1/peers response this session. */
    PROVISIONED_LIVE,

    /** Loaded from ProfileStore at startup - a prior session's provisioning result. */
    RESTORED_PERSISTED,

    /** Neither of the above - whatever BuildConfigGatewaySource/gateway-dev.properties provides. */
    DEV_FALLBACK,
}
