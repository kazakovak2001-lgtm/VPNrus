package net.pocvpn.client.bootstrap

import net.pocvpn.client.vpn.config.ProductionGatewayId

/**
 * B36 - the deterministic bootstrap-candidate fallback order for the
 * pre-activation bootstrap tunnel (see docs/B36_BOOTSTRAP_PRE_ACTIVATION_TUNNEL.md).
 *
 * Deliberately NOT Smart Connect scoring - task scope explicitly excludes
 * "complicated Smart Connect scoring" for this PoC slice. A plain, fixed
 * list is sufficient: try the preferred/default candidate first, fall back
 * to the other known candidate, then stop (never loop, never retry an
 * already-attempted candidate within one bootstrap sequence).
 *
 * Sourced from [net.pocvpn.client.vpn.config.ProductionGatewayCatalog.all]
 * (the SAME real gateway facts every other gateway-aware call site already
 * uses) - never a second, independently-maintained gateway list.
 */
object BootstrapCatalog {
    /** Frankfurt first (today's original/most-established gateway), then Stockholm. */
    val candidatesInOrder: List<ProductionGatewayId> = listOf(
        ProductionGatewayId.GERMANY,
        ProductionGatewayId.STOCKHOLM,
    )
}
