package net.pocvpn.client.vpn.config

/**
 * B16 - the exact production gateway a connect() attempt CURRENTLY in
 * flight targets, when that attempt is an AUTOMATIC
 * (GatewaySelectionMode.Auto) one. Set exactly once, explicitly, by
 * MainViewModel BEFORE calling controller.connect() for a given candidate -
 * never inferred, never changed mid-attempt (see
 * PROJECT_ARCHITECTURE.md's "Candidate identity" invariant: "Never infer
 * gateway identity after the attempt starts. Do not reread
 * SelectedGatewayStore during the attempt.").
 *
 * [SelectedProductionGatewaySource]'s own `selectedGatewayId` supplier
 * consults [resolve] ahead of the persisted [SelectedGatewayStore], so a
 * real connect-time GatewayConfigSnapshot for an Auto candidate is built
 * from THIS explicit target. [fallback] is a lazily-evaluated supplier
 * (never a plain value) specifically so [SelectedGatewayStore.read] is
 * genuinely NEVER invoked while an Auto attempt has an override set - not
 * merely "invoked and ignored".
 *
 * For MANUAL mode, [current] stays null for the entire attempt (MainViewModel
 * never sets it for a manual connect()), so [resolve] always falls through
 * to [fallback] - byte-for-byte the pre-B16 behavior, manual gateway
 * selection is completely unaffected by this class's existence.
 */
class ActiveAttemptGatewaySource {
    @Volatile private var current: ProductionGatewayId? = null

    fun setForAttempt(id: ProductionGatewayId) {
        current = id
    }

    /** Called on every connect() (manual or auto) and on disconnect() - a fresh request never inherits a stale override from a prior one. */
    fun clear() {
        current = null
    }

    fun resolve(fallback: () -> ProductionGatewayId): ProductionGatewayId = current ?: fallback()
}
