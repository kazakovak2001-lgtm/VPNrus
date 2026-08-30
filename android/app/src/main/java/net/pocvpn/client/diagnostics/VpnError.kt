package net.pocvpn.client.diagnostics

/**
 * Structured, non-secret error categories. Every variant carries only a
 * short diagnostic reason string - never a full exception, stack trace, or
 * anything derived from key/config material.
 */
sealed class VpnError(val category: String, val reason: String? = null) {
    object PermissionDenied : VpnError("PermissionDenied")
    object GatewayConfigurationMissing : VpnError("GatewayConfigurationMissing")
    data class InvalidGatewayConfiguration(val detail: String) : VpnError("InvalidGatewayConfiguration", detail)
    data class BackendStartFailure(val detail: String) : VpnError("BackendStartFailure", detail)
    data class BackendStopFailure(val detail: String) : VpnError("BackendStopFailure", detail)
    object NetworkUnavailable : VpnError("NetworkUnavailable")
    object ReconnectExhausted : VpnError("ReconnectExhausted")
    data class ConfigurationMappingFailure(val detail: String) : VpnError("ConfigurationMappingFailure", detail)
    object AlreadyInProgress : VpnError("AlreadyInProgress")
    object HandshakeTimeout : VpnError("HandshakeTimeout")
    // B8H - VPN_ONLY_SELECTED resolved to zero installed apps (see
    // EffectiveRoutingResult.NoAppsSelected's own docs for why this must
    // fail rather than silently behave like ALL_APPS).
    object SplitTunnelingNoAppsSelected : VpnError("SplitTunnelingNoAppsSelected")

    // B8I2 - Smart Connect preflight (MainViewModel.connect()) found no usable
    // candidate at all - SmartConnectCandidateSelector.decide() returned
    // NoCandidateAvailable (network unusable, no gateway configured, or no
    // transport available - see that class's own docs for the exact cases
    // this covers). Distinct from NetworkUnavailable above so this state
    // never implies "the network specifically" when the real cause might be
    // a missing/invalid gateway instead.
    object NoCandidateAvailable : VpnError("NoCandidateAvailable")

    // B8I2 - Smart Connect selected a real transport, but it is not
    // TransportKind.AMNEZIA_WG - this slice does not implement transport
    // switching, so connect() must fail closed rather than silently connect
    // with the wrong transport. [kind] is a TransportKind's own enum name -
    // never secret.
    data class UnsupportedTransportSelected(val kind: String) : VpnError("UnsupportedTransportSelected", kind)

    /** Safe to show a developer, e.g. in the diagnostics panel - never includes key material. */
    fun displayText(): String = if (reason != null) "$category: $reason" else category
}
