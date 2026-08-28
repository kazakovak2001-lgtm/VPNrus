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

    /** Safe to show a developer, e.g. in the diagnostics panel - never includes key material. */
    fun displayText(): String = if (reason != null) "$category: $reason" else category
}
