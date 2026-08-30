package net.pocvpn.client.vpn.xray

import net.pocvpn.client.identity.XrayProfileRepository

/**
 * What [XrayRuntimeResolver.resolve] decided about the currently stored
 * Xray profile. Never carries uuid/realityPublicKey/shortId in [Rejected]'s
 * reason - only an exception class name or a validation-error count, same
 * discipline as every other error string in this adapter (see
 * [XrayVlessRealityConfig]'s own redacted toString).
 */
sealed class XrayRuntimeResolution {
    data class Ready(val config: XrayVlessRealityConfig, val renderedConfig: String) : XrayRuntimeResolution()
    data class Rejected(val reason: String) : XrayRuntimeResolution()
}

/**
 * B8K4C - the ONE place a stored [net.pocvpn.client.identity.XrayProfile]
 * becomes (or is rejected as) a runtime-ready Xray core config: load -> fail
 * closed if absent/corrupt -> map (XrayProfileMapper's toXrayVlessRealityConfig)
 * -> validate (validateXrayVlessRealityConfig) -> render (XrayConfigRenderer).
 * Pure - no Android framework dependency - so this decision is unit-testable
 * on the plain JVM (this project has no Robolectric dependency). Used by
 * BOTH [NovaXrayVpnService] (to decide whether to actually start the core)
 * and [net.pocvpn.client.vpn.VlessRealityTransport] (as a pre-flight check
 * before even requesting a start) against the SAME [XrayProfileRepository]
 * instance-shape, so neither side can diverge from what the other will
 * actually use - see VlessRealityTransport's own docs for why it no longer
 * trusts the config object callers pass into connect().
 */
object XrayRuntimeResolver {
    suspend fun resolve(repository: XrayProfileRepository): XrayRuntimeResolution {
        val profile = try {
            repository.getProfileOrNull()
        } catch (t: Throwable) {
            return XrayRuntimeResolution.Rejected("failed to load Xray profile: ${t.javaClass.simpleName}")
        } ?: return XrayRuntimeResolution.Rejected("no Xray profile configured")

        val config = profile.toXrayVlessRealityConfig()
        return when (val validation = validateXrayVlessRealityConfig(config)) {
            is XrayConfigValidationResult.Invalid ->
                XrayRuntimeResolution.Rejected("stored Xray profile failed validation: ${validation.errors.size} error(s)")
            is XrayConfigValidationResult.Valid ->
                XrayRuntimeResolution.Ready(validation.config, XrayConfigRenderer.render(validation.config))
        }
    }
}
