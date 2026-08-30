package net.pocvpn.client.provisioning

/**
 * B8K4B - the outcome of one [XrayProfileProvisioner.provision] attempt, kept
 * a small closed set so a caller can distinguish exactly what happened
 * without inspecting the underlying [XrayProfileResult]. Deliberately
 * coarser than [XrayProfileResult]: several distinct wire outcomes
 * (Unauthorized/Revoked/DeviceNotBound) collapse into one
 * [AuthorizationFailed] state here because every one of them means the same
 * thing to a caller deciding what to do next - stop retrying automatically
 * and surface a re-activation prompt.
 */
sealed class XrayProfileProvisioningOutcome {

    /** The fetched profile passed validation and was persisted via [XrayProfileRepository][net.pocvpn.client.identity.XrayProfileRepository]. */
    object Saved : XrayProfileProvisioningOutcome()

    /** Network/TLS failure or HTTP 503 - transient, safe to retry later. Any previously stored profile is left untouched. */
    object Unavailable : XrayProfileProvisioningOutcome()

    /** HTTP 401, or 403 revoked/device_not_bound - not retryable without new activation. Any previously stored profile is left untouched. */
    object AuthorizationFailed : XrayProfileProvisioningOutcome()

    /** HTTP 200/201 but the body failed structural validation - never persisted. Any previously stored profile is left untouched. */
    data class Malformed(val reason: String) : XrayProfileProvisioningOutcome()
}
