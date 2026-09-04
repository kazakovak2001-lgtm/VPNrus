package net.pocvpn.client.provisioning

/**
 * Russia field-test zero-touch enrollment - the outcome of one
 * POST /v1/field-enroll attempt (see gateway/api/field_enrollment.py's own
 * docs for the server-side design). Deliberately mirrors [ProvisioningResult]'s
 * own shape/exhaustiveness discipline - this is the SAME kind of response,
 * with exactly one new field ([Success.activationCredential]) - never a
 * second, differently-shaped result type invented for its own sake.
 */
sealed class FieldEnrollmentResult {

    data class Success(
        val activationCredential: String,
        val clientTunnelIp: String,
        val gatewayPublicKey: String,
        val gatewayTunnelIp: String,
        val endpointHost: String,
        val endpointPort: Int,
    ) : FieldEnrollmentResult()

    /** HTTP 400 error=invalid_public_key - should not happen for a locally-generated key; fails closed rather than retried blindly. */
    object BadRequest : FieldEnrollmentResult()

    /** HTTP 403 error=device_limit_reached - the field-test device cap has been reached, or this credential's own single-device slot is unexpectedly already taken. */
    object DeviceLimitReached : FieldEnrollmentResult()

    /** HTTP 403 error=revoked - an operator revoked this device's enrollment. */
    object Revoked : FieldEnrollmentResult()

    /** HTTP 403 error=expired - should not happen (field-enrollment records carry no expiry today); kept for exhaustiveness/future-proofing, never expected in practice. */
    object Expired : FieldEnrollmentResult()

    /** HTTP 503/504, including field_enrollment_not_configured (feature disabled on this deployment) - the normal state for any non-field-test gateway. */
    object ServiceUnavailable : FieldEnrollmentResult()

    /** HTTP 200 but the body failed narrow structural validation - never used unparsed. */
    data class MalformedResponse(val reason: String) : FieldEnrollmentResult()

    /** Anything else: connection failure, TLS failure, timeout, or an unexpected HTTP status. */
    data class NetworkError(val message: String) : FieldEnrollmentResult()
}
