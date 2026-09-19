package net.pocvpn.client.activation

import java.util.Base64

/**
 * B56-4B1 - the production population of [FixedActivationIssuerTrustAnchors]
 * for the ACTIVATION authority. This is the real, offline-ceremony-generated
 * production activation-issuer public key - see
 * `docs/B56_ACTIVATION_ISSUER_KEY_CEREMONY.md`'s "Production ceremony -
 * 2026-09-20" section for the fingerprint, ceremony date, and cross-
 * verification record.
 *
 * The corresponding PRIVATE key was generated entirely inside one offline
 * `generate-key` invocation on an operator-controlled Linux/WSL machine and
 * exists ONLY outside this repository, in that operator-controlled ceremony
 * location - never printed, never committed, never transmitted. This object
 * carries the PUBLIC key bytes only, exactly matching the ceremony's
 * `publicKeyBase64` metadata field (JVM `Base64` decode pattern reused
 * verbatim from [net.pocvpn.client.reachability.EmbeddedBootstrapManifest]).
 *
 * B56-5 boundary: this object is only the production trust-root SOURCE. It
 * is NOT wired into bootstrap networking, UI, `MainViewModel`,
 * `ActivationScreen`, or any reachability/lane-selection code in this slice
 * - that composition is B56-5's job. Nothing in this file performs I/O, and
 * nothing else in the app currently calls [trustAnchors].
 */
object ProductionActivationIssuerTrustAnchors {

    const val PRIMARY_KEY_ID = "prod-activation-issuer-2026-09-20"

    private const val PRIMARY_PUBLIC_KEY_BASE64 = "HZLHOiOrEXM3VXvpIudoBORhJBXUXh7lNcRry5Gcg1M="

    fun trustAnchors(): ActivationIssuerTrustAnchors =
        FixedActivationIssuerTrustAnchors(
            mapOf(
                ActivationIssuerKeyId(PRIMARY_KEY_ID) to
                    Base64.getDecoder().decode(PRIMARY_PUBLIC_KEY_BASE64),
            ),
        )
}
