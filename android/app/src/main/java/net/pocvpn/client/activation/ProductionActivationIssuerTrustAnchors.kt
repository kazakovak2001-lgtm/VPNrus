package net.pocvpn.client.activation

import java.util.Base64

/**
 * B56-4B1 - the production population of [FixedActivationIssuerTrustAnchors]
 * for the ACTIVATION authority. This is the real, ceremony-generated
 * production activation-issuer public key - see
 * `docs/B56_ACTIVATION_ISSUER_KEY_CEREMONY.md`'s "Production ceremony -
 * 2026-09-20 (final, network-isolated)" section for the fingerprint,
 * ceremony date, network-isolation evidence, and cross-verification record.
 *
 * The corresponding PRIVATE key was generated entirely inside one
 * `generate-key` invocation run inside an explicitly network-isolated Linux
 * network namespace (`unshare --net`, verified to have no externally
 * routable interface or route before generation) on an operator-controlled
 * Linux/WSL machine, and exists ONLY outside this repository, in that
 * operator-controlled ceremony location - never printed, never committed,
 * never transmitted. This object carries the PUBLIC key bytes only, exactly
 * matching the ceremony's `publicKeyBase64` metadata field (JVM `Base64`
 * decode pattern reused verbatim from
 * [net.pocvpn.client.reachability.EmbeddedBootstrapManifest]).
 *
 * An earlier candidate key (`prod-activation-issuer-2026-09-20`, no `-r2`
 * suffix) was generated in a first ceremony pass but its network-isolation
 * provenance could not be positively established after the fact - it was
 * abandoned before merge, was never trusted by any merged client, and never
 * issued a redeemable activation. See the ceremony doc's "Abandoned
 * candidate" note. It does not appear anywhere in [trustAnchors].
 *
 * B56-5 boundary: this object is only the production trust-root SOURCE. It
 * is NOT wired into bootstrap networking, UI, `MainViewModel`,
 * `ActivationScreen`, or any reachability/lane-selection code in this slice
 * - that composition is B56-5's job. Nothing in this file performs I/O, and
 * nothing else in the app currently calls [trustAnchors].
 */
object ProductionActivationIssuerTrustAnchors {

    const val PRIMARY_KEY_ID = "prod-activation-issuer-2026-09-20-r2"

    private const val PRIMARY_PUBLIC_KEY_BASE64 = "zevmlNdAu9l7ofRx9MFvp1oK2dSMA0ckIgqVYvuLtNE="

    fun trustAnchors(): ActivationIssuerTrustAnchors =
        FixedActivationIssuerTrustAnchors(
            mapOf(
                ActivationIssuerKeyId(PRIMARY_KEY_ID) to
                    Base64.getDecoder().decode(PRIMARY_PUBLIC_KEY_BASE64),
            ),
        )
}
