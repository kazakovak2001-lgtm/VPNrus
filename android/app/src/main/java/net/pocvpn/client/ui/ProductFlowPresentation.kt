package net.pocvpn.client.ui

import net.pocvpn.client.provisioning.ProvisioningUiState
import net.pocvpn.client.vpn.TransportState
import net.pocvpn.client.vpn.VpnSessionHealth
import net.pocvpn.client.vpn.config.ProfileSource
import net.pocvpn.client.vpn.policy.AppRoutingMode
import net.pocvpn.client.vpn.policy.AppRoutingPolicy

/**
 * B8D - pure, Android-framework-free presentation logic for the product
 * flow (first-run activation vs normal Home). Kept out of MainActivity so
 * it is unit-testable on the JVM without Robolectric/instrumentation -
 * MainActivity should only call these, never re-derive the same decisions
 * inline.
 */

/** Which top-level screen the user sees. */
enum class AppScreen { ACTIVATION, HOME }

/**
 * B8D requirement: "the existence of a valid provisioned/restored profile
 * should determine whether the user sees Activation or Home". ProfileSource
 * .DEV_FALLBACK is the ONLY value MainViewModel ever leaves in place when
 * NO profile has ever been provisioned or restored - see
 * MainViewModel.restorePersistedProfile(), which deliberately leaves it
 * untouched for BOTH ProfileLoadResult.NotFound and ProfileLoadResult
 * .Corrupted (fail closed - a corrupt file is treated exactly like no
 * file). So this one comparison already implements "corrupt/missing
 * profile -> activation screen, valid persisted/provisioned profile ->
 * home screen" with no new state of its own.
 */
fun screenFor(profileSource: ProfileSource): AppScreen =
    if (profileSource == ProfileSource.DEV_FALLBACK) AppScreen.ACTIVATION else AppScreen.HOME

/**
 * Russia field-test zero-touch enrollment - the SAME decision as
 * [screenFor] above, except a build with [zeroTouchEnrollmentEnabled] set
 * NEVER shows [AppScreen.ACTIVATION]: an unprovisioned device goes straight
 * to Home, and MainViewModel.connect()'s own ensureZeroTouchEnrollment()
 * handles first-time activation silently the moment the tester presses
 * Connect - see that function's own docs. `false` (the default for every
 * ordinary debug/release build) reproduces [screenFor]'s exact behavior,
 * byte-for-byte - this is a strict widening, never a second decision
 * authority.
 */
fun screenFor(profileSource: ProfileSource, zeroTouchEnrollmentEnabled: Boolean): AppScreen =
    if (zeroTouchEnrollmentEnabled) AppScreen.HOME else screenFor(profileSource)

/**
 * B8D "CONNECTION WORDING" - truthful, non-technical status text for the
 * normal Home screen. Never reads "Protected" before TransportState
 * .Connected - that state is only reached after a real handshake was
 * already observed (see VpnController.awaitFreshHandshake), never from
 * interface-up/TX>0 alone.
 */
fun TransportState.toHomeStatusText(): String = when (this) {
    is TransportState.Disconnected -> "Disconnected"
    is TransportState.Connecting -> "Connecting…"
    is TransportState.Connected -> "Protected"
    is TransportState.Disconnecting -> "Disconnecting…"
    is TransportState.Reconnecting -> "Reconnecting…"
    is TransportState.Error -> "Connection failed"
    is TransportState.HandshakeFailed -> "Connection failed"
}

/**
 * B25 (task B) - the Protected-gating-aware counterpart of
 * [TransportState.toHomeStatusText]: dispatches on [VpnSessionHealth]
 * instead of a raw [TransportState], so a relayed session mid-handshake
 * (real [TransportState.Connected] for the ingress hop, but no real
 * end-to-end proof yet - see that type's own docs) never reads "Protected".
 * For every Direct/manual/private-gateway attempt this produces the
 * IDENTICAL text [TransportState.toHomeStatusText] always has - [VpnSessionHealth
 * .DirectProtected] is reached under EXACTLY the same condition
 * [TransportState.Connected] already was, so this is not a second, possibly-
 * diverging wording surface, only a widened INPUT to the same decision.
 */
fun VpnSessionHealth.toHomeStatusText(): String = when (this) {
    is VpnSessionHealth.Idle -> "Disconnected"
    is VpnSessionHealth.InProgress -> "Connecting…"
    is VpnSessionHealth.DirectProtected -> "Protected"
    is VpnSessionHealth.RelayHandshake -> "Connecting…"
    is VpnSessionHealth.RelayProtected -> "Protected"
    is VpnSessionHealth.Reconnecting -> "Reconnecting…"
    is VpnSessionHealth.Failed -> "Connection failed"
}

/** [VpnSessionHealth] counterpart of [TransportState.toHomeVisualState] - see that function's own docs for the grouping rationale, unchanged here. */
fun VpnSessionHealth.toHomeVisualState(): HomeVisualState = when (this) {
    is VpnSessionHealth.Idle -> HomeVisualState.DISCONNECTED
    is VpnSessionHealth.InProgress, is VpnSessionHealth.RelayHandshake, is VpnSessionHealth.Reconnecting -> HomeVisualState.IN_PROGRESS
    is VpnSessionHealth.DirectProtected, is VpnSessionHealth.RelayProtected -> HomeVisualState.CONNECTED
    is VpnSessionHealth.Failed -> HomeVisualState.FAILED
}

/**
 * B8E - which of the four visual states (power button style + subtitle
 * copy) the Home screen should show. Purely a grouping of the SAME
 * TransportState this file's toHomeStatusText() already maps - Disconnecting
 * groups with Connecting/Reconnecting (all "something is in flight", same
 * progress-ring visual) rather than getting a fifth visual state of its own.
 * Never reads differently from toHomeStatusText() as to which states are
 * failures vs in-progress vs settled.
 */
enum class HomeVisualState { DISCONNECTED, IN_PROGRESS, CONNECTED, FAILED }

fun TransportState.toHomeVisualState(): HomeVisualState = when (this) {
    is TransportState.Disconnected -> HomeVisualState.DISCONNECTED
    is TransportState.Connecting, is TransportState.Reconnecting, is TransportState.Disconnecting -> HomeVisualState.IN_PROGRESS
    is TransportState.Connected -> HomeVisualState.CONNECTED
    is TransportState.Error, is TransportState.HandshakeFailed -> HomeVisualState.FAILED
}

/** Whether the primary Home button should currently read DISCONNECT (true) or CONNECT (false). */
fun TransportState.isConnectedOrConnecting(): Boolean = when (this) {
    is TransportState.Connecting, is TransportState.Connected, is TransportState.Reconnecting -> true
    is TransportState.Disconnected, is TransportState.Disconnecting, is TransportState.Error, is TransportState.HandshakeFailed -> false
}

/**
 * B8D "ACTIVATION SCREEN" simple user-facing errors. Returns null for
 * Idle/Provisioning/Success - the caller should treat null as "no error
 * banner to show". The Error branch's text match is coupled to the exact
 * strings MainViewModel.activateDevice emits for ProvisioningResult
 * .ServiceUnavailable/BadRequest - deliberately NOT re-deriving that
 * mapping here (this file never touches provisioning logic), just
 * translating its existing output into product copy.
 */
fun ProvisioningUiState.toActivationErrorText(): String? = when (this) {
    is ProvisioningUiState.Unauthorized -> "Invalid activation"
    is ProvisioningUiState.Revoked -> "Activation revoked"
    is ProvisioningUiState.Expired -> "Activation expired"
    is ProvisioningUiState.DeviceLimitReached -> "Device limit reached"
    is ProvisioningUiState.Error ->
        if (message == "service temporarily unavailable") "Service temporarily unavailable" else "Invalid activation"
    is ProvisioningUiState.Idle, is ProvisioningUiState.Provisioning, is ProvisioningUiState.Success -> null
}

/**
 * B8D requirement 4: "clear the credential from UI memory" as soon as
 * activation succeeds - a pure predicate so MainActivity's clearing logic
 * is unit-testable without Robolectric/instrumentation.
 */
fun shouldClearCredentialInput(state: ProvisioningUiState): Boolean = state is ProvisioningUiState.Success

/**
 * B26 review fix (blocker 1) - the ingress-activation counterpart of
 * [toActivationErrorText], for the SAME reused `ActivationScreen`
 * composable's `errorText` slot. `null` for every non-terminal/success
 * state (nothing to show), same convention as the AWG one.
 */
fun net.pocvpn.client.relay.IngressActivationOutcome?.toIngressActivationErrorText(): String? = when (this) {
    null, is net.pocvpn.client.relay.IngressActivationOutcome.Saved -> null
    is net.pocvpn.client.relay.IngressActivationOutcome.AuthorizationFailed -> "Invalid activation"
    is net.pocvpn.client.relay.IngressActivationOutcome.Unavailable -> "Service temporarily unavailable"
    is net.pocvpn.client.relay.IngressActivationOutcome.UnsupportedTransport -> "This connection type is not supported yet"
    is net.pocvpn.client.relay.IngressActivationOutcome.Mismatched -> "Activation did not match the expected server - try again"
}

/** B26 review fix (blocker 1) - same "clear the credential from UI memory on success" discipline as [shouldClearCredentialInput]. */
fun shouldClearIngressCredentialInput(state: net.pocvpn.client.relay.IngressActivationOutcome?): Boolean =
    state is net.pocvpn.client.relay.IngressActivationOutcome.Saved

/**
 * B8D "DEBUG / DIAGNOSTICS" gate, expressed as a pure function of an
 * explicit flag rather than reading BuildConfig.DEBUG directly, so the
 * decision itself (not just the compile-time constant) is unit-testable.
 */
fun shouldShowDiagnostics(isDebugBuild: Boolean): Boolean = isDebugBuild

/**
 * B8G - true whenever the app-session kill switch is genuinely "holding":
 * a full-tunnel VpnService session that has been intentionally requested is
 * either recovering from a hiccup or has not yet proven itself, so internet
 * access is expected to be blocked rather than silently available outside
 * the tunnel. Deliberately EXCLUDES Connected (working normally) and
 * Disconnected/Disconnecting (no protection requested, or a user-initiated
 * teardown in progress - not a failure the kill switch is "holding" against).
 * See VpnController.doConnectAttempt/reconnectLoop's own docs for why none
 * of these automatic states ever call transport.disconnect() themselves.
 */
fun TransportState.showsKillSwitchNotice(): Boolean = when (this) {
    is TransportState.Connecting, is TransportState.Reconnecting,
    is TransportState.HandshakeFailed, is TransportState.Error -> true
    is TransportState.Connected, is TransportState.Disconnected, is TransportState.Disconnecting -> false
}

/**
 * B8G diagnostics-only: whether a VPN session currently exists at all (has
 * been intentionally requested and not yet fully torn down), regardless of
 * whether it is presently succeeding. Disconnected is the ONLY state that
 * means "no session" - every other state is some phase of one session's
 * lifetime (connecting, protected, recovering, or mid-teardown).
 */
fun TransportState.isSessionActive(): Boolean = this !is TransportState.Disconnected

/**
 * B8H - "Reconnect to apply changes": true only while a session actually
 * exists ([appliedPolicy] non-null, i.e. VpnController.appliedRoutingPolicy)
 * AND the user has since saved a DIFFERENT split-tunneling policy. Never
 * true while disconnected (nothing to reconnect) and never true merely
 * because a policy was saved - only a real divergence from what the ACTIVE
 * tunnel was actually built with. See VpnController class docs' own
 * "Reconnect to apply changes" flow for why this is read-only/display-only:
 * saving a policy must never itself trigger a rebuild.
 */
fun hasPendingRoutingPolicyChange(appliedPolicy: AppRoutingPolicy?, savedPolicy: AppRoutingPolicy): Boolean =
    appliedPolicy != null && appliedPolicy != savedPolicy

/**
 * B8H1 - which Home CONNECTED subtitle to show. Only meaningful while
 * visualState == CONNECTED (HomeScreen ignores this otherwise) - a plain
 * enum, not a raw string, so HomeScreen keeps resolving actual copy through
 * stringResource() exactly like every other Home subtitle, and this stays
 * pure/JVM-testable with no Android dependency.
 *
 * MUST be driven by the APPLIED routing policy (VpnController
 * .appliedRoutingPolicy - what the live tunnel actually is), never the
 * merely-saved one: see hasPendingRoutingPolicyChange's own "Reconnect to
 * apply changes" docs - Home must keep describing the CURRENT tunnel until
 * an explicit reconnect actually applies a newly saved policy. Callers must
 * pass appliedRoutingPolicy.mode, never savedAppRoutingPolicy.mode.
 */
enum class HomeConnectedSubtitle { ALL_APPS_SECURE, BYPASS_SELECTED_APPS, VPN_ONLY_SELECTED_APPS }

fun homeConnectedSubtitle(appliedRoutingMode: AppRoutingMode): HomeConnectedSubtitle = when (appliedRoutingMode) {
    AppRoutingMode.ALL_APPS -> HomeConnectedSubtitle.ALL_APPS_SECURE
    AppRoutingMode.BYPASS_SELECTED -> HomeConnectedSubtitle.BYPASS_SELECTED_APPS
    AppRoutingMode.VPN_ONLY_SELECTED -> HomeConnectedSubtitle.VPN_ONLY_SELECTED_APPS
}
