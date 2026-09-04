package net.pocvpn.client.vpn.xray

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import net.pocvpn.client.identity.XrayProfileRepository
import net.pocvpn.client.identity.XrayTlsProfileRepository
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.vpn.policy.RoutingMode

/**
 * What one [XrayCoreController.requestStart] call actually did - the caller
 * ([NovaXrayVpnService]) turns this into logging/stopSelf() decisions. Never
 * carries anything but an exception class name or [XrayRuntimeResolution]'s
 * own reason string - no secret ever appears here.
 */
sealed class XrayCoreStartOutcome {
    /** startLoop() was called and returned without throwing. */
    object Started : XrayCoreStartOutcome()

    /** A start was already running - see [XrayServiceLifecycleGate]. No Builder/core/tun touched. */
    object AlreadyRunning : XrayCoreStartOutcome()

    /** Another start is currently in flight - see [XrayServiceLifecycleGate]. No Builder/core/tun touched. */
    object StartInFlight : XrayCoreStartOutcome()

    /** [XrayRuntimeResolver] rejected the stored profile (absent/corrupt/invalid) - startLoop() never called. */
    data class Rejected(val reason: String) : XrayCoreStartOutcome()

    /** establishTun threw or returned null - startLoop() never called. */
    data class EstablishFailed(val reason: String) : XrayCoreStartOutcome()

    /** startLoop() itself threw - the just-established tun is closed before returning. */
    data class CoreStartFailed(val reason: String) : XrayCoreStartOutcome()

    /**
     * B33 - startLoop() itself returned without throwing (the LOCAL core is
     * genuinely running), but the bounded post-start remote/data-plane
     * confirmation (see [XrayCoreController.requestStart]'s own docs) never
     * proved the tunnel is actually usable - a real handshake/HTTP round
     * trip through the just-established outbound never succeeded within the
     * bound. Deliberately distinct from [CoreStartFailed] (that means the
     * LOCAL startLoop() call itself threw - a different, earlier failure)
     * - callers must never conflate "local process wouldn't even start" with
     * "local process started but the remote gateway never confirmed". The
     * loop is stopped and the tun closed before this is ever returned -
     * never left half-up.
     */
    data class RemoteUnconfirmed(val reason: String) : XrayCoreStartOutcome()
}

/**
 * B33 relay follow-up - which real, positive confirmation
 * [XrayCoreController.requestStart] must obtain beyond local process startup
 * before ever reporting [XrayCoreStartOutcome.Started], keyed to the actual
 * execution context of THIS attempt - never decided by this class itself
 * from an endpoint id or transport kind (this class has, and must keep
 * having, zero knowledge of "stockholm-ingress-1"/CHAIN_DIRECT or any other
 * specific ingress). The caller that already knows which kind of attempt
 * this is ([NovaXrayVpnService], threaded from [net.pocvpn.client.relay.VpnAttemptContext]
 * all the way from [net.pocvpn.client.vpn.VpnController] - see that sealed
 * class's own docs) picks the variant; this class only ever executes it.
 *
 * [Direct] is the default for every pre-existing call site - byte-for-byte
 * the SAME generic `/v1/manifest` round trip [confirmRemoteConnectivity]
 * already performed before this type existed. Physical integration testing
 * (combined PR #55 + PR #53 pre-merge validation) proved that same generic
 * probe is UNSOUND for a Relayed attempt: the client's rendered Xray config
 * has exactly one outbound and no routing rules (see [XrayConfigRenderer]),
 * so ANY destination [confirmRemoteConnectivity] asks for is dialed through
 * that one outbound - the ingress. The ingress's OWN server-side routing
 * (verified directly against the deployed `/etc/nova-xray-ingress/config.json`,
 * not assumed) then unconditionally forwards EVERY destination to its fixed
 * relay-upstream hop, with no exception for the ingress's own address - so a
 * generic `https://<ingressHost>/v1/manifest` probe does not test "is the
 * client<->ingress hop alive", it accidentally asks the exit hop to dial
 * back to the ingress's own control-plane over the public internet, an
 * unrelated, fragile, self-referential round trip that has nothing to do
 * with genuine relay health and was observed to fail even while real
 * end-user DNS/HTTPS traffic was concurrently, successfully traversing the
 * SAME tunnel (confirmed server-side in the ingress's own access log).
 *
 * **B33 relay follow-up (round 2) - now a genuine Xray-native in-tunnel
 * primitive, not the out-of-band HTTP check this class used before.** An
 * earlier version of [Relayed] carried a `confirm: suspend () -> Boolean`
 * action backed by [net.pocvpn.client.relay.HttpRelayEndToEndProbe.probeProfile]
 * - an ordinary `java.net.URL.openConnection()` call issued from Nova's own
 * process. [net.pocvpn.client.vpn.xray.NovaXrayVpnService.establishInterface]
 * always excludes that process from its own VPN
 * (`addDisallowedApplication`, recursion prevention), so that request never
 * traversed the just-started tunnel - it reached
 * [net.pocvpn.client.relay.IngressClientProfile.endToEndProbeUrl] (the
 * EXIT's own publicly-reachable `/v1/relay-health` host, see
 * `gateway/api/handler.py`) over the device's ordinary default network,
 * regardless of whether the relay tunnel itself worked - the confirmed
 * cause of a real physical false negative (see
 * PROJECT_ARCHITECTURE.md's "B33 relay follow-up" sections).
 *
 * [Relayed] now instead carries [exitProbeHost] - the EXIT endpoint's own
 * plaintext HTTPS host (never the ingress host [Direct]'s own branch
 * effectively targets for a Direct attempt) - and [confirmRemoteConnectivity]
 * dials `https://$exitProbeHost/v1/manifest` via the SAME
 * [XrayCoreRuntime.measureDelay] primitive [Direct] already uses, through
 * the SAME just-started core's own outbound/routing. **Empirically verified
 * safe end to end, read-only, against the real deployed Stockholm
 * ingress/Frankfurt exit pair (2026-09-04):** the ingress's rendered config
 * (`/etc/nova-xray-ingress/config.json`) has exactly one unconditional
 * routing rule forwarding EVERY destination from the client inbound to its
 * `nova-relay-upstream-out` VLESS outbound (dialing the exit's own
 * `nova-vless-reality-in` inbound directly, by IP:port - never CDN/DNS
 * dependent); the exit's own rendered config
 * (`/etc/nova-xray/config.json`) has NO routing rules at all beyond its
 * single `freedom`/`direct` outbound, which dials whatever destination the
 * proxied connection names - so a client dialing `152.70.43.1:443` through
 * this exact ingress genuinely arrives at the EXIT, which then dials
 * `152.70.43.1:443` AS ITSELF (a real self-connect, not a guess): confirmed
 * via direct read-only SSH to both hosts that (a) the exit's own public IP
 * self-TCP-connects on 443, (b) `curl https://152.70.43.1/v1/manifest`
 * from the exit itself completes a REAL TLS 1.3 handshake with certificate
 * verification (`SSL certificate verify ok`, IP-SAN match, no `-k`) and
 * returns HTTP 200 with genuine signed-manifest bytes served by the same
 * nginx this deployment already trusts for Direct's own confirmation, and
 * (c) the SAME request works identically when issued from the Stockholm
 * ingress host toward the Frankfurt exit's public IP. This is architecturally
 * DIFFERENT from the original round-1 bug: that bug dialed the INGRESS's
 * own address (which the ingress's blanket forwarding rule then bounced
 * back out to the exit and beyond, a genuinely unrelated public round trip);
 * this dials the EXIT's address, which the SAME forwarding rule delivers TO
 * the exit, which then serves it locally - never leaving the exit machine a
 * second time. This class stays entirely free of any dependency on the
 * `relay` package - [exitProbeHost] is a plain string, resolved by the
 * caller from [net.pocvpn.client.relay.RelayedExecutionPlan.exitBinding]
 * (see [net.pocvpn.client.vpn.config.TransportConfig.Xray.relayExitProbeHost]'s
 * own docs for the threading path).
 *
 * [net.pocvpn.client.relay.HttpRelayEndToEndProbe] is NOT removed - it
 * remains real and useful as an out-of-band control-plane/credential
 * diagnostic (a 401 IS proof the token/HMAC binding is broken) - but it is
 * no longer wired as this gate, and callers must never let its result
 * overturn a [TransportState.Connected] this Xray-native check already
 * produced (see `MainViewModel.armFailoverWatch`'s own docs).
 */
sealed class RemoteConfirmationContext {
    object Direct : RemoteConfirmationContext()
    data class Relayed(val exitProbeHost: String) : RemoteConfirmationContext()
}

/** Result of one [XrayCoreController.requestStop] call. */
data class XrayCoreStopOutcome(
    /** False (no-op - matches [XrayServiceLifecycleGate.tryBeginTeardown]'s own contract) if nothing was running. */
    val didTeardown: Boolean,
    /** Non-null only if stopLoop() itself threw - the tun is still closed regardless (see [requestStop][XrayCoreController.requestStop]). */
    val stopLoopFailureReason: String? = null,
)

/**
 * B8K4C - [NovaXrayVpnService]'s actual start/stop decision and sequencing,
 * decoupled from android.app.Service/android.net.VpnService.Builder so
 * "duplicate start creates no duplicate core", "absent/corrupt/invalid
 * profile never starts Xray", "stop calls stopLoop and releases the tun fd
 * exactly once" are all unit-testable on the plain JVM against a fake
 * [XrayCoreRuntime] (this project has no Robolectric dependency). Reuses
 * [XrayServiceLifecycleGate] verbatim for the duplicate-start/duplicate-
 * teardown invariant rather than reimplementing it.
 *
 * [establishTun] returns a raw file descriptor [Int] (not a
 * android.os.ParcelFileDescriptor) so this class stays entirely free of
 * Android SDK types - [NovaXrayVpnService] owns the real
 * ParcelFileDescriptor's lifetime and hands back only its `.fd`.
 */
class XrayCoreController(
    private val repository: XrayProfileRepository,
    private val coreRuntime: XrayCoreRuntime,
    private val novaPackageId: String,
    private val ensureCoreEnvInitialized: () -> Unit,
    private val establishTun: (XrayVpnBuilderPlan) -> Int?,
    private val closeTun: () -> Unit,
    // B8O2 - additive, defaults to null so every existing call site (real or
    // test) is byte-for-byte unaffected: with no TLS repository wired,
    // requestStart(TransportKind.TLS_TCP) simply rejects (see below) rather
    // than throwing - the same fail-closed shape as a missing REALITY
    // profile, never a crash.
    private val tlsRepository: XrayTlsProfileRepository? = null,
    // B33 review fix (round 2, blocker) - a scope the bounded remote-
    // confirmation probe's BLOCKING native call runs on, deliberately NOT
    // derived from the calling coroutine (see confirmRemoteConnectivity's
    // own docs for exactly why: a coroutine timeout cannot preempt an
    // ordinary blocking JNI call with no suspension point, so the call must
    // run somewhere the timeout can walk away from without cancelling it).
    // Defaults to a real, independent, long-lived scope for production;
    // test-injectable (same "collaborator injection" pattern this class
    // already uses for [establishTun]/[closeTun]/[coreRuntime]) so a test
    // can use its own controllable scope/dispatcher instead of a real
    // background thread.
    private val probeScope: CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.IO),
) {
    private val lifecycleGate = XrayServiceLifecycleGate()

    // B33 - [serverHost] carries the exact plaintext destination host THIS
    // attempt resolved (XrayVlessRealityConfig.server / XrayVlessTlsConfig.server -
    // never re-derived from anywhere else) so the post-start confirmation
    // probe below targets the SAME real gateway this attempt actually
    // dials, never a different/fabricated address.
    private class ReadyToStart(val plan: XrayVpnBuilderPlan, val renderedConfig: String, val serverHost: String)

    /**
     * [kind] defaults to [TransportKind.XRAY_REALITY] so every existing
     * call site (real or test) that calls `requestStart()` with no argument
     * is byte-for-byte unaffected - REALITY's own resolve/build path below
     * is untouched. [TransportKind.TLS_TCP] resolves against [tlsRepository]
     * instead (see [XrayRuntimeResolver.resolveTls]) - both share the SAME
     * [lifecycleGate]/tun/coreRuntime, so REALITY and TLS_TCP can never run
     * concurrently through this one controller instance (there is only ever
     * one active Xray session per [net.pocvpn.client.vpn.xray.NovaXrayVpnService]).
     * Any other [kind] is rejected before touching the tun/core at all -
     * structurally unreachable via the public API today (only these two
     * kinds are ever passed in), same "defensive, not a real code path"
     * shape [XrayCoreStartOutcome.Rejected]'s other call sites already use.
     */
    // B18-2 - [routingMode] defaults to FULL_VPN so every pre-B18-2 call site
    // (real or test) is byte-for-byte unaffected - see buildXrayVpnPlan's own
    // docs for the exact route-set contract this threads into.
    // B33 relay follow-up - [confirmationContext] defaults to
    // [RemoteConfirmationContext.Direct] so every pre-existing call site
    // (real or test) is byte-for-byte unaffected - see that sealed class's
    // own docs for why a Relayed attempt must supply a different value here.
    // B33 relay follow-up (round 3) - the ONE post-Connected relay-health
    // watchdog job for the CURRENTLY active session, or null when none is
    // running (every Direct session, and any session before/after its own
    // Relayed watchdog runs) - see [startRelayHealthWatchdog]'s own docs.
    // Never a field per-attempt list/map: this controller only ever has ONE
    // active session at a time ([lifecycleGate]'s own invariant), so a
    // single nullable field is the whole lifecycle this needs - a NEW
    // [requestStart] can only ever begin after the previous session's own
    // watchdog (if any) has already been cancelled, either by [requestStop]
    // (see that function's own docs) or by the watchdog's own terminal
    // failure branch clearing itself.
    @Volatile private var relayHealthWatchdogJob: Job? = null

    suspend fun requestStart(
        kind: TransportKind = TransportKind.XRAY_REALITY,
        routingMode: RoutingMode = RoutingMode.FULL_VPN,
        confirmationContext: RemoteConfirmationContext = RemoteConfirmationContext.Direct,
        // B33 relay follow-up (round 3) - called AFTER this controller has
        // ALREADY synchronously torn down the just-failed session (stopLoop
        // + tun closed - see [startRelayHealthWatchdog]'s own docs), exactly
        // once, ONLY when the post-Connected relay-health watchdog itself
        // (never [confirmRemoteConnectivity]'s own pre-Started gate, which
        // reports its outcome through this function's own return value
        // instead) declares the active Relayed session unhealthy. Default
        // no-op so every pre-existing/Direct call site is byte-for-byte
        // unaffected. This class stays entirely free of any dependency on
        // `relay`/`XrayRuntimeState` - the caller ([NovaXrayVpnService])
        // supplies whatever real publish/stopSelf action it needs, the same
        // "opaque caller-supplied action" shape [RemoteConfirmationContext
        // .Relayed] already established.
        onRelayHealthLost: suspend () -> Unit = {},
    ): XrayCoreStartOutcome {
        when (lifecycleGate.tryBeginStart()) {
            XrayServiceStartDecision.IGNORE_ALREADY_RUNNING -> return XrayCoreStartOutcome.AlreadyRunning
            XrayServiceStartDecision.IGNORE_START_IN_FLIGHT -> return XrayCoreStartOutcome.StartInFlight
            XrayServiceStartDecision.PROCEED -> Unit
        }
        // Defensive - [lifecycleGate] already guarantees a NEW start only
        // ever proceeds after any previous session (and therefore its own
        // watchdog) has ended, so this should always find null. Never skip
        // it on that assumption alone: a leaked job here would otherwise run
        // forever against nothing.
        relayHealthWatchdogJob?.cancel()
        relayHealthWatchdogJob = null

        var success = false
        try {
            val ready = when (kind) {
                TransportKind.TLS_TCP -> {
                    val tlsRepo = tlsRepository
                        ?: return XrayCoreStartOutcome.Rejected("Xray TLS profile repository not wired")
                    when (val resolution = XrayRuntimeResolver.resolveTls(tlsRepo)) {
                        is XrayTlsRuntimeResolution.Rejected -> return XrayCoreStartOutcome.Rejected(resolution.reason)
                        is XrayTlsRuntimeResolution.Ready ->
                            ReadyToStart(buildXrayVpnPlan(resolution.config, novaPackageId, routingMode), resolution.renderedConfig, resolution.config.server)
                    }
                }
                TransportKind.XRAY_REALITY -> {
                    when (val resolution = XrayRuntimeResolver.resolve(repository)) {
                        is XrayRuntimeResolution.Rejected -> return XrayCoreStartOutcome.Rejected(resolution.reason)
                        is XrayRuntimeResolution.Ready ->
                            ReadyToStart(buildXrayVpnPlan(resolution.config, novaPackageId, routingMode), resolution.renderedConfig, resolution.config.server)
                    }
                }
                else -> return XrayCoreStartOutcome.Rejected("unsupported transport kind for NovaXrayVpnService: $kind")
            }

            val plan = ready.plan
            val fd = try {
                establishTun(plan)
            } catch (t: Throwable) {
                return XrayCoreStartOutcome.EstablishFailed(t.javaClass.simpleName)
            } ?: return XrayCoreStartOutcome.EstablishFailed("establish() returned null")

            return try {
                ensureCoreEnvInitialized()
                coreRuntime.startLoop(ready.renderedConfig, fd)
                // B33 - startLoop() returning without throwing proves ONLY
                // that the LOCAL core/tun exist - see confirmRemoteConnectivity's
                // own docs for why that is never, by itself, sufficient
                // evidence the tunnel is actually usable.
                if (confirmRemoteConnectivity(ready.serverHost, confirmationContext)) {
                    success = true
                    // B33 relay follow-up (round 3) - a genuine Connected
                    // relayed session gets ongoing health monitoring; a
                    // Direct one does not (no ownerless-relay-tun class of
                    // bug exists for Direct - see [startRelayHealthWatchdog]'s
                    // own docs for exactly why only [RemoteConfirmationContext
                    // .Relayed] qualifies).
                    if (confirmationContext is RemoteConfirmationContext.Relayed) {
                        startRelayHealthWatchdog(confirmationContext.exitProbeHost, onRelayHealthLost)
                    }
                    XrayCoreStartOutcome.Started
                } else {
                    // B33 - the local loop IS running (startLoop() did not
                    // throw) but was never confirmed usable within the
                    // bound - stop it and release the tun ourselves (never
                    // left half-up): lifecycleGate.endStart(false) below
                    // means tryBeginTeardown() will never fire for this
                    // attempt (isRunning was never set true), so this is the
                    // ONLY teardown this attempt will ever get.
                    val stopReason = try {
                        coreRuntime.stopLoop()
                        null
                    } catch (t: Throwable) {
                        t.javaClass.simpleName
                    }
                    closeTun()
                    XrayCoreStartOutcome.RemoteUnconfirmed(stopReason?.let { "remote handshake not confirmed (stopLoop also failed: $it)" } ?: "remote handshake not confirmed")
                }
            } catch (t: Throwable) {
                closeTun()
                XrayCoreStartOutcome.CoreStartFailed(t.javaClass.simpleName)
            }
        } finally {
            lifecycleGate.endStart(success)
        }
    }

    /**
     * B33 - the ONE real, positive, production-capable confirmation that the
     * just-started Xray tunnel is genuinely usable beyond local process
     * startup: a bounded [XrayCoreRuntime.measureDelay] round trip through
     * the JUST-STARTED core's own configured outbound/routing (the exact
     * same real native primitive v2rayNG's own "test configuration" feature
     * uses - see [XrayCoreRuntime.measureDelay]'s own docs), targeting THIS
     * attempt's own real gateway's already-deployed, unauthenticated
     * `/v1/manifest` endpoint on port 443 (a real Let's Encrypt IP-SAN
     * certificate is deployed on both production gateways - verified
     * directly against both live hosts without `-k`/any certificate bypass,
     * `SSL certificate verify ok` in both cases - so this dials cleanly by
     * IP with full TLS verification, never a bypass) - never a third-party
     * public-IP service (task's own explicit prohibition), never a
     * fabricated/local check ("process alive"/"tun exists"), never a fixed
     * sleep.
     *
     * B33 review fix (round 2, blocker) - [XrayCoreRuntime.measureDelay] is
     * an ORDINARY BLOCKING native/JNI call with no suspension point: a
     * coroutine timeout cannot preempt it once it has started (cancellation
     * only takes effect at a suspension point, and a raw blocking call never
     * suspends) - wrapping the blocking call directly in
     * [withTimeoutOrNull] (an earlier, WRONG version of this function) does
     * NOT bound it at all, since the very coroutine running that
     * `withTimeoutOrNull` block is the SAME thread stuck inside the blocking
     * call - there is no separate execution path left for the timeout to
     * even fire on. Fixed by giving the blocking call its OWN, independent
     * coroutine on [probeScope] (deliberately NOT a structured child of THIS
     * function's own coroutine - see that field's own docs) and having
     * [withTimeoutOrNull] bound only the SUSPENDING `deferred.await()` call,
     * which genuinely can be abandoned. This makes the caller-visible
     * deadline real: [requestStart] always receives an answer within
     * [REMOTE_CONFIRM_TIMEOUT_MS], regardless of how long the underlying
     * native call actually takes.
     *
     * Safety of the abandoned call after a timeout (task's own explicit
     * requirements):
     * - **Late success/failure is inert.** [deferred] is a fresh, local
     *   object created new by EVERY call - never shared/instance-level
     *   state - so a late completion after [withTimeoutOrNull] already gave
     *   up has nothing left reading it; `complete()` on an
     *   already-abandoned (but not yet completed) deferred is harmless, and
     *   nothing in this class ever inspects a [CompletableDeferred] after
     *   its owning [confirmRemoteConnectivity] call has returned.
     * - **Never publishes Started after timeout.** [requestStart] only
     *   proceeds past this function once it has ALREADY returned (Boolean,
     *   not a background promise) - a timeout returns `false` HERE, so
     *   [requestStart] takes the [XrayCoreStartOutcome.RemoteUnconfirmed]
     *   branch synchronously, before the abandoned native call could ever
     *   complete.
     * - **Never mutates a newer attempt.** Because [deferred] is
     *   call-local (never a field on this class), a SUBSEQUENT
     *   [requestStart]/[confirmRemoteConnectivity] call - whether a retry of
     *   the same candidate or a genuinely different one - gets its OWN
     *   fresh [deferred] and its own fresh probe coroutine; there is no
     *   shared mutable state through which one attempt's abandoned probe
     *   could reach into another's outcome, by construction.
     * - **Teardown stays deterministic.** [requestStart]'s
     *   `RemoteUnconfirmed` branch calls `coreRuntime.stopLoop()`/[closeTun]
     *   synchronously the instant this function returns `false` - bounded by
     *   the SAME [REMOTE_CONFIRM_TIMEOUT_MS] deadline, never waiting on the
     *   abandoned probe.
     * - **Bounded resource growth.** Each timed-out probe leaves at most one
     *   coroutine running on [probeScope] (backed by [Dispatchers.IO]'s own
     *   bounded elastic thread pool) until the underlying native call
     *   itself eventually returns/throws (its own OS-level socket-timeout
     *   bound, outside this class's control - the pinned AAR exposes no
     *   configurable timeout parameter for `measureDelay`, confirmed against
     *   its decompiled native method signature) - at that point the
     *   coroutine completes and is automatically removed from [probeScope]'s
     *   own job bookkeeping. Never literally unbounded: the number of
     *   concurrently abandoned probes for one connect() sequence is capped
     *   by the SAME [net.pocvpn.client.smartconnect.AutoGatewaySelector.MAX_ATTEMPTS]
     *   bound that already caps the whole combined attempt sequence - this
     *   introduces no new unbounded-retry surface.
     *
     * B33 relay follow-up - [context] selects WHICH host [measureDelay]
     * dials `/v1/manifest` against inside the abandonable probe coroutine
     * below (see [RemoteConfirmationContext]'s own docs for exactly why a
     * Relayed attempt must dial the EXIT's host, never the INGRESS host
     * [serverHost] names for that attempt) - every other guarantee described
     * above (the independent probe coroutine, the real bounded
     * [withTimeoutOrNull] deadline, "late completion is inert") is
     * completely unchanged and applies identically to both branches: the
     * [RemoteConfirmationContext.Relayed] branch's `measureDelay` call is
     * just as much an ordinary blocking-native call running on [probeScope]
     * here, abandoned exactly the same way on timeout.
     */
    private suspend fun confirmRemoteConnectivity(serverHost: String, context: RemoteConfirmationContext): Boolean {
        val url = when (context) {
            is RemoteConfirmationContext.Direct -> "https://$serverHost/v1/manifest"
            // B33 relay follow-up (round 2) - the EXIT's own host,
            // never [serverHost] (that is the client's dial target -
            // the INGRESS for a Relayed attempt, see this function's
            // own top-level docs for why that host specifically
            // reintroduces the round-1 self-referential-ingress bug).
            // Same real native primitive, same just-started core's
            // outbound/routing, same unauthenticated `/v1/manifest`
            // path every gateway already serves for Direct - see
            // [RemoteConfirmationContext.Relayed]'s own docs for the
            // empirical proof this target is safe.
            is RemoteConfirmationContext.Relayed -> "https://${context.exitProbeHost}/v1/manifest"
        }
        return boundedMeasureDelay(url)
    }

    /**
     * B33 relay follow-up (round 3) - the SAME bounded-abandonable
     * [XrayCoreRuntime.measureDelay] primitive [confirmRemoteConnectivity]
     * already established (see that function's own docs and its own docs on
     * [XrayCoreStartOutcome.RemoteUnconfirmed] for the full "why a fresh
     * coroutine on [probeScope], why [withTimeoutOrNull] only bounds the
     * suspending await, why a late completion is inert" rationale - byte-
     * for-byte the same guarantees, extracted here so [startRelayHealthWatchdog]'s
     * periodic probe reuses the identical safety properties rather than a
     * second, independently-written bounded-call pattern). Returns `true`
     * only on a genuine, non-throwing `measureDelay` completion within
     * [REMOTE_CONFIRM_TIMEOUT_MS] - a timeout or any thrown exception both
     * report `false`, never propagated.
     */
    private suspend fun boundedMeasureDelay(url: String): Boolean {
        val deferred = CompletableDeferred<Boolean>()
        probeScope.launch {
            val ok = try {
                coreRuntime.measureDelay(url)
                true
            } catch (t: Throwable) {
                false
            }
            deferred.complete(ok)
        }
        return withTimeoutOrNull(REMOTE_CONFIRM_TIMEOUT_MS) { deferred.await() } ?: false
    }

    /**
     * B33 relay follow-up (round 3) - the fix for the physically-proven
     * "stale Protected" defect: a genuinely healthy CHAIN_DIRECT session
     * (Android -> Stockholm ingress -> Germany exit, real Protected/HTTPS/
     * DNS) whose relay-upstream link was then black-holed server-side
     * stayed reported Connected/Protected for 6+ minutes with a dead data
     * plane, tun0 still up, and Xray still running - because
     * [net.pocvpn.client.MainViewModel.armFailoverWatch] cancels its own
     * watcher the moment a Relayed attempt first reaches genuine success
     * (see that function's own docs), and no other mechanism in this
     * codebase ever re-checks a relayed session's data-plane health after
     * that point (`VpnController.handleNetworkLost`/`reconnectLoop` only
     * ever fire on an OS-level network-loss callback - never on a
     * relay-upstream failure with the underlying network, and the
     * client<->ingress link, both still healthy - exactly this scenario).
     *
     * Started ONLY for a genuinely Connected [RemoteConfirmationContext
     * .Relayed] session (never Direct - see [requestStart]'s own call site),
     * on [probeScope] (the SAME scope every other probe in this class
     * already uses - real, independent, `NovaXrayVpnService`-scoped in
     * production). Periodically repeats the EXACT SAME Xray-native
     * EXIT-manifest [boundedMeasureDelay] check [confirmRemoteConnectivity]
     * already used to prove this session healthy in the first place - never
     * the out-of-band Nova-process `HttpURLConnection` check
     * ([net.pocvpn.client.relay.HttpRelayEndToEndProbe]), which cannot serve
     * as tunnel liveness for the same reason it was removed from the
     * pre-Started gate (see [RemoteConfirmationContext.Relayed]'s own docs).
     *
     * A single transient probe miss is deliberately NOT terminal - only
     * [RELAY_HEALTH_FAILURE_THRESHOLD] *consecutive* failures (reset to zero
     * by any intervening success) declare the relay unhealthy, the same
     * "bounded, not trigger-happy" discipline this codebase already applies
     * elsewhere (e.g. [net.pocvpn.client.reachability.PathHistoryEntry
     * .consecutiveFailures]) - never a single noisy probe tearing down a
     * genuinely-recoverable session.
     *
     * On reaching the threshold: tears down THIS exact session via
     * [requestStop] - the SAME real, gate-serialized, "stopLoop then close
     * tun, exactly once" path `ACTION_STOP`/[NovaXrayVpnService.teardown]
     * already uses, called SYNCHRONOUSLY on this coroutine and awaited to
     * completion BEFORE [onUnhealthy] is invoked - so by the time the caller
     * publishes a terminal/failure event, the tun/core are ALREADY released;
     * the exact "terminal state must never coexist with an ownerless active
     * relay tun" invariant task requirements demanded, achieved by ordering
     * alone (tear down, then notify), never a new ack/wait primitive - the
     * SAME ordering [XrayCoreStartOutcome.RemoteUnconfirmed]'s own branch in
     * [requestStart] already establishes. [requestStop]'s own
     * [XrayServiceLifecycleGate] guarantees this can never double-teardown a
     * session an external `ACTION_STOP`/[requestStop] call raced with (at
     * most one of the two ever proceeds - see that gate's own invariant),
     * and never leaves [relayHealthWatchdogJob] pointing at a job that
     * already finished (cleared here, on this same coroutine, right before
     * returning).
     *
     * Cancelled (never left running against a session that no longer
     * exists, and never overlapping a NEWER session's own watchdog) by:
     * [requestStop] (covers explicit disconnect, an activeTransport switch -
     * which always disconnects the OLD transport first, see
     * `VpnController.switchActiveTransport`'s own docs - and the
     * coordinator's own endpoint-switch teardown), and defensively at the
     * top of every [requestStart] (a fresh session never inherits a leaked
     * watchdog job). Never watches for longer than the SAME session it was
     * started for: [relayHealthWatchdogJob] is this controller's own single
     * field, and [lifecycleGate] guarantees only one session is ever active
     * at a time, so a stale watchdog cannot outlive into - or act on - a
     * later, different session, by construction (never keyed on a
     * separately-tracked session id that could drift).
     */
    private fun startRelayHealthWatchdog(exitProbeHost: String, onUnhealthy: suspend () -> Unit) {
        val url = "https://$exitProbeHost/v1/manifest"
        relayHealthWatchdogJob = probeScope.launch {
            var consecutiveFailures = 0
            while (isActive) {
                delay(RELAY_HEALTH_PROBE_INTERVAL_MS)
                if (!isActive) return@launch
                val healthy = boundedMeasureDelay(url)
                if (healthy) {
                    consecutiveFailures = 0
                    continue
                }
                consecutiveFailures++
                if (consecutiveFailures >= RELAY_HEALTH_FAILURE_THRESHOLD) {
                    // Cleared BEFORE requestStop() - requestStop() itself
                    // also cancels relayHealthWatchdogJob (see that
                    // function's own docs), and this coroutine IS that job:
                    // clearing the field first makes that a safe no-op on
                    // null, rather than this coroutine cancelling itself and
                    // risking onUnhealthy() below never running (cancellation
                    // is cooperative, but there is no reason to court it).
                    relayHealthWatchdogJob = null
                    requestStop()
                    onUnhealthy()
                    return@launch
                }
            }
        }
    }

    private companion object {
        /**
         * B33 - bounded independently of VpnController's own
         * HANDSHAKE_TIMEOUT_MS (AWG's cheap local-stats poll budget - a
         * different signal with a different cost shape, see that constant's
         * own docs): a real network round trip needs its own, longer-tail-
         * tolerant bound, but still bounded, never unbounded. This IS the
         * real caller-visible deadline (see confirmRemoteConnectivity's own
         * round-2 docs for why the ORIGINAL version of this bound was not
         * actually enforced). Also the per-probe bound [startRelayHealthWatchdog]
         * reuses via [boundedMeasureDelay] - the same real network round
         * trip, the same abandon-on-timeout safety.
         */
        const val REMOTE_CONFIRM_TIMEOUT_MS = 6_000L

        /**
         * B33 relay follow-up (round 3) - no existing "ongoing session
         * health poll" cadence constant exists anywhere in this codebase to
         * reuse (audited: [net.pocvpn.client.vpn.ReconnectManager]'s
         * BASE_DELAY_MS/MAX_DELAY_MS govern reconnect BACKOFF after a
         * network-loss event, a different concern; [VpnController
         * .HANDSHAKE_TIMEOUT_MS]/HANDSHAKE_POLL_INTERVAL_MS govern AWG's
         * cheap local-stats poll during ONE connect attempt, not an ongoing
         * background health check). A conservative, deliberately
         * infrequent interval - this is a REAL network round trip against
         * production infrastructure, run for as long as the session stays
         * connected, never a cheap local check.
         */
        const val RELAY_HEALTH_PROBE_INTERVAL_MS = 20_000L

        /**
         * B33 relay follow-up (round 3) - consecutive (not cumulative)
         * failures required before the session is declared unhealthy - see
         * [startRelayHealthWatchdog]'s own docs for why a single transient
         * miss must never be terminal.
         */
        const val RELAY_HEALTH_FAILURE_THRESHOLD = 2
    }

    fun requestStop(): XrayCoreStopOutcome {
        // B33 relay follow-up (round 3) - cancelled FIRST, before this
        // session's own teardown runs, so an external disconnect/switch
        // never races a still-polling watchdog against the very teardown it
        // would otherwise (harmlessly, per requestStop's own idempotency,
        // but wastefully) attempt a second time - see
        // [startRelayHealthWatchdog]'s own docs on why a raced second call
        // is safe regardless, this just avoids the pointless overlap.
        relayHealthWatchdogJob?.cancel()
        relayHealthWatchdogJob = null
        if (!lifecycleGate.tryBeginTeardown()) return XrayCoreStopOutcome(didTeardown = false)
        val failureReason = try {
            coreRuntime.stopLoop()
            null
        } catch (t: Throwable) {
            t.javaClass.simpleName
        } finally {
            closeTun()
        }
        return XrayCoreStopOutcome(didTeardown = true, stopLoopFailureReason = failureReason)
    }
}
