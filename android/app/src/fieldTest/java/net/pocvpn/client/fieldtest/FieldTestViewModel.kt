package net.pocvpn.client.fieldtest

import android.app.Application
import android.content.Intent
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import java.net.InetSocketAddress
import java.net.Socket
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import net.pocvpn.client.network.NetworkProfile
import net.pocvpn.client.network.currentNetworkProfileSnapshot
import net.pocvpn.client.smartconnect.RestrictionClass
import net.pocvpn.client.smartconnect.RestrictionClassifier
import net.pocvpn.client.smartconnect.RestrictionEvidence
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.vpn.AmneziaWgTransport
import net.pocvpn.client.vpn.TransportState
import net.pocvpn.client.vpn.VpnTransport
import net.pocvpn.client.vpn.config.ProductionGatewayId
import net.pocvpn.client.vpn.policy.RoutingMode

/**
 * The UI-facing state this build's ONE screen renders (task's required UX:
 * "Nova VPN" / [Connect] / Connecting…/Protected/Connection failed - nothing
 * else). Deliberately a tiny, closed vocabulary - no activation/provisioning
 * state exists in this build at all.
 */
sealed class FieldTestUiState {
    object Idle : FieldTestUiState()
    object Connecting : FieldTestUiState()
    object Protected : FieldTestUiState()
    object Failed : FieldTestUiState()
}

/**
 * Owns the field test's one real action: press Connect -> try Frankfurt,
 * then Stockholm, using the real production AWG transport -> Protected or
 * Connection failed. Also owns the sanitized [FieldTestReport] this run
 * always produces (task requirement: "a failed VPN connection must still
 * produce a complete local diagnostic report" - reporting is NEVER a
 * prerequisite for the VPN attempt itself, see [connect]'s own structure:
 * the connect attempt runs and settles completely before any report/upload
 * logic begins, and a report/upload failure can never roll back or affect
 * [uiState]).
 *
 * **VPN permission (PR #61 follow-up)** - a real-device incident showed
 * Frankfurt/Stockholm both "failing" within milliseconds on a fresh
 * install: [FieldTestTunnelController] used to check
 * `transport.preparePermissionIntent()` PER CANDIDATE and mark that
 * candidate failed without ever launching the Android system permission
 * dialog. Permission is device/app-level, not gateway-specific, so
 * [connect] now resolves it EXACTLY ONCE, via [ensureVpnPermission],
 * BEFORE [controller] ever starts its candidate loop - a pending or denied
 * permission is never confused with a real AWG/network failure on either
 * gateway.
 */
class FieldTestViewModel(
    private val transportFactory: (ProductionGatewayId) -> VpnTransport,
    private val appVersionName: String,
    private val appVersionCode: Long,
    private val reportUploader: FieldTestReportUploader = NoOpFieldTestReportUploader,
    /**
     * B37 senior-review pass (task D1/D2) - a REAL, synchronous underlying-
     * network read ([currentNetworkProfileSnapshot]), never a stub. Must be
     * called BEFORE [controller]'s candidate loop starts (see [connect]) so
     * it reflects the network truthfully in place BEFORE this build's own
     * full-tunnel VPN attempt can change what `activeNetwork` even reports -
     * never inferred from whether that attempt went on to succeed.
     * Returns [NetworkProfile.unavailable] (never a guess) when no real
     * evidence is available.
     */
    private val networkProfileProvider: () -> NetworkProfile,
    private val nowProvider: () -> Long = System::currentTimeMillis,
    /**
     * Device/app-level VPN permission check, resolved once per [connect]
     * call - null means "already granted, nothing to ask". Defaults to
     * asking a fresh transport instance (which candidate's transport
     * answers this is irrelevant - AmneziaWgTransport.preparePermissionIntent
     * simply wraps `VpnService.prepare(context)`, a device/app fact, never a
     * gateway-specific one); a throwaway GERMANY instance is used only
     * because asking requires SOME transport instance to exist.
     */
    private val preparePermissionIntent: () -> Intent? = { transportFactory(ProductionGatewayId.GERMANY).preparePermissionIntent() },
    /**
     * C2 fix - null (the production default) means "use the real
     * [probeDataPlane] bounded post-handshake connectivity check" (never
     * the old constant-true stub). Overridable purely so tests can
     * substitute a deterministic fake instead of performing real network
     * I/O against a JVM unit test - production code (this class's own
     * [Factory]) never overrides it. A Kotlin primary-constructor default
     * parameter cannot itself reference an instance method like
     * [probeDataPlane] (only [effectiveHealthCheck] below, a regular
     * property initializer, can), hence the null-then-fallback shape here.
     */
    private val healthCheckOverride: (suspend (VpnTransport) -> Boolean)? = null,
) : ViewModel() {

    private val diagnostics = FieldTestDiagnosticsRecorder(nowProvider)
    private val effectiveHealthCheck: suspend (VpnTransport) -> Boolean = healthCheckOverride ?: { probeDataPlane() }

    /**
     * B37 - the ONE line that switches this build from the legacy AWG
     * profile to the real, isolated AWG 3.1 field-test profile
     * ([FieldTestAwg31GatewayCatalog]/[AwgGeneration.AWG_3_1]). Frankfurt-
     * first/Stockholm-fallback, handshake proof, and health check are all
     * unchanged - only WHICH interface/port/profile each candidate resolves
     * to is different (see [FieldTestTunnelController]'s own docs).
     */
    private val controller = FieldTestTunnelController(
        transportFactory = transportFactory,
        diagnostics = diagnostics,
        nowProvider = nowProvider,
        gatewayLookup = FieldTestAwg31GatewayCatalog::byId,
        awgGeneration = AwgGeneration.AWG_3_1,
        // C2 fix: a real, bounded, post-handshake data-plane probe - NOT the
        // constant `{ true }` default (which reported PROTECTED on a bare
        // handshake alone, never actually proving the data plane carries
        // traffic). See [probeDataPlane]'s own docs for exactly what this
        // does and does not prove.
        healthCheck = effectiveHealthCheck,
    )

    private val _uiState = MutableStateFlow<FieldTestUiState>(FieldTestUiState.Idle)
    val uiState: StateFlow<FieldTestUiState> = _uiState.asStateFlow()

    private val _lastReport = MutableStateFlow<FieldTestReport?>(null)
    /** The most recent run's report, or null before any Connect attempt - [FieldTestActivity]'s manual "Share report" action reads this directly (`lastReport.value != null`). */
    val lastReport: StateFlow<FieldTestReport?> = _lastReport.asStateFlow()

    private val _permissionRequest = MutableStateFlow<Intent?>(null)
    /** Non-null exactly while [FieldTestActivity] must launch the Android VPN-permission system dialog for this pending [connect] call - see [ensureVpnPermission]/[onVpnPermissionResult]. */
    val permissionRequest: StateFlow<Intent?> = _permissionRequest.asStateFlow()

    @Volatile private var pendingPermissionResult: CompletableDeferred<Boolean>? = null

    /** [FieldTestActivity]'s permission-launcher callback reports the real system result here - completes whatever [connect] call is currently suspended in [ensureVpnPermission], if any (a stray call with none pending is a no-op). */
    fun onVpnPermissionResult(granted: Boolean) {
        _permissionRequest.value = null
        pendingPermissionResult?.complete(granted)
        pendingPermissionResult = null
    }

    /**
     * Resolves the ONE device/app-level VPN permission decision for this
     * [connect] call, exactly once, before any gateway candidate is ever
     * attempted. Returns `true` immediately (no dialog, no diagnostics
     * event) when [preparePermissionIntent] reports permission is already
     * granted - task requirement "already granted -> Connect goes directly
     * to Frankfurt". Otherwise records [FieldTestDiagnosticsRecorder
     * .recordPermissionRequested], surfaces the intent via
     * [permissionRequest] for the Activity to launch, and suspends until
     * [onVpnPermissionResult] reports the real system outcome - the SAME
     * coroutine then continues straight into [controller]'s candidate loop
     * on grant, with no second manual Connect tap required.
     */
    private suspend fun ensureVpnPermission(): Boolean {
        val intent = preparePermissionIntent() ?: return true
        diagnostics.recordPermissionRequested()
        val deferred = CompletableDeferred<Boolean>()
        pendingPermissionResult = deferred
        _permissionRequest.value = intent
        val granted = deferred.await()
        if (granted) diagnostics.recordPermissionGranted() else diagnostics.recordPermissionDenied()
        return granted
    }

    fun connect() {
        if (_uiState.value != FieldTestUiState.Idle && _uiState.value != FieldTestUiState.Failed) return
        _uiState.value = FieldTestUiState.Connecting
        // C1 fix: FieldTestTunnelController.connect() itself refuses to run
        // unless its OWN internal state is Idle - after a Failed run, only
        // resetting THIS ViewModel's uiState (the old retry() behavior)
        // left the controller stuck in FieldTestState.Failed forever, so
        // every subsequent connect() silently no-op'd and returned the SAME
        // stale Failed state without ever attempting a new candidate. Reset
        // it here, unconditionally, right before every connect() attempt -
        // a no-op when the controller is already Idle (the normal
        // first-ever-attempt case), so this is safe on every call path.
        controller.resetAfterFailure()
        // D1/D2 fix: read the REAL underlying network exactly once, HERE,
        // before this build's own full-tunnel VPN attempt can change what
        // the OS reports as the active network - never after the attempt
        // settles (which is what the pre-existing code did), and never
        // inferred from whether the attempt went on to succeed.
        val preConnectNetworkProfile = networkProfileProvider()
        viewModelScope.launch {
            if (!ensureVpnPermission()) {
                _uiState.value = FieldTestUiState.Failed
                _lastReport.value = buildReport(
                    networkProfile = preConnectNetworkProfile,
                    gatewaysAttempted = emptyList(),
                    finalGateway = null,
                    finalTransportKind = null,
                    outcome = FieldTestOutcome.FAILED,
                    failureCategory = FieldTestFailureCategory.VPN_PERMISSION_DENIED,
                )
                return@launch
            }

            val finalState = controller.connect()

            when (finalState) {
                is FieldTestState.Protected -> {
                    _uiState.value = FieldTestUiState.Protected
                    val report = buildReport(
                        networkProfile = preConnectNetworkProfile,
                        gatewaysAttempted = attemptedFrom(finalState.candidate),
                        finalGateway = finalState.candidate,
                        finalTransportKind = TransportKind.AMNEZIA_WG,
                        outcome = FieldTestOutcome.PROTECTED,
                        failureCategory = FieldTestFailureCategory.NONE,
                    )
                    _lastReport.value = report
                    // Report upload is attempted ONLY now, AFTER the tunnel is
                    // genuinely Protected, and its outcome never feeds back
                    // into uiState - a failed upload leaves the VPN exactly
                    // as connected as it was (task requirement 5).
                    attemptUploadThroughTunnel(report)
                }
                is FieldTestState.Failed -> {
                    _uiState.value = FieldTestUiState.Failed
                    // D3 fix: distinguish "no candidate ever produced a
                    // handshake" from "at least one candidate handshook but
                    // then failed its post-handshake health/data-plane
                    // check" - collapsing every failure shape into
                    // ALL_CANDIDATES_EXHAUSTED (the old behavior) discarded
                    // real, already-recorded diagnosis. The exact per-
                    // candidate reason remains available in full in
                    // diagnostics.snapshot() regardless (recordCandidateResult/
                    // recordHealthResult/recordTransportError, each keyed by
                    // candidate) - this is the coarser TOP-LEVEL summary.
                    val anyHandshakeSucceeded = diagnostics.snapshot().any {
                        it.type == net.pocvpn.client.diagnostics.support.DiagnosticEventType.FIELD_TEST_HEALTH_RESULT
                    }
                    val failureCategory = if (anyHandshakeSucceeded) {
                        FieldTestFailureCategory.HEALTH_CHECK_FAILED
                    } else {
                        FieldTestFailureCategory.NO_HANDSHAKE
                    }
                    val report = buildReport(
                        networkProfile = preConnectNetworkProfile,
                        gatewaysAttempted = finalState.attempted,
                        finalGateway = null,
                        finalTransportKind = null,
                        outcome = FieldTestOutcome.FAILED,
                        failureCategory = failureCategory,
                    )
                    _lastReport.value = report
                }
                is FieldTestState.Idle, is FieldTestState.Connecting -> Unit
            }
        }
    }

    /** Lets the tester retry after a failure - same [connect] entry point, which now (C1) also resets [controller]'s own internal state, so this is a genuinely fresh Frankfurt -> Stockholm attempt, not a stale no-op. */
    fun retry() {
        if (_uiState.value == FieldTestUiState.Failed) {
            _uiState.value = FieldTestUiState.Idle
            connect()
        }
    }

    /**
     * B37 senior-review pass (task C2/C3) - the field test's real post-
     * handshake data-plane confidence check, wired as [controller]'s
     * `healthCheck` above. Opens a plain bounded TCP connection to one of
     * two well-known public IPs on port 443 - deliberately NOT anything
     * that depends on this app's own activation/control-plane API (task
     * requirement), and deliberately a raw [Socket] rather than an HTTP
     * client so there is no DNS resolution step to confound "did the tunnel
     * carry traffic" with "did DNS work".
     *
     * Why this is expected to actually go THROUGH the tunnel, not around
     * it: this field-test build's own transport
     * ([AmneziaWgTransport]/[buildFieldTestAwgConfig]) never calls
     * `excludedApplications`/`includedApplications` to exclude this app's
     * own UID from the VPN, and never calls `VpnService.protect(socket)` on
     * a socket this class opens (that API exists only for a VPN
     * implementation to protect ITS OWN control-channel socket from a
     * routing loop - this probe is application code, not the transport
     * implementation, so it is never called here) - Android routes a VPN
     * app's own non-protected sockets through its own tun interface by
     * default once the tunnel is up, the same as every other app's traffic.
     *
     * Honest limitation, reported rather than hidden: this reasoning has
     * NOT been confirmed against real on-device packet capture in this
     * pass (task requirement: "do not claim server runtime verification
     * that was not actually performed" - the same discipline applies here).
     * If a future device test shows this probe can succeed even with the
     * tunnel down (i.e. it is silently bypassing the VPN), that is a
     * correctness bug in THIS probe and must be fixed before trusting a
     * PROTECTED result from it.
     */
    private suspend fun probeDataPlane(): Boolean {
        val targets = listOf("1.1.1.1" to 443, "8.8.8.8" to 443)
        return withContext(Dispatchers.IO) {
            for ((host, port) in targets) {
                val ok = try {
                    withTimeoutOrNull(DATA_PLANE_PROBE_TIMEOUT_MS) {
                        Socket().use { socket ->
                            socket.connect(InetSocketAddress(host, port), DATA_PLANE_PROBE_TIMEOUT_MS.toInt())
                        }
                        true
                    } ?: false
                } catch (c: CancellationException) {
                    throw c
                } catch (t: Throwable) {
                    false
                }
                if (ok) return@withContext true
            }
            false
        }
    }

    private suspend fun attemptUploadThroughTunnel(report: FieldTestReport) {
        diagnostics.recordReportUploadAttempted()
        val uploaded = try {
            reportUploader.uploadThroughTunnel(report)
        } catch (t: Throwable) {
            false
        }
        diagnostics.recordReportUploadResult(uploaded)
        // Refresh the retained report with the upload attempt's own events
        // folded in, so the manual "Share report" fallback (task requirement
        // 4's own "keep the report locally... preserve the existing export/
        // share mechanism") still reflects the full, final timeline even
        // when upload succeeded.
        _lastReport.value = report.copy(events = diagnostics.snapshot())
    }

    private fun attemptedFrom(finalCandidate: ProductionGatewayId): List<ProductionGatewayId> {
        val order = listOf(ProductionGatewayId.GERMANY, ProductionGatewayId.STOCKHOLM)
        val idx = order.indexOf(finalCandidate)
        return if (idx < 0) listOf(finalCandidate) else order.subList(0, idx + 1)
    }

    private fun buildReport(
        networkProfile: NetworkProfile,
        gatewaysAttempted: List<ProductionGatewayId>,
        finalGateway: ProductionGatewayId?,
        finalTransportKind: TransportKind?,
        outcome: FieldTestOutcome,
        failureCategory: FieldTestFailureCategory,
    ): FieldTestReport {
        // B37 - every report this build produces identifies itself as the
        // real AWG 3.1 field test (task requirement A/G) - see this class's
        // own `controller` wiring, the ONE place that actually selects the
        // AWG generation exercised.
        // Reuses the app's REAL restriction-classification logic (task
        // requirement: "restriction/network classification already produced
        // by the app") - RestrictionClassifier.classify is a pure function,
        // no live probe pipeline needs to be wired here (see that object's
        // own docs: missing evidence correctly yields UNKNOWN, never a
        // guess). gatewayHttpsReachable/diverseInternetReachable are not
        // probed by this small flow - null, matching classify()'s own
        // "unknown until observed" contract.
        //
        // D2 fix: [networkProfile] is REAL, pre-connect evidence
        // ([FieldTestViewModel.connect]'s own `preConnectNetworkProfile`,
        // see [currentNetworkProfileSnapshot]) - never synthesized from
        // whether this run's OWN VPN attempt went on to succeed (the
        // original bug: `validatedInternet = outcome == PROTECTED` made a
        // VPN failure look identical to "ordinary Internet doesn't work",
        // even when the underlying network was completely fine and only
        // THIS field-test tunnel failed to come up). vpnActive still
        // correctly reflects THIS run's own outcome (that part is genuinely
        // about the tunnel, not the underlying network).
        val evidence = RestrictionEvidence(
            networkProfile = networkProfile.copy(vpnActive = outcome == FieldTestOutcome.PROTECTED),
            transportState = if (outcome == FieldTestOutcome.PROTECTED) TransportState.Connected else TransportState.HandshakeFailed,
            awgHandshakeFresh = outcome == FieldTestOutcome.PROTECTED,
            gatewayHttpsReachable = null,
        )
        val restrictionClass: RestrictionClass = RestrictionClassifier.classify(evidence)

        return FieldTestReport(
            buildLabel = FieldTestBuildInfo.BUILD_LABEL,
            appVersionName = appVersionName,
            appVersionCode = appVersionCode,
            generatedAtEpochMillis = nowProvider(),
            networkType = networkProfile.type,
            routingMode = RoutingMode.FULL_VPN,
            restrictionClass = restrictionClass,
            gatewaysAttempted = gatewaysAttempted,
            finalGateway = finalGateway,
            finalTransportKind = finalTransportKind,
            awgGeneration = AwgGeneration.AWG_3_1,
            outcome = outcome,
            failureCategory = failureCategory,
            events = diagnostics.snapshot(),
        ).sanitizedForExport()
    }

    private companion object {
        const val DATA_PLANE_PROBE_TIMEOUT_MS = 4_000L
    }

    class Factory(private val application: Application) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            val versionName = try {
                application.packageManager.getPackageInfo(application.packageName, 0).versionName ?: "unknown"
            } catch (t: Throwable) {
                "unknown"
            }
            val versionCode = try {
                application.packageManager.getPackageInfo(application.packageName, 0).let {
                    @Suppress("DEPRECATION")
                    it.versionCode.toLong()
                }
            } catch (t: Throwable) {
                0L
            }
            return FieldTestViewModel(
                transportFactory = { AmneziaWgTransport(application) },
                appVersionName = versionName,
                appVersionCode = versionCode,
                networkProfileProvider = { currentNetworkProfileSnapshot(application) },
            ) as T
        }
    }
}
