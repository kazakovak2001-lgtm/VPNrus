package net.pocvpn.client.debug

import android.os.Bundle
import android.os.SystemClock
import android.util.Log
import android.view.Gravity
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import net.pocvpn.client.identity.XrayProfile
import net.pocvpn.client.identity.XrayProfileRepositoryFactory
import net.pocvpn.client.identity.XrayTlsProfile
import net.pocvpn.client.identity.XrayTlsProfileRepositoryFactory
import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.smartconnect.ProductionGateway
import net.pocvpn.client.vpn.IndependentEgressProbeResult
import net.pocvpn.client.vpn.TransportState
import net.pocvpn.client.vpn.VlessRealityTransport
import net.pocvpn.client.vpn.VlessTlsTransport
import net.pocvpn.client.vpn.VpnTransport
import net.pocvpn.client.vpn.config.TransportConfig
import net.pocvpn.client.vpn.xray.IndependentEgressTargets
import net.pocvpn.client.vpn.xray.XrayRuntimeEvent
import net.pocvpn.client.vpn.xray.XrayRuntimeState
import net.pocvpn.client.vpn.xray.toXrayVlessRealityConfig
import net.pocvpn.client.vpn.xray.toXrayVlessTlsConfig

/**
 * B8K1B - debug-build-only screen for manually exercising the isolated Xray
 * adapter shell on a physical device. Debug-only via the `debug` Gradle
 * source set's own AndroidManifest.xml (see that file's docs) - never
 * present in a release APK.
 *
 * Uses NO fabricated credentials: if no real profile has been saved via
 * [net.pocvpn.client.identity.XrayProfileRepository.saveProfile] (a future
 * real provisioning flow's job, not this activity's, EXCEPT the one-time
 * manual-save path below), this screen shows a refusal message and does
 * nothing else. There is no UUID/public key/short ID hardcoded anywhere in
 * this file.
 *
 * B13 (2026-08-30, Stockholm physical validation) - endpoint-aware
 * ([EXTRA_ENDPOINT_ID], defaults to the production/Germany endpoint so
 * every pre-B13 launch - including a plain tap from the launcher, with no
 * extras at all - is byte-for-byte unaffected) and REALITY/TLS-aware
 * ([EXTRA_KIND]). Adds a genuine, minimal manual-save path
 * ([EXTRA_SAVE_PROFILE]) for exactly ONE reason: AndroidKeyStore-encrypted
 * profile storage (SecureXrayProfileRepository) cannot be constructed
 * off-device - there is no way to pre-build a valid encrypted profile file
 * and push it in, unlike the plaintext AWG PersistedProfile. A real,
 * operator-provisioned server-side credential (never invented here) is the
 * ONLY thing this path can ever save - it is a save mechanism, not a
 * credential generator.
 */
class XrayDiagnosticsActivity : AppCompatActivity() {

    private lateinit var endpointId: EndpointId
    private lateinit var statusText: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        endpointId = intent.getStringExtra(EXTRA_ENDPOINT_ID)?.takeIf { it.isNotBlank() }
            ?.let { EndpointId(it) } ?: EndpointId(ProductionGateway.ID)
        val kind = intent.getStringExtra(EXTRA_KIND) ?: "reality"

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            setPadding(48, 48, 48, 48)
        }
        statusText = TextView(this).apply { text = "endpoint=${endpointId.value} kind=$kind\nChecking for a saved Xray profile..." }
        root.addView(statusText)

        val startButton = Button(this).apply {
            text = "Start Xray test tunnel"
            isEnabled = false
            setOnClickListener {
                lifecycleScope.launch {
                    if (kind == "tls") {
                        val repository = XrayTlsProfileRepositoryFactory.create(applicationContext, endpointId)
                        val profile = repository.getProfileOrNull()
                        if (profile == null) {
                            statusText.text = "No Xray TLS profile configured for ${endpointId.value} - refusing to start."
                            return@launch
                        }
                        VlessTlsTransport(applicationContext).also { startedTransport = it; startedEndpointId = endpointId }
                            .connect(TransportConfig.XrayTls(profile.toXrayVlessTlsConfig(), endpointId = endpointId))
                    } else {
                        val repository = XrayProfileRepositoryFactory.create(applicationContext, endpointId)
                        val profile = repository.getProfileOrNull()
                        if (profile == null) {
                            statusText.text = "No Xray profile configured for ${endpointId.value} - refusing to start."
                            return@launch
                        }
                        VlessRealityTransport(applicationContext).also { startedTransport = it; startedEndpointId = endpointId }
                            .connect(TransportConfig.Xray(profile.toXrayVlessRealityConfig(), endpointId = endpointId))
                    }
                    statusText.text = "Start requested (endpoint=${endpointId.value}, kind=$kind) - see logcat NovaXrayVpnService for real lifecycle detail."
                }
            }
        }
        root.addView(startButton)

        val stopButton = Button(this).apply {
            text = "Stop Xray test tunnel"
            setOnClickListener {
                lifecycleScope.launch {
                    startedTransport = null
                    startedEndpointId = null
                    if (kind == "tls") VlessTlsTransport(applicationContext).disconnect() else VlessRealityTransport(applicationContext).disconnect()
                    statusText.text = "Stop requested - see logcat NovaXrayVpnService for real lifecycle detail."
                }
            }
        }
        root.addView(stopButton)

        // B-WL7 M1 test hook - see [runEgressProbe]. Same DUMP-gated, debug-only activity; no new component.
        val probeButton = Button(this).apply {
            text = "Probe independent egress (debug)"
            setOnClickListener { lifecycleScope.launch { runEgressProbe() } }
        }
        root.addView(probeButton)

        setContentView(root)

        if (intent.getBooleanExtra(EXTRA_PROBE_EGRESS, false)) {
            lifecycleScope.launch { runEgressProbe() }
        }

        if (intent.getBooleanExtra(EXTRA_SAVE_PROFILE, false)) {
            lifecycleScope.launch {
                saveProfileFromIntent(kind)
                refreshStatus(kind, startButton)
            }
        } else {
            lifecycleScope.launch { refreshStatus(kind, startButton) }
        }
    }

    /**
     * B13 - saves EXACTLY the fields the launcher passed as Intent extras -
     * never a default/invented value for any credential field. Requires
     * every field for the requested [kind] to be present; otherwise no-ops
     * (never a partial/corrupt save).
     */
    private suspend fun saveProfileFromIntent(kind: String) {
        if (kind == "tls") {
            val server = intent.getStringExtra("server") ?: return
            val port = intent.getIntExtra("port", -1).takeIf { it > 0 } ?: return
            val uuid = intent.getStringExtra("uuid") ?: return
            val serverName = intent.getStringExtra("serverName") ?: return
            val fingerprint = intent.getStringExtra("fingerprint") ?: return
            XrayTlsProfileRepositoryFactory.create(applicationContext, endpointId).saveProfile(
                XrayTlsProfile(server = server, serverPort = port, uuid = uuid, serverName = serverName, fingerprint = fingerprint),
            )
        } else {
            val server = intent.getStringExtra("server") ?: return
            val port = intent.getIntExtra("port", -1).takeIf { it > 0 } ?: return
            val uuid = intent.getStringExtra("uuid") ?: return
            val flow = intent.getStringExtra("flow") ?: ""
            val serverName = intent.getStringExtra("serverName") ?: return
            val fingerprint = intent.getStringExtra("fingerprint") ?: return
            val realityPublicKey = intent.getStringExtra("realityPublicKey") ?: return
            val shortId = intent.getStringExtra("shortId") ?: return
            XrayProfileRepositoryFactory.create(applicationContext, endpointId).saveProfile(
                XrayProfile(
                    server = server, serverPort = port, uuid = uuid, flow = flow, serverName = serverName,
                    fingerprint = fingerprint, realityPublicKey = realityPublicKey, shortId = shortId,
                ),
            )
        }
    }

    private suspend fun refreshStatus(kind: String, startButton: Button) {
        val hasProfile = try {
            if (kind == "tls") {
                XrayTlsProfileRepositoryFactory.create(applicationContext, endpointId).getProfileOrNull() != null
            } else {
                XrayProfileRepositoryFactory.create(applicationContext, endpointId).getProfileOrNull() != null
            }
        } catch (t: Throwable) {
            false
        }
        statusText.text = "endpoint=${endpointId.value} kind=$kind\n" + if (hasProfile) {
            "Profile found. Ready to start (server/UUID/keys are never shown here)."
        } else {
            "No Xray profile configured - refusing to start. Provision a real profile first."
        }
        startButton.isEnabled = hasProfile
    }

    /**
     * B-WL7 M1 test hook - asks the transport THIS activity started for one
     * [VpnTransport.probeIndependentEgress] (the same production entry point
     * VpnController uses: existing IPC, existing `:xray` 6 s / bridge 8 s
     * bounds) and shows the result. Diagnostic only: this session runs
     * outside VpnController, so no data-plane gate, failover or reconnect
     * reads this result or the probe's bytes. REACHED means only that the
     * target answered through this core; it is NOT proof the request left
     * through the first gateway's egress (that needs the target's access log).
     */
    private suspend fun runEgressProbe() {
        val transport = startedTransport
        val endpoint = startedEndpointId
        val targets = IndependentEgressTargets.forSession(endpoint)
        val connected = transport != null && transport.observeState().first() is TransportState.Connected
        val preflight = EgressProbeHookGate.preflight(connected, probeInFlight, XrayRuntimeState.events.value, targets)
        if (preflight is EgressProbeHookGate.Preflight.Refused) {
            report("egress probe refused: ${preflight.reason}")
            return
        }
        val ready = preflight as EgressProbeHookGate.Preflight.Ready
        probeInFlight = true
        try {
            report("egress probe running: coreSessionAtStart=${ready.sessionId} target=${ready.target} ...")
            val startedAt = SystemClock.elapsedRealtime()
            var error: Throwable? = null
            val result = try {
                withTimeoutOrNull(EgressProbeHookGate.CALLER_TIMEOUT_MS) { transport!!.probeIndependentEgress() }
            } catch (e: CancellationException) {
                throw e
            } catch (t: Throwable) {
                error = t
                null
            }
            val elapsedMs = SystemClock.elapsedRealtime() - startedAt
            val outcome = EgressProbeHookGate.classify(ready.sessionId, XrayRuntimeState.events.value, result, error)
            report(
                "egress probe: endpoint=${endpoint?.value} ${EgressProbeHookGate.sessionLabel(ready.sessionId, outcome)} target=${ready.target} " +
                    "outcome=$outcome elapsedMs=$elapsedMs (REACHED != proof of first-gateway egress)",
            )
        } finally {
            probeInFlight = false
        }
    }

    /** Non-secret only: endpoint id, session id, public gateway IP, enum outcome, elapsed time. */
    private fun report(line: String) {
        statusText.text = line
        Log.i(EGRESS_PROBE_LOG_TAG, line)
    }

    companion object {
        const val EXTRA_ENDPOINT_ID = "endpointId"
        const val EXTRA_KIND = "kind"
        const val EXTRA_SAVE_PROFILE = "saveProfile"
        const val EXTRA_PROBE_EGRESS = "probeEgress"
        private const val EGRESS_PROBE_LOG_TAG = "XrayDiagEgressProbe"

        // Process-wide so a later `am start --ez probeEgress true` (a new
        // activity instance) still probes the transport the Start button started.
        @Volatile private var startedTransport: VpnTransport? = null
        @Volatile private var startedEndpointId: EndpointId? = null
        @Volatile private var probeInFlight = false
    }
}

/** Pure decisions of the [XrayDiagnosticsActivity] egress-probe hook (JVM-tested). */
internal object EgressProbeHookGate {

    /** Same bound as VpnController.INDEPENDENT_EGRESS_PROBE_TIMEOUT_MS (private there). */
    const val CALLER_TIMEOUT_MS = 10_000L

    sealed class Preflight {
        data class Ready(val sessionId: Long, val target: String) : Preflight()
        data class Refused(val reason: String) : Preflight()
    }

    enum class Outcome { REACHED, NOT_REACHED, UNAVAILABLE, TIMEOUT, ERROR, STALE_SESSION }

    fun preflight(transportConnected: Boolean, inFlight: Boolean, currentEvent: XrayRuntimeEvent?, targets: List<String>): Preflight = when {
        inFlight -> Preflight.Refused("a probe is already running")
        !transportConnected -> Preflight.Refused("no Connected session started from this screen")
        currentEvent !is XrayRuntimeEvent.Started -> Preflight.Refused("the Xray core is not Started")
        targets.isEmpty() -> Preflight.Refused("no independent catalog target for this endpoint")
        else -> Preflight.Ready(currentEvent.sessionId, targets.first())
    }

    /** A result only counts for the session that was Started before AND is still Started after the probe. */
    fun classify(sessionBefore: Long, eventAfter: XrayRuntimeEvent?, result: IndependentEgressProbeResult?, error: Throwable?): Outcome = when {
        eventAfter !is XrayRuntimeEvent.Started || eventAfter.sessionId != sessionBefore -> Outcome.STALE_SESSION
        error != null -> Outcome.ERROR
        result == null -> Outcome.TIMEOUT
        else -> Outcome.valueOf(result.name)
    }

    /**
     * The preflight id is the core's CURRENT Started session, not necessarily
     * the one this screen's transport owns (its id is private to the
     * transport). Only REACHED proves they are the same: the bridge answers
     * REACHED solely for the transport's own Started session, and [classify]
     * already required that same id before and after. Any other outcome may
     * come from the transport's own (older) session, so no id is claimed.
     */
    fun sessionLabel(coreSessionAtStart: Long, outcome: Outcome): String =
        if (outcome == Outcome.REACHED) "session=$coreSessionAtStart" else "session=unattributed coreSessionAtStart=$coreSessionAtStart"
}
