package net.pocvpn.client.debug

import android.os.Bundle
import android.view.Gravity
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.launch
import net.pocvpn.client.identity.XrayQuicProfileRepositoryFactory
import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.smartconnect.ProductionGateway
import net.pocvpn.client.vpn.xray.LibXrayCoreRuntime
import net.pocvpn.client.vpn.xray.XrayConfigRenderer
import net.pocvpn.client.vpn.xray.XrayCoreDiagnostics
import net.pocvpn.client.vpn.xray.XrayDataPlaneReadiness
import net.pocvpn.client.vpn.xray.XrayDataPlaneReadinessCheck
import net.pocvpn.client.vpn.xray.toXrayVlessQuicConfig

/**
 * B21-fix - DEBUG-ONLY outbound-isolation harness. Proves/disproves whether
 * the pinned AndroidLibXrayLite core can originate a real XHTTP/H3 dial to
 * Frankfurt 2087 INDEPENDENT of Nova's VpnService/TUN routing path - this
 * Activity never calls VpnService.prepare()/Builder.establish() and never
 * requests VPN permission at all. It uses a fresh, standalone
 * [LibXrayCoreRuntime] instance (NOT [net.pocvpn.client.vpn.xray.NovaXrayVpnService]'s)
 * started with [XrayConfigRenderer.renderOutboundOnly] (no inbounds - the tun
 * fd `startLoop` takes is meaningless here) and exercises the SAME real,
 * already-provisioned QUIC outbound the real connect path uses via the SAME
 * [XrayDataPlaneReadinessCheck] mechanism ([net.pocvpn.client.vpn.xray.XrayCoreController]
 * already uses) - deliberately no new test mechanism, no new native runtime,
 * no second production connection architecture.
 *
 * Uses NO fabricated credentials - refuses if no real QUIC profile has
 * already been provisioned for the endpoint via the real control-plane path
 * (same discipline as [XrayDiagnosticsActivity]).
 */
class XrayOutboundIsolationActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val endpointId = intent.getStringExtra(EXTRA_ENDPOINT_ID)?.takeIf { it.isNotBlank() }
            ?.let { EndpointId(it) } ?: EndpointId(ProductionGateway.ID)

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            setPadding(48, 48, 48, 48)
        }
        val statusText = TextView(this).apply {
            text = "endpoint=${endpointId.value}\nNo VpnService/TUN involved in this test at all."
        }
        root.addView(statusText)

        val runButton = Button(this).apply {
            text = "Run outbound-only QUIC dial (no VpnService)"
            setOnClickListener {
                lifecycleScope.launch {
                    statusText.text = "Running..."
                    statusText.text = runIsolatedQuicDial(endpointId)
                }
            }
        }
        root.addView(runButton)
        setContentView(root)
    }

    private suspend fun runIsolatedQuicDial(endpointId: EndpointId): String {
        val profile = XrayQuicProfileRepositoryFactory.create(applicationContext, endpointId).getProfileOrNull()
            ?: return "No Xray QUIC profile configured for ${endpointId.value} - refusing to run (never fabricates a credential)."

        val renderedConfig = XrayConfigRenderer.renderOutboundOnly(profile.toXrayVlessQuicConfig())
        val runtime = LibXrayCoreRuntime()

        return try {
            runtime.ensureCoreEnvInitialized(applicationContext)
            // No "tun" inbound exists in renderOutboundOnly's config, so this
            // fd is never read by the Go runtime - -1 documents that
            // explicitly rather than reusing a real tun fd from elsewhere.
            runtime.startLoop(renderedConfig, NO_TUN_FD)
            val readiness = XrayDataPlaneReadinessCheck.check(runtime)
            val diagnostics = XrayCoreDiagnostics.events.value.joinToString("\n") { "[${it.level}] ${it.message}" }
            runCatching { runtime.stopLoop() }

            val readinessLine = when (readiness) {
                is XrayDataPlaneReadiness.Ready -> "READY (latency=${readiness.latencyMs}ms) - outbound dial SUCCEEDED with no VpnService/TUN involved."
                is XrayDataPlaneReadiness.Timeout -> "TIMEOUT - outbound dial did not complete within the bounded timeout, no VpnService/TUN involved."
                is XrayDataPlaneReadiness.Failed -> "FAILED: ${readiness.reason}"
            }
            "endpoint=${endpointId.value}\n$readinessLine\n\ncore diagnostics:\n${diagnostics.ifBlank { "(none)" }}"
        } catch (t: Throwable) {
            runCatching { runtime.stopLoop() }
            "startLoop itself threw: ${t.javaClass.simpleName}: ${XrayCoreDiagnostics.sanitize(t.message)}"
        }
    }

    companion object {
        const val EXTRA_ENDPOINT_ID = "endpointId"
        private const val NO_TUN_FD = -1
    }
}
