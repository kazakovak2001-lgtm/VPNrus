package net.pocvpn.client.vpn

import android.content.Intent
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import net.pocvpn.client.identity.ClientIdentity
import net.pocvpn.client.identity.ClientKeyRepository
import net.pocvpn.client.smartconnect.ConnectionOutcome
import net.pocvpn.client.smartconnect.ConnectionOutcomeStore
import net.pocvpn.client.transport.TransportCapabilities
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.transport.TransportStats
import net.pocvpn.client.vpn.config.GatewayConfiguration
import net.pocvpn.client.vpn.config.GatewayConfigurationRepository
import net.pocvpn.client.vpn.config.TransportConfig
import net.pocvpn.client.vpn.policy.AppRoutingPolicy
import net.pocvpn.client.vpn.policy.AppRoutingPolicyStore
import net.pocvpn.client.vpn.policy.InstalledPackageChecker
import net.pocvpn.client.vpn.policy.RoutingMode
import net.pocvpn.client.vpn.policy.RoutingModeStore

/** Test double for VpnTransport. `connectGate`, if set, makes connect() suspend until completed - for concurrency tests. */
class FakeVpnTransport(
    private val permission: Intent? = null,
    // B8I2 - additive, defaults to AMNEZIA_WG so every existing call site is
    // byte-for-byte unaffected; lets a test build a TransportRegistry whose
    // ONLY available transport is something else (e.g. XRAY_REALITY), to
    // prove Smart Connect's AWG-only preflight blocks a non-AWG selection.
    override val kind: TransportKind = TransportKind.AMNEZIA_WG,
) : VpnTransport {
    override val name: String = "fake"
    override val capabilities: TransportCapabilities = TransportCapabilities.amneziaWg()

    private val stateFlow = MutableStateFlow<TransportState>(TransportState.Disconnected)
    var connectCallCount = 0
        private set
    var disconnectCallCount = 0
        private set
    var connectGate: CompletableDeferred<Unit>? = null
    var failConnectWith: Throwable? = null
    var lastConfig: TransportConfig? = null

    // B8B3D - controls what stats() reports. Defaults to a fresh handshake
    // (real wall-clock "now", computed at call time - see stats() below) so
    // every pre-existing test, which knows nothing about handshake-awaiting,
    // keeps observing prompt Connected exactly as before. Set
    // handshakeAvailable = false to exercise HandshakeFailed/TX-without-
    // handshake behavior.
    var handshakeAvailable = true
    var statsBytesReceived = 0L
    var statsBytesSent = 0L

    override fun preparePermissionIntent(): Intent? = permission

    override suspend fun connect(config: TransportConfig) {
        connectCallCount++
        lastConfig = config
        stateFlow.value = TransportState.Connecting
        connectGate?.await()
        failConnectWith?.let { throw it }
        stateFlow.value = TransportState.Connected
    }

    override suspend fun disconnect() {
        disconnectCallCount++
        stateFlow.value = TransportState.Disconnected
    }

    override fun observeState(): Flow<TransportState> = stateFlow

    // B8I5 - lets a test simulate a late/stale emission from THIS instance
    // (e.g. after VpnController has switched its active transport away from
    // it, or after shutdown()) without going through connect()/disconnect() -
    // proving a detached/cancelled observer never lets it leak into
    // VpnController's own state.
    fun forceState(state: TransportState) {
        stateFlow.value = state
    }

    override suspend fun stats(): TransportStats = TransportStats.Counters(
        bytesReceived = statsBytesReceived,
        bytesSent = statsBytesSent,
        lastHandshakeEpochMillis = if (handshakeAvailable) System.currentTimeMillis() else null,
    )
}

class FakeGatewayConfigurationRepository(private var config: GatewayConfiguration) : GatewayConfigurationRepository {
    var getCallCount = 0
        private set

    override fun get(): GatewayConfiguration {
        getCallCount++
        return config
    }
    fun set(new: GatewayConfiguration) {
        config = new
    }
}

class FakeReconnectManager : ReconnectManager {
    private var onLost: (() -> Unit)? = null
    private var onAvailable: (() -> Unit)? = null
    var networkAvailable = true
    var startCallCount = 0
        private set
    var stopCallCount = 0
        private set

    override fun start(onNetworkLost: () -> Unit, onNetworkAvailable: () -> Unit) {
        startCallCount++
        onLost = onNetworkLost
        onAvailable = onNetworkAvailable
    }

    override fun stop() {
        stopCallCount++
        onLost = null
        onAvailable = null
    }

    override fun isNetworkAvailable(): Boolean = networkAvailable

    fun triggerNetworkLost() {
        networkAvailable = false
        onLost?.invoke()
    }

    fun triggerNetworkAvailable() {
        networkAvailable = true
        onAvailable?.invoke()
    }
}

class FakeClientKeyRepository(private val privateKey: String = "FAKE_PRIVATE_KEY_NOT_REAL_BASE64==", private val publicKey: String = "FAKE_PUBLIC_KEY_NOT_REAL_BASE64===") : ClientKeyRepository {
    var clearCallCount = 0
        private set

    override suspend fun getOrCreateIdentity(): ClientIdentity = ClientIdentity(publicKey)
    override suspend fun getPublicKey(): String = publicKey
    override suspend fun getPrivateKeyForTunnel(): String = privateKey
    override suspend fun clearIdentity() {
        clearCallCount++
    }
}

/** B8H - in-memory AppRoutingPolicyStore double. read() always reflects the LATEST write(), exactly like the real file-backed store. */
class FakeAppRoutingPolicyStore(private var policy: AppRoutingPolicy = AppRoutingPolicy.Default) : AppRoutingPolicyStore {
    var writeCallCount = 0
        private set

    override fun read(): AppRoutingPolicy = policy

    override fun write(policy: AppRoutingPolicy) {
        writeCallCount++
        this.policy = policy
    }
}

/** B8H - InstalledPackageChecker double backed by an explicit installed-set, so "stale package" scenarios are one-line to set up. */
class FakeInstalledPackageChecker(private val installedPackages: MutableSet<String> = mutableSetOf()) : InstalledPackageChecker {
    fun markInstalled(vararg packageNames: String) {
        installedPackages.addAll(packageNames)
    }

    fun markUninstalled(packageName: String) {
        installedPackages.remove(packageName)
    }

    override fun isInstalled(packageName: String): Boolean = packageName in installedPackages
}

/** B18 - in-memory RoutingModeStore double. read() always reflects the LATEST write(), exactly like the real file-backed store. */
class FakeRoutingModeStore(private var mode: RoutingMode = RoutingMode.FULL_VPN) : RoutingModeStore {
    override fun read(): RoutingMode = mode
    override fun write(mode: RoutingMode) {
        this.mode = mode
    }
}

/** B8I - in-memory ConnectionOutcomeStore double; recorded() exposes every call in order for assertions. */
class FakeConnectionOutcomeStore : ConnectionOutcomeStore {
    private val outcomes = mutableListOf<ConnectionOutcome>()

    override fun recent(): List<ConnectionOutcome> = outcomes.toList()

    override fun record(outcome: ConnectionOutcome) {
        outcomes.add(outcome)
    }
}
