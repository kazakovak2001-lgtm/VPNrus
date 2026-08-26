package net.pocvpn.client.vpn

import android.content.Intent
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import net.pocvpn.client.identity.ClientIdentity
import net.pocvpn.client.identity.ClientKeyRepository
import net.pocvpn.client.vpn.config.GatewayConfiguration
import net.pocvpn.client.vpn.config.GatewayConfigurationRepository
import net.pocvpn.client.vpn.config.TransportConfig

/** Test double for VpnTransport. `connectGate`, if set, makes connect() suspend until completed - for concurrency tests. */
class FakeVpnTransport(private val permission: Intent? = null) : VpnTransport {
    override val name: String = "fake"

    private val stateFlow = MutableStateFlow<TransportState>(TransportState.Disconnected)
    var connectCallCount = 0
        private set
    var disconnectCallCount = 0
        private set
    var connectGate: CompletableDeferred<Unit>? = null
    var failConnectWith: Throwable? = null
    var lastConfig: TransportConfig? = null

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
}

class FakeGatewayConfigurationRepository(private var config: GatewayConfiguration) : GatewayConfigurationRepository {
    override fun get(): GatewayConfiguration = config
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
