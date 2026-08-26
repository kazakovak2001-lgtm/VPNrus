package net.pocvpn.client

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import net.pocvpn.client.diagnostics.DiagnosticsSnapshot
import net.pocvpn.client.diagnostics.DiagnosticsStore
import net.pocvpn.client.identity.ClientKeyRepository
import net.pocvpn.client.identity.ClientKeyRepositoryFactory
import net.pocvpn.client.vpn.AmneziaWgTransport
import net.pocvpn.client.vpn.AndroidReconnectManager
import net.pocvpn.client.vpn.ControllerEvent
import net.pocvpn.client.vpn.ReconnectManager
import net.pocvpn.client.vpn.TransportState
import net.pocvpn.client.vpn.VpnController
import net.pocvpn.client.vpn.VpnTransport
import net.pocvpn.client.vpn.config.BuildConfigGatewaySource
import net.pocvpn.client.vpn.config.DefaultGatewayConfigurationRepository
import net.pocvpn.client.vpn.config.GatewayConfiguration
import net.pocvpn.client.vpn.config.GatewayConfigurationRepository

/**
 * Thin state holder above VpnController - MainActivity observes this instead
 * of owning tunnel/connection state itself, so Activity recreation (rotation,
 * process death+restore of the Activity only) doesn't lose or duplicate it.
 * VpnController is built here (not in the Factory) because it needs
 * viewModelScope, which only exists once this ViewModel instance exists.
 */
class MainViewModel(
    private val clientKeyRepository: ClientKeyRepository,
    transport: VpnTransport,
    gatewayConfigurationRepository: GatewayConfigurationRepository,
    reconnectManager: ReconnectManager,
    private val diagnosticsStore: DiagnosticsStore,
) : ViewModel() {

    private val controller = VpnController(
        transport = transport,
        clientKeyRepository = clientKeyRepository,
        gatewayConfigurationRepository = gatewayConfigurationRepository,
        reconnectManager = reconnectManager,
        diagnostics = diagnosticsStore,
        scope = viewModelScope,
    )

    val transportState: StateFlow<TransportState> = controller.state
    val diagnostics: StateFlow<DiagnosticsSnapshot> = diagnosticsStore.snapshot
    val events: SharedFlow<ControllerEvent> = controller.events

    private val _publicKey = MutableStateFlow<String?>(null)
    val publicKey: StateFlow<String?> = _publicKey.asStateFlow()

    init {
        viewModelScope.launch {
            _publicKey.value = clientKeyRepository.getPublicKey()
        }
    }

    fun gatewayStatus(): GatewayConfiguration = controller.gatewayStatus()

    fun connect() {
        viewModelScope.launch { controller.connect() }
    }

    fun disconnect() {
        viewModelScope.launch { controller.disconnect() }
    }

    fun onVpnPermissionResult(granted: Boolean) {
        viewModelScope.launch { controller.onVpnPermissionResult(granted) }
    }

    fun regenerateIdentity() {
        viewModelScope.launch {
            clientKeyRepository.clearIdentity()
            _publicKey.value = clientKeyRepository.getOrCreateIdentity().publicKeyBase64
        }
    }

    override fun onCleared() {
        controller.shutdown()
    }

    class Factory(private val appContext: Context) : ViewModelProvider.Factory {
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            val context = appContext.applicationContext
            @Suppress("UNCHECKED_CAST")
            return MainViewModel(
                clientKeyRepository = ClientKeyRepositoryFactory.create(context),
                transport = AmneziaWgTransport(context),
                gatewayConfigurationRepository = DefaultGatewayConfigurationRepository(BuildConfigGatewaySource),
                reconnectManager = AndroidReconnectManager(context),
                diagnosticsStore = DiagnosticsStore(),
            ) as T
        }
    }
}
