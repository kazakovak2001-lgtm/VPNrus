package net.pocvpn.client.chaos

import net.pocvpn.client.reachability.ManifestFetchFailureKind
import net.pocvpn.client.reachability.ManifestFetchResult
import net.pocvpn.client.reachability.RemoteManifestFetcher
import net.pocvpn.client.smartconnect.GatewayReachabilityProbe

class ScriptedGatewayReachabilityProbe(
    private val engine: ScriptedChaosEngine,
    private val operation: ChaosOperation,
) : GatewayReachabilityProbe {
    override suspend fun isReachable(): Boolean = engine.next(operation) is ChaosOutcome.Success
}

class ScriptedRemoteManifestFetcher(
    private val engine: ScriptedChaosEngine,
    private val operation: ChaosOperation,
) : RemoteManifestFetcher {
    override suspend fun fetch(): ManifestFetchResult = when (val outcome = engine.next(operation)) {
        ChaosOutcome.Success -> error("a successful manifest fetch requires signed fixture bytes")
        is ChaosOutcome.Failure -> ManifestFetchResult.Failed(outcome.failure.toManifestFetchKind(), outcome.failure.safeCode())
    }
}

fun ChaosFailure.toManifestFetchKind(): ManifestFetchFailureKind = when (this) {
    is ChaosFailure.Tls -> ManifestFetchFailureKind.TLS_ERROR
    is ChaosFailure.Http -> if (kind == ChaosFailure.HttpKind.MALFORMED_RESPONSE || kind == ChaosFailure.HttpKind.TRUNCATED_RESPONSE) ManifestFetchFailureKind.MALFORMED else ManifestFetchFailureKind.HTTP_ERROR
    is ChaosFailure.Manifest -> if (kind == ChaosFailure.ManifestKind.CORRUPT_SIGNED) ManifestFetchFailureKind.MALFORMED else ManifestFetchFailureKind.NETWORK_ERROR
    else -> ManifestFetchFailureKind.NETWORK_ERROR
}

/** Closed enum-derived diagnostic code; never contains credentials, hosts, URLs, or exception text. */
fun ChaosFailure.safeCode(): String = when (this) {
    is ChaosFailure.Dns -> "DNS_${kind.name}"
    is ChaosFailure.Tcp -> "TCP_${kind.name}"
    is ChaosFailure.Udp -> "UDP_${kind.name}"
    is ChaosFailure.Tls -> "TLS_${kind.name}"
    is ChaosFailure.Http -> "HTTP_${kind.name}"
    is ChaosFailure.Manifest -> "MANIFEST_${kind.name}"
    is ChaosFailure.Transport -> "TRANSPORT_${kind.name}"
    is ChaosFailure.Infrastructure -> "INFRASTRUCTURE_${kind.name}"
}
