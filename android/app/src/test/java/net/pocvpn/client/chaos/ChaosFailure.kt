package net.pocvpn.client.chaos

/** B49's closed, test-only fault vocabulary. Detail strings are deliberately absent. */
sealed class ChaosFailure {
    enum class DnsKind { NXDOMAIN, SERVFAIL, TIMEOUT, EMPTY_ANSWER, MALFORMED_RESPONSE, RESOLVER_UNAVAILABLE }
    data class Dns(val kind: DnsKind) : ChaosFailure()

    enum class TcpKind { CONNECT_TIMEOUT, CONNECTION_REFUSED, CONNECTION_RESET, IMMEDIATE_CLOSE, DELAYED_CLOSE, NO_APPLICATION_RESPONSE }
    data class Tcp(val kind: TcpKind) : ChaosFailure()

    enum class UdpKind { SILENT_DROP, LOCAL_OR_NETWORK_FAILURE, ONE_WAY_REACHABILITY, DELAYED_OR_NO_RESPONSE }
    data class Udp(val kind: UdpKind) : ChaosFailure()

    enum class TlsKind { HANDSHAKE_TIMEOUT, ALERT, CERTIFICATE_VALIDATION_FAILED, HOSTNAME_MISMATCH, PEER_CLOSED_DURING_HANDSHAKE, TCP_CONNECTED_TLS_FAILED }
    data class Tls(val kind: TlsKind) : ChaosFailure()

    enum class HttpKind { CONNECTION_UNAVAILABLE, TIMEOUT, STATUS_400, STATUS_401, STATUS_403, STATUS_404, STATUS_429, STATUS_500, STATUS_502, STATUS_503, MALFORMED_RESPONSE, TRUNCATED_RESPONSE }
    data class Http(val kind: HttpKind) : ChaosFailure()

    enum class ManifestKind { ALL_LIVE_ORIGINS_UNREACHABLE, ONE_ORIGIN_UNAVAILABLE, STALE_OR_OLDER, CORRUPT_SIGNED, INVALID_SIGNATURE, EXPIRED, NO_TRUSTED_LKG, TOTAL_TRUSTED_SOURCE_EXHAUSTION }
    data class Manifest(val kind: ManifestKind) : ChaosFailure()

    enum class TransportKind { AWG_SILENT_DROP, REALITY_ALERT_OR_CLOSE, TLS_CONNECT_THEN_CLOSE, SHADOWSOCKS_RESET, XHTTP_PATH_HTTP_ERROR }
    data class Transport(val kind: TransportKind) : ChaosFailure()

    enum class InfrastructureKind { PRIMARY_GATEWAY_UNREACHABLE, ALL_GATEWAYS_UNREACHABLE, CONTROL_PLANE_UNAVAILABLE, INGRESS_CONNECTION_REFUSED, INGRESS_TIMEOUT, RELAY_UNAVAILABLE, RELAY_HEALTH_TIMEOUT, RELAY_DIED, EXIT_HEALTH_FAILURE, STOCKHOLM_2093_CONNECTION_REFUSED }
    data class Infrastructure(val kind: InfrastructureKind) : ChaosFailure()
}

object B48SimulationProfiles {
    val AWG_SILENT_DROP = ChaosFailure.Transport(ChaosFailure.TransportKind.AWG_SILENT_DROP)
    val REALITY_TLS_ALERT_OR_CLOSE = ChaosFailure.Transport(ChaosFailure.TransportKind.REALITY_ALERT_OR_CLOSE)
    val TLS_TCP_CONNECT_THEN_CLOSE = ChaosFailure.Transport(ChaosFailure.TransportKind.TLS_CONNECT_THEN_CLOSE)
    val SHADOWSOCKS_RESET = ChaosFailure.Transport(ChaosFailure.TransportKind.SHADOWSOCKS_RESET)
    val XHTTP_EXPECTED_PATH_HTTP_ERROR = ChaosFailure.Transport(ChaosFailure.TransportKind.XHTTP_PATH_HTTP_ERROR)
    val INGRESS_CONNECTION_REFUSED = ChaosFailure.Infrastructure(ChaosFailure.InfrastructureKind.INGRESS_CONNECTION_REFUSED)
    val CONTROL_PLANE_UNAVAILABLE = ChaosFailure.Infrastructure(ChaosFailure.InfrastructureKind.CONTROL_PLANE_UNAVAILABLE)
}
