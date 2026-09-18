package net.pocvpn.client.debug.b45a

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import kotlin.random.Random

/**
 * B45A - SPIKE ONLY, NOT PRODUCTION CONNECTION AUTHORITY.
 *
 * Smallest possible ordinary-app UDP round-trip probe against the temporary
 * Frankfurt echo endpoint (see docs/B45A_SHADOWSOCKS_RUST_SPIKE.md's UDP
 * proof section). Deliberately a plain `java.net.DatagramSocket` with NO
 * `VpnService.protect()` call - this socket's traffic MUST be captured by
 * the B45A TUN's default route like any other app traffic (see
 * B45ATunNetworkConfig's own default-route doc comment), so a successful
 * round trip proves the tunnel actually carries UDP end to end rather than
 * the request leaving directly. [ECHO_HOST] is a hardcoded IPv4 literal
 * (never a hostname) so it can never resolve to an IPv6 address and exit
 * through the IPv6-unrouted bypass path B45ATunNetworkConfig already
 * documents. The echo port is deliberately different from the Shadowsocks
 * listener port so the decrypted forward ssserver performs is a real,
 * distinct hop rather than a self-destination loop back into itself.
 */
internal object B45AUdpEchoProbe {

    const val ECHO_HOST = "152.70.43.1"
    const val ECHO_PORT = 28389
    private const val TIMEOUT_MILLIS = 3000
    private const val NONCE_PREFIX = "B45A-UDP-"

    /** Not secret - a random correlation token, safe to log. */
    fun newNonce(): String = NONCE_PREFIX + Random.nextBytes(8).joinToString("") { "%02x".format(it) }

    data class RoundTripResult(
        val nonce: String,
        val matched: Boolean,
        val latencyMillis: Long,
        val error: String? = null,
    )

    /**
     * One send+receive+exact-compare round trip. Caller gates this on
     * B45ARuntimePhase.RUNNING. [host]/[port] default to the real temporary
     * Frankfurt endpoint; overridable only so unit tests can point this at a
     * local, deterministic destination instead of doing real network I/O
     * against production-adjacent infrastructure.
     */
    fun roundTrip(nonce: String = newNonce(), host: String = ECHO_HOST, port: Int = ECHO_PORT): RoundTripResult {
        val payload = nonce.toByteArray(Charsets.UTF_8)
        val socket = DatagramSocket()
        return try {
            socket.soTimeout = TIMEOUT_MILLIS
            val address = InetAddress.getByName(host)
            val start = System.currentTimeMillis()
            socket.send(DatagramPacket(payload, payload.size, address, port))
            val buffer = ByteArray(256)
            val reply = DatagramPacket(buffer, buffer.size)
            socket.receive(reply)
            val latency = System.currentTimeMillis() - start
            val received = String(reply.data, reply.offset, reply.length, Charsets.UTF_8)
            RoundTripResult(nonce = nonce, matched = received == nonce, latencyMillis = latency)
        } catch (e: Exception) {
            RoundTripResult(nonce = nonce, matched = false, latencyMillis = -1, error = "${e.javaClass.simpleName}: ${e.message}")
        } finally {
            socket.close()
        }
    }
}
