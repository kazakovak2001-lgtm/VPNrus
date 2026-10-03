package net.pocvpn.client.vpn.hysteria

import java.security.SecureRandom

/**
 * B46-4A - the local SOCKS5 hop between the tun2socks child and the
 * Hysteria2 child is authenticated with credentials generated fresh for every
 * Hysteria2 session and listens on an ephemeral 127.0.0.1 port.
 *
 * The credentials live only in memory for the session, in the Hysteria2
 * child's mode-600 config file (deleted on stop/failure/child death) and in
 * the tun2socks control header sent over the app-private Unix socket. They
 * are never persisted as user data and never logged - [toString] is redacted.
 */
class Hysteria2LocalSocksCredentials private constructor(
    val username: String,
    val password: String,
) {
    override fun toString(): String = "Hysteria2LocalSocksCredentials(<redacted>)"

    companion object {
        /** 128-bit username, 256-bit password, hex-encoded (no escaping anywhere). */
        const val USERNAME_BYTES = 16
        const val PASSWORD_BYTES = 32

        fun generate(random: SecureRandom = SecureRandom()): Hysteria2LocalSocksCredentials =
            Hysteria2LocalSocksCredentials(
                username = random.hex(USERNAME_BYTES),
                password = random.hex(PASSWORD_BYTES),
            )

        private fun SecureRandom.hex(byteCount: Int): String {
            val bytes = ByteArray(byteCount).also { nextBytes(it) }
            return bytes.joinToString("") { "%02x".format(it.toInt() and 0xff) }
        }
    }
}

/** The Hysteria2 child binds an ephemeral loopback port and reports the real one via `SOCKS5_LISTENING`. */
internal const val LOCAL_SOCKS_LISTEN = "127.0.0.1:0"

private const val SOCKS5_LISTENING_PREFIX = "SOCKS5_LISTENING addr="
private const val SOCKS5_AUTH_REQUIRED_SUFFIX = " auth=required"
private val LOOPBACK_SOCKS_ADDRESS = Regex("""127\.0\.0\.1:(\d{1,5})""")

/**
 * Returns [address] if it is exactly `127.0.0.1:<1-65535>`, otherwise null.
 * Port 0, other hosts (including `0.0.0.0`, `localhost`, IPv6) and anything
 * malformed are rejected.
 */
internal fun parseLoopbackSocksAddress(address: String): String? {
    val match = LOOPBACK_SOCKS_ADDRESS.matchEntire(address) ?: return null
    val port = match.groupValues[1].toIntOrNull() ?: return null
    return if (port in 1..65535) address else null
}

/**
 * Parses the Hysteria2 child's readiness line. The hardened Go child logs
 * `SOCKS5_LISTENING addr=<host:port> auth=required` (after the standard log
 * timestamp prefix); returns the bound address only if it is a valid
 * 127.0.0.1 address with a non-zero port AND the line carries the
 * `auth=required` marker. A pre-hardening child (anonymous SOCKS5, no
 * marker) is therefore refused - startup fails closed.
 */
internal fun parseSocksListeningLine(line: String): String? {
    val start = line.indexOf(SOCKS5_LISTENING_PREFIX)
    if (start < 0) return null
    val rest = line.substring(start + SOCKS5_LISTENING_PREFIX.length).trimEnd()
    if (!rest.endsWith(SOCKS5_AUTH_REQUIRED_SUFFIX)) return null
    return parseLoopbackSocksAddress(rest.removeSuffix(SOCKS5_AUTH_REQUIRED_SUFFIX))
}
