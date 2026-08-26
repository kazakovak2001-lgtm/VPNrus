package net.pocvpn.client.vpn.config

/** Structural validation only - a WireGuard/AmneziaWG key is 32 raw bytes, base64-encoded. */
object WgKeyFormat {
    private val PATTERN = Regex("^[A-Za-z0-9+/]{43}=$")

    fun isValid(key: String): Boolean = PATTERN.matches(key)
}
