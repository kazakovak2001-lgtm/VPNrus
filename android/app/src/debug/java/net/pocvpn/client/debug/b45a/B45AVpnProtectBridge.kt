package net.pocvpn.client.debug.b45a

import java.io.File

/**
 * B45A - SPIKE ONLY. Wraps whatever real Android mechanism actually protects
 * a socket fd from being recursively captured by the VPN interface -
 * `VpnService.protect(fd)` and/or `ConnectivityManager.Network.bindSocket(fd)`.
 * Abstracted so [B45AVpnProtectBridge] implementations are testable against
 * a fake without a real `VpnService` instance.
 */
fun interface B45AVpnProtector {
    /** Must return the REAL result - never fabricate success (Phase 7's own explicit requirement). */
    fun protect(fd: Int): Boolean
}

/** One handled protect request, reported for typed status/testing - never fed into B29 production diagnostics. */
data class B45AProtectRequestOutcome(val succeeded: Boolean, val reason: String? = null)

/**
 * B45A - SPIKE ONLY, NOT PRODUCTION CONNECTION AUTHORITY.
 *
 * Implements the exact upstream `outbound_vpn_protect_path` protocol, read
 * directly from the pinned v1.25.0 source
 * (`crates/shadowsocks/src/net/sys/unix/linux/mod.rs::send_vpn_protect_uds`,
 * `crates/shadowsocks-service/src/config.rs::outbound_vpn_protect_path`,
 * `src/service/local.rs`'s `--vpn` flag) - see
 * docs/B45A_SHADOWSOCKS_RUST_SPIKE.md's own protocol table for the full
 * citation. Android is the LISTENER/SERVER in this protocol - the OPPOSITE
 * role from [B45ATunFdBridge] - because `sslocal` itself CONNECTS to this
 * path fresh, once per outbound socket it wants protected:
 *
 * 1. `sslocal` connects to the Unix domain socket at [socketPath].
 * 2. It sends exactly 1 byte (`[1]`, upstream's own "dummy" payload - the
 *    byte's VALUE is not otherwise inspected by us; only its presence,
 *    alongside the ancillary fd, matters) plus 1 file descriptor via
 *    `SCM_RIGHTS` ancillary data (`stream.send_with_fd(&dummy, &fds)`).
 * 3. We call [protector] on the received fd.
 * 4. We write back exactly 1 byte: `0xFF` means failure (this is the ONLY
 *    value `sslocal` itself checks for - `response[0] == 0xFF` -> treated as
 *    `protect() failed`; any other single byte is treated as success).
 *    `0x00` is used here for success, matching `shadowsocks-android`'s own
 *    established convention (not itself required by this pinned `sslocal`
 *    version, but safe and unambiguous).
 * 5. `sslocal` enforces its OWN 3-second timeout on the whole RPC
 *    (connect+send+response) - if we do not respond in time, `sslocal`
 *    treats it as a protect() timeout and fails that one outbound
 *    connection attempt. This bridge does not itself impose a shorter
 *    timeout, since `sslocal`'s own timeout is already the binding
 *    constraint.
 *
 * This interface's real Android implementation (binding a
 * `android.net.LocalServerSocket`, accepting connections, reading ancillary
 * fds) requires a real Android runtime and has NOT been exercised end to
 * end in this session - see docs/B45A_SHADOWSOCKS_RUST_SPIKE.md.
 */
interface B45AVpnProtectBridge {
    /**
     * Binds [socketPath] and begins accepting connections in the background.
     * Must be called BEFORE `sslocal` is spawned with `--vpn` and a working
     * directory that resolves to [socketPath] (see
     * `src/service/local.rs`'s hardcoded `"protect_path"` relative-path
     * convention - this bridge does not choose the path, the caller must
     * derive it from `sslocal`'s own working directory).
     */
    fun start(socketPath: File, protector: B45AVpnProtector)

    /** Stops accepting new connections, closes the listener, and unlinks [socketPath] from the filesystem (Phase 6/8's own cleanup requirement). */
    fun stop()

    val state: B45AProtectBridgeState
    val requestCount: Int
    val failureCount: Int
}
