package net.pocvpn.client.debug.b45a

import java.io.File

/**
 * B45A - SPIKE ONLY, NOT PRODUCTION CONNECTION AUTHORITY.
 *
 * Implements the exact upstream `tun_device_fd_from_path` protocol, read
 * directly from the pinned v1.25.0 source
 * (`crates/shadowsocks-service/src/local/mod.rs`'s `ProtocolType::Tun`
 * branch) - see docs/B45A_SHADOWSOCKS_RUST_SPIKE.md's own protocol table.
 * Android is the CLIENT/CONNECTOR in this protocol - the OPPOSITE role from
 * [B45AVpnProtectBridge]:
 *
 * 1. `sslocal` removes any stale file at the configured path, binds a Unix
 *    domain LISTENER there, and loops `accept()`.
 * 2. We CONNECT to that same path (retrying with a bounded wait, since
 *    `sslocal` binds asynchronously sometime after it starts - there is no
 *    signal other than the socket becoming connectable).
 * 3. We send an arbitrary non-empty payload (upstream only checks that
 *    `fd_size != 0`; the payload bytes themselves are not otherwise
 *    inspected) plus the TUN file descriptor via `SCM_RIGHTS` ancillary
 *    data.
 * 4. `sslocal` reads it, logs the fd, and proceeds to build its TUN device -
 *    it sends back NO response/ack byte on this path (unlike the protect
 *    protocol) - so a successful handoff is inferred from the send
 *    succeeding, never from a reply we don't expect.
 *
 * The real Android implementation requires an actual Android runtime and has
 * NOT been exercised end to end in this session.
 */
interface B45ATunFdBridge {
    /**
     * Attempts the handoff, retrying the connect step until [timeoutMillis]
     * elapses. Returns the final [B45ATunFdBridgeState] - never throws for an
     * ordinary connect-refused/timeout outcome (those are reported as
     * [B45ATunFdBridgeState.FAILED], with detail available via the returned
     * [B45ASpikeError] when applicable).
     */
    fun handOff(tunFd: Int, socketPath: File, timeoutMillis: Long): B45ATunFdBridgeState
}
