package net.pocvpn.client.debug.b45a

import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.io.File

/**
 * A clearly fake, non-production test credential (Phase 9) - never a real
 * secret, never connects to any real server in this phase.
 *
 * **Format correction (round 3 physical test, see
 * docs/B45A_SHADOWSOCKS_RUST_SPIKE.md Section 27):** an earlier plain-string
 * fake value made real `sslocal` panic immediately on startup
 * (`failed to create ServerConfig, error: invalid key encoding for
 * 2022-blake3-aes-256-gcm, Invalid symbol 45, offset 4`) - AEAD-2022 methods
 * take the key as base64-encoded RAW KEY BYTES of the cipher's exact length
 * (32 bytes for `aes-256-gcm`), never a password string (unlike legacy AEAD
 * methods, which derive a key from an arbitrary password via a KDF). This
 * value is `base64(b"B45A-SPIKE-FAKE-TEST-KEY-NOTREAL")` (32 fixed,
 * human-readable ASCII bytes, not CSPRNG output) - correct FORMAT for
 * `2022-blake3-aes-256-gcm`, while remaining exactly as fake/non-secret as
 * the string it replaces.
 *
 * **Verified against the pinned shadowsocks-rust v1.25.0 source directly**
 * (round 4, see docs/B45A_SHADOWSOCKS_RUST_SPIKE.md Section 28.1), not
 * merely "looks right": `crates/shadowsocks/src/config.rs`'s
 * `make_derived_key()` decodes an AEAD-2022 password with
 * `AEAD2022_PASSWORD_BASE64_ENGINE` - `base64::alphabet::STANDARD` with
 * `DecodePaddingMode::Indifferent` (padded or unpadded both accepted) - and
 * requires the decoded length to equal `CipherKind::key_len()`, which for
 * `AEAD2022_BLAKE3_AES_256_GCM` is `Aes256Gcm::key_size()` = 32 (the
 * standard AES-256 key size, via `KeySizeUser::KeySize` in the `aes-gcm`
 * crate). `internal` (not `private`) specifically so
 * [B45ARuntimeTest]/a dedicated key-format test can assert this without
 * duplicating the literal.
 */
internal const val SPIKE_FAKE_PSK = "QjQ1QS1TUElLRS1GQUtFLVRFU1QtS0VZLU5PVFJFQUw="
private const val PROTECT_SOCKET_FILENAME = "protect_path"
private const val TUN_FD_SOCKET_FILENAME = "tun_fd_path"
private const val DEFAULT_TUN_FD_HANDOFF_TIMEOUT_MILLIS = 5_000L
private const val DEFAULT_GRACEFUL_STOP_TIMEOUT_MILLIS = 3_000L
private const val DEFAULT_FORCE_STOP_WAIT_MILLIS = 1_000L

/**
 * B45A - SPIKE ONLY, NOT PRODUCTION CONNECTION AUTHORITY.
 *
 * Owns the pinned `sslocal` [B45ASpawnedProcess], the [B45AVpnProtectBridge]
 * listener, and the [B45ATunFdBridge] handoff - the ONLY class that touches
 * all three, so single-instance enforcement and shutdown ordering live in
 * exactly one place (Phase 8's own requirement). Every I/O dependency is
 * injected so this class's state-machine behavior is unit-testable against
 * fakes without spawning a real process or touching real Android sockets -
 * see `B45ARuntimeTest` in the `test` source set.
 *
 * This is not, and must never become, a second production connection/
 * reconnect/diagnostics authority (architecture principle 11). It is never
 * referenced from [net.pocvpn.client.vpn.VpnController],
 * `TransportOrchestrator`, or any production Smart Connect class - only from
 * the debug-only [B45ASpikeVpnService]/[net.pocvpn.client.debug.b45a] UI.
 */
class B45ARuntime(
    private val launcher: B45AProcessLauncher,
    private val tunFdBridge: B45ATunFdBridge,
    private val protectBridge: B45AVpnProtectBridge,
    private val protector: B45AVpnProtector,
    private val scope: CoroutineScope,
    private val tunFdHandoffTimeoutMillis: Long = DEFAULT_TUN_FD_HANDOFF_TIMEOUT_MILLIS,
    private val gracefulStopTimeoutMillis: Long = DEFAULT_GRACEFUL_STOP_TIMEOUT_MILLIS,
    // Injectable so tests can substitute a deterministic test dispatcher -
    // production always uses the real Dispatchers.IO, since the tun-fd
    // handoff performs real blocking socket I/O.
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
) {
    private val _status = MutableStateFlow(B45ASpikeStatus.IDLE)
    val status: StateFlow<B45ASpikeStatus> = _status.asStateFlow()

    private var process: B45ASpawnedProcess? = null
    private var workingDir: File? = null

    /**
     * [binaryPath] must already exist (Section "Binary packaging" -
     * `applicationInfo.nativeLibraryDir + "/libsslocal_spike.so"` in the real
     * caller). [tunFd] is the raw fd of an ALREADY-ESTABLISHED
     * `VpnService.Builder.establish()` result - this class never establishes
     * the TUN itself (that stays [B45ASpikeVpnService]'s job, matching the
     * "one VpnService owner" pattern [NovaXrayVpnService] already uses).
     * [tunInterfaceAddressCidr] MUST be the exact same address/prefix the
     * caller already configured on the real Android TUN via
     * `VpnService.Builder.addAddress()` - see [B45ATunNetworkConfig] (round
     * 4/5's own root-cause finding: the pinned `tun` crate's Android backend
     * cannot derive this from the received fd itself; it must be told
     * explicitly via `--tun-interface-address`, or `Tun::run()`'s own
     * `device.address()`/`netmask()` calls fail with `NotImplemented`).
     *
     * Returns false immediately (Phase 8/13.B - never a double-start) if a
     * runtime is already STARTING/RUNNING/STOPPING.
     */
    fun start(binaryPath: String, tunFd: Int, workingDir: File, tunInterfaceAddressCidr: String): Boolean {
        val current = _status.value
        if (!B45ASpikeTransitions.canStart(current)) {
            return false
        }
        this.workingDir = workingDir
        _status.value = B45ASpikeTransitions.starting()

        if (!File(binaryPath).exists()) {
            _status.value = B45ASpikeTransitions.failed(_status.value, B45ASpikeError.BinaryMissing(binaryPath))
            return false
        }

        // Phase 1 (round 6) - validate the active data-plane target's key
        // BEFORE touching the protect bridge/spawning sslocal, never after:
        // base64-decodable AND exactly 32 bytes, matching AEAD-2022's real
        // requirement (see B45ADataPlaneConfig's own doc comment for the
        // exact source citation). Fails closed with a typed error rather
        // than letting a malformed key reach sslocal's own CLI and panic.
        val dataPlaneConfig = when (val resolution = B45ADataPlaneConfig.resolve()) {
            is B45ADataPlaneConfig.Result.Invalid -> {
                _status.value = B45ASpikeTransitions.failed(
                    _status.value,
                    B45ASpikeError.InvalidTestCredential(resolution.reason),
                )
                return false
            }
            is B45ADataPlaneConfig.Result.Valid -> resolution
        }

        workingDir.mkdirs()
        val protectSocketPath = File(workingDir, PROTECT_SOCKET_FILENAME)
        val tunSocketPath = File(workingDir, TUN_FD_SOCKET_FILENAME)

        // Phase 6: the protect listener MUST be bound before sslocal starts -
        // `--vpn` makes sslocal connect to it fresh per outbound socket, and
        // a connect against a not-yet-bound path would simply fail.
        try {
            protectBridge.start(protectSocketPath, protector)
        } catch (t: Throwable) {
            _status.value = B45ASpikeTransitions.failed(
                _status.value,
                B45ASpikeError.ProtectListenerFailed(t.message ?: "unknown"),
            )
            return false
        }
        _status.value = B45ASpikeTransitions.withProtectBridgeState(_status.value, protectBridge.state)

        val args = listOf(
            "--protocol", "tun",
            "-s", dataPlaneConfig.serverAddr,
            "-m", dataPlaneConfig.method,
            "-k", dataPlaneConfig.key,
            "--tun-device-fd-from-path", tunSocketPath.absolutePath,
            "--tun-interface-address", tunInterfaceAddressCidr,
            "--vpn",
            // Section 34's own root-cause finding: local-tun's Mode defaults
            // to TcpOnly for every ProtocolType except Dns (LocalConfig::new,
            // pinned commit's own crates/shadowsocks-service/src/config.rs),
            // so every UDP packet read off the TUN was silently discarded
            // before any Shadowsocks UDP encoding ever ran
            // (local/tun/mod.rs's own `if !self.mode.enable_udp() { ...;
            // return Ok(()); }` gate). `-U` is the exact, real sslocal CLI
            // flag (src/service/local.rs's own `TCP_AND_UDP` arg) that sets
            // `Mode::TcpAndUdp` - both TCP and UDP stay enabled, not a
            // UDP-only swap.
            "-U",
        )

        val spawned = try {
            launcher.launch(binaryPath, args, workingDir)
        } catch (t: Throwable) {
            protectBridge.stop()
            _status.value = B45ASpikeTransitions.failed(_status.value, B45ASpikeError.SpawnFailed(t.message ?: "unknown"))
            return false
        }
        process = spawned
        spawned.onExit { exitCode -> onProcessExitedUnexpectedly(exitCode) }

        _status.value = B45ASpikeTransitions.running(_status.value, spawned.pid ?: -1)

        scope.launch(ioDispatcher) {
            val bridgeState = tunFdBridge.handOff(tunFd, tunSocketPath, tunFdHandoffTimeoutMillis)
            _status.value = B45ASpikeTransitions.withTunFdBridgeState(_status.value, bridgeState)
            if (bridgeState == B45ATunFdBridgeState.FAILED && _status.value.phase == B45ARuntimePhase.RUNNING) {
                _status.value = B45ASpikeTransitions.failed(
                    _status.value,
                    B45ASpikeError.TunFdHandoffTimedOut(tunFdHandoffTimeoutMillis),
                )
            }
        }

        return true
    }

    /**
     * Round 6 (data-plane validation) - a genuine, physically-found
     * observability gap: [RealB45AVpnProtectBridge] tracks its own
     * `state`/`requestCount`/`failureCount` on real fields, but nothing
     * previously re-read them after the one-time snapshot taken right
     * after `protectBridge.start()` in [start] - a REAL protect request
     * happening while RUNNING would silently never reach the UI. A no-op
     * (deliberately NOT an unconditional background loop launched inside
     * [start] - that broke `runTest`'s completion invariant for every test
     * that doesn't itself call [stop], since a loop bound only to "while
     * RUNNING" never naturally completes) when not RUNNING, so callers can
     * poll this safely/idempotently without needing to track runtime
     * state themselves. [B45ASpikeVpnService] is the one, Android-only,
     * not-unit-tested caller (see its own status-collection coroutine) -
     * pure read-side observability, never touches
     * [RealB45AVpnProtectBridge]'s own accept-loop/protocol code.
     */
    fun refreshProtectStatus() {
        val current = _status.value
        if (current.phase != B45ARuntimePhase.RUNNING) return
        _status.value = current.copy(
            protectBridgeState = protectBridge.state,
            protectRequestCount = protectBridge.requestCount,
            protectFailureCount = protectBridge.failureCount,
        )
    }

    /** Idempotent (Phase 13.C) - stopping an already-STOPPED runtime is a no-op. */
    fun stop() {
        val current = _status.value
        if (!B45ASpikeTransitions.canStop(current)) {
            return
        }
        _status.value = B45ASpikeTransitions.stopping(current)

        val proc = process
        if (proc != null && proc.isAlive()) {
            proc.requestStop()
            val exited = proc.waitForExit(gracefulStopTimeoutMillis)
            if (exited == null) {
                // Bounded grace period elapsed - force-kill as final cleanup only.
                proc.forceStop()
                proc.waitForExit(DEFAULT_FORCE_STOP_WAIT_MILLIS)
            }
        }

        protectBridge.stop()
        process = null
        workingDir = null
        _status.value = B45ASpikeTransitions.stopped()
    }

    /** A process that exits on its own (crash, upstream error) always clears ownership rather than staying falsely RUNNING. */
    private fun onProcessExitedUnexpectedly(exitCode: Int) {
        val phase = _status.value.phase
        if (phase == B45ARuntimePhase.RUNNING || phase == B45ARuntimePhase.STARTING) {
            protectBridge.stop()
            process = null
            _status.value = B45ASpikeTransitions.processExitedUnexpectedly(_status.value, exitCode)
        }
        // If phase is already STOPPING/STOPPED, this exit was expected - stop() owns the transition.
    }
}
