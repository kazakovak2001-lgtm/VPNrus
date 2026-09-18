# B45B-3P — Shadowsocks 2022 Production Adapter: Physical Validation

## 1. Scope

This slice physically validates the **production** Shadowsocks 2022 adapter
shell (B45B-3) on a real Android device, using a reproducible locally-built
native binary in the `debug` build variant only. It is a validation pass, not
a feature slice: no production selection wiring changed.

## 2. Production classes tested

Real device execution exercised, unmodified except for the fixes recorded
below:

- `net.pocvpn.client.vpn.shadowsocks.ShadowsocksTransport`
- `net.pocvpn.client.vpn.shadowsocks.ShadowsocksVpnService`
- `net.pocvpn.client.vpn.shadowsocks.ShadowsocksRuntime`
- `net.pocvpn.client.vpn.shadowsocks.RealShadowsocksTunFdBridge`
- `net.pocvpn.client.vpn.shadowsocks.RealShadowsocksVpnProtectBridge`
- `net.pocvpn.client.vpn.shadowsocks.ShadowsocksNativeBinaryResolver`
- `net.pocvpn.client.identity.SecureShadowsocks2022CredentialRepository` (B45B-2, reused unmodified)

None of B45A's debug-only spike classes (`B45ARuntime`, `B45ASpikeVpnService`,
etc.) were used as the implementation under test.

## 3. Debug-carrier limitation

The production binary was packaged **debug-build-only**
(`android/app/src/debug/jniLibs/arm64-v8a/libsslocal.so`, gitignored, not
committed - see `.gitignore`). Release native packaging is a separate,
unresolved decision (see §18) - this validation proves the adapter *code*,
not a shippable release artifact.

Invocation used a debug-only, isolated validation harness
(`net.pocvpn.client.debug.shadowsocksvalidation.ShadowsocksAdapterValidationActivity`)
that constructs `ShadowsocksTransport` directly - never through
`TransportRegistry`/`TransportOrchestrator`/Smart Connect. The harness takes
its test endpoint/credential from an external staging file at runtime (never
hardcoded in source) and stores it into the real, production, encrypted
`Shadowsocks2022CredentialRepository` before deleting the staging file.

## 4. Binary provenance

- Upstream: `shadowsocks/shadowsocks-rust`
- Tag: `v1.25.0`
- Commit: `ab388c7466d21f979430e33cc9ef10e22fb05955`
- Build command: `cargo ndk -t arm64-v8a -P 26 -- build --release --bin sslocal --no-default-features --features "local,local-tun,aead-cipher-2022"`
- Target: `aarch64-linux-android` (arm64-v8a), Android API 26 (matches `minSdk`)
- License: MIT (upstream `LICENSE`)
- Dynamic dependencies: `libc.so`, `libdl.so` only (verified via `llvm-readelf -d`)

## 5. Binary SHA-256

`333eafee26e5e7fdad91892bdb7400ad397e7d7f99d42f26b37c8ca92bc2c1f6`

(Byte-identical to the pre-existing debug-only `libsslocal_spike.so` - same
reproducible build from the same pinned commit, independently re-verified
this round rather than assumed.)

## 6. FD ownership bug discovered

The first physical run crashed the whole app process with `SIGABRT`
(`fdsan: failed to exchange ownership of file descriptor ... was expected to
be unowned`) inside `RealShadowsocksTunFdBridge.handOff`, reproduced twice
with an identical backtrace.

## 7. Final direct-borrow FileDescriptor design

`ShadowsocksTunFdBridge.handOff` now takes a plain `java.io.FileDescriptor`
(never an `Int`, never a second `ParcelFileDescriptor`) - the caller's
`ParcelFileDescriptor.fileDescriptor` getter (a side-effect-free borrow) is
passed straight to `LocalSocket.setFileDescriptorsForSend`, which performs a
kernel `sendmsg()`/`SCM_RIGHTS` duplication into the receiving process. No
dup, no adopt, no close - the original TUN `ParcelFileDescriptor` remains the
sole owner throughout and after the call.

## 8. Why `ParcelFileDescriptor.adoptFd` was invalid

`adoptFd()` performs an fdsan ownership-tag *exchange* that requires the raw
fd to be currently untagged. The fd handed to it was already tagged/owned by
`ShadowsocksVpnService`'s own TUN `ParcelFileDescriptor` from
`Builder.establish()` - attempting a second tag-claim on an already-owned fd
aborts the process. Verified directly against the AOSP
`LocalSocketImpl.java` source (not inferred from method names): the
`setFileDescriptorsForSend` path never touches `ParcelFileDescriptor`/fdsan
at all, so the borrow-only design has no such hazard.

## 9. Abnormal-crash stale-state sweep

A process-level `SIGABRT`/`SIGKILL` bypasses every Kotlin `finally` block, so
an abnormal death can leave the plaintext `runtime_config.json` or a stale
Unix-domain-socket path behind (physically observed after the crash in §6).
`ShadowsocksRuntime.start()` now sweeps its own known ephemeral filenames
(and only those - never the encrypted credential repository, a different
directory entirely) before writing any new plaintext config, failing closed
if a stale file cannot actually be removed.

## 10. Normal-stop `tun_fd_path` cleanup bug and fix

A normal `Stop()` was physically found to also leave `tun_fd_path` behind -
that socket is bound/listened-on by `sslocal` itself (Android is only the
client in that protocol), and `sslocal` does not unlink its own bound socket
on a plain `SIGTERM`. Fixed by having `ShadowsocksRuntime` confirm the
spawned process is terminated (`stopSpawnedProcessIfAny`) before unlinking
the known `tun_fd_path` (`cleanupEphemeralFiles`), applied consistently to
both `stop()` and the failure-teardown path (which also previously left an
orphaned running process on a handoff-timeout failure - fixed alongside).
Re-verified physically: a normal Stop now leaves the working directory
completely empty.

## 11. TCP proof

Real browser traffic through the production adapter to
`https://ipv4.icanhazip.com` returned the expected Frankfurt exit IP, run
twice (before and after a full disconnect/reconnect cycle), corroborated
server-side by real established TCP connections on the Shadowsocks port
arriving from the test device.

## 12. UDP 3/3 proof

Three independent UDP round trips through the production adapter to a
temporary, test-only UDP echo fixture, each with a unique payload -
**3 of 3 exact byte-for-byte matches**.

## 13. Server-side relay evidence

A packet capture on the server during one round trip showed the complete
relay chain: an encrypted UDP packet arriving at the Shadowsocks port from
the device, a decrypted plaintext UDP packet (exact length matching the
original payload) forwarded locally to the echo fixture, the echo reply,
and the re-encrypted packet returned to the device - confirming genuine
decrypt-and-relay through the real server process, not a passthrough or
coincidence.

## 14. 120s stability

Held the connection for >120 seconds: same `sslocal` PID throughout, no
crash, no respawn, adapter remained Connected.

## 15. Restart/new PID proof

After a full Stop, restarting produced a genuinely new `sslocal` PID (not a
reused/stale one) and reached Connected again, with a second successful TCP
proof.

## 16. Final cleanup proof

Both the first and second full Stop cycles left the transport's working
directory completely empty (no plaintext config, no protect socket, no
TUN-fd socket), no `sslocal` process, no bound production service, no active
VPN registration.

## 17. Approximate RSS evidence

`sslocal`'s resident set size was measured at roughly 22 MB during a stable
connected hold. This is a single sample from one test session and should not
be over-interpreted as a general production memory budget.

## 18. Release packaging still unresolved

Extending the existing debug-only AGP `useLegacyPackaging` mechanism to
`release` was evaluated and explicitly **not applied** this round: it was
found to recompress every native library the app already ships for release
(not only the new binary), a whole-variant behavioral change out of scope for
an isolated validation slice. Release-safe native packaging for
`SHADOWSOCKS_2022` remains a separate, explicit future decision.

## 19. TransportRegistry still NOT_IMPLEMENTED

`TransportKind.SHADOWSOCKS_2022` remains `NOT_IMPLEMENTED` in
`TransportRegistry`, with no live factory. Unchanged by this slice.

## 20. Smart Connect not wired

`SmartConnectDecisionEngine` cannot select `SHADOWSOCKS_2022`. Unchanged by
this slice.

## 21. TransportOrchestrator not wired

No production registration exists. Unchanged by this slice.

## 22. Q7 unverified

Seamless network handover (Wi-Fi/cellular) remains unverified;
`ShadowsocksTransport.underlyingNetworkRecovery` stays `RESTART_SESSION`,
never claimed as `IN_PLACE`.

## 23. Russia / hard-whitelist unverified

No censorship-resistance or restrictive-network testing was performed or is
claimed by this slice.
