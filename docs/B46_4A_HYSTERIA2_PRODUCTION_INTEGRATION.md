# B46-4A: Hysteria2 Production Integration - Wiring and Provisioning Foundation

## Status

**HYSTERIA2 PRODUCTION INTEGRATION CODE READY / DEPLOYMENT AND NORMAL-UI PHYSICAL VALIDATION PENDING**

This slice adds the production Android and gateway *code* required for Hysteria2 to become a real Nova transport. It does **not** deploy a production Hysteria2 server, open any firewall/Security Group rule, sign or deploy a production manifest binding, or enable real users. Those actions belong to a separate, explicit **B46-4P** deployment gate.

## Research evidence inherited

| Slice | PR | Result | What it proves |
|---|---|---|---|
| B46-3A | #99 | **FAILED** physically | Same-process, multi-Go-runtime coexistence (Xray + tun2socks + Hysteria in one process) does not work reliably. This is *why* B46-4A's architecture is process-isolated. |
| B46-3B | #109 | **PASSED** physically | Process-isolated tun2socks child (separate PID, its own Go/gVisor runtime), SCM_RIGHTS TUN-fd handoff, `PR_SET_PDEATHSIG` parent-death propagation, deterministic lifecycle (repeated-start rejection, graceful/force stop, unexpected-death detection). |
| B46-3C | #110 | **PASSED** physically (OPPO CPH2173) | The *complete* process-isolated Hysteria2 data plane: app/VpnService process, tun2socks child, minimal Hysteria2 child, each a separate OS process; real `VpnService` TUN; real `protect(fd)`; real QUIC; DNS, TCP, direct-IP TCP, UDP, expected exit IP, server-side packet correlation; two clean reconnect cycles; tun2socks death cleanup; Hysteria death cleanup; ~130s screen-off smoke; clean server/device teardown. |

**Neither #109 nor #110 is production code and neither was merged to obtain this implementation.** B46-4A selectively ports the *hardened architecture* those two PRs physically proved - the process-isolated child runtimes, the SCM_RIGHTS control channel, the lifecycle-hardening state machine (repeated-start rejection, stop idempotency, unexpected-death claiming) - into new production-namespaced classes under `android/app/src/main/java/net/pocvpn/client/vpn/hysteria/`, with one load-bearing correction (see "Debug-spike secret correction" below). It does **not** carry across: the debug-only `Tun2SocksHysteriaDataPlaneSpikeVpnService` itself, B46-specific spike naming/config-file names, the `EXTRA_AUTH`/`EXTRA_INSECURE` Intent extras, or any test-server host/port/credential.

B46-3A/#99 and B46-3B/#109 and B46-3C/#110 are **untouched** by this slice - used strictly as evidence/reference.

## Production architecture

### Three process boundaries (preserved from B46-3A's own finding)

```
┌─────────────────────────────┐   SCM_RIGHTS (dup TUN fd)   ┌──────────────────────┐
│ App / VpnService process    │ ───────────────────────────▶│ tun2socks child      │
│  - Kotlin/Android           │                              │  - separate PID      │
│  - Xray Go runtime MAY live │   local SOCKS5 (127.0.0.1)   │  - tun2socks/gVisor  │
│    here (unrelated to       │◀────────────────────────────│    Go runtime        │
│    Hysteria2)               │                              └──────────────────────┘
│  - NO tun2socks runtime     │                                         │
│  - NO Hysteria runtime      │        local SOCKS5 listener            │
└──────────────┬──────────────┘                                         │
               │ protect(fd) via                                        ▼
               │ Unix-domain SCM_RIGHTS                     ┌──────────────────────┐
               │ (RealShadowsocksVpnProtectBridge,           │ Hysteria2 child      │
               │  reused, not reimplemented)                 │  - separate PID      │
               └─────────────────────────────────────────────│  - minimal Hysteria2 │
                                                               │    Go runtime, QUIC │
                                                               └──────────────────────┘
```

No process ever hosts two independent Go runtimes. Startup order (unchanged from B46-3C): the Hysteria2 child starts **first** (it must report `SOCKS5_LISTENING` and, ideally, a successful QUIC connect before tun2socks is told to proxy through it); `Hysteria2VpnService` duplicates its own TUN fd and hands it to the tun2socks child over the SCM_RIGHTS control channel. Either child dying unexpectedly tears down the **whole** session (both children, the TUN, all per-session artifacts) - never a half-alive state.

### Files

| File | Ported from | What changed |
|---|---|---|
| `vpn/hysteria/Hysteria2Tun2SocksChildRuntime.kt` | B46-3B `Tun2SocksChildRuntime.kt` | Renamed only - no secret-handling logic, no change needed. |
| `vpn/hysteria/Hysteria2Tun2SocksChildProcessLauncher.kt` | B46-3B `Tun2SocksChildProcessLauncher.kt` | Renamed, packaging doc updated (`src/main/jniLibs` not `src/debug/jniLibs`). |
| `vpn/hysteria/Hysteria2Tun2SocksChildControlChannel.kt` | B46-3B `Tun2SocksChildControlChannel.kt` | Renamed only. |
| `vpn/hysteria/Hysteria2ChildProcessLauncher.kt` | B46-3C `HysteriaChildProcessLauncher.kt` | Renamed, packaging doc updated. |
| `vpn/hysteria/Hysteria2ChildRuntime.kt` | B46-3C `HysteriaChildRuntime.kt` | Renamed; **added a hard production gate**: `start()` refuses to launch the child at all when `config.insecure == true` (see "TLS policy" below). |
| `vpn/hysteria/Hysteria2AdapterEligibility.kt` | New (mirrors `ShadowsocksAdapterEligibility.kt`) | ABI + both-binaries eligibility gate. |
| `vpn/hysteria/Hysteria2Transport.kt` | New (mirrors `ShadowsocksTransport.kt`) | Production `VpnTransport` adapter; sends **only public facts** through its start `Intent`. |
| `vpn/hysteria/Hysteria2VpnService.kt` | New (composes the ported runtimes; mirrors `ShadowsocksVpnService.kt`'s service shape and `Tun2SocksHysteriaDataPlaneSpikeVpnService.kt`'s child-orchestration order) | Loads the secret credential from `Hysteria2CredentialRepository` itself; never accepts a secret via Intent. |

## Debug-spike secret correction (the load-bearing fix this slice makes)

B46-3C's debug spike (`Tun2SocksHysteriaDataPlaneSpikeVpnService`) accepted `EXTRA_AUTH` and `EXTRA_INSECURE` as Intent extras, read directly by its `onStartCommand`, before its own harness wrote/used the runtime config - acceptable for a disposable research spike against a disposable test server, **not** acceptable in production.

Production `Hysteria2Transport` sends only: `sessionId`, `endpointId`, `host`, `port`, `sni`, `obfuscationMode` (a public identifier, `"NONE"`/`"SALAMANDER"` - never the Salamander password), `routingMode`. There is **no** `EXTRA_AUTH`, **no** `EXTRA_OBFS_PASSWORD`, no secret Bundle/Intent extra of any kind. `Hysteria2VpnService` independently loads the endpoint-scoped encrypted credential from `Hysteria2CredentialRepository` (Android Keystore AES-256-GCM, its own dedicated key alias) at connect() time.

## Public/secret config separation

Follows the existing Shadowsocks2022 architecture exactly (`SignedTransportProfile.Shadowsocks2022` / `Shadowsocks2022Credential`):

| | Public (signed manifest) | Secret (device-local encrypted) |
|---|---|---|
| Type | `SignedTransportProfile.Hysteria2` → `Hysteria2Profile(sni, obfuscationMode)` | `Hysteria2Credential(endpointId, authSecret, obfuscationSecret?)` |
| Carries | `EndpointTransportBinding.host`/`.port` (already existing) + SNI + public obfuscation-mode identifier | The Hysteria2 wire `auth` secret; the Salamander obfuscation password, if `obfuscationMode == "SALAMANDER"` |
| Where it lives | The already-signed `EndpointManifest` (canonicalized, ordinal-stable - see below) | `Hysteria2CredentialRepository`, AES-256-GCM under Android Keystore alias `net.pocvpn.client.identity.hysteria2.aesgcm.v1` (dedicated - never Xray/AWG/Shadowsocks aliases), `noBackupFilesDir`, atomic-replace file store |

`insecure=true` is never representable in the signed profile or the credential - it is a hardcoded `false` in `Hysteria2VpnService`, additionally enforced inside `Hysteria2ChildRuntime.start()` itself (defense in depth: even a future caller that forgets the service-level constant cannot launch an insecure child).

### Signed profile metadata schema (`hysteria2Profile`, version 1)

```json
{"version": 1, "sni": "hy2.example.com", "obfuscationMode": "NONE"}
```

Closed schema (`Hysteria2ProfileMetadata.kt`, mirrors `Shadowsocks2022ProfileMetadata.kt`): rejects unknown fields (exact key-set match), an unsupported `version`, oversized metadata (>512 bytes), a blank/invalid SNI (DNS-name-shaped charset only), and an unsupported `obfuscationMode` (closed set: `NONE`, `SALAMANDER`). An endpoint with no `hysteria2Profile` key reads as `SignedTransportProfile.Legacy` (never silently mapped into a fabricated Hysteria2 profile) - so old manifests without Hysteria2 continue decoding **identically**, byte-for-byte, to how they decoded before this slice.

### Secret credential schema

`Hysteria2Credential(endpointId, authSecret: Hysteria2AuthSecret, obfuscationSecret: Hysteria2ObfuscationSecret?)`. Both secret wrappers are opaque classes with a hardcoded, permanently redacted `toString()` (`"Hysteria2AuthSecret(<redacted>)"` / `"Hysteria2ObfuscationSecret(<redacted>)"`) - the real value can never leak through a default `toString()`/log/crash-report call the way a bare `String` field would. `Hysteria2CredentialValidator` bounds both secrets (non-blank, ≤256 chars) before ever constructing a `Hysteria2Credential` - a tampered/corrupted decrypted payload fails the SAME validation fresh untrusted input would, never silently trusted because it came from local storage.

### Encrypted credential repository

`Hysteria2CredentialStore.kt` / `Hysteria2CredentialRepositoryFactory.kt` / `Hysteria2CredentialRepositoryResolver.kt` mirror `Shadowsocks2022CredentialRepository`'s exact shape and file/lock discipline:
- Endpoint-scoped file naming (`hysteria2_credential_<hash>.bin`) - endpoint A's credential can never collide with, or be silently read as, endpoint B's.
- `noBackupFilesDir` (excluded from Android Auto Backup - a restored ciphertext would be undecryptable anyway, the key is device-bound).
- `Files.move` with `ATOMIC_MOVE`+`REPLACE_EXISTING` - a failed rotation never destroys the old, still-usable credential; no delete-then-rename window.
- Android Keystore AES-256-GCM, **dedicated key alias** (`net.pocvpn.client.identity.hysteria2.aesgcm.v1`) - never reuses the Xray, AWG, or Shadowsocks2022 aliases, so this credential is independently rotatable/revocable.
- Wrong Keystore key (device/app-state change) → `Hysteria2CredentialGetResult.Corrupted`, never treated as `Absent`.
- Corrupted ciphertext → `Corrupted`, distinct from `Absent` (see `Hysteria2CredentialRepositoryTest`).
- No plaintext fallback anywhere in the read/write path.

## Pinned-upstream auth mechanism (verified, not assumed)

Before designing server auth, this slice inspected the **exact** pinned Hysteria2 server source at commit `e1366b173ccf5706e1e4630fe8aa654a4b574085` (`apernet/hysteria`, the same pin B46-2P/B46-2C/B46-3C physically validated against), fetched directly from GitHub at that commit:

- **`app/cmd/server.go`, `fillAuthenticator`** (lines ~1440-1500 at this commit): the server's `auth.type` config field dispatches to exactly four backends - `password` (`extras/auth/password.go`, one global static string compared with `==`), `userpass` (`extras/auth/userpass.go`, a static `map[string]string` built once at process start from config), `http`/`https` (`extras/auth/http.go`, `HTTPAuthenticator`), `command`/`cmd` (`extras/auth/command.go`, shells out per attempt). **There is no `hysteria2` production `TransportKind` and no fifth auth backend at this pin** - nothing was invented from memory.
- **`extras/auth/http.go`** (fetched in full): `HTTPAuthenticator.Authenticate` POSTs `{"addr": "<net.Addr.String()>", "auth": "<presented secret>", "tx": <uint64>}` as JSON to the configured URL and expects `{"ok": <bool>, "id": <string>}` back (HTTP 200 required; any other status or unparseable body is treated as a failed auth). `NewHTTPAuthenticator(url, insecure)` builds its own `http.Client`, with `insecure` only controlling whether *this outbound* TLS connection to the auth URL validates certs.

### Why `http`, not `password`/`userpass`/`command`

| Backend | Per-device revocable? | Requires Hysteria server reload to add/revoke? | Raw secret at rest on this gateway? |
|---|---|---|---|
| `password` | No - one global secret for every user | N/A (there is no per-device state at all) | N/A |
| `userpass` | Yes, but only via a static in-config map | **Yes** - adding/revoking one device means restarting or re-templating+reloading the Hysteria server | Yes, in the Hysteria server's own plaintext config |
| `command` | Yes, in principle | No | Depends on the script; real per-connection process-spawn overhead and a much larger review surface |
| **`http`** (chosen) | **Yes**, live per-request | **No** - this gateway answers with current `activations.py` state on every attempt | **No** - see below |

`http` is the only backend that lets this gateway answer with **live** activation state (ACTIVE/revoked/expired) on every single connection attempt, with **zero** Hysteria server restart/reload needed to add or revoke one device - directly satisfying the task's "revoked/expired activation cannot silently mint valid new Hysteria access" and "existing activation expiration/revocation remains authoritative" requirements. It also means the raw secret **never has to sit in the Hysteria server's own config file** the way `password`/`userpass` require - see "server storage" below.

## Server auth architecture (design + code; not deployed)

```
Hysteria2 server (auth.type: http)
   │  POST http://127.0.0.1:<port>/internal/hysteria-auth   {"addr","auth","tx"}
   ▼
gateway/api/hysteria_auth_backend.py  (pure request/response adapter, no socket of its own)
   │  handle_auth_request(body, verify_fn)
   ▼
gateway/api/hysteria_provisioning.py: verify_hysteria_auth(secret, ...)
   │  1. linear scan of hysteria_store.json for a matching salted-SHA-256 hash
   │  2. on hash match, LIVE read of activations.json: ACTIVE? not expired? device CONFIRMED?
   ▼
{"ok": true, "id": "<8-hex digest prefix>:<8-hex device-key prefix>"}   (never the raw secret)
```

**Provisioning** (`POST /v1/hysteria-profile`, `gateway/api/hysteria_provisioning.provision_hysteria_identity`): reuses the **existing** activation/device-binding model (`gateway/api/activations.py`) exactly like `xray_provisioning.py` does for VLESS identities - same activation credential, same device public key, same `per_activation_lock` ordering, same eligibility outcomes (`NOT_ELIGIBLE_UNKNOWN`/`REVOKED`/`EXPIRED`/`DEVICE_NOT_BOUND`). **No new user activation/token system was created.** The activation credential authorizes this HTTP call only; it is never stored as, or reused as, the Hysteria2 wire `auth_secret` - a fresh, distinct, high-entropy secret (`secrets.token_hex(32)`, 256 bits) is minted server-side per (activation, device) pair.

**Storage**: unlike `xray_provisioning.py`'s VLESS UUID (a non-secret identifier, safe to store in plaintext), the Hysteria2 `auth_secret` **is** the wire credential. `gateway/api/hysteria_store.py` never persists the raw secret: it stores only `sha256(salt || secret)` plus its own random salt. The raw secret is generated once, handed to the client in the (TLS-protected) provisioning response, and never needed in raw form again - `verify_hysteria_auth` only ever needs to *compare* a presented secret's hash against the stored hash (`secrets.compare_digest`, constant-time). This is a genuine advantage over `password`/`userpass`, which require the Hysteria server's own config file to hold the raw secret.

**Concurrency/locking**: `hysteria_store.py` mirrors `xray_provisioning.py`'s own store/lock discipline byte-for-byte (mkstemp mode 0600, write+fsync, restore prior mode/ownership, `os.replace`, fsync the containing directory, `fcntl.flock`). The per-activation lock (`activations.per_activation_lock`, reused) is always the outermost lock; this module's own store lock is a separate, independent file, never held while acquiring an `activations.py` lock - the same fixed lock ordering `xray_provisioning.py` already documents, so the two stores can never deadlock against each other.

**No raw secret in logs**: `hysteria_auth_backend.handle_auth_request` never includes the presented secret in its response, in any exception message, or in anything a caller might reasonably log; `test_hysteria_auth_backend.py`'s `test_presented_secret_is_never_echoed_in_the_response` and the provisioning suite's log-safety-adjacent tests assert this directly.

**Not deployed**: `gateway/api/hysteria_provisioning.py`, `gateway/api/hysteria_store.py`, and `gateway/api/hysteria_auth_backend.py` exist as reviewable, tested code. No systemd unit, no firewall rule, no nginx route, and no live `/v1/hysteria-profile` dispatch registration in `gateway/api/handler.py` were added or started - see "remaining B46-4P work" below for exactly what deployment requires.

## Client provisioning API

`ProvisioningClient.fetchHysteria2Profile(publicKey, bearerToken, endpointHost)` → `POST /v1/hysteria-profile` with the SAME `{"public_key": ...}` body shape and `Authorization: Bearer <activation credential>` header every other profile-fetch endpoint uses; redirects remain disabled (`instanceFollowRedirects = false`, unchanged executor). `mapHysteria2ProfileResponse`/`parseHysteria2ProfileSuccessBody` are `internal` and unit-testable without a live connection; they validate `profile_version` (must be `1`), `server_address` (non-blank), `server_port` (1-65535), `auth_secret` (non-blank, ≤ max length), `sni` (non-blank), `obfuscation_mode` (closed set), the Salamander-secret/obfuscation-mode consistency, and `issued_at`/`expires_at` ordering. The raw response body is never logged.

`Hysteria2ProfileProvisioner.provision(endpointId, endpointBinding, publicKey, activationCredential)` (mirrors `IngressProfileProvisioner`'s "pinned-fact fails closed" discipline, since Hysteria2 - like an ingress - is endpoint-scoped, not one of the two fixed production gateways): cross-checks the response's own `server_address`/`server_port` against the caller's already-pinned, trusted `endpointBinding` and fails closed (`Mismatched`) on any disagreement - a compromised or misconfigured control plane cannot silently redirect this device's credential to a different host. Validates the response's own secret content through `Hysteria2CredentialValidator` before ever calling `repository.storeCredential`. No Smart Connect changes live inside this provisioner.

## Service/runtime lifecycle, process isolation, TUN/protect boundary

`Hysteria2VpnService` establishes the TUN itself (`10.206.49.1/24`, MTU 1400, `VpnDnsPolicy`'s canonical resolvers, `RoutingDecisionEngine.resolveIpv4Routes` for the full-tunnel `0.0.0.0/0` route - the SAME routing authority every other transport already uses, never a parallel decision), then:

1. Resolves ABI/binary eligibility (`Hysteria2AdapterEligibilityChecker` - arm64-v8a only, both `tun2socks-child` and `hysteria-child` binaries must resolve).
2. Loads the endpoint-scoped credential from `Hysteria2CredentialRepository` - absent/corrupted fails closed before any child is spawned.
3. Starts the Hysteria2 child first (`Hysteria2ChildRuntime.start`, `insecure = false` always), which itself starts the `protect(fd)` bridge over a reused SCM_RIGHTS Unix-domain-socket protocol (`RealShadowsocksVpnProtectBridge`, the *exact* already-physically-proven implementation - not reimplemented) and writes a per-session, mode-600, app-private `--config-file` (never secret argv flags) that is deleted on every stop/failure path.
4. Duplicates the TUN fd and hands it to the tun2socks child over its own SCM_RIGHTS control channel (`Hysteria2Tun2SocksChildRuntime`), which the child ACKs with its own PID.
5. Publishes `Hysteria2RuntimePhase.RUNNING` **only** after both of the above genuinely succeeded.

Either child's `onUnexpectedExit` tears down the *whole* session (both children, the TUN) and publishes `FAILED` with a typed, non-secret `Hysteria2RuntimeError` - `PR_SET_PDEATHSIG` parent-death propagation and the SCM_RIGHTS fd-ownership contract are inherited unchanged from the pinned native child binaries B46-3B/B46-3C already built and proved (a native-binary-packaging property, not Kotlin source in this repo - see "native binary packaging" below).

### Connected definition

`Hysteria2Transport`/`hysteria2TransportStateFor` never reports `Connected` merely because the TUN was established, a child process object exists, or a SOCKS listener exists. `RUNNING` requires: the Hysteria2 child's own `SOCKS5_LISTENING` readiness line **and** the tun2socks child's own successful SCM_RIGHTS-ack'd start. `hysteriaRuntime.quicConnected` (set only on the child's own `connected: udpEnabled=...` log line) is recorded for diagnostics; a future slice may choose to gate `RUNNING` on it too once that signal has its own physical false-negative/timing characterization - not required to be stronger than B46-3C's own proven readiness bar for this code-readiness slice.

### Session model

`Hysteria2Transport` mirrors `ShadowsocksTransport` exactly: a fresh, monotonically increasing `sessionId` per `connect()`, an observer that only reacts to a status update carrying the *current* session's id - a stale previous session's terminal event can never mark a new session `Connected`. `underlyingNetworkRecovery = RESTART_SESSION` until seamless roaming is physically proven (unverified this slice, per B46-3C's own scope - a stationary session plus two clean reconnect cycles, not a live handover).

## TLS policy (hard production gate)

Production **must not** use `insecure=true`. This is enforced in two places:
1. `Hysteria2VpnService` always constructs `Hysteria2ChildConfig(insecure = false, ...)` - there is no code path in that class that can set it otherwise.
2. `Hysteria2ChildRuntime.start()` itself refuses to launch the child at all when `config.insecure == true` - defense in depth, proven by `Hysteria2ChildRuntimeTest`'s dedicated `` `production hard gate refuses insecure TLS and never launches the child` `` test.

If current Stockholm production infrastructure cannot yet provide a valid certificate + signed SNI for a Hysteria2 UDP listener, implementation **remains fail-closed/pending deployment** - this slice does not weaken TLS to make a test connection work, and none was attempted.

## TransportKind ordinal compatibility

`ManifestCanonicalizer` (`EndpointManifest.kt`) serializes a binding's `TransportKind` by `.ordinal` (`d.writeInt(b.kind.ordinal)` / `TransportKind.entries.getOrNull(kindOrdinal)`). `HYSTERIA2` was **appended at the end** of the enum - `AMNEZIA_WG=0, XRAY_REALITY=1, QUIC=2, TLS_TCP=3, XRAY_XHTTP=4, SHADOWSOCKS_2022=5, HYSTERIA2=6` - never inserted between existing constants. `TransportKindOrdinalCompatibilityTest` asserts every pre-existing ordinal by literal integer, proves `HYSTERIA2` is exactly `entries.size - 1`, and round-trips a manifest built from every pre-HYSTERIA2 kind through the real canonicalizer to byte-identical output - a future accidental reordering would fail this test, not silently invalidate an already-signed production manifest.

## Registry eligibility, VpnController wiring, MainViewModel wiring

- `TransportRegistry.defaults()` registers `HYSTERIA2` as `NOT_IMPLEMENTED`/`TransportCapabilities.notImplemented()` by default - the same shape `SHADOWSOCKS_2022` already uses.
- `MainViewModel.isHysteria2AvailableFor(endpointId)` is the **one** place device-eligibility is decided (mirrors `isShadowsocksAvailableFor` exactly): requires (1) `hysteria2BinaryEligibility.isEligible` (ABI + both binaries), (2) a validated credential present for this exact endpoint (`hysteria2AvailableEndpoints`, checked once at init, never polled), and (3) the *currently trusted* signed manifest naming a real, typed `SignedTransportProfile.Hysteria2` binding for this exact endpoint - never a Legacy/missing/invalid profile, a wrong-kind binding, or another endpoint's binding. A locally persisted secret alone can **never** make an endpoint available.
- `MainViewModel.buildTransportRegistry(endpointId)` registers `hysteria2Transport` as `AVAILABLE` only when `isHysteria2AvailableFor(endpointId)` is true - otherwise `NOT_IMPLEMENTED`, no factory.
- `VpnController.supportedKinds` includes `HYSTERIA2` only when a real `hysteria2Transport` was wired (constructor-injected, same as every other optional transport).
- `VpnController.buildTransportConfig`'s `HYSTERIA2` branch resolves `host`/`port`/`sni`/`obfuscationMode` **exclusively** from `pendingConnectTransportBinding` and its typed `SignedTransportProfile.Hysteria2` - never a hardcoded Stockholm host/port, never the AWG snapshot, never a secret. Fails closed (`Hysteria2ProfileNotReadyException` → `VpnError.ConfigurationMappingFailure`) for a missing binding, wrong endpoint/kind, an invalid/legacy/unsupported-version signed profile, or a requested `RoutingMode` other than `FULL_VPN`.
- Manual selection is **not** a bypass: `MainViewModel`'s manual-connect path resolves the pinned `EndpointTransportBinding` through the SAME `trustedTransportBindingFor` call `isHysteria2AvailableFor` already required - a "Force HYSTERIA2" debug preference gets no shortcut around the trusted signed binding.
- `AndroidManifest.xml` declares `.vpn.hysteria.Hysteria2VpnService` with `android:exported="false"` and `android:permission="android.permission.BIND_VPN_SERVICE"` - the same security boundary every other VpnService in this app uses. No debug Activity was added.

## Smart Connect boundary

No Hysteria-specific heuristic was added this slice. Registry eligibility (above), `TransportCapabilities.hysteria2AdapterShell()`, `TransportScorer`, `TransportHealth`, and `SmartConnectDecisionEngine` remain the only policy authorities - HYSTERIA2 does not automatically win merely by existing, and its scoring is whatever those existing, unmodified authorities compute from its truthful capabilities.

### `TransportCapabilities.hysteria2AdapterShell()`

| Field | Value | Why |
|---|---|---|
| `usesUdp` | `true` | B46-3C physically proved real UDP/QUIC data plane. |
| `usesTcp` | `false` | Hysteria2's own substrate is QUIC/UDP. |
| `supportsPort443` | `true` | QUIC commonly runs on 443; no evidence against it. |
| `supportsObfuscation` | `true` | Salamander obfuscation is a real, typed profile option. |
| `suitableForRestrictiveNetworks` | **`false`** | No qualifying B54 `FIELD_MEASURED` restricted-network evidence exists yet (B54 PR #108 still represents Hysteria2 as pending). Never set from the protocol's intended purpose or marketing framing. |
| `supportsRoaming` | `false` | Unverified - B46-3C covers a stationary session + reconnect cycles, not a live handover. |
| `supportsFullTunnel` | `true` | Physically proven. |
| `supportsSplitRouting` | `false` | This slice wires FULL_VPN only; a different `RoutingMode` fails closed rather than silently downgrading. |
| `supportsIpv6` | `false` | Not implemented/tested. |
| `supportsTrafficStatistics` | `false` | Not implemented. |
| `supportsProbing` | `false` | Not implemented. |
| `maturity` | `EXPERIMENTAL` | Real adapter code + real (lab/architecture) device evidence, zero production-deployment/normal-selection physical validation yet. |

## ABI eligibility

Physical evidence exists for **arm64-v8a only** (OPPO CPH2173). `Hysteria2AdapterEligibilityChecker` fails closed to `UnsupportedAbi` for any other device ABI set, and to `BinaryUnavailable` when either required child binary (`libnovatun2sockschild.so`, `libnovahysteriachild.so`) is missing/unreadable/non-executable - `HYSTERIA2` becomes `NOT_IMPLEMENTED`/unavailable for selection, never a crash, never an attempted launch with a missing binary.

## Native binary packaging

Both child binaries were already reproducibly built and physically verified for B46-3B/B46-3C:
- `libnovatun2sockschild.so` - tun2socks-child, pinned per B46-3B's own reproducible build record (`docs/B46_3B_HYSTERIA_PROCESS_ISOLATION.md`).
- `libnovahysteriachild.so` - the minimal Hysteria2 child, built from unmodified upstream `apernet/hysteria` at commit `e1366b173ccf5706e1e4630fe8aa654a4b574085`, `CGO_ENABLED=0 go build .`, SHA-256 `ed3d020aa193f8cf9f097d9e7996636f772bb1e2450460a23b4d5eb740e3048b` (B46-3C's own record, `docs/B46_3C_HYSTERIA_PROCESS_ISOLATED_DATAPLANE.md`).

This slice does **not** rebuild these binaries or move them into `src/main/jniLibs/arm64-v8a/` - that is explicit **B46-4P** work (moving/re-verifying the artifact from its research `src/debug/jniLibs` location into production packaging, re-confirming the SHA-256, and recording the dependency/license inventory in the production build record). `Hysteria2ChildProcessLauncher.kt`/`Hysteria2Tun2SocksChildProcessLauncher.kt`'s own doc comments now point at `src/main/jniLibs/arm64-v8a/` as the production location, consistent with the existing AWG/Xray/sslocal gitignored-rebuild-locally convention - no fourth packaging convention was created.

## Server deployment proposal (NOT executed this slice)

Prepared, not deployed:
- **Process/service**: a new, narrowly-scoped systemd unit for the pinned Hysteria2 server binary (`apernet/hysteria` server mode, same commit pin), with its own resource limits and sandboxing directives, mirroring the existing `nova-xray.service` discipline.
- **Auth backend listener**: a small, loopback-only (or Unix-domain-socket) HTTP listener wrapping `gateway/api/hysteria_auth_backend.handle_auth_request`, started by its own unit, reachable **only** from the Hysteria2 server process on the same host - never the public interface, never routed through the internet-facing nginx edge.
- **UDP listen port**: current Stockholm UDP/TCP listeners must be audited before picking a port - **do not assume UDP 443 is free**. If UDP 443 is technically available and operationally desirable, that is a B46-4P finding to document, not assumed here.
- **TLS certificate/SNI**: a valid certificate + signed SNI, `InsecureSkipVerify = false` end to end (client and server) - see "TLS policy" above.
- **Credential verification**: `auth.type: http` pointed at the loopback auth backend above.
- **Firewall rule**: opening the chosen UDP port is explicitly **out of scope** for B46-4A.
- **Logs/restart policy/resource limits**: to be specified alongside the systemd unit in B46-4P, following this project's existing operator-storage/logging conventions (no raw secret in application logs - already enforced at the code layer by `hysteria_auth_backend.py`/`hysteria_provisioning.py`).

## Signed manifest preparation (NOT signed/deployed this slice)

A proposed binding, for documentation only:

```
EndpointTransportBinding(
  kind = HYSTERIA2,
  host = "<Stockholm's existing production host>",
  port = <to be chosen after the UDP-port audit above>,
  metadata = { "hysteria2Profile": "{\"version\":1,\"sni\":\"<TBD>\",\"obfuscationMode\":\"NONE\"}" }
    (+ the endpoint's existing failure-domain/operational-state metadata, inherited unchanged)
)
```

This binding is **not** written into any signed manifest artifact and no existing signed binary artifact was edited. The future deployment slice must use the existing production manifest-signing ceremony/tooling to produce it - never a manual edit.

## Tests

- `TransportKindOrdinalCompatibilityTest` (Android `test` source set) - 5 tests: every pre-HYSTERIA2 ordinal, HYSTERIA2 appended last, declaration-order stability, byte-identical pre-existing-manifest round-trip, HYSTERIA2-binding round-trip.
- `Hysteria2ProfileTest` - 10 tests: Missing/Legacy fallback, round-trip, endpoint-identity binding, unsupported obfuscation mode, unsupported version, blank SNI, no-secret-field invariant, cross-kind non-interference, wrong-kind-binding fail-closed.
- `Hysteria2CredentialTest` - 9 tests: valid validation (with/without obfuscation secret), blank/oversized auth secret, blank-vs-absent obfuscation secret, oversized obfuscation secret, redacted `toString()` (credential, auth secret, obfuscation secret), value-based `equals`.
- `Hysteria2CredentialRepositoryTest` - 13 tests: absent/present round-trip (single and dual-secret), endpoint isolation, rotation, deletion, `credentialExists`, wrong-Keystore-key fail-closed, structurally-corrupt-file fail-closed, wrong-endpoint write refusal, absent-vs-corrupted distinction, no leftover `.tmp`, no secret in a `Corrupted` reason string.
- `Hysteria2TransportStateMappingTest` - exhaustive phase→state mapping.
- `Hysteria2ChildRuntimeTest` (ported from B46-3C, `insecure` flipped to `false` by default, **plus a new dedicated test** for the hard production TLS gate) - 9 tests: valid start, readiness timeout, config-file write/delete, repeated-start rejection, stop idempotency, unexpected-exit notification (exactly once), stop-after-death idempotency, protect-callback forwarding, insecure-TLS refusal.
- `Hysteria2Tun2SocksChildRuntimeTest` (ported from B46-3B, renamed only - zero secret-handling logic to correct) - the full lifecycle-hardening suite: fd ownership, repeated-start rejection, stop idempotency, unexpected-death claiming/no-double-notify, control-channel bind/close discipline.
- Gateway (Python): `test_hysteria_provisioning.py` - 15 tests covering eligibility (unknown/never-activated/revoked/expired/device-mismatch), issuance (auth secret shape, optional obfuscation secret, raw-secret-never-at-rest, idempotent retry, independent secrets per device), and auth verification (valid, wrong secret, live revocation without reprovisioning, live expiry, non-leaking device id). `test_hysteria_auth_backend.py` - 11 tests covering request parsing (valid/missing/extra field/non-JSON/blank/negative-tx/oversized) and the handler (valid/wrong/malformed-indistinguishable-from-wrong/secret-never-echoed/exact-secret-forwarded).

**Execution note**: this development session ran on Windows without an Android SDK/NDK installed, so the Kotlin/Android test suite above was written and carefully cross-checked against the exact APIs of the classes it mirrors, but **could not be compiled or executed** in this session - `:app:testDebugUnitTest` must be run in an environment with the Android SDK before this slice is considered verified. The Python gateway test files were written and `python -m py_compile`-clean, but this session's environment lacks the POSIX `fcntl` module `activations.py`/`hysteria_store.py` depend on (Windows has no `fcntl`) - `hysteria_auth_backend.py`'s own tests (no `fcntl` dependency) **did run and pass, 13/13**; `test_hysteria_provisioning.py` needs a POSIX (Linux/macOS) environment or CI to execute, matching the pre-existing `test_xray_provisioning.py`'s own identical environment constraint in this repo.

## Security review (self-assessment against the task's own gates)

- No insecure TLS anywhere in the production path (double-enforced - see "TLS policy").
- No secret Intent/Bundle extra anywhere in the production path (see "debug-spike secret correction").
- Signed-binding gate exists and is fail-closed for every listed failure mode (missing/legacy/malformed/unsupported-version binding, missing/corrupted credential, ABI/binary unavailable).
- Normal transport-selection wiring is implemented end to end but cannot become `AVAILABLE` without a real trusted binding *and* a real credential *and* ABI/binary eligibility, all three independently checked.
- No production infrastructure was changed by this slice (no systemd unit started, no firewall opened, no manifest signed/deployed, no credential provisioned against a real server).
- Server never persists a raw Hysteria2 secret at rest (salted-hash-only storage) - a stronger property than the `password`/`userpass` alternatives this design explicitly rejected.
- No raw secret in any log line, exception message, or HTTP response this slice's code paths can produce (asserted directly by tests on both the Kotlin and Python sides).

## Remaining B46-4P work (deployment gate - explicitly out of scope here)

1. Audit current Stockholm UDP/TCP listeners; choose a real UDP port (do not assume 443 is free).
2. Provision a real TLS certificate + SNI for that listener; confirm `InsecureSkipVerify=false` end to end against it physically.
3. Write and review the Hysteria2 server systemd unit (sandboxing, resource limits, restart policy) and the loopback-only auth-backend listener unit.
4. Wire `gateway/api/handler.py`'s live route table to `hysteria_provisioning`/`hysteria_auth_backend` (currently code-only, not dispatched).
5. Move/re-verify `libnovatun2sockschild.so`/`libnovahysteriachild.so` into `src/main/jniLibs/arm64-v8a/` production packaging; re-run the release-artifact inspection checklist (`:app:assembleRelease`, `lintVitalRelease`, no debug B46 spike classes/services in the release APK, no test credential, no B46 temporary server IP/port hardcoding).
6. Run the full Kotlin/Android test suite in a real Android-SDK environment (this slice's own tests were authored but not executed here - see "Execution note" above) and the Python gateway suite in a POSIX/CI environment.
7. Compose and run the production manifest-signing ceremony to produce the real, signed `EndpointTransportBinding(HYSTERIA2, ...)` for Stockholm; provision one real test device's Hysteria2 credential against the real deployed server; physically validate Smart Connect/manual-selection end to end through the *normal app UI* (not a debug spike).
8. Open the chosen firewall/Security Group rule only once the above are green.
9. A B55-equivalent reconciliation slice updates B54 (PR #108) to represent Hysteria2 with real `FIELD_MEASURED` restricted-network evidence, once available - B54 itself was **not** modified by B46-4A.

## Decision gate

B46-4A is complete for its own scope: production code exists (client + gateway), a secure credential/provisioning path exists (verified-not-assumed upstream auth mechanism, no raw activation credential reused as Hysteria auth, no raw secret persisted at rest), no insecure TLS anywhere, no secret Intent path, a signed-binding gate exists, and normal transport-selection wiring is implemented but cannot become `AVAILABLE` without a real trusted binding + credential + ABI/binary eligibility. No production infrastructure was changed.

**Do not call Hysteria2 production-deployed.** B46-4P is a separate, explicit gate.
