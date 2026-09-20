# B46-3A - Hysteria2 native tun2socks coexistence bridge

Status: research/build-in-progress. See `docs/ROADMAP.md`'s B46 row for the
authoritative status line once this pass concludes.

Branch: `research/b46-3a-hysteria-native-coexistence`
Worktree: `C:\Users\akaza\Downloads\VPN-B46-3A`
Baseline: `origin/main` @ `75cb4b249da24dc5d13197b0cc016147d79e0a81` (PR #98 /
B46-2P, merged)

## Problem statement (from B46-2P)

Xray's `AndroidLibXrayLite` AAR is built with `gomobile bind` and ships
`go.Seq`/`go.Universe`/`go.error` runtime classes plus
`jni/<abi>/libgojni.so`. B46-2P's own tun2socks bridge AAR was ALSO built
with `gomobile bind`, producing an IDENTICALLY-named `go.*` class set and a
second, colliding `libgojni.so`. `checkDebugDuplicateClasses` fails; the
two native libraries cannot both be packaged under the same name. This is
why the B46-2P harness shipped as a fully separate application
(`b46harness/`, package `net.pocvpn.b46harness`) rather than inside `:app`.

## Goal

Prove a path where the EXISTING Xray AAR is completely unchanged, and the
pinned `xjasonlyu/tun2socks` engine is exposed to Android through a
NON-GOMOBILE native ABI/JNI boundary instead:

```
Kotlin/Java
    |
small Nova JNI adapter        (jni/nova_tun2socks_jni.c)
    |
unique Nova native library    (native/main.go -> libnovatun2socks.so)
    |
pinned xjasonlyu/tun2socks Go engine
```

## Pins (unchanged from B46-2P/B46-2C)

- `github.com/xjasonlyu/tun2socks/v2`, MIT, commit
  `5d9fac67bb1095a5d2bd959216f85e6434524731`, pseudo-version
  `v2.0.0-20260913205830-5d9fac67bb10`.
- `gvisor.dev/gvisor` `v0.0.0-20260906120324-45bde0d1defa` (transitive,
  inherited unchanged via `go.mod`/`go.sum`).
- Bridge lifecycle semantics reused verbatim: `StartBridge(fd, mtu,
  socksAddr)` / `StopBridge()` / `IsStarted()`, same FD ownership contract
  as `research/b46-2p-android-physical/tun2socks-bridge/bridge.go`. The
  tun2socks engine implementation itself was NOT modified - only the export
  layer around it changed (cgo `-buildmode=c-shared` instead of `gomobile
  bind`).

## Part A - non-gomobile build feasibility

### c-archive (preferred, attempted first)

```
export ANDROID_NDK_HOME=.../Sdk/ndk/27.0.12077973
cd research/b46-3a-hysteria-native-bridge/native
CGO_ENABLED=1 GOOS=android GOARCH=arm64 \
  CC=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/windows-x86_64/bin/aarch64-linux-android26-clang.cmd \
  go build -buildmode=c-archive -trimpath -o libnovatun2socks.a .
```

Result: **rejected by the Go toolchain itself**, not a project/NDK
configuration issue:

```
-buildmode=c-archive not supported on android/arm64
```

This is Go's own `cmd/go` build-mode support table for `GOOS=android`
(`c-shared` is listed there; `c-archive` is not). No amount of NDK/CGO flag
correction changes this - confirmed by attempting the build with the
correct NDK clang wrapper and the correct `androidapi 26` target, exactly
the working configuration later used for `c-shared` below.

### c-shared (fallback, used)

```
CGO_ENABLED=1 GOOS=android GOARCH=arm64 \
  CC=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/windows-x86_64/bin/aarch64-linux-android26-clang.cmd \
  go build -buildmode=c-shared -trimpath -o out/arm64-v8a/libnovatun2socks.so .
```

Result: **succeeded on the first correctly-configured attempt.**

| Field | Value |
|---|---|
| Go version | `go1.26.5 windows/amd64` (host toolchain; `GOOS=android GOARCH=arm64` cross-compile, no WSL needed for this artifact) |
| NDK version | `27.0.12077973` |
| Compiler | `aarch64-linux-android26-clang` (NDK's own clang wrapper, API level 26 - same convention as B46-2P's `gomobile bind -androidapi 26`) |
| CGO flags | `CGO_ENABLED=1`, `CC=<ndk>/aarch64-linux-android26-clang.cmd` |
| Build command | `go build -buildmode=c-shared -trimpath -o libnovatun2socks.so .` (see `scripts/build-c-shared.sh`) |
| Artifact | `libnovatun2socks.so` (16,997,624 bytes) + `libnovatun2socks.h` (generated cgo export header) |
| `libnovatun2socks.so` SHA-256 | `9eb58cd11ab2762f8d1fddd32dbade167b6dedcd44d9ca0ac04c3eab18abeebb` |
| `libnovatun2socks.h` SHA-256 | `6d44a20b99d000be267de1e2097627b8e08de0ec0bb2dcbc99b254042144a913` |
| Dynamic deps (`llvm-readelf -d`, NEEDED) | `liblog.so`, `libdl.so`, `libc.so` only |
| Exported symbols (`llvm-nm -D`) | `NovaTun2SocksStart`, `NovaTun2SocksStop`, `NovaTun2SocksIsStarted`, `NovaTun2SocksLastErrorString`, `NovaTun2SocksFreeString` (plus cgo's internal `_cgoexp_*` trampolines for the same five) |

### JNI shim build

```
$CC -shared -fPIC -O2 -I out/arm64-v8a \
  -o out/arm64-v8a/libnovatun2socks_jni.so \
  jni/nova_tun2socks_jni.c \
  -L out/arm64-v8a -lnovatun2socks \
  -Wl,-soname,libnovatun2socks_jni.so
```

Result: succeeded.

| Field | Value |
|---|---|
| Artifact | `libnovatun2socks_jni.so` (6,504 bytes) |
| SHA-256 | `e24d8a5c464e9d698de4acfb73104a6c63a31600a9a4956463940284e74f84b8` |
| NEEDED | `libnovatun2socks.so`, `libdl.so`, `libc.so` |
| Exported symbols | `Java_net_pocvpn_client_vpn_hysteria_NativeTun2SocksBridge_nativeStart`, `..._nativeStop`, `..._nativeIsStarted` |

`libnovatun2socks_jni.so` is the ONLY library the JVM ever `dlopen()`s
directly (loaded first: `libnovatun2socks.so`, then
`libnovatun2socks_jni.so` - see `NativeTun2SocksBridge.kt`'s load order
comment; loading in the reverse order fails with `UnsatisfiedLinkError`
since the shim's own `NEEDED` entry isn't resident yet).

## Part B - unique runtime / symbol proof

Audited with `llvm-nm`, `llvm-readelf`, `llvm-strings` (NDK 27's own LLVM
toolchain) against `libnovatun2socks.so`:

| Check | Result |
|---|---|
| `github.com/xjasonlyu/tun2socks` symbols present | **931** (identical count to B46-2P's own gomobile-built AAR's `libgojni.so` - same engine, same code) |
| `gvisor.dev/gvisor` symbols present | **4,976** (identical count to B46-2P's own AAR) |
| `github.com/apernet/sing-tun` symbols | **0** |
| `github.com/sagernet/sing-tun` symbols | **0** |
| Generated `go.Seq`/`go.Universe`/`go.error` Java classes | **0** - none exist, because this artifact is not gomobile-bound at all (a plain cgo `c-shared` build produces no Java source/classes of any kind; the entire JVM-facing surface is the three hand-written `external fun`s in `NativeTun2SocksBridge.kt`) |
| Second `libgojni.so` | **0** - the artifact is named `libnovatun2socks.so` (never `libgojni.so`); Xray's own `libgojni.so` is untouched and still the only file of that name |
| Dynamic deps beyond the Android system libs | none (`liblog.so`/`libdl.so`/`libc.so` only, per Part A) |

The B46-2C permissive dependency boundary (no GPL `sing-tun` anywhere in
this path) is intact - the 0/0 sing-tun counts above are the same audit
B46-2C/B46-2P already ran, re-run here against the new artifact shape.

## Part C - JNI contract

Implemented in `jni/nova_tun2socks_jni.c` + `native/main.go`, surfaced to
Kotlin as `net.pocvpn.client.vpn.hysteria.NativeTun2SocksBridge`
(debug-only, `android/app/src/debug/java/...`):

- `start(fd, mtu, socksAddr)` - validated in Go (`fd < 0` /`mtu <= 0`/empty
  `socksAddr` each return a typed negative error code, never a panic; a
  second `start()` while already started returns
  `novaErrAlreadyStarted` without touching the engine) AND, redundantly, in
  Kotlin (`NativeTun2SocksController`, so bad input never even reaches the
  JNI boundary and the "already started" state is deterministic regardless
  of whether the native library loaded at all - see its own doc comment).
- `stop()` - idempotent both in Go (`engine.Stop()` only called when
  `started`) and in Kotlin (`NativeTun2SocksController.stop()` always
  returns `Ok`/the native result and clears local state, safe to call
  repeatedly).
- `isStarted()` - diagnostic only, never used to gate a production
  decision (same convention as B46-2P's `IsStarted`).
- FD ownership: reused verbatim from B46-2C/B46-2P - the caller must pass
  `ParcelFileDescriptor.dup(original.fileDescriptor).detachFd()`, never the
  original; the native engine owns and closes the duplicate on `stop()`.

## Part D - Xray coexistence proof

Ran against the REAL Nova `:app` module with its real pinned Xray AAR -
neither was faked, mocked, or reduced in scope.

### Xray AAR: reproduced locally, unmodified

`android/app/libs/libv2ray-androidlibxraylite-c634d1b-nova-b35xhttp1.aar`
was missing on this machine (gitignored, as documented) and was rebuilt
exactly per `third_party/xray/build-xray-wsl.sh` / `VERSION` (pinned
`AndroidLibXrayLite@c634d1baea97e94320c0bf6a9cf637369c4f11d4` wrapping
`Xray-core@5ca6f4b7d4dc20a881d4330e498892697627ec0c` +
the tracked `nova-b35-xhttp-dial-bound-v1` patch, patch SHA-256 verified
`114a7abed6b3b9b6490d1f9740b62b84f3a82df9cf77d45bbc35559e13697445`,
`go test ./transport/internet/splithttp -run '^TestNovaXhttpDialTimeout'`
passed) inside WSL2 Ubuntu, then copied into `android/app/libs/` verbatim -
`gomobile bind` was invoked exactly as `build-xray-wsl.sh` specifies, with
no edits to its output. (The checked-out `.sh`/patch files carry CRLF line
endings on this Windows checkout - a pre-existing repo/checkout property,
unrelated to B46-3A - so the build was run from a line-ending-normalized
copy in `~/build/xray-runner/`; the tracked patch's SHA-256 was verified to
match the pinned value in `VERSION` after normalization, confirming the
content itself, not just the checkout artifact, is exactly the pinned one.)

- `libv2ray.aar` SHA-256: `078578b99aa419d197fda35474ef49742329b8762f3073e40d1c0f54a2149084`
- The pinned `amneziawg-tunnel-v3.1.20260814-debug.aar` (also required to
  build `:app`) was likewise reproduced from the already-cloned, pinned-commit
  `amneziawg-android` checkout (`5c16489e2cd9ed3a0a7a27c7445bba5238132f86`,
  matching `docs/ROADMAP.md`'s pin) already present in this machine's WSL2
  build cache from prior work.

### `libnovatun2socks.so` / `libnovatun2socks_jni.so` staged as debug jniLibs

Copied to `android/app/src/debug/jniLibs/arm64-v8a/` (gitignored, per
`.gitignore`'s new B46-3A entries) - the same debug-only jniLibs convention
already used for `libsslocal_spike.so`. No `build.gradle.kts` change was
needed: AGP already picks up `src/debug/jniLibs/<abi>/*.so` automatically,
and the debug variant's `useLegacyPackaging` fix (pre-existing, B45A) already
applies uniformly.

### `:app:checkDebugDuplicateClasses`

```
> Task :app:checkAwgTunnelAar
> Task :app:checkXrayAar
> Task :app:preBuild
> Task :app:preDebugBuild
> Task :app:checkDebugDuplicateClasses

BUILD SUCCESSFUL in 39s
3 actionable tasks: 3 executed
```

**PASSED** - Xray's AAR and the native tun2socks bridge coexist in one
dependency graph with zero duplicate-class conflicts (the exact failure
B46-2P hit and could not clear).

### `:app:assembleDebug`

```
BUILD SUCCESSFUL in 2m 46s
40 actionable tasks: 39 executed, 1 up-to-date
```

**PASSED**. `compileDebugKotlin` compiled `NativeTun2SocksBridge.kt` /
`NativeTun2SocksController.kt` cleanly (zero errors; the build's only
warnings are pre-existing, unrelated to this slice). Output:
`android/app/build/outputs/apk/debug/app-debug.apk` (89,229,600 bytes).

### APK native-library inventory

```
lib/arm64-v8a/libandroidx.graphics.path.so
lib/arm64-v8a/libgojni.so                    <- Xray, the ONLY one for this ABI
lib/arm64-v8a/libnovatun2socks.so            <- B46-3A, tun2socks engine
lib/arm64-v8a/libnovatun2socks_jni.so        <- B46-3A, JNI shim
lib/arm64-v8a/libwg-go.so                    <- AmneziaWG (pre-existing)
lib/arm64-v8a/libwg-quick.so
lib/arm64-v8a/libwg.so
lib/armeabi-v7a/libgojni.so                  <- Xray, the ONLY one for this ABI
... (same libgojni.so/libwg* pattern repeats for armeabi-v7a/x86/x86_64;
     libnovatun2socks*.so was built for arm64-v8a only in this pass)
```

- **Exactly one `libgojni.so` per ABI, four total across the whole APK** -
  confirmed by `unzip -l` count (`4`), matching the four ABIs exactly. No
  second `libgojni.so` anywhere.
- `libnovatun2socks.so`/`libnovatun2socks_jni.so` extracted from the APK
  and re-verified with `llvm-nm -D`: all five `NovaTun2Socks*` exports and
  all three `Java_net_pocvpn_client_vpn_hysteria_NativeTun2SocksBridge_*`
  JNI exports are present and intact (AGP's `stripDebugDebugSymbols` strips
  debug info, not the dynamic symbol table - byte hashes differ from the
  pre-packaging build for this reason; the same stripping is applied
  uniformly to Xray's own `libgojni.so`, not something singled out for our
  artifact).
- Xray's `classes.jar` was inspected directly: `go/Seq.class`,
  `go/Seq$*.class`, `go/Universe.class`, `go/Universe$proxyerror.class`,
  `go/error.class` all come from EXACTLY ONE source - Xray's own AAR. The
  B46-3A native artifacts (`libnovatun2socks.so`/`libnovatun2socks_jni.so`)
  contain zero `.class` files of any kind (they are pure ELF `.so`s), so
  there is no possible second definition of any `go.*` Java class -
  consistent with `checkDebugDuplicateClasses`' own PASS above.

### Local release packaging

Not attempted in this pass - `:app`'s release variant requires the
production `libsslocal.so`/signing config setup, out of scope for proving
in-process debug coexistence (the actual acceptance gate). The debug-variant
proof above is the load-bearing evidence for this slice's goal.

## Part E - real Android JNI smoke

**No physical device was connected during this pass** (`adb devices -l`
returned an empty list throughout). Real-device JNI smoke (native library
`dlopen`, `isStarted()` initial-state check, invalid-fd fail-closed
behavior, idempotent stop, no crash) is therefore NOT claimed as physically
proven here - this is a genuine gap against Part E's full ask, reported
honestly rather than papered over.

What WAS proven, at the Kotlin/JVM level (`NativeTun2SocksControllerTest`,
`NativeTun2SocksBridgeTest`, 13 tests, 0 failures - see Part G/Tests below):
native-library-load failure maps to a typed `Failed` result rather than a
crash (deterministically true in the JVM unit-test environment, since
`System.loadLibrary` always fails there - a real, not simulated, exercise
of that code path), `isStarted()` starts `false`, `stop()` is a harmless
no-op before any `start()`, and all four invalid-input paths (bad fd, bad
mtu, empty address, double-start) are rejected before ever reaching the
native call. The real on-device `dlopen`/JNI call path itself (once a
device is available) is the one remaining unverified step.

If a physical device becomes available in a follow-up pass, the minimum
smoke per the task's own Part E list should be run before this gate is
marked fully closed.

## Part F - architecture decision

Compared:

| Option | Verdict |
|---|---|
| A. Go `c-archive` + JNI `.so` | **Ruled out by the Go toolchain itself** - `-buildmode=c-archive not supported on android/arm64` (Part A). Not a matter of preference. |
| B. Go `c-shared` + JNI boundary | **Selected** - builds cleanly, produces a uniquely-named `.so` with only standard Android system-library dependencies, zero gomobile runtime classes/collisions (Part B), and preserves the exact B46-2P bridge lifecycle semantics (Part C). |
| C. Keep gomobile, relocate the runtime | Not attempted: B46-2P's own finding already established `gomobile bind -javapkg` relocates only the user package, not the shared `go.Seq`/`go.Universe`/`go.error`/`libgojni.so` runtime - the actual collision surface. No new evidence in this pass changes that. |
| D. Separate APK/process architecture | Not selected for this slice's goal (proving in-process coexistence) - this is what B46-2P already fell back to (`b46harness` as a standalone app) specifically because the AAR collision blocked in-process integration; this slice's whole purpose is to remove that blocker rather than re-accept it. |

Production robustness / lifecycle / collision risk / testability /
reproducibility: Option B is a plain Go+NDK+JNI build with no third-party
mobile-binding tool in the loop, the smallest possible moving-parts count,
and a symbol/class footprint that is fully inspectable with stock NDK
tools (this pass's own Part A/B). Binary size: `libnovatun2socks.so` is
~17MB unstripped (same engine/gvisor weight as the B46-2P AAR's own
`libgojni.so`; `-ldflags="-s -w"` was not applied in this pass and is a
reasonable follow-up before any real release-path use). License/dependency
implications: unchanged from B46-2C/B46-2P (MIT/Apache-2.0 runtime graph,
no GPL).

**Verdict: keep Xray's gomobile AAR unchanged; replace the tun2socks
gomobile AAR with the unique native JNI bridge built in this slice
(Option B).**

## Part G - repository scope

- `docs/B46_3A_HYSTERIA_NATIVE_BRIDGE_COEXISTENCE.md` (this file)
- `docs/ROADMAP.md` - B46 row updated
- `research/b46-3a-hysteria-native-bridge/` - Go native package, JNI shim,
  build scripts, README (source only; `.a`/`.so`/`.h` build output is
  gitignored under `out/`)
- `android/app/src/debug/java/net/pocvpn/client/vpn/hysteria/` -
  `NativeTun2SocksBridge.kt` (JNI boundary), `NativeTun2SocksController.kt`
  (testable Kotlin-side lifecycle gate)
- `android/app/src/testDebug/java/net/pocvpn/client/vpn/hysteria/` - unit
  tests
- `.gitignore` - entries for the locally-built native artifacts

No production code changed: `TransportKind.HYSTERIA` was NOT added,
`TransportRegistry`/`VpnController`/`SmartConnectDecisionEngine` were not
touched, and no production server/firewall/manifest was modified.

## Tests

`android/app/src/testDebug/java/net/pocvpn/client/vpn/hysteria/` - run via
`:app:testDebugUnitTest --tests "net.pocvpn.client.vpn.hysteria.*"`:

- `NativeTun2SocksControllerTest` (10 tests): initial not-started state,
  valid start, repeated-start rejection, stop idempotency, stop-after-start
  state reset, invalid fd, invalid MTU (zero and negative), empty SOCKS
  address, native error-code pass-through, native stop-failure still
  clears local state.
- `NativeTun2SocksBridgeTest` (3 tests): against the REAL
  `NativeTun2SocksBridge` singleton (not a fake) - `start()` maps a missing
  native library to a typed failure (never throws), `stop()` is a harmless
  no-op, `isStarted()` is `false` when the library never loaded. This is
  real JNI-load-failure-mapping coverage, not simulated: in the JVM unit
  test environment `System.loadLibrary` genuinely throws.

**Result: `BUILD SUCCESSFUL`, 13/13 tests, 0 failures, 0 errors.**

Not covered by an automated test: "zero production selection change" was
verified by inspection (`git diff` against `origin/main` touches no file
under `android/app/src/main/java/net/pocvpn/client/transport/` or
`.../vpn/` production controllers - see Part G's file list) rather than by
a dedicated test, since no existing test harness in this repo asserts
repo-wide "no new TransportKind" as a CI-checked invariant.

## Acceptance gates (final status)

1. real pinned tun2socks engine builds through a non-gomobile Android
   boundary - **PASS** (Part A)
2. real JNI entrypoints work - **PASS at the Kotlin-boundary/unit-test
   level and confirmed present/callable in the real packaged APK's
   `.so`s** (Part C, Part D symbol re-verification); the real on-device
   `dlopen`+call has NOT been physically exercised - **NO DEVICE WAS
   AVAILABLE IN THIS PASS** (Part E) - reported as a genuine open item, not
   claimed
3. no tun2socks `go.*` Java runtime classes exist - **PASS** (Part B - none
   are generated by this build path; Part D re-confirms the APK's only
   `go.*` classes come from Xray's own AAR)
4. no second `libgojni.so` exists - **PASS** (Part B build-time; Part D
   confirms in the real packaged APK - exactly 4 `libgojni.so` entries,
   one per ABI)
5. existing Xray AAR remains unchanged - **PASS** (Part D - rebuilt exactly
   per the existing pinned `build-xray-wsl.sh`/`VERSION`, copied verbatim,
   never repacked/edited)
6. Nova app with Xray + native tun2socks bridge passes duplicate-class
   checking - **PASS** (Part D, `:app:checkDebugDuplicateClasses` BUILD
   SUCCESSFUL)
7. Nova debug APK builds - **PASS** (Part D, `:app:assembleDebug` BUILD
   SUCCESSFUL)
8. APK inspection proves both runtimes coexist under distinct native
   boundaries - **PASS** (Part D - `libgojni.so` x4 and
   `libnovatun2socks*.so` x2 all present, symbols verified post-packaging)
9. lifecycle/invalid-input JNI smoke does not crash - **PASS** at the
   Kotlin/unit-test level (Part C, 13/13 tests green); real-device
   confirmation NOT done - no device available (Part E)
10. no GPL sing-tun is linked into the selected bridge - **PASS** (Part B)
11. no production transport-selection behavior changed - **PASS** (Part G -
    `TransportKind`/`TransportRegistry`/`VpnController`/
    `SmartConnectDecisionEngine` untouched; only new debug-only files and
    `.gitignore` entries were added)
12. no generated binaries/secrets are committed - **PASS** (`.gitignore`
    entries added; verified via `git status` before every commit in this
    pass)

**Overall: 10 of 12 gates fully PASSED with real evidence; gates 2 and 9
are PASSED at the Kotlin/JVM level but NOT physically confirmed on a real
device, because no physical device was connected during this pass.** No
gate was papered over - this is reported as the one concrete remaining
blocker to a full PASSED verdict, not hidden inside a broader claim.
