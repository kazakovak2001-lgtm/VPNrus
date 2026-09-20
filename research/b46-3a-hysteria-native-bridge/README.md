# B46-3A - Hysteria2 native tun2socks coexistence bridge (research, debug-only)

Resolves the concrete B46-2P production-integration blocker: Xray's
`AndroidLibXrayLite` AAR and the B46-2P tun2socks AAR were BOTH built with
`gomobile bind`, so both ship `go.Seq`/`go.Universe`/`go.error` runtime
classes and a `jni/<abi>/libgojni.so` - identical names, so they collide
(`checkDebugDuplicateClasses` fails; one `libgojni.so` silently shadows the
other at install time). See `docs/B46_3A_HYSTERIA_NATIVE_BRIDGE_COEXISTENCE.md`
for the full report.

This directory replaces ONLY the tun2socks half with a plain Go
`-buildmode=c-shared` artifact + a small hand-written JNI shim - no
`gomobile`/`gobind` anywhere in this path, so no second `libgojni.so`, no
`go.*` Java classes. Xray's existing AAR (`android/app/libs/libv2ray-*.aar`)
is completely untouched.

Same pinned engine as B46-2P/B46-2C (unchanged):
`github.com/xjasonlyu/tun2socks/v2`, MIT, commit
`5d9fac67bb1095a5d2bd959216f85e6434524731` /
`v2.0.0-20260913205830-5d9fac67bb10`.

## Layout

- `native/` - the Go c-shared package (`main.go`), exporting
  `NovaTun2SocksStart`/`NovaTun2SocksStop`/`NovaTun2SocksIsStarted`/
  `NovaTun2SocksLastErrorString`/`NovaTun2SocksFreeString` via cgo. Wraps
  `engine.Insert`/`engine.Start`/`engine.Stop` - identical lifecycle calls
  to `research/b46-2p-android-physical/tun2socks-bridge/bridge.go`, not
  reimplemented.
- `jni/nova_tun2socks_jni.c` - the ONLY code exposed to the JVM. Forwards
  1:1 to the exported C functions above. Implements
  `net.pocvpn.client.vpn.hysteria.NativeTun2SocksBridge`'s three native
  methods.
- `scripts/build-c-shared.sh` - builds `libnovatun2socks.so` (Go c-shared,
  android/arm64).
- `scripts/build-jni-shim.sh` - compiles+links `libnovatun2socks_jni.so`
  against the artifact above.
- `out/` - build output (gitignored, not committed).

The Kotlin adapter lives in the app module itself (debug-only, so it never
reaches the release build/manifest):
`android/app/src/debug/java/net/pocvpn/client/vpn/hysteria/`.

## Build

Requires Go (this pass used `go1.26.5`) and an installed Android NDK (this
pass used `27.0.12077973`).

```bash
export ANDROID_NDK_HOME=/path/to/Sdk/ndk/27.0.12077973
cd research/b46-3a-hysteria-native-bridge
bash scripts/build-c-shared.sh   # -> out/arm64-v8a/libnovatun2socks.so + .h
bash scripts/build-jni-shim.sh   # -> out/arm64-v8a/libnovatun2socks_jni.so
```

Then copy both `.so`s into the app module's debug jniLibs directory
(gitignored, never committed - see repo-root `.gitignore`):

```bash
cp out/arm64-v8a/libnovatun2socks.so out/arm64-v8a/libnovatun2socks_jni.so \
   ../../android/app/src/debug/jniLibs/arm64-v8a/
```

## Why c-shared, not c-archive

`-buildmode=c-archive` is genuinely rejected by the Go toolchain itself for
`GOOS=android`:

```
-buildmode=c-archive not supported on android/arm64
```

(confirmed by running the build, not assumed - see the coexistence doc's
Part A). `-buildmode=c-shared` IS supported and was used instead, per the
task's own fallback instruction. This does not reintroduce any gomobile
runtime: `c-shared` is a plain Go toolchain feature, unrelated to
`golang.org/x/mobile`/`gobind`, and produces an ordinary ELF `.so` whose
only NEEDED entries are `liblog.so`/`libdl.so`/`libc.so` (confirmed via
`llvm-readelf -d`).

## FD ownership contract (load-bearing, reused verbatim from B46-2C/B46-2P)

The caller (a future `VpnService`) must pass a DUPLICATE of the original
TUN fd, never the original. `NovaTun2SocksStart` takes ownership of exactly
the fd number it is given; the real tun2socks engine closes that fd
internally on `NovaTun2SocksStop`/`engine.Stop()`. The caller must never
also close that same fd number itself.

## Verification requirement before using these artifacts anywhere

After building, confirm (see the coexistence doc's Part B for the full
transcript of this pass's own run):

- 0 `apernet/sing-tun` / `sagernet/sing-tun` symbols
- real `github.com/xjasonlyu/tun2socks`/`gvisor.dev/gvisor` symbols present
- 0 second `libgojni.so` anywhere in the coexistence APK
- 0 `go.Seq`/`go.Universe`/`go.error` Java classes introduced

Record artifact SHA-256 hashes in the coexistence doc. Do not commit either
binary.
