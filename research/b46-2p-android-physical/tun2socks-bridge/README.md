# B46-2P tun2socks Android AAR bridge (research, debug-only)

Real gomobile-bindable wrapper around the exact tun2socks engine already
audited and proven host-side in B46-2C
(`docs/B46_2C_PERMISSIVE_HYSTERIA_PATH.md` Part A/B/C/G). Not production
code, not wired into Nova's release build.

## Build

```
GOFLAGS=-mod=mod go install golang.org/x/mobile/cmd/gomobile@latest
GOFLAGS=-mod=mod go install golang.org/x/mobile/cmd/gobind@latest
export ANDROID_HOME=<sdk path>
export ANDROID_NDK_HOME=<ndk path>
cd research/b46-2p-android-physical/tun2socks-bridge
gomobile bind -target=android/arm64 -androidapi 26 -o b46-tun2socks.aar .
```

Do not commit the resulting `.aar`. Copy it to
`android/app/src/debug/local-libs/b46-tun2socks.aar` (gitignored).

## API

- `StartBridge(fd int, mtu int, socksAddr string) error`
- `StopBridge() error`
- `IsStarted() bool`

## FD ownership contract (load-bearing)

`fd` must already be a **duplicate** of the VpnService's original TUN fd
(see B46-2C Part B and
`docs/B46_2P_HYSTERIA2_ANDROID_PHYSICAL_VALIDATION.md`). `StartBridge` takes
over that exact fd number; the real tun2socks engine closes it internally on
`StopBridge()`/`engine.Stop()`. The caller must never also close that same
fd number itself, and must never pass the original VpnService fd directly.

## Verification requirement before shipping the AAR anywhere

Per B46-2P's task, after building, extract `jni/arm64-v8a/libgojni.so` from
the AAR and confirm via `go tool nm`:

- 0 symbols from `github.com/apernet/sing-tun`
- 0 symbols from `github.com/sagernet/sing-tun`
- real `github.com/xjasonlyu/tun2socks` symbols present
- real `gvisor.dev/gvisor` symbols present

Record the AAR SHA-256 and `libgojni.so` SHA-256 in the physical validation
doc. Do not commit either binary.
