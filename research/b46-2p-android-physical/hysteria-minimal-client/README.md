# B46-2P minimal Hysteria2 Android child (research, debug-only)

`novaminimal_main.go` here is the B46-2P extension of the B46-2C prototype
(`research/b46-2c-permissive-hysteria-path/hysteria-minimal-client/novaminimal_main.go`),
additively extended with:

- `--protect-path <unix-socket-path>`: real Android `VpnService.protect(fd)`
  analog via SCM_RIGHTS, reusing the exact wire protocol
  `RealShadowsocksVpnProtectBridge` already proves physically
  (`android/app/src/main/java/net/pocvpn/client/vpn/shadowsocks/ShadowsocksVpnProtectBridge.kt`).
  Used on Android. Fails closed on any dial/sendmsg/timeout/negative-ack
  failure.
- `--config-file <path>`: JSON config (`server`, `auth`, `sni`, `insecure`,
  `obfsSalamander`, `socksListen`, `protectPath`) so the auth password never
  appears in argv/env/process-title/logcat. Used on Android - `--auth` is
  never passed on Android.

`--protect-stub` and `--fwmark` (B46-2C) are untouched and remain host-research-only.

No upstream Hysteria file is modified. This still cannot be a standalone Go
module (imports the `app/internal/socks5` internal package).

## Build (reproduce)

```
git clone https://github.com/apernet/hysteria.git
cd hysteria
git checkout e1366b173ccf5706e1e4630fe8aa654a4b574085
mkdir -p app/novaminimal
cp <this file> app/novaminimal/main.go
cd app
CGO_ENABLED=0 GOOS=android GOARCH=arm64 go build -o novaminimal-android-arm64 ./novaminimal
```

Do not commit the resulting binary. Copy it to
`android/app/src/debug/jniLibs/arm64-v8a/libnovahysteria.so` (gitignored;
named as a `.so` so Android's package installer extracts it into the app's
native-library directory with executable permissions, the same convention
already used for `libsslocal.so`).

## Required verification before using the binary (per B46-2P)

```
go list -deps ./novaminimal          # zero sing-tun / internal/tun matches
go version -m <binary>                # zero sing-tun mentions
go tool nm <binary>                   # zero sing-tun/sagernet symbols
strings <binary> | grep -i sing-tun   # zero matches
```

Record the binary's SHA-256 in the physical validation doc. Never commit it.

## Config-file schema

```json
{
  "server": "<ip:port>",
  "auth": "<password>",
  "sni": "<server name>",
  "insecure": true,
  "obfsSalamander": "",
  "socksListen": "127.0.0.1:41080",
  "protectPath": "/data/user/0/net.pocvpn.client.debug/files/b46-protect.sock"
}
```

Keep this file under app-private storage with mode 600. Delete it after the
test session (the child also best-effort-deletes it on graceful SIGTERM
shutdown when `--config-file` was used).

Not production code. Not wired into Nova's release build.
