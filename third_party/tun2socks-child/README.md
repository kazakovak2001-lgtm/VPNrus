# tun2socks-child (`libnovatun2sockschild.so`)

Nova's process-isolated tun2socks bridge for Hysteria2 (B46-3B / B46-4A): a
plain Go executable that receives the duplicated TUN fd over an app-private
Unix control socket and forwards traffic to the local Hysteria2 SOCKS5
listener.

## Sources

| File | Origin |
|---|---|
| `src/main.go` | Nova wrapper. Identical to the B46-3B source (`research/b46-3b-hysteria-process-isolation/tun2socks-child/main.go` @ `1c8140b`) plus the B46-4A changes below |
| `src/novasocks5.go` | Nova `novasocks5` proxy protocol, derived from upstream `proxy/socks5/socks5.go` @ the pin (MIT, see `UPSTREAM-LICENSE`), deviations marked `NOVA B46-4A` |
| `src/novasocks5_test.go` | B46-4A tests |
| `src/go.mod`, `src/go.sum` | standalone module `nova.pocvpn/tun2socks-child` (renamed from `nova.research/b46-3b-tun2socks-child`), same pins |

Upstream: `github.com/xjasonlyu/tun2socks/v2` `v2.0.0-20260913205830-5d9fac67bb10`
(commit `5d9fac67bb1095a5d2bd959216f85e6434524731`). Registered through the
public `proxy.RegisterProtocol` API; no upstream file is modified.

## B46-4A local SOCKS5 hardening

- The control header carries `socksUser`/`socksPass` (per-session, from the
  app); the child refuses to start without them or with a `socksAddr` that is
  not `127.0.0.1:<non-zero>`.
- Credentials are captured by the registering closure and never put in the
  proxy URL (the engine logs `novasocks5://127.0.0.1:<port>` only); the start
  log line prints address, protocol and `authenticated=true`, never secrets.
- UDP: the socket is bound to `127.0.0.1:0` before UDP ASSOCIATE and that exact
  address is declared in the request (never `0.0.0.0:0`, never bound on
  `0.0.0.0`).
- Every received datagram must come from the negotiated relay address
  (checked on the real network source); anything else is dropped.
- The success ack carries `"socksAuth": true`; the app refuses a success ack
  without it, so a pre-hardening child can never run unauthenticated.

Must ship together with the matching `hysteria2-child`: the hardened Hysteria
side refuses the `0.0.0.0:0` declaration an old tun2socks sends.

## Build (reproducible)

```bash
bash third_party/tun2socks-child/build-tun2socks-child.sh            # -> android/app/src/main/jniLibs/arm64-v8a/
bash third_party/tun2socks-child/build-tun2socks-child.sh /some/dir  # elsewhere
```

`GOTOOLCHAIN=go1.26.5`, `CGO_ENABLED=0 GOOS=android GOARCH=arm64`,
`GOFLAGS=-mod=readonly`, `go build -trimpath -buildvcs=false`. Sources must
be LF (`.gitattributes`; the script refuses CRLF).

## Provenance record (B46-4A, 2026-10-02)

| Field | Value |
|---|---|
| Upstream | `github.com/xjasonlyu/tun2socks/v2 v2.0.0-20260913205830-5d9fac67bb10` |
| Toolchain | `go1.26.5` (built on windows/amd64 and linux/amd64 hosts) |
| Target | `android/arm64`, ELF64 `EM_AARCH64`, PIE, `CGO_ENABLED=0` |
| SHA-256 (`libnovatun2sockschild.so`) | `15f95403a415035cba5226c297bf3818d99baadff40197d4ef83c478c8e2c381` |
| Reproducibility | identical on 2 Windows builds and 1 Linux (WSL) build |
| In APK (after AGP strip) | `bac1d93c8fa703635cf6ee8020d20ce24437707283c70b1f7d5f83a3b5448dc2` (debug and release) |

Superseded pre-hardening artifact: `3ee51b0bbfec55f3b1f05c7b55057110fda1d9b64187822b6efeb9621349621f`
(reproduced byte-for-byte from the B46-3B source before this change).
