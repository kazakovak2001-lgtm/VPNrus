# hysteria-server-prototype (B46-4P research prototype)

**Not production code. Not an official upstream artifact. Not wired into
any Nova build, deployment, or release process.** This is a standalone
experiment answering one narrow technical question for the B46-4P
licensing investigation:

> Can a standalone Hysteria2 server binary be built directly against
> `github.com/apernet/hysteria/core/v2/server`'s public library API,
> without `github.com/apernet/hysteria/app/...` (the upstream CLI),
> `github.com/apernet/sing-tun`, or `github.com/sagernet/sing` - at either
> the source or compiled-binary level?

See `docs/B46_4P_HYSTERIA2_SERVER_ONLY_PROTOTYPE.md` and
`docs/B46_4P_HYSTERIA2_LICENSING_REVIEW.md` section 7A for the full
evidence this binary was built to produce. **This is a technical
feasibility experiment only - it does not resolve the legal question. See
those documents' own "Legal status" sections.**

## What this is

`main.go` is a from-scratch, Nova-authored `package main` that imports
only:

- `github.com/apernet/hysteria/core/v2/server` (MIT) - the upstream
  server library
- the Go standard library

It never imports `github.com/apernet/hysteria/app/...`,
`github.com/apernet/sing-tun`, or `github.com/sagernet/sing`, directly or
transitively.

Lifecycle implemented: `config -> hyserver.NewServer -> Serve()
(goroutine) -> wait for signal or timeout -> Close() -> wait for Serve()
to return`. Nothing else. In particular this prototype does NOT implement:

- Nova's real `auth.type: http` design (`gateway/hysteria/render_server_config.py`,
  `hysteria_auth_backend.py`) - it uses a single fixed in-memory password
  instead, only to prove a connection attempt reaches the `Authenticator`
  hook at all.
- ACME/masquerade/DNS-provider/obfuscation/bandwidth/congestion
  configuration - all left at library defaults.
- Any client-compatibility, TLS-handshake-completion, or UDP-proxy
  correctness test. See "Limitations" below.

## Build

Pinned to the exact same upstream commit already pinned in
`gateway/hysteria/VERSION` for the server-side runtime
(`e1366b173ccf5706e1e4630fe8aa654a4b574085` / tag `app/v2.12.3`), resolved
by Go's module system to `github.com/apernet/hysteria/core/v2 v2.12.3`
(see `go.mod`/`go.sum` in this directory - the pinned commit IS that
tagged release, confirmed by `go get ...@e1366b173ccf...` resolving to
`v2.12.3` directly, not a pseudo-version).

```bash
cd tools/hysteria-server-prototype
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
  -o hysteria-server-prototype-linux-amd64 .
```

Built and verified this pass with `go1.26.0 linux/amd64` (matches
`core/v2`'s own `go 1.26.0` directive and the WSL Ubuntu toolchain already
used elsewhere in this project for Linux-target verification, e.g.
`docs/B46_4P_HYSTERIA2_PRODUCTION_DEPLOYMENT.md`'s own gateway test runs).

The resulting binary is gitignored (reproducible from `go.mod`/`go.sum` +
`main.go` - same convention as the B45A/B45B-3P locally-built binaries
already gitignored in this repo's `.gitignore`, see the comment there).

## Binary evidence (this pass)

```text
File:      hysteria-server-prototype-linux-amd64
GOOS:      linux
GOARCH:    amd64
Go:        go1.26.0
CGO:       disabled
Static:    yes (file(1): "statically linked")
SHA256:    1184c06bc808002fd3d0b92b5d6e990a9cca112783603d24081bbd718d45e768
Size:      11763865 bytes
```

Reproducibility: the build is deterministic in dependency content
(`go.sum` pins every module's exact hash) but this pass did NOT verify
byte-for-byte reproducibility across independent builds/machines - not
claimed as reproducible in that stronger sense, only as "rebuildable from
pinned inputs".

## Module graph (`go version -m`, this pass)

```text
hysteria-server-prototype-linux-amd64: go1.26.0
	path	nova-hysteria-server-prototype
	dep	github.com/andybalholm/brotli	v1.1.0
	dep	github.com/apernet/hysteria/core/v2	v2.12.3
	dep	github.com/apernet/quic-go	v0.62.1-0.20260912175848-73339f7edbb9
	dep	github.com/klauspost/compress	v1.17.9
	dep	github.com/quic-go/qpack	v0.6.0
	dep	github.com/refraction-networking/utls	v1.8.2
	dep	github.com/stretchr/objx	v0.5.3
	dep	github.com/stretchr/testify	v1.12.1
	dep	go.yaml.in/yaml/v3	v3.0.5
	dep	golang.org/x/crypto	v0.54.0
	dep	golang.org/x/exp	v0.0.0-20240506185415-9bf2ced13842
	dep	golang.org/x/net	v0.57.0
	dep	golang.org/x/sys	v0.47.0
	dep	golang.org/x/text	v0.40.0
	build	-buildmode=exe
	build	CGO_ENABLED=0
	build	GOARCH=amd64
	build	GOOS=linux
```

`github.com/apernet/sing-tun` and `github.com/sagernet/sing`: **ABSENT**
(exhaustive list above - not filtered/redacted).

Cross-checked by three independent methods, all agreeing (see the parent
docs for full transcripts):

1. `go version -m <binary>` (Go's own embedded module metadata) - absent.
2. `strings <binary> | grep -iE "sing-tun|sagernet"` - zero matches.
3. `go tool nm <binary> | grep -iE "sing-tun|sagernet"` - zero matches.
4. `go list -deps .` (source-level dependency graph, pre-build) - zero
   matches.

Confirmed by direct diff against the same-pass download of the official
`hysteria-linux-amd64` v2.12.3 release asset (SHA-256
`8c7a68a906998b747a0db87586e364f995fbfddb95693ae6e2fdb68a6e920d3e`,
matching `gateway/hysteria/VERSION`'s own pinned digest exactly), whose
`go version -m` DOES list both:

```text
dep   github.com/apernet/sing-tun   v0.2.6-0.20250920121535-299f04629986
dep   github.com/sagernet/sing      v0.3.2
```

## Runtime test (this pass, local loopback only)

```bash
./hysteria-server-prototype-linux-amd64 -listen 127.0.0.1:0 -run-for 4s
```

```text
2026/09/22 05:32:41 PROTOTYPE_LISTENING addr=127.0.0.1:58472
2026/09/22 05:32:42 PROTOTYPE_ALIVE
2026/09/22 05:32:46 PROTOTYPE_AUTO_SHUTDOWN after=4s
2026/09/22 05:32:46 PROTOTYPE_SHUTDOWN_COMPLETE
```

Process exit code: `0`. Run against `127.0.0.1` on an OS-assigned
ephemeral port only, with an in-memory, never-persisted, one-hour-validity
self-signed test certificate generated fresh by the binary itself at
startup (`generateEphemeralSelfSignedCert` in `main.go`) - never a
production certificate, hostname, port, or credential.

**This proves only**: the process starts, `hyserver.NewServer` succeeds,
the UDP listener opens, `Serve()` runs without erroring, and `Close()`
shuts it down cleanly. It does **not** prove a real Hysteria2 client can
successfully complete a QUIC handshake against it, that auth/TLS/UDP
proxying work end-to-end, or any Android/manifest/production behavior -
see "Limitations".

## Limitations - what this prototype does NOT prove

- No real Hysteria2 client connection was attempted against this
  prototype this pass (no QUIC handshake completion, no auth success/
  failure exercised beyond the `Authenticator` interface being wired at
  all, no UDP relay correctness).
- No TLS client-compatibility test (the self-signed cert is for local
  loopback listen-only evidence, not a handshake-completion proof).
- No Android/manifest/production integration - this binary is
  API-compatible in principle but was never connected to
  `gateway/hysteria/render_server_config.py`'s real config shape,
  `hysteria_auth_backend.py`'s real `auth.type: http` callback, or any
  Nova client.
- Not a drop-in replacement for the official CLI: no ACME, no masquerade,
  no config file parsing, no CLI flags beyond the four listed above - a
  real production server-only build would need meaningfully more code
  (see the licensing review's own Option B engineering-cost estimate).

## Reproduce

```bash
cd tools/hysteria-server-prototype
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
  -o hysteria-server-prototype-linux-amd64 .
go version -m hysteria-server-prototype-linux-amd64
sha256sum hysteria-server-prototype-linux-amd64
./hysteria-server-prototype-linux-amd64 -listen 127.0.0.1:0 -run-for 4s
```
