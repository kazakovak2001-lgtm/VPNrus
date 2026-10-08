# B46-4P: Server-only Hysteria2 Prototype - Technical Evidence Report

> **Historical snapshot (written 2026-09-20/22, preserved 2026-10-09 from an uncommitted worktree).** Facts here describe that date; current status lives in `docs/ROADMAP.md`.

## 1. Scope and status

This document reports the results of a single technical experiment: build
a standalone Hysteria2 server binary directly against
`github.com/apernet/hysteria/core/v2/server`'s public library API, and
determine whether the resulting binary is free of the GPL-3.0-or-later
`github.com/apernet/sing-tun` / `github.com/sagernet/sing` dependencies
that `docs/B46_4P_HYSTERIA2_LICENSING_REVIEW.md` found in the official
unified `hysteria-linux-amd64` release binary.

```text
TECHNICAL QUESTION ONLY - NOT A LEGAL CONCLUSION.
NOT PRODUCTION CODE. NOT DEPLOYED. NOT AN OFFICIAL UPSTREAM ARTIFACT.
```

This experiment supersedes nothing in
`B46_4P_HYSTERIA2_LICENSING_REVIEW.md` (that document's sections 1-10
remain authoritative for the licensing evidence and open legal
questions) - it fills in the one item that document's section 7 marked
"not yet prototyped": Option B's actual feasibility, now with a real
build.

Prototype source: [`tools/hysteria-server-prototype/`](../tools/hysteria-server-prototype/)
(`main.go`, `go.mod`, `go.sum`, `README.md`).

## 2. Repository state

```text
Branch:                     feature/b46-4a-hysteria2-production-integration
HEAD before this pass:      4aad729f92fe34f078d7b036dd1fa059174a71c8
Working tree before pass:   clean
B37 (field-test/b37-awg31-upgrade worktree): untouched by this pass
Production code touched:    NO (gateway/api/handler.py, gateway/api/config.py,
                             gateway/api/tests/test_hysteria_profile_endpoint.py,
                             all Hysteria production deployment config,
                             Android, systemd, manifest, hostname, port: all
                             untouched)
```

## 3. Prototype

```text
Created:     this pass
Path:        tools/hysteria-server-prototype/
Module:      nova-hysteria-server-prototype
GOOS:        linux
GOARCH:      amd64
Go version:  go1.26.0 (matches core/v2's own `go 1.26.0` directive)
Build:       CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o hysteria-server-prototype-linux-amd64 .
Build host:  WSL Ubuntu (this project's existing Linux-verification
             environment for gateway/Python work - reused here for a
             genuine, non-cross-compiled linux/amd64 toolchain match)
```

Imports only `github.com/apernet/hysteria/core/v2/server` (MIT) and the Go
standard library. Never imports `github.com/apernet/hysteria/app/...`
(the upstream CLI package containing `client.go`/`app/internal/tun`),
`github.com/apernet/sing-tun`, or `github.com/sagernet/sing`.

Pinned to the exact same upstream commit already pinned in
`gateway/hysteria/VERSION` for the production server binary
(`e1366b173ccf5706e1e4630fe8aa654a4b574085` / tag `app/v2.12.3`) - `go get
github.com/apernet/hysteria/core/v2@e1366b173ccf5706e1e4630fe8aa654a4b574085`
resolved directly to the tagged release `v2.12.3` (not a pseudo-version),
confirming the pinned commit IS that release, consistent with the parent
licensing review's own tag->commit verification.

## 4. Binary evidence

```text
Static/dynamic: statically linked (file(1) confirms; CGO_ENABLED=0)
SHA256:         1184c06bc808002fd3d0b92b5d6e990a9cca112783603d24081bbd718d45e768
Size:           11763865 bytes
Build timestamp: this pass, 2026-09-22 (not reproducible-build-verified -
                 see README's own reproducibility caveat)
```

`go version -m` (full, unredacted):

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

## 5. GPL dependency result

```text
sing-tun:                ABSENT
sagernet/sing:           ABSENT
Other GPL/AGPL/LGPL/MPL:  NONE FOUND
```

Verified by four independent methods, all agreeing:

1. **`go version -m`** (Go's own embedded module-tracking metadata, read
   directly from the built binary) - neither package listed among the 14
   compiled-in dependencies (section 4 above, exhaustive, not filtered).
2. **`strings hysteria-server-prototype-linux-amd64 | grep -iE
   "sing-tun|sagernet"`** - zero matches (grep exit code 1).
3. **`go tool nm hysteria-server-prototype-linux-amd64 | grep -iE
   "sing-tun|sagernet"`** - zero matches (grep exit code 1).
4. **`go list -deps .`** (source-level import graph, computed before
   building) - zero matches (grep exit code 1).

Cross-checked against a same-pass re-download of the official
`hysteria-linux-amd64` v2.12.3 release asset (SHA-256
`8c7a68a906998b747a0db87586e364f995fbfddb95693ae6e2fdb68a6e920d3e`,
matching `gateway/hysteria/VERSION`'s pinned digest exactly), whose `go
version -m` **does** list both as `dep` entries - confirming the
prototype's build-graph difference is real, not a tooling artifact.

## 6. Module graph (relevant subset)

```text
tools/hysteria-server-prototype (main, Nova-authored, this pass)
 └── github.com/apernet/hysteria/core/v2/server        [MIT]
      ├── github.com/apernet/hysteria/core/v2/errors              [MIT, same module]
      ├── github.com/apernet/hysteria/core/v2/internal/congestion [MIT, same module]
      ├── github.com/apernet/hysteria/core/v2/internal/pmtud      [MIT, same module]
      ├── github.com/apernet/hysteria/core/v2/internal/utils      [MIT, same module]
      └── github.com/apernet/quic-go                    [fork of quic-go; upstream MIT -
                                                           this fork not independently
                                                           re-verified this pass, same
                                                           caveat as the parent licensing
                                                           review's section 3]
           └── (brotli, compress, qpack, utls, x/crypto, x/net, x/sys,
               x/text - see section 7 inventory)

 => ZERO edges anywhere in this graph to app/cmd, app/internal/tun,
    github.com/apernet/sing-tun, or github.com/sagernet/sing.
```

`core/v2`'s own `go.mod` (independently re-confirmed this pass by reading
the pinned-commit source tree directly, same as the parent licensing
review's section 4) requires only: `apernet/quic-go`, `stretchr/testify`,
`go.uber.org/goleak`, `golang.org/x/exp`, `golang.org/x/time` - zero
`sagernet`/`sing-tun` entries, at either direct or indirect level.

## 7. License inventory for the prototype's compiled-in dependency graph

Only the 14 dependencies `go version -m` reports as actually compiled
into the binary (section 4) are listed - not the broader `go.sum`
build list, which also includes test-only tooling (`testify`,
`go-cmp`, `gcassert`, etc.) that ships in `go.sum` for module-graph
resolution but is not linked into this binary (confirmed absent from the
`go version -m` dep list above, except `testify`/`objx`, which are pulled
in transitively as ordinary runtime deps of `core/v2/server` itself, not
test-only in this context - see note below).

| Module | Version | License | Reachable from prototype | Evidence |
|---|---|---|---|---|
| `github.com/apernet/hysteria/core/v2` | v2.12.3 | **MIT** | Yes (direct import) | `core/LICENSE.md` fetched directly at the pinned commit - same primary-source evidence as the parent licensing review's section 3, re-confirmed this pass (no change). |
| `github.com/andybalholm/brotli` | v1.1.0 | **MIT** | Yes (transitive, via quic-go's compression support) | Well-known public license (Andy Balholm's brotli Go port) - not independently refetched this pass; not GPL-family. |
| `github.com/apernet/quic-go` | v0.62.1-0.20260912175848-... | Fork of `quic-go` (upstream **MIT**) | Yes (direct dependency of `core/v2/server`) | Same caveat as the parent licensing review's section 3, row `quic-go`: not independently re-verified this pass whether apernet's fork changed the license; upstream `quic-go` is MIT. Not GPL-relevant to the sing-tun/sing question. |
| `github.com/klauspost/compress` | v1.17.9 | **Apache-2.0** (some files BSD-3) | Yes (transitive, via quic-go) | Well-known public license - not independently refetched this pass; not GPL-family. |
| `github.com/quic-go/qpack` | v0.6.0 | **MIT** | Yes (transitive, via quic-go, QPACK/HTTP3 support) | Well-known public license - not independently refetched this pass; not GPL-family. |
| `github.com/refraction-networking/utls` | v1.8.2 | **BSD-3-Clause** (fork of Go's own `crypto/tls`) | Yes (transitive, via quic-go) | Well-known public license - not independently refetched this pass; not GPL-family. |
| `github.com/stretchr/objx` | v0.5.3 | **MIT** | Yes (transitive) | Well-known public license - not independently refetched this pass; not GPL-family. |
| `github.com/stretchr/testify` | v1.12.1 | **MIT** | Yes (transitive - `core/v2/server` itself references testify-adjacent helpers outside `_test.go` files in this dependency closure; confirmed present in `go version -m`'s own `dep` list, not just `go.sum`) | Well-known public license - not independently refetched this pass; not GPL-family. |
| `go.yaml.in/yaml/v3` | v3.0.5 | **MIT / Apache-2.0** (dual, community continuation of `gopkg.in/yaml.v3`) | Yes (transitive) | Well-known public license - not independently refetched this pass; not GPL-family. |
| `golang.org/x/crypto` | v0.54.0 | **BSD-3-Clause** (Go project) | Yes (transitive) | Go project's own standard license - not independently refetched this pass; not GPL-family. |
| `golang.org/x/exp` | v0.0.0-20240506... | **BSD-3-Clause** (Go project) | Yes (transitive) | Same as above. |
| `golang.org/x/net` | v0.57.0 | **BSD-3-Clause** (Go project) | Yes (transitive) | Same as above. |
| `golang.org/x/sys` | v0.47.0 | **BSD-3-Clause** (Go project) | Yes (transitive) | Same as above. |
| `golang.org/x/text` | v0.40.0 | **BSD-3-Clause** (Go project) | Yes (transitive) | Same as above. |

**GPL / AGPL / LGPL / MPL scan result across this table: NONE FOUND.**
Every compiled-in dependency is MIT, Apache-2.0, or BSD-3-Clause. This
inventory covers the prototype's actual compiled-in graph exhaustively
(14 of 14 `go version -m` entries addressed above); it does not
re-verify by primary-source LICENSE-file fetch every row the way the
parent licensing review did for `core/v2` itself and for
`sing-tun`/`sagernet/sing` specifically - those rows marked "well-known
public license, not independently refetched this pass" carry that lower
evidence tier explicitly, consistent with the parent document's own
scoping decision (its section 3, closing row) not to re-verify every
non-GPL-relevant dependency.

## 8. Runtime test

```text
Starts:    YES - process starts, hyserver.NewServer succeeds
Listens:   YES - PROTOTYPE_LISTENING addr=127.0.0.1:58472 (OS-assigned
           ephemeral port, loopback only)
Serves:    YES - PROTOTYPE_ALIVE logged after Serve() has been running
           200ms with no error; ran for the full requested duration with
           no crash
Shutdown:  YES - graceful: Close() called, Serve() returns, process exits
           0
```

Full log (this pass, `-listen 127.0.0.1:0 -run-for 4s`):

```text
2026/09/22 05:32:41 PROTOTYPE_LISTENING addr=127.0.0.1:58472
2026/09/22 05:32:42 PROTOTYPE_ALIVE
2026/09/22 05:32:46 PROTOTYPE_AUTO_SHUTDOWN after=4s
2026/09/22 05:32:46 PROTOTYPE_SHUTDOWN_COMPLETE
```

Process exit code: `0`. Bound to `127.0.0.1` only (the binary itself
refuses to bind any non-loopback host - see `main.go`'s explicit check).
TLS certificate: generated fresh, in-memory, one-hour validity,
self-signed, never written to disk, never a production certificate. Auth
password: randomly generated per run if not supplied, never a production
credential. No production Stockholm IP, hostname, port, or credential was
used anywhere in this test.

**Not tested** (explicitly, not silently): a real Hysteria2 client
completing a QUIC handshake against this server; auth success/failure
under a real client; UDP relay correctness; Nova manifest/Android
integration. See `tools/hysteria-server-prototype/README.md`'s own
"Limitations" section.

## 9. Comparison

| Evidence | Official unified (`hysteria-linux-amd64` v2.12.3) | Server-only prototype |
|---|---|---|
| Hysteria version | app/v2.12.3 | Built against the same pinned commit / `core/v2 v2.12.3` |
| Linux amd64 | Yes | Yes |
| Static | Yes (confirmed via `file`) | Yes (confirmed via `file`, `CGO_ENABLED=0`) |
| `sing-tun` | **PRESENT** (`go version -m`: `v0.2.6-0.20250920121535-299f04629986`) | **ABSENT** (4 independent methods, section 5) |
| `sagernet/sing` | **PRESENT** (`go version -m`: `v0.3.2`) | **ABSENT** (4 independent methods, section 5) |
| Server API | Yes (`app/cmd/server.go`, full CLI) | Yes (direct `core/v2/server` library use, no CLI) |
| Client command | Yes (`app/cmd/client.go`, in the same binary) | **No client code at all** - `client` was never imported |
| TUN functionality | Yes (compiled in, via `app/internal/tun`, unreachable at runtime for a `server`-only invocation but present in the binary) | **No TUN code at all** - absent from the binary, not merely unreachable at runtime |

The key structural difference from the official binary: for the official
binary, `sing-tun`/`sagernet/sing` are *unreachable at runtime* when only
`hysteria server` is invoked, but still *physically present* in the
compiled artifact (per the parent licensing review's section 4). For this
prototype, they are *absent from the compiled artifact entirely*, because
the source-level import that pulls them in (`app/cmd/client.go` →
`app/internal/tun`) was never written into this binary's own `main`
package in the first place.

## 10. Technical conclusion

```text
SERVER-ONLY BUILD TECHNICALLY VERIFIED
```

A from-scratch, Nova-authored Go program built directly against
`github.com/apernet/hysteria/core/v2/server`'s public, MIT-licensed
library API compiles, links statically, starts, opens a UDP listener,
serves, and shuts down cleanly - and its compiled binary contains no
trace of `github.com/apernet/sing-tun` or `github.com/sagernet/sing` by
four independent verification methods, cross-checked against a same-pass
download of the official binary that does contain both.

## 11. Legal status

```text
LEGAL DECISION STILL REQUIRED
```

A confirmed GPL-free module graph for this one prototype is a technical
fact about this one binary. It is not a legal opinion about Hysteria2,
about `core/v2/server`'s license in every possible usage, or about
whether Option A (the current unified binary) is itself acceptable for
Nova's actual deployment model. The five open legal questions in
`B46_4P_HYSTERIA2_LICENSING_REVIEW.md` section 8 remain open and
unaffected by this experiment's result. Precisely because of this, this
document deliberately avoids the phrase "Hysteria2 server is MIT" -
the correct, narrower claim is: **this specific server-only prototype has
a verified module graph, by four independent methods, containing no
identified `sing-tun`/`sagernet/sing` GPL dependency.**

## 12. Production readiness

```text
NOT READY - LICENSING DECISION OPEN
```

Independent of the licensing question, this prototype is also not
production-ready on pure engineering grounds (see section 8's "Not
tested" list and the README's "Limitations" section): no real auth
backend integration, no ACME/cert-file wiring beyond a throwaway
self-signed test cert, no client-compatibility proof, no config-file
parsing, no wiring to any Nova deployment artifact
(`gateway/hysteria/render_server_config.py`, `nova-hysteria2.service`,
`hysteria_auth_backend.py`).

## 13. Single next step

**Predat legal review dvě konkrétní varianty: současný unified binary vs.
Nova-authored server-only binary, s přesným module/license evidence** -
this document plus `B46_4P_HYSTERIA2_LICENSING_REVIEW.md` together now
give legal counsel both a documented existing-binary dependency graph
(Option A) and a documented, actually-built alternative (Option B) to
weigh against the five open legal questions in the licensing review's
section 8. No further engineering work on Option B (auth integration,
ACME, config parsing, deployment wiring) should begin until that decision
is made - building it out further before the legal question is answered
would risk wasted or half-finished GPL-adjacent engineering effort, per
the licensing review's own section 10 closing note.
