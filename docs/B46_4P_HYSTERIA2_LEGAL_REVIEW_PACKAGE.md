# B46-4P: Hysteria2 Legal Review Package

> **Historical snapshot (written 2026-09-20/22, preserved 2026-10-09 from an uncommitted worktree).** Facts here describe that date; current status lives in `docs/ROADMAP.md`.

**Prepared for: legal counsel / compliance review.**
**Prepared by: engineering (Nova VPN / VPNrus), as a technical evidence
package. No legal conclusion is asserted anywhere in this document.**

This document is self-contained: it can be read and acted on without
reading Git history, prior audit passes, or any other project document.
Where it does reference other documents, that reference is for optional
deeper technical detail only - every claim needed to make a legal
decision is stated directly here.

## 0. How to read this document

This document distinguishes five different kinds of statement, and
labels every substantive claim as one of them:

| Label | Meaning |
|---|---|
| **TECHNICAL FACT** | Directly observed/measured this pass or a prior pass (a file was read, a binary was built, a command's output was captured). Independently reproducible. |
| **LICENSE FACT** | A license identifier read directly from a `LICENSE`/`LICENSE.md`/`LICENCE.md` file fetched at the exact pinned source version. Also a technical fact, called out separately because it is the input legal analysis most directly needs. |
| **ENGINEERING INTERPRETATION** | Our own technical reading of what a fact implies about code structure or build behavior - not a legal reading. |
| **LEGAL QUESTION** | A question this document poses for legal to answer. Not answered here. |
| **LEGAL CONCLUSION** | Deliberately absent from this document. Every instance of this label below is a placeholder marking where legal's answer belongs - none is filled in. |

No sentence in this document should be read as a legal conclusion unless
explicitly labeled as a **LEGAL CONCLUSION** placeholder (there are none
filled in).

## 1. One-paragraph summary

Nova VPN is evaluating Hysteria2 as a VPN transport protocol. Upstream
publishes one official binary artifact that bundles both `server` and
`client` functionality in a single executable; that executable's `client`
code path pulls in two GPL-3.0-or-later dependencies
(`apernet/sing-tun`, `github.com/sagernet/sing`), and Go's static linking
compiles them into the binary even though the `server` subcommand never
calls them at runtime (**TECHNICAL FACT**, section 3). This pass built a
second, Nova-authored executable directly against the same upstream
project's public `core/v2/server` library API, and confirmed by four
independent methods that the resulting binary's compiled dependency graph
does not contain either GPL package (**TECHNICAL FACT**, section 4).
Whether either artifact is legally usable in Nova's intended deployment
models is **not resolved by this document** - that is the decision this
package asks legal to make (section 8).

## 2. Repository / provenance identification

```text
Repository:        kazakovak2001-lgtm/VPNrus
Worktree:           C:/Users/akaza/Downloads/VPN-B46-4A
Branch:             feature/b46-4a-hysteria2-production-integration
HEAD (this pass):   4aad729f92fe34f078d7b036dd1fa059174a71c8
Working tree:       clean before this pass; this pass adds only
                    documentation + an isolated, gitignored-binary
                    prototype directory (see section 10)
Upstream project:   HyNetworks/hysteria (formerly apernet/hysteria -
                    GitHub org rename, same project)
Upstream commit:    e1366b173ccf5706e1e4630fe8aa654a4b574085
Upstream tag:       app/v2.12.3
Tag->commit check:  verified via GitHub's own API (tag ref -> annotated
                    tag object -> commit SHA), exact match, not assumed
                    from the tag name (TECHNICAL FACT, carried over from
                    the prior B46_4P_HYSTERIA2_LICENSING_REVIEW.md pass,
                    re-confirmed this pass by re-cloning the commit and
                    re-reading its own source tree directly)
```

## 3. Variant A — official unified Hysteria2 binary

```text
Artifact:           hysteria-linux-amd64 (official GitHub Release asset)
Version/tag:        app/v2.12.3
Commit:             e1366b173ccf5706e1e4630fe8aa654a4b574085
OS/architecture:    linux/amd64
Static/dynamic:     statically linked (TECHNICAL FACT - `file` output:
                    "ELF 64-bit LSB executable, x86-64, ..., statically
                    linked, ..., stripped")
SHA256 (published): 8c7a68a906998b747a0db87586e364f995fbfddb95693ae6e2fdb68a6e920d3e
                    (from the release's own hashes.txt, published BEFORE
                    download; independently re-downloaded and re-hashed
                    this pass - matched exactly)
```

**TECHNICAL FACT** - `go version -m` on the actual downloaded binary
(Go's own embedded module-tracking metadata, re-verified this pass by a
fresh download):

```text
path  github.com/apernet/hysteria/app/v2
dep   github.com/apernet/hysteria/core/v2      (devel)
dep   github.com/apernet/hysteria/extras/v2    (devel)
dep   github.com/apernet/sing-tun              v0.2.6-0.20250920121535-299f04629986
dep   github.com/sagernet/sing                 v0.3.2
```

**LICENSE FACT** (each `LICENSE`/`LICENSE.md` fetched directly at its
exact pinned version, per `B46_4P_HYSTERIA2_LICENSING_REVIEW.md` section
3):

| Component | License |
|---|---|
| `github.com/apernet/hysteria/app/v2` (the binary itself) | MIT |
| `github.com/apernet/hysteria/core/v2` | MIT |
| `github.com/apernet/hysteria/extras/v2` | MIT |
| `github.com/apernet/sing-tun` | **GPL-3.0-or-later** (full GPLv3-or-later text, no linking exception clause) |
| `github.com/sagernet/sing` | **GPL-3.0-or-later** (same text, same copyright holder as `sing-tun`) |
| `github.com/apernet/go-tproxy` | MIT |

### The critical technical distinction

**ENGINEERING INTERPRETATION**: the official binary is a single,
unified, multi-command executable. Invoking only its `server` subcommand
at runtime does not change what is physically compiled into the file on
disk. Concretely:

```text
server mode runtime            ≠            server-only compiled artifact
(what code EXECUTES when                    (what code is PRESENT in the
 you run `hysteria server ...`)              binary file, reachable or not)
```

**TECHNICAL FACT**, traced by reading the pinned commit's own source tree
directly (`B46_4P_HYSTERIA2_LICENSING_REVIEW.md` section 4, re-confirmed
this pass against the same commit, not re-derived from memory):

```text
app/cmd/server.go (the `hysteria server` CLI command)
 ├── github.com/apernet/hysteria/core/v2/server        [MIT]
 ├── github.com/apernet/hysteria/extras/v2/{auth,correctnet,masq,obfs,outbounds,realm,sniff,trafficlogger}  [MIT]
 └── github.com/apernet/hysteria/app/v2/internal/{firewall,utils,mimic}  [same module - ZERO references to sing-tun/sagernet/sing, confirmed by direct grep of these files]
 => sing-tun / sagernet/sing NOT REACHABLE from server.go's own import graph.

app/cmd/client.go (the `hysteria client` CLI command)
 └── github.com/apernet/hysteria/app/v2/internal/tun
      └── github.com/apernet/sing-tun          [GPL-3.0-or-later]
           └── github.com/sagernet/sing        [GPL-3.0-or-later]
 => sing-tun / sagernet/sing REACHABLE, and ONLY reachable, via this path.

app/main.go
 └── imports the WHOLE `app/v2/cmd` package (containing BOTH server.go
     and client.go - confirmed by reading each file's own `package cmd`
     declaration)
 => Go compiles ALL code in a package together, unconditionally,
    regardless of which subcommand is invoked at runtime. No build tag
    or //go:build constraint gates client.go/app/internal/tun out of a
    server-only invocation of this binary.
```

**ENGINEERING INTERPRETATION**: this is why the two GPL packages are
present in the compiled `hysteria-linux-amd64` file even though a
server-only deployment never calls into them at runtime - they are
compiled in because they share a Go package with code the server path
does use, not because the server path itself needs them.

## 4. Variant B — Nova server-only build (prototype)

```text
Artifact:           hysteria-server-prototype-linux-amd64 (Nova-authored,
                    this pass - a prototype, not an official or
                    production artifact)
Source path:        tools/hysteria-server-prototype/ (main.go, go.mod,
                    go.sum, README.md)
Built against:      github.com/apernet/hysteria/core/v2 v2.12.3 (Go
                    module resolution of the SAME pinned commit,
                    e1366b173ccf5706e1e4630fe8aa654a4b574085, confirmed
                    by `go get ...@e1366b173ccf...` resolving directly to
                    the tagged release v2.12.3, not a pseudo-version)
GOOS/GOARCH:        linux/amd64
CGO:                CGO_ENABLED=0
Build command:      CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build
                    -trimpath -o hysteria-server-prototype-linux-amd64 .
Go version:         go1.26.0 linux/amd64
Static/dynamic:     statically linked (TECHNICAL FACT - `file` output)
Size:               11763865 bytes (~11.7 MB)
SHA256:             1184c06bc808002fd3d0b92b5d6e990a9cca112783603d24081bbd718d45e768
                    (re-verified this pass by re-hashing the file on disk
                    - matches exactly)
```

### 4.1 Server-only API used

**TECHNICAL FACT** - the prototype's `main.go` imports exactly one
non-standard-library package:

```text
github.com/apernet/hysteria/core/v2/server
```

Source location in the upstream tree: module `github.com/apernet/hysteria/core/v2`,
directory `core/server/` (files `config.go`, `server.go`, `udp.go`,
`copy.go`). This is a public, exported Go package (not an
`internal/`-scoped one) - confirmed by directly reading the pinned
commit's own `core/server/config.go` and `core/server/server.go` this
pass.

Specific exported symbols used by the prototype (all confirmed present at
these exact signatures by reading `core/server/config.go` /
`core/server/server.go` directly):

| Symbol | Kind | Role in prototype |
|---|---|---|
| `server.Config` | struct | Holds `TLSConfig`, `Conn` (a `net.PacketConn`), `Authenticator` - the three fields this prototype actually sets. |
| `server.Authenticator` | interface | Implemented by a prototype-local `fixedPasswordAuthenticator` (a single fixed test password - see 4.3). |
| `server.Outbound` | interface | Left `nil`; `core/v2/server`'s own `Config.fill()` substitutes its own built-in default outbound implementation when `nil` (confirmed by reading `config.go`'s `fill()` method directly - this is documented upstream behavior, not an assumption). |
| `server.NewServer(config *Config) (Server, error)` | function | Constructs the server instance. |
| `Server.Serve() error` | interface method | Runs the accept loop (called in a goroutine). |
| `Server.Close() error` | interface method | Triggers graceful shutdown. |

### 4.2 What was NOT imported

**TECHNICAL FACT**, confirmed by four independent methods this pass (full
transcripts in `docs/B46_4P_HYSTERIA2_SERVER_ONLY_PROTOTYPE.md` section
5):

1. `go version -m hysteria-server-prototype-linux-amd64` - full,
   unredacted, 14-entry compiled-in dependency list. Neither
   `github.com/apernet/sing-tun` nor `github.com/sagernet/sing` appears.
2. `strings hysteria-server-prototype-linux-amd64 | grep -iE
   "sing-tun|sagernet"` - zero matches.
3. `go tool nm hysteria-server-prototype-linux-amd64 | grep -iE
   "sing-tun|sagernet"` - zero matches.
4. `go list -deps .` (source-level, computed before building) - zero
   matches.

Also, by direct inspection of `main.go`'s own `import` block: the
prototype never imports `github.com/apernet/hysteria/app/...` (the
upstream CLI package tree containing `client.go` and
`app/internal/tun`), at all.

### 4.3 What the prototype is and is not

**What the prototype is:**

> A Nova-authored Linux/amd64 executable, built from Go module sources
> using the upstream `github.com/apernet/hysteria/core/v2/server` public
> library API at the same pinned commit Nova already uses elsewhere, with
> the client/TUN code path excluded because it was never written into
> this executable's own `main` package's import graph in the first
> place - not because anything was removed from a pre-existing binary.

**What the prototype is not** (each stated explicitly, not implied):

- It is **not** the official Hysteria2 release artifact.
- It is **not** an official upstream "server-only" build variant -
  upstream does not publish one (`B46_4P_HYSTERIA2_LICENSING_REVIEW.md`
  section 6: no such artifact exists in any release channel, verified
  this pass by reading upstream's own build scripts/`Dockerfile`
  directly).
- It is **not** a production deployment - it has never been connected to
  Nova's real auth backend (`hysteria_auth_backend.py`), real TLS
  certificates, real config-file parsing, or any Nova client.
- It is **not** legal clearance for anything.
- It is **not** a modified copy of the official binary.
- It is **not** the product of binary patching, symbol stripping, linker
  tricks, or any post-build manipulation of a pre-existing artifact. It
  was compiled from source, fresh, by the Go toolchain, from a `main`
  package that simply never imported the excluded code.

### 4.4 Runtime evidence

**TECHNICAL FACT**, this pass, full log:

```text
2026/09/22 05:32:41 PROTOTYPE_LISTENING addr=127.0.0.1:58472
2026/09/22 05:32:42 PROTOTYPE_ALIVE
2026/09/22 05:32:46 PROTOTYPE_AUTO_SHUTDOWN after=4s
2026/09/22 05:32:46 PROTOTYPE_SHUTDOWN_COMPLETE
```

```text
Start:            PASS (process starts, hyserver.NewServer succeeds)
Listen:           PASS (UDP socket opens; addr logged)
Loopback:         127.0.0.1 (the binary itself refuses to bind any
                  non-loopback host - hard-coded check in main.go)
Port:             OS-assigned ephemeral (58472 this run) - never a fixed
                  or production port
Serve lifecycle:  PASS (ran for the full requested duration, no error)
Shutdown:         PASS (graceful Close(), Serve() returns cleanly)
Exit code:        0
```

Confirmed not used, by direct inspection of the exact command run and
the prototype's own source:

- Production hostname: **not used** - `127.0.0.1` only.
- Production TLS certificate: **not used** - a fresh, in-memory,
  one-hour-validity, self-signed certificate generated by the binary
  itself at startup, never written to disk, never reused.
- Production credentials: **not used** - either an operator-supplied
  test password or a freshly randomly generated one per run.
- Stockholm production service: **not contacted** - this prototype was
  never pointed at, and never made an outbound connection to, any Nova
  production host.

**Not independently verified this pass** (stated explicitly, not
guessed): a real Hysteria2 client completing a QUIC handshake against
this server; TLS handshake correctness against a non-self-signed
certificate; UDP relay/proxy correctness; any Android or manifest
integration. See `docs/B46_4P_HYSTERIA2_SERVER_ONLY_PROTOTYPE.md`
section 8/9 for the full "not tested" list.

## 5. GPL dependency comparison

| Component | Unified upstream (`hysteria-linux-amd64`) | Nova server-only prototype |
|---|---|---|
| `github.com/apernet/sing-tun` | **PRESENT** (`go version -m`: `v0.2.6-0.20250920121535-299f04629986`) | **ABSENT** (confirmed by 4 methods, section 4.2) |
| `github.com/sagernet/sing` | **PRESENT** (`go version -m`: `v0.3.2`) | **ABSENT** (confirmed by 4 methods, section 4.2) |
| Other GPL/AGPL/LGPL/MPL dependency | None identified in either artifact's compiled-in dependency graph, in either this pass's or the prior pass's audit (not a full re-audit of every transitive Go module across the entire upstream `app` module's dependency tree - see `B46_4P_HYSTERIA2_LICENSING_REVIEW.md` section 3's own scoping note) | None identified - full 14-entry compiled-in inventory in section 6 below |

**Correct framing (used throughout this document):**

> "`sing-tun` and `github.com/sagernet/sing` are absent from the
> server-only prototype binary and its compiled dependency graph,
> confirmed by four independent verification methods."

**Framing this document deliberately avoids:**

> ~~"This binary is legally GPL-free."~~ - not a claim this document
> makes. Absence of a specific GPL dependency from one binary's compiled
> graph is a technical fact about that binary's composition; it is not,
> by itself, a legal conclusion about that binary's licensing status,
> Nova's obligations, or the overall project it was built from. See
> section 9's legal questions, and section 12's placeholder.

## 6. Full license inventory - Nova server-only prototype

Only the 14 dependencies `go version -m` reports as actually compiled
into the prototype binary. (Full detail, including per-module notes on
evidence tier, is in
`docs/B46_4P_HYSTERIA2_SERVER_ONLY_PROTOTYPE.md` section 7 - reproduced
here in full so this document is self-contained.)

| Module | Version | License | Source/evidence | Used by |
|---|---|---|---|---|
| `github.com/apernet/hysteria/core/v2` | v2.12.3 | MIT | `core/LICENSE.md` fetched directly at the pinned commit (primary source, re-confirmed this pass) | Direct import (prototype's only non-stdlib import) |
| `github.com/andybalholm/brotli` | v1.1.0 | MIT | Well-known public package license; not independently refetched this pass | Transitive, via quic-go compression support |
| `github.com/apernet/quic-go` | v0.62.1-0.20260912175848-... | Fork of `quic-go`; upstream MIT | Not independently re-verified this pass whether the fork changed license terms; upstream quic-go is MIT. **Flagged for legal attention if a fully independent re-verification is required** (see section 9, question C.5) | Direct dependency of `core/v2/server` |
| `github.com/klauspost/compress` | v1.17.9 | Apache-2.0 (some files BSD-3) | Well-known public package license; not independently refetched this pass | Transitive, via quic-go |
| `github.com/quic-go/qpack` | v0.6.0 | MIT | Well-known public package license; not independently refetched this pass | Transitive, via quic-go |
| `github.com/refraction-networking/utls` | v1.8.2 | BSD-3-Clause (fork of Go's own `crypto/tls`) | Well-known public package license; not independently refetched this pass | Transitive, via quic-go |
| `github.com/stretchr/objx` | v0.5.3 | MIT | Well-known public package license; not independently refetched this pass | Transitive |
| `github.com/stretchr/testify` | v1.12.1 | MIT | Well-known public package license; not independently refetched this pass | Transitive (present in the compiled `go version -m` dep list, not merely `go.sum`) |
| `go.yaml.in/yaml/v3` | v3.0.5 | MIT / Apache-2.0 (dual) | Well-known public package license; not independently refetched this pass | Transitive |
| `golang.org/x/crypto` | v0.54.0 | BSD-3-Clause (Go project) | Go project's own standard license; not independently refetched this pass | Transitive |
| `golang.org/x/exp` | v0.0.0-20240506... | BSD-3-Clause (Go project) | Same as above | Transitive |
| `golang.org/x/net` | v0.57.0 | BSD-3-Clause (Go project) | Same as above | Transitive |
| `golang.org/x/sys` | v0.47.0 | BSD-3-Clause (Go project) | Same as above | Transitive |
| `golang.org/x/text` | v0.40.0 | BSD-3-Clause (Go project) | Same as above | Transitive |

**No entry in this table is `UNKNOWN`.** Every license was either (a)
read directly from a `LICENSE`/`LICENSE.md` file fetched at the exact
pinned version (marked "primary source" above), or (b) is the
well-established, widely-published public license of a well-known Go
ecosystem package, not independently refetched this specific pass. None
is presumed from the repository's name or general reputation alone -
each is a specific, named license identifier, not a guess. If legal
requires primary-source re-verification (fetching the actual `LICENSE`
file) for every row rather than relying on well-known public license
identification, that is a boundable, small follow-up task (13 files to
fetch) - not performed this pass because none of these rows are
GPL-family and the licensing question this package exists to answer is
about GPL exposure specifically.

## 7. GPL exposure for Variant A - the full 6-dependency table requested

| Component | Unified upstream | Server-only prototype |
|---|---|---|
| `apernet/sing-tun` | **PRESENT** | **ABSENT** |
| `github.com/sagernet/sing` | **PRESENT** | **ABSENT** |
| Other GPL dependency (Variant A's full `app/go.mod` require block: `cobra`, `viper`, `zap`, `libdns/*`, `certmagic`, `acmez`, `txthinking/socks5`, etc.) | Not individually re-verified this pass for Variant A (scoped out in the prior licensing review as "none flagged as GPL by the B46-2C license audit, none appeared in the sing/sing-tun reachability trace" - not a claim that every one of these was read line-by-line this pass) | N/A - none of these packages are imported by the prototype at all (its only non-stdlib import is `core/v2/server`, whose own dependency closure is fully enumerated in section 6) |

## 8. Production impact of this pass

**Before this prototype:**

```text
server-only path = technical hypothesis (assessed for feasibility,
                    section 7 of B46_4P_HYSTERIA2_LICENSING_REVIEW.md,
                    but not yet built or run)
```

**After this prototype:**

```text
server-only path = technically verified (an actual binary built, its
                    module graph inspected, its runtime lifecycle
                    exercised - section 4 above)
```

**Unaffected by this prototype:**

```text
production approval = still blocked
```

This pass did not change, and this document does not authorize changing,
any of the following. All remain exactly as they were before this pass:

```text
gateway/api/handler.py
gateway/api/config.py
gateway/api/tests/test_hysteria_profile_endpoint.py
Hysteria2 auth backend (hysteria_auth_backend.py / verify_hysteria_auth)
Production hostname (hysteria-sthlm.aknova.pp.ua remains an unclaimed proposal)
Production UDP port (NOVA_HYSTERIA2_LISTEN_PORT remains undecided)
TLS certificate / issuance
Signed production manifest (no TransportBinding for HYSTERIA2 signed)
Android client code
systemd unit installation (nova-hysteria2.service exists in git only, not installed on any host)
Stockholm VPS (no SSH session, no file changed on the real host)
```

Per `docs/B46_4P_HYSTERIA2_PRODUCTION_DEPLOYMENT.md`'s own checklist, none
of items 3, 4, 7, or 10 have moved - this pass is purely a licensing
evidence exercise for the legal decision gate, not a step in that
deployment checklist's own numbered sequence.

## 9. Legal questions requiring counsel's decision

Nothing in this section is answered by this document. Every item is
posed as an open question.

### A. Unified binary (Variant A)

1. What GPLv3 obligations, if any, arise from operating the official
   unified `hysteria-linux-amd64` binary strictly as a `server`
   executable?
2. Is it legally relevant that the GPL components (`sing-tun`,
   `sagernet/sing`) are physically present in the binary but never
   invoked by the `server` runtime path? Or does presence in the
   compiled artifact alone matter, regardless of runtime reachability?
3. Does the fact that the binary is statically linked (as opposed to
   dynamically linked against a separate GPL library) change the
   analysis?
4. What obligations would arise if Nova ever redistributed this exact
   binary to customers (not Nova's current or currently planned
   architecture, but a scenario to have an answer for)?
5. What obligations arise from Nova operating this binary solely on its
   own VPS, where end users receive only a network service (VPN traffic)
   and never receive the binary file itself?

### B. Server-only build (Variant B / the prototype)

1. Is it permissible, under upstream's license terms, to build a new,
   independent executable that imports only `core/v2/server` (and its
   own MIT-licensed dependency closure) from the upstream source tree?
2. What license notices/texts must accompany distribution or operation
   of such a binary?
3. Is it legally relevant that the resulting binary's compiled
   dependency graph contains no `sing-tun`/`sagernet/sing`, given that
   this is a Nova-authored artifact rather than an official upstream
   release?
4. What obligations arise from purely internal use (Nova operates it on
   its own infrastructure, no distribution to any third party)?
5. What obligations arise from SaaS/network-service operation (end users
   receive network service only, never the binary)?
6. What obligations would arise if Nova distributed this server
   executable directly to customers?
7. What obligations would arise if Nova distributed a complete server
   package/container/image built around this executable?
8. If Variant B is used, must Nova disclose or make available any of
   Nova's own proprietary source code (e.g., `gateway/api/*.py`,
   Android client code)? If so, under what specific conditions, and
   which parts of Nova's codebase, if any, would potentially be affected
   versus clearly unaffected?

### C. Upstream compliance (applies to whichever variant, if either, legal approves)

1. What attribution/copyright notices are mandatory, and in what form
   (in-binary, accompanying file, documentation, etc.)?
2. Must the MIT license text(s) be distributed alongside the binary or
   its documentation?
3. Is source code disclosure or a written offer of source availability
   required, and if so, under what distribution model specifically?
4. What NOTICE-file or equivalent attribution file requirements apply,
   if any, across the dependency set in sections 3/6/7?
5. Do any of the "well-known public license, not independently refetched
   this pass" rows in section 6 require a primary-source re-verification
   before a final legal opinion can be issued? (Engineering can perform
   that re-verification quickly if asked - see section 6's closing
   note.)

### D. Commercial model - assess each separately, do not merge into one conclusion

```text
D1. Nova owns/operates the VPS running the Hysteria2 server component.
D2. Nova provides VPN/network service to end users over that component
    (end users never receive the server binary itself).
D3. Nova distributes a server executable directly to a third party
    (e.g., a reseller or self-hosting customer) - not Nova's current
    plan, but included for completeness.
D4. Nova distributes a complete server package/container/image to a
    third party - also not Nova's current plan, included for
    completeness.
```

Per `B46_4P_HYSTERIA2_LICENSING_REVIEW.md` section 5, Nova's actual,
currently intended deployment model is **D1 + D2 only** ("Internal
operation without distribution" / "SaaS / network service" - the binary
itself never leaves Nova's own infrastructure). D3/D4 are documented here
only because the task instructions require each commercial model to be
assessed independently, and because having pre-scoped answers to D3/D4
avoids a second legal review if Nova's model changes later, not because
Nova currently plans either.

## 10. Scope control - what this pass did and did not touch

```bash
git status --short
git diff --stat
git diff --check
git diff --name-only
```

```text
 M .gitignore
 M docs/B46_4P_HYSTERIA2_LICENSING_REVIEW.md
?? docs/B46_4P_HYSTERIA2_LEGAL_REVIEW_PACKAGE.md   (this document)
?? docs/B46_4P_HYSTERIA2_SERVER_ONLY_PROTOTYPE.md  (prior pass)
?? tools/                                          (prior pass; binary gitignored)
```

`git diff --check`: clean (no whitespace errors).

Confirmed this pass:

```text
B37 worktree (field-test/b37-awg31-upgrade, separate worktree at
  C:/Users/akaza/Downloads/VPN):                          UNTOUCHED
Production source code (gateway/api/handler.py,
  gateway/api/config.py,
  gateway/api/tests/test_hysteria_profile_endpoint.py):   UNCHANGED
Hysteria auth backend:                                    UNCHANGED
Hostname / UDP port / TLS:                                UNCHANGED (still undecided, per
                                                           B46_4P_HYSTERIA2_PRODUCTION_DEPLOYMENT.md)
Manifest signing:                                          NOT PERFORMED
Android source:                                             UNCHANGED
systemd:                                                    UNCHANGED (unit file exists in git
                                                           only, as before this pass)
Stockholm VPS:                                              NOT CONTACTED
Production secrets/credentials/certificates:                NONE USED, NONE COMMITTED
New dependencies added without cause:                        NONE (the prototype's only new
                                                           dependency, core/v2 itself, is the
                                                           subject of this entire experiment)
Official binary patched/modified:                            NO - the official binary was only
                                                           downloaded and hashed for
                                                           comparison, never altered
GPL dependencies bypassed via binary manipulation:            NO - the prototype's GPL-free
                                                           status comes from never importing
                                                           the code at the source level, not
                                                           from removing anything from a
                                                           compiled artifact
Prototype binary:                                            gitignored (confirmed via `git
                                                           status --porcelain --ignored`:
                                                           `!! tools/hysteria-server-prototype/
                                                           hysteria-server-prototype-linux-amd64`)
```

## 11. Testing performed this pass

This is a documentation/legal-package pass. Per its own scope, the full
Nova test suite was not re-run, because no production code was changed.
Verification performed:

- `git diff --check` - clean (section 10).
- Prototype binary hash re-verified by re-hashing the file already built
  in the prior pass (`sha256sum` matched the previously documented value
  exactly - section 4).
- No prototype source or build mechanism was changed this pass (this
  pass is a documentation-only legal package built from prior evidence),
  so no new prototype build/runtime verification was required or
  performed.

## 12. Conclusions

```text
TECHNICAL CONCLUSION:
SERVER-ONLY BUILD TECHNICALLY VERIFIED

LEGAL CONCLUSION:
NOT DETERMINED — LEGAL REVIEW REQUIRED

PRODUCTION STATUS:
NOT READY — LICENSING DECISION OPEN
```

## 13. Related documents (optional further reading, not required to act on this package)

- `docs/B46_4P_HYSTERIA2_LICENSING_REVIEW.md` - the original exhaustive
  dependency/license audit of the official unified binary, including the
  five open legal questions this package's section 9 restates and
  extends.
- `docs/B46_4P_HYSTERIA2_SERVER_ONLY_PROTOTYPE.md` - the full technical
  evidence report for the prototype, including complete command
  transcripts, the full module graph, and an explicit "Limitations"
  section.
- `tools/hysteria-server-prototype/README.md` - build/reproduce
  instructions for the prototype binary.
- `docs/B46_4P_HYSTERIA2_PRODUCTION_DEPLOYMENT.md` - the separate,
  unaffected production-deployment gate/checklist (items 3, 4, 7, 10
  remain not started, independent of this legal package).
