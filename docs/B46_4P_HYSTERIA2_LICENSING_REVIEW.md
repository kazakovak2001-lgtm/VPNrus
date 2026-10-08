# B46-4P: Hysteria2 Server Binary — Licensing Review

> **Historical snapshot (written 2026-09-20/22, preserved 2026-10-09 from an uncommitted worktree).** Facts here describe that date; current status lives in `docs/ROADMAP.md`.

## 1. Scope

This document exists to answer one narrow, well-defined question with technical evidence only:

> Does Nova VPN have a technically usable Hysteria2 server artifact it can distribute/operate in its intended model without an unresolved licensing risk?

It does **not** answer that question itself. It separates **technical fact** from **legal interpretation**, states the **exact legal question** the repository owner/legal counsel must answer, and lays out the **technical options** that remain open regardless of how that question is answered. No production deployment, hostname, port, TLS, or manifest work is touched by this document or this pass — see `docs/B46_4P_HYSTERIA2_PRODUCTION_DEPLOYMENT.md` for that separate track, unaffected by this slice.

All evidence below was gathered directly from upstream primary sources this pass: the pinned commit's own source tree (`HyNetworks/hysteria` at `e1366b173ccf5706e1e4630fe8aa654a4b574085` / tag `app/v2.12.3`), its own `go.mod`/`go.sum`, its own GitHub Actions build scripts (`hyperbole.py`, `platforms.txt`, `Dockerfile`), its own official GitHub Release assets and their published checksums, each dependency's own `LICENSE` file fetched at its exact pinned version, and Go's own embedded build-info metadata (`go version -m`) read directly from the actual downloaded official release binary. No blog, forum post, or SEO article was used as evidence for any technical or licensing claim in this document.

## 2. Current binary composition

```text
Binary:         hysteria-linux-amd64
Version/tag:    app/v2.12.3
Commit:         e1366b173ccf5706e1e4630fe8aa654a4b574085
                (verified this pass and previously: GitHub API tag ref -> annotated
                tag object -> commit, exact match, not assumed from the tag name)
Platform:       linux/amd64 (matches Stockholm's real AWS eu-north-1 host architecture)
Static/dynamic: statically linked (confirmed via `file`: "ELF 64-bit LSB executable,
                x86-64, ..., statically linked, ..., stripped")
Published SHA-256: 8c7a68a906998b747a0db87586e364f995fbfddb95693ae6e2fdb68a6e920d3e
                (from the release's own hashes.txt, published BEFORE download;
                independently re-downloaded and re-hashed this pass and previously -
                matched exactly both times)
```

## 3. Dependency / license inventory

| Component | Version (pinned) | License | Direct/Transitive (of `app` module) | In server (`cmd server`) binary reachability graph | Evidence |
|---|---|---|---|---|---|
| `github.com/apernet/hysteria/app/v2` (Hysteria2 itself) | `app/v2.12.3` | **MIT** | — (the module itself) | Yes (it IS the binary) | `app/LICENSE.md` fetched directly at pinned commit - standard MIT text, copyright "Toby" 2023. |
| `github.com/apernet/hysteria/core/v2` | in-repo, same commit | **MIT** | Direct | Yes (server.go directly imports `core/v2/server`) | `core/LICENSE.md` fetched directly - same MIT text/copyright. |
| `github.com/apernet/hysteria/extras/v2` | in-repo, same commit | **MIT** | Direct | Yes (server.go directly imports six `extras/v2/*` packages) | `extras/LICENSE.md` fetched directly - same MIT text/copyright. |
| `github.com/apernet/sing-tun` | `v0.2.6-0.20250920121535-299f04629986` | **GPL-3.0-or-later** | Direct (listed in `app/go.mod`'s own `require` block, not `// indirect`) | **No** at source level from `server.go`'s own import graph - only reachable via `app/cmd/client.go` | `LICENSE` fetched directly at the exact pinned pseudo-version commit (`299f04629986`) - full GPLv3-or-later text, copyright nekohasekai/sagernet 2022, no linking exception clause. `go version -m` on the actual downloaded release binary lists it as a compiled-in `dep` (authoritative - Go's own embedded build metadata, not a symbol-name heuristic). |
| `github.com/sagernet/sing` | `v0.3.2` | **GPL-3.0-or-later** | Direct (listed in `app/go.mod`'s own `require` block) | **No** at source level from `server.go`'s own import graph - only reachable via `app/internal/tun` (imported only by `client.go`) | `LICENSE` fetched directly at the pinned tag (`v0.3.2`) - **same GPLv3-or-later text as `sing-tun`, same copyright holder** (a NEWLY CONFIRMED finding this pass - the base "sing" library itself, not just its "tun" extension, is also GPL). `go version -m` on the actual binary confirms it is compiled in. |
| `github.com/apernet/go-tproxy` | `8f4723fd742f...` | **MIT** | Direct | Not determined this pass which exact package uses it (not GPL-relevant, not investigated further) | `LICENCE.md` (British spelling) fetched directly at the pinned commit. |
| `github.com/apernet/quic-go` | `v0.62.1-...` | Not verified this pass | Indirect | Presumed yes (server needs QUIC) | Not fetched - not GPL-relevant to the question at hand (a fork of `quic-go`, upstream `quic-go` is MIT/Apache-2.0-family; this project's own fork was not independently re-checked this pass since it does not change the sing-tun/sing finding). |
| Everything else in `app/go.mod`'s `require` block (cobra, viper, zap, libdns/\*, certmagic, acmez, txthinking/socks5, ...) | various | Not individually re-verified this pass | Direct/Indirect | Server.go imports several of these (cobra, viper, zap, certmagic/acmez/libdns for its own ACME feature) | Out of scope for THIS question - none of these were flagged as GPL by the B46-2C license audit this project already performed, and none appeared in the `sing`/`sing-tun` reachability trace. A full re-audit of every one of these was not performed this pass (would be a much larger, separate task with no bearing on the sing-tun/sing question). |

## 4. Build graph

Traced exhaustively this pass by downloading the full pinned-commit source tree and grepping it directly (not inferred from documentation) - both the `import` statements in every relevant file AND each module's own `go.mod` `require` list:

```text
app/cmd/server.go (1874 lines - the `hysteria server` CLI command)
 ├── github.com/apernet/hysteria/core/v2/server        [MIT, clean]
 ├── github.com/apernet/hysteria/extras/v2/{auth,correctnet,masq,obfs,outbounds,realm,sniff,trafficlogger}  [MIT, clean]
 ├── github.com/apernet/hysteria/app/v2/internal/{firewall,utils,mimic}  [same module, grepped directly: ZERO references to sing-tun or sagernet/sing]
 ├── github.com/caddyserver/certmagic, github.com/mholt/acmez, github.com/libdns/*  [ACME/DNS-provider libs, not GPL, not investigated further]
 ├── github.com/spf13/cobra, github.com/spf13/viper, go.uber.org/zap  [CLI/config/logging, not GPL]
 └── (transitively, via core/v2 and extras/v2's OWN go.mod files, independently checked: ZERO occurrences of "sagernet" or "sing-tun" anywhere in either)
 => sing-tun / sagernet/sing: NOT REACHABLE from server.go's own source-level import graph.

app/cmd/client.go (1548 lines - the `hysteria client` CLI command)
 └── github.com/apernet/hysteria/app/v2/internal/tun
      └── github.com/apernet/sing-tun          [GPL-3.0-or-later]
           └── github.com/sagernet/sing        [GPL-3.0-or-later, also used directly by app/internal/tun's own log.go/server.go]
 => sing-tun / sagernet/sing: REACHABLE, and ONLY reachable, via this one path.

app/main.go (the ONE and ONLY `main` package in the entire `app` module)
 └── imports the WHOLE `app/v2/cmd` package (which is package `cmd`, containing
     BOTH server.go and client.go - confirmed by reading each file's own
     `package cmd` declaration)
 => Go compiles ALL code in a package together, unconditionally, regardless of
    which registered cobra subcommand a user actually invokes at runtime. There
    is no existing build tag, no `//go:build` constraint, anywhere in
    app/cmd/client.go or app/internal/tun gating them out of a `server`-only build.
```

**`go version -m` on the actual official release binary** (Go's own embedded module-tracking metadata, read this pass directly from the downloaded `hysteria-linux-amd64` asset - the single most authoritative confirmation available, stronger than a symbol-name grep):

```text
path  github.com/apernet/hysteria/app/v2
dep   github.com/apernet/hysteria/core/v2      (devel)
dep   github.com/apernet/hysteria/extras/v2    (devel)
dep   github.com/apernet/sing-tun              v0.2.6-0.20250920121535-299f04629986
dep   github.com/sagernet/sing                 v0.3.2
```

**Conclusion, source-level, exhaustively verified**: `server.go`'s own dependency graph is genuinely, entirely free of the GPL-licensed code. Both GPL packages are compiled into the SAME final binary artifact *only* because Go links one package (`cmd`) as a single unit, and that package also contains `client.go`.

## 5. Distribution scenarios

Analyzed separately, as raw scenario descriptions only - **no legal conclusion drawn for any of them**:

| Scenario | Description |
|---|---|
| Own VPS only | Nova installs the official `hysteria-linux-amd64` binary on its own Stockholm server, runs `hysteria server ...`, and never hands the binary file itself to any third party. |
| Customer distribution | Not applicable to this binary in Nova's current architecture - the binary itself is never shipped to an end user's device (the Android app is a SEPARATE artifact - see below). |
| Android app | Nova's Android app does NOT embed or ship this `hysteria-linux-amd64` binary at all - it embeds a SEPARATE, independently-built Go binary (`libnovahysteriachild.so`, built by this project from the SAME upstream source at the SAME pinned commit, but as a minimal from-scratch client per B46-2C, confirmed at that time to contain zero `sing-tun`/`sagernet/sing` symbols via `go tool nm`/`strings`). This scenario is about a DIFFERENT artifact than the one this document is about. |
| SaaS / network service | Nova's own users connect to the Hysteria2 protocol as a network service (they never receive the server binary itself, only network packets/a VPN tunnel) - this is the scenario Nova's actual production deployment would be. |
| Server package distribution | Not applicable - Nova does not currently plan to distribute this server binary or package to any third party (e.g., a reseller, a self-hosting customer). |
| Internal operation without distribution | The specific real scenario Stockholm's deployment would be: Nova installs and runs the binary on infrastructure it operates, for its own service, with no copy of the binary ever leaving Nova's own infrastructure. |

## 6. Official upstream artifacts

| Artifact | Official | Server-only | `sing-tun`/`sing` included | Platform |
|---|---|---|---|---|
| `hysteria-linux-amd64` (and every other `hysteria-<os>-<arch>` release asset - all ~28 of them, one per OS/ARCH combination in `platforms.txt`) | Yes | **No** - single unified CLI (`server`+`client`+`client-tun`+`server-acme`+... all in one binary) | Yes (confirmed via `go version -m`, this specific asset) | All (Windows/macOS/Linux/Android/FreeBSD, multiple architectures) |
| Docker image (`ghcr.io`/similar, via `.github/workflows/docker.yml` + `Dockerfile`) | Yes | **No** - the `Dockerfile` runs the SAME `python hyperbole.py build -r` as every other release asset, producing the SAME unified binary, then just copies it into an Alpine base image alongside `iptables`/`nftables` (needed for the client's tun mode) | Yes (same binary) | linux (whatever the Docker build host targets) |
| Alpine/Debian/RPM native packages | Not found - no evidence in the repository's own release/build tooling that upstream produces or publishes any OS-native package format | N/A | N/A | N/A |
| Source-only release / tarball | GitHub's own auto-generated source tarball exists for every tag (standard GitHub behavior, not upstream-authored tooling) | N/A - it's source, not a binary | N/A | N/A |

**Conclusion**: no official server-only artifact, in any form (binary, Docker image, OS package), exists anywhere in upstream's own release/build/CI tooling. Every distribution channel produces the identical unified binary.

## 7. Server-only build feasibility

```text
Technically possible:     YES, with reasonable confidence
Evidence:                 core/v2/server exposes a small, clean, dependency-light
                           public API (NewServer(config *Config) (Server, error),
                           Serve(), Close()) with NO sing-tun/sagernet/sing
                           dependency anywhere in its own module (core/go.mod has
                           zero "sagernet"/"sing-tun" references, verified this
                           pass). The `Config` struct itself is minimal: TLS
                           config, a plain net.PacketConn (no ACME/DNS-provider
                           machinery required - Nova would supply its own
                           already-issued certificate file path, exactly like
                           gateway/hysteria/render_server_config.py's own
                           tls_cert_file/tls_key_file design already assumes),
                           an Authenticator interface (Nova's existing auth.type:
                           http design, or a direct Go-level implementation
                           calling the SAME verify_hysteria_auth logic), an
                           Outbound interface (direct outbound suffices), and
                           optional Congestion/Bandwidth/Masquerade settings
                           (all safely omittable/nil for Nova's own minimal
                           architecture, matching gateway/hysteria/README.md's
                           own "no quic:/masquerade:/acl:/outbounds: block"
                           minimalism decision already made independently of
                           this licensing question).
Confidence:                Confirmed by an actual build this pass - see
                           section 7A below and the dedicated
                           B46_4P_HYSTERIA2_SERVER_ONLY_PROTOTYPE.md - not
                           merely a structural/API-level assessment
                           anymore. app/cmd/server.go's
                           own 1874 lines are overwhelmingly CLI/config-parsing/
                           ACME/masquerade/DNS-provider glue that Nova's own
                           minimal architecture does not need at all - a
                           from-scratch, much smaller wrapper directly against
                           core/v2/server's own public API is the realistic path,
                           NOT attempting to strip client.go out of the existing
                           app/cmd package (which would require forking and
                           maintaining upstream's own CLI package).
Upstream-supported:        NO - this would be entirely Nova-authored code against
                           upstream's own core/v2/server library API (which IS a
                           stable, intentionally-public, MIT-licensed interface -
                           not a private/internal package), not a build flag or
                           configuration upstream itself provides or supports.
```

This mirrors a methodology this project has **already successfully executed once**: B46-2C built a "minimal Hysteria2 SOCKS5-only client" directly against `core/v2/client` + `app/internal/socks5`, deliberately bypassing the full `hysteria` CLI and its own `app/internal/tun` import, and proved via four independent methods (`go list -deps`, `go version -m`, `go tool nm` on both host and Android-arm64 builds, and a binary `strings` scan) that the resulting artifact contained zero `sing-tun`/`app/internal/tun` symbols. The identical methodology, applied to `core/v2/server` instead of `core/v2/client`, is the concrete technical path for Option B below - not a novel, unproven idea for this project, but a repeat of a pattern it has already carried out and verified once.

## 7A. Server-only prototype evidence

A from-scratch server-only build was actually attempted this pass (not
just assessed for feasibility as in section 7 above). Full evidence,
comparison tables, and limitations are in the dedicated document
[`B46_4P_HYSTERIA2_SERVER_ONLY_PROTOTYPE.md`](B46_4P_HYSTERIA2_SERVER_ONLY_PROTOTYPE.md);
summary:

```text
Source API:      github.com/apernet/hysteria/core/v2/server (MIT), the
                  exact public API named in section 7 (NewServer/Serve/Close)
Prototype path:  tools/hysteria-server-prototype/
Build command:   CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath
                 -o hysteria-server-prototype-linux-amd64 .
Go version:      go1.26.0 linux/amd64
Binary SHA256:   1184c06bc808002fd3d0b92b5d6e990a9cca112783603d24081bbd718d45e768
Module graph:    14 compiled-in deps (go version -m, exhaustive) - ZERO
                 GPL/AGPL/LGPL/MPL entries; see the dedicated doc's
                 section 7 for the full per-module license inventory
GPL status:      sing-tun ABSENT, sagernet/sing ABSENT - confirmed by
                 go version -m, strings, go tool nm, AND go list -deps
                 (four independent methods, all agreeing), cross-checked
                 against a same-pass download of the official binary
                 (which DOES contain both)
Runtime result:  starts, listens on 127.0.0.1 (ephemeral port), serves,
                 shuts down cleanly (exit 0) - loopback-only, throwaway
                 self-signed test cert, randomly generated test password;
                 no production host/port/cert/credential involved
Limitations:     no real Hysteria2 client handshake was attempted; no
                 auth/TLS/UDP-proxy correctness proof; no ACME/config-
                 file/deployment-wiring; not a drop-in CLI replacement
```

**This confirms section 7's feasibility assessment with an actual working
build**, upgrading Option B's status from "TECHNICALLY INVESTIGATE" to
"TECHNICALLY VERIFIED, ENGINEERING COST STILL TO BE INCURRED FOR
PRODUCTION" (auth-backend integration, ACME/cert wiring, config parsing,
and deployment plumbing remain unbuilt - see the dedicated document's
section 12). It does **not** change any answer to the open legal
questions in section 8 below, which remain entirely for the repository
owner/legal to resolve - a GPL-free module graph for one Nova-authored
prototype binary is a technical fact about that one binary, not a legal
conclusion about Hysteria2 licensing in general or about whether Option A
is acceptable as-is.

## 8. Open legal questions

Posed as questions, not conclusions - **legal review required for all**:

1. Does running the exact official, statically-linked, multi-command `hysteria-linux-amd64` binary - where only the `server` subcommand is ever invoked at runtime, and Nova's own server-side code (`gateway/api/*.py`) is an entirely separate OS process that never links against this binary at the code level - constitute "conveying" or "distribution" of a work in a way that triggers GPLv3 §5/§6 obligations for Nova's own surrounding proprietary systems?
2. Does the mere presence of unreachable (at runtime, for Nova's use) GPL-licensed object code inside a binary Nova operates carry different licensing weight than the fact that Nova's OWN source code never imports or calls that code? (I.e., is the relevant boundary "what code is compiled into this one file" or "what code Nova's own systems actually invoke/depend on"?)
3. Does operating the binary purely as an internal network service (scenario "Own VPS only" / "Internal operation without distribution" above), with the binary itself never leaving Nova's infrastructure, change the analysis relative to a scenario where the binary file itself were handed to a third party?
4. If Option B (a from-scratch server-only build against `core/v2/server`'s public API) is pursued instead, does a NEW, Nova-authored `main` package that imports ONLY the MIT-licensed `core/v2/server` and `extras/v2/*` packages - and never imports `app/cmd`, `app/internal/tun`, `sing-tun`, or `sagernet/sing` at all, at either the source or compiled-binary level - fully and unambiguously resolve the GPL question, or are there residual concerns (e.g., regarding the resulting artifact's overall relationship to the upstream project) legal should still consider?
5. Does Nova already have an internal legal opinion covering the structurally identical Android client-side finding (B46-2B/2C, the SAME `sing-tun`/`sagernet/sing` pair, reached via a different import path) that could be directly extended to this server-side finding, or does this require an independent review?

## 9. Technical options

No ranking, no recommendation - presented as parallel options for the repository owner/legal to weigh against the open questions above:

**Option A — current unified binary**
```text
Hysteria2 official hysteria-linux-amd64 binary
  + client subcommand (unused at runtime)
  + sing-tun (GPL-3.0-or-later)
  + sagernet/sing (GPL-3.0-or-later)
```
Status: `LEGAL REVIEW REQUIRED`. Zero engineering cost - `gateway/hysteria/fetch-hysteria-server.sh` already fetches/verifies this exact asset today.

**Option B — server-only build (Nova-authored, against upstream's public library API)**
```text
NEW Nova-authored main package
  + github.com/apernet/hysteria/core/v2/server   (MIT, imported directly)
  + github.com/apernet/hysteria/extras/v2/*      (MIT, only the pieces Nova needs:
                                                    auth, obfs is unused - NONE-only
                                                    per B46-4A Finding 8)
  (never imports app/cmd, app/internal/tun, sing-tun, or sagernet/sing,
   at source or binary level)
```
Status: `TECHNICALLY VERIFIED` this pass by an actual working prototype - see section 7A and `B46_4P_HYSTERIA2_SERVER_ONLY_PROTOTYPE.md` (`tools/hysteria-server-prototype/`: builds, module graph confirmed GPL-free by four methods, starts/listens/serves/shuts down cleanly on loopback). Remaining engineering cost for a PRODUCTION version (not yet incurred): a real auth-backend integration (this prototype uses a single fixed test password, not `hysteria_auth_backend.py`'s `auth.type: http` design), ACME/cert-file wiring beyond a throwaway self-signed test cert, config-file parsing, its own test suite, its own build/pin/release process (would need its OWN `gateway/hysteria/VERSION`-style pinning, but pinned to the SAME upstream commit's `core`/`extras` modules, not a release binary), and ongoing maintenance burden of tracking upstream `core/v2/server` API changes independently (a real, standing cost, though bounded - `core/v2/server`'s own public API is small and has an incentive to stay stable since upstream's own CLI depends on it too).

**Option C — official server-only artifact**
Status: `VERIFY` → **verified this pass: does not exist.** No official binary, Docker image, or package variant excludes `client`/`tun`/`sing-tun` in any release channel upstream provides (see section 6).

**Option D — alternative architecture (described only, not implemented)**
```text
A completely separate, non-Hysteria2 QUIC/UDP transport implementation
Nova would author or adopt instead, sidestepping the Hysteria2 wire
protocol entirely.
```
This would abandon Hysteria2 compatibility altogether (a much larger product/architecture decision, well outside a licensing-mitigation option) - described here only because the task asked for it to be named as a theoretical fallback if A/B/C all prove unworkable; not evaluated further, not recommended, not scoped.

## 10. Decision gate

```text
NOT READY — LICENSING GATE OPEN
```

**What we know**: the exact, source-verified reachability graph (section 4); the exact licenses of every directly-relevant dependency (section 3); that no official server-only artifact exists (section 6); that a from-scratch server-only build is structurally plausible against a small, stable, MIT-licensed public library API (section 7), mirroring a methodology this project has already executed once for the client side (B46-2C).

**What we don't know**: whether Option A (the current unified binary) is legally acceptable for Nova's intended distribution/operation model, or whether it requires Option B instead.

**What legal must decide**: the five open questions in section 8 - centrally, whether running the official unified binary in Nova's own internal-service, server-only-invocation model triggers GPLv3 distribution obligations for Nova's surrounding proprietary systems.

**What remains technically open regardless of the legal answer**: if legal clears Option A, `gateway/hysteria/fetch-hysteria-server.sh` is already real, verified, and ready to use as-is - zero further engineering needed on this front. If legal requires Option B, the feasibility groundwork above gives a concrete, bounded starting point, but no code for it exists yet and none should be written before that decision is made (writing it speculatively would itself be wasted or, worse, half-finished GPL-adjacent engineering effort with no clear purpose until the legal question is actually answered).

**Do not begin any production deployment of the Hysteria2 server binary (Option A) until this gate is explicitly closed by the repository owner/legal.**
