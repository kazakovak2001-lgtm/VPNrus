# B21 - QUIC transport/fallback implementation audit

Read this before touching any B21 code. Labels: **FACT** (verified against the
pinned xray-core v26.7.28 source at commit `5ca6f4b7d4dc20a881d4330e498892697627ec0c`,
tag `v26.7.28`, or this repo's own already-committed pins), **INFERENCE**
(reasoned from FACTs, not yet empirically re-run), **DECISION** (what this
slice actually does and why), **LIMITATION** (an honest gap this slice does
not close).

## 1. Pinned runtime

**FACT** - both the Android client (`third_party/xray/VERSION`) and the
gateway server (`gateway/xray/VERSION`) pin the exact same xray-core release:
`v26.7.28`, commit `5ca6f4b7d4dc20a881d4330e498892697627ec0c`. This is not an
independently-chosen version for B21 - it is the version already running in
production (server) and already bundled in the Android AAR (client). No
version bump was made or is needed for this slice.

## 2. Does the pinned core have a production-usable "quic" transport?

**FACT, cited directly from the pinned tag** -
`infra/conf/transport_internet.go` (`TransportProtocol.Build()`), commit
`5ca6f4b7d4dc20a881d4330e498892697627ec0c`:

```go
case "h2", "h3", "http":
    return "", errors.PrintRemovedFeatureError("HTTP transport (without header padding, etc.)", "XHTTP stream-one H2 & H3")
case "quic":
    return "", errors.PrintRemovedFeatureError("QUIC transport (without web service, etc.)", "XHTTP stream-one H3")
```

The standalone `"quic"` `streamSettings.network` value is **removed** in this
exact pinned version. Any config that sets `"network": "quic"` fails to build
at all (`errors.PrintRemovedFeatureError`, a hard config-load error, not a
runtime warning) - it is not merely discouraged, it does not work. **Do not
select it merely because the word matches "QUIC".**

`ws`/`httpupgrade`/`grpc` are also present but flagged
`errors.PrintNonRemovalDeprecatedFeatureWarning(...)`, each explicitly
recommending migration to XHTTP.

## 3. The current supported QUIC-capable alternative

**FACT, same file, same function**:

```go
case "xhttp", "splithttp":
    return "splithttp", nil
```

`"xhttp"` (alias `"splithttp"`) is the real, currently-supported transport.
Its config type is `SplitHTTPConfig` (`transport/internet/splithttp/config.proto`,
same tag), with (among others) `host`, `path`, `mode` string fields and a
`headers` map. `infra/conf/transport_internet.go`'s `StreamConfig` wires it as
`XHTTPSettings *SplitHTTPConfig \`json:"xhttpSettings"\`` (or the
`splithttpSettings` alias key) - i.e. a normal, first-class `streamSettings`
value alongside `tcp`/`grpc`, not a side mechanism.

**FACT, `transport/internet/splithttp/dialer.go`, same tag** - when the
negotiated TLS ALPN is `h3` (`tlsConfig.NextProtocol[0] == "h3"`), the dialer
switches to a REAL HTTP/3-over-QUIC client built on
`github.com/apernet/quic-go` and `github.com/apernet/quic-go/http3` - a
widely-used, actively-maintained, RFC 9000/9114-compliant QUIC
implementation, not a custom/hand-rolled protocol and not xray-core's own
old bespoke "quic" pseudo-transport. This is genuinely real QUIC.

**INFERENCE** (from the same source, not yet empirically re-confirmed at the
time of writing this section - closed by Phase M below): the client-facing
JSON field names for `SplitHTTPConfig` follow this codebase's own
already-established convention (proto field name -> identical camelCase JSON
key, exactly how `realitySettings`/`tlsSettings` already work in this app's
own `XrayConfigRenderer`) - i.e. `"host"`, `"path"`, `"mode"`. `"mode":
"stream-one"` combined with `streamSettings.security: "tls"` and
`tlsSettings.alpn: ["h3"]` is what actually selects the real QUIC/HTTP-3 code
path (`errors.PrintRemovedFeatureError`'s own message names this exact
combination: "XHTTP stream-one H3"). Phase M (below) locally validates this
inference against the real pinned `xray` binary via `-test`, not just by
reading Go source - no code in this PR claims IMPLEMENTED on JSON-shape
inference alone.

## 4. Answering the required sub-questions

- **Exact protocol/transport type**: XHTTP (`splithttp` internally),
  `mode: "stream-one"`, `security: "tls"`, ALPN `h3` - real HTTP/3-over-QUIC
  via `quic-go`/`quic-go/http3`.
- **Client config shape**: `streamSettings = { network: "xhttp", security:
  "tls", tlsSettings: { serverName, alpn: ["h3"], fingerprint, allowInsecure:
  false }, xhttpSettings: { host, path, mode: "stream-one" } }` - see §6 for
  the exact renderer.
- **Server config shape**: an `xhttp` inbound alongside the existing
  `reality`/`tls` VLESS inbounds, same `vless` protocol, its own `streamSettings`
  block mirroring the client's, on its own UDP port (H3 is UDP-only - it
  cannot share a TCP listener).
- **Authentication model**: **FACT** - `vless` outbound/inbound `users[].id`
  (the UUID) is completely independent of `streamSettings` (already true for
  REALITY vs plain TLS in this codebase's own `XrayConfigRenderer` - the user
  object is identical in both `renderVlessRealityOutbound`/
  `renderVlessTlsOutbound`). XHTTP does not change this: the SAME VLESS UUID
  identity model applies.
- **Certificate requirements**: a real, publicly-trusted TLS certificate for
  the gateway's own hostname/IP - i.e. the SAME model `TLS_TCP` already uses
  (`gateway/edge`'s existing Let's Encrypt short-lived IP cert machinery), not
  REALITY's borrowed-certificate trick. **REALITY does not apply to this
  transport** - see §5.
- **UDP listener requirements**: yes, a dedicated UDP port (see Phase H/§9 -
  production port gate).
- **Can it share the existing Xray process?** **FACT** - yes. Both client and
  server already run ONE xray-core process with multiple `inbounds`/
  `outbounds` array entries (`gateway/api/xray_config_renderer.py` already
  renders REALITY + TLS inbounds side by side in the SAME config; the Android
  side's `XrayCoreController` starts exactly one `startLoop(configContent,
  fd)` per session, always has). Adding an `xhttp` inbound/outbound is
  additive to the same array, not a second process.
- **Can it reuse the existing VLESS UUID identity?** **FACT/DECISION** - yes,
  same model as REALITY/TLS_TCP (see above). No new credential *type* is
  needed - just a distinct, endpoint-and-transport-scoped stored profile
  (own listener/port means its own provisioning record, same pattern
  `XrayTlsProfileRepository` already established for TLS_TCP relative to
  REALITY - see Phase E/F).
- **Android/TUN implications**: **FACT/DECISION** - none beyond what already
  exists. The `tun` inbound (`XrayConfigRenderer.renderTunInbound`) is
  identical for every outbound security mode today (REALITY and TLS render
  the exact byte-identical tun inbound) - QUIC needs no TUN-side change,
  reuses the SAME `NovaXrayVpnService`/`XrayCoreController`/
  `XrayVpnBuilderPlan` shell.
- **Upstream status/deprecation caveats**: XHTTP is XTLS/Xray-core's actively
  maintained, currently-recommended modern transport family (explicitly named
  as the migration target for the NOW-REMOVED `quic`/`h2`/`h3`/`http`
  transports and the DEPRECATED `ws`/`httpupgrade`/`grpc` ones, per the exact
  source quoted in §2). Real production risk, stated honestly
  (**LIMITATION**): XHTTP is a comparatively newer transport family than
  REALITY/plain-TLS within xray-core's own history, with a smaller real-world
  deployment track record than REALITY specifically; no independent
  third-party audit of XHTTP's own censorship-resistance properties is cited
  anywhere in this repo, and this slice makes no such claim either (see
  ROADMAP status rules - FOUNDATION until physically proven, and no
  restrictive-network/Russia claim until actually tested there).

## 5. Why not REALITY for the QUIC transport

**FACT** - `infra/conf/transport_internet.go`'s `security` switch DOES allow
REALITY with `splithttp` (`if config.ProtocolName != "tcp" && ... != "splithttp"
&& ... != "grpc" { return error }`), so "XHTTP + REALITY" is a real xray-core
combination. **DECISION** - this slice does not use it for the QUIC
transport specifically, because:

1. REALITY's entire mechanism (splicing into a real TLS 1.3 ClientHello
   toward a real camouflage destination) is fundamentally a TCP-handshake
   trick - it has no defined behavior for a genuine QUIC/UDP transport, and
   the dialer-level evidence in §3 shows H3 mode is selected purely by TLS
   ALPN (`h3`) with a REAL certificate/SNI, not a REALITY handshake.
2. "XHTTP + REALITY" (where it IS documented/supported) is for XHTTP's
   TCP/H2 modes (`stream-up`/`packet-up`/`auto`) - a genuinely different,
   REALITY-flavored transport this slice does not build, to keep scope to
   exactly one new transport (real QUIC/H3), not two.
3. Reusing the plain-TLS credential model (§4) is simpler, already-proven in
   this codebase (`TLS_TCP`), and does not require a second REALITY keypair
   ceremony per gateway.

A REALITY-flavored XHTTP transport remains a possible FUTURE slice, not
something this one silently forecloses.

## 6. Exact rendered client `streamSettings` (this slice's implementation)

```json
{
  "network": "xhttp",
  "security": "tls",
  "tlsSettings": {
    "serverName": "<gateway serverName>",
    "fingerprint": "<chrome|firefox|safari|edge>",
    "alpn": ["h3"],
    "allowInsecure": false
  },
  "xhttpSettings": {
    "host": "<gateway serverName>",
    "path": "<per-gateway, provisioned, not hardcoded>",
    "mode": "stream-one"
  }
}
```

Mirrors `XrayConfigRenderer.renderVlessTlsOutbound`'s existing
`tlsSettings` shape byte-for-byte, adding only `alpn`/`xhttpSettings`. See
`XrayConfigRenderer.render(XrayVlessQuicConfig)` for the real implementation.

## 7. Decision

**DECISION** - implement `TransportKind.QUIC` as XHTTP `mode: "stream-one"`
over TLS with ALPN `h3` (real QUIC/HTTP-3 via `quic-go`), on its own new UDP
port, reusing:

- the SAME VLESS UUID identity model as REALITY/TLS_TCP (no new credential
  *type*, a new endpoint-and-transport-scoped profile/repository - own
  listener, own provisioning record);
- the SAME `NovaXrayVpnService`/`XrayCoreController`/tun-inbound shell (no
  second VpnService, no second TUN/protect stack);
- the SAME `TransportRegistry`/`TransportOrchestrator`/`VpnController`
  dispatch pattern TLS_TCP already established;
- the SAME `PathScorer`/`ReachabilityEngine`/`TransportHealth` generic
  pipeline (no protocol-specific ranking logic).

No Hysteria, sing-box, TUIC, or second native core was considered further
than a documentation check (**FACT** - none of those are referenced anywhere
in this repo's pinned dependencies) - the pinned runtime already has a real,
current, non-deprecated answer.

## 8. Local validation results (empirical, not just source-reading)

**FACT** - the exact pinned `xray` binary (downloaded fresh, sha256
`8195d909f1109b8f3d99eefe401a3c451d7bf4af71f24d3815420f77e5dd2a40`, matching
`gateway/xray/VERSION` byte-for-byte; `xray version` output confirmed commit
`5ca6f4b`) was run locally (WSL2, no production host touched) with `xray run
-test -c <config>` against two configs:

1. A synthetic CLIENT `vless` outbound with `streamSettings` exactly as
   rendered by `XrayConfigRenderer.render(XrayVlessQuicConfig)` (§6 above) -
   result: `Configuration OK.`
2. The REAL SERVER config as produced by `xray_config_renderer.render_server_config`
   with all three inbounds (REALITY + TLS + the new QUIC) together - result:
   `Configuration OK.` (only pre-existing REALITY camouflage-target/port
   warnings, unrelated to QUIC).

This empirically confirms the §3 INFERENCE about exact JSON field names
(`host`/`path`/`mode`/`xhttpSettings`/`tlsSettings.alpn`) - the pinned
binary's own config loader accepts it, not just a reading of the Go source.

## 9. What this audit does NOT resolve (left to later phases in this PR)

- **LIMITATION** - a real UDP port for this listener does not exist on
  either production gateway today (AWG already owns `51820/udp`; REALITY/TLS
  use TCP `2053`/`2083`). Opening one is a production-visible firewall
  change requiring explicit operator approval - see this PR's own
  `PRODUCTION APPROVAL REQUIRED` gate. No such change is made in this PR.
- **LIMITATION** - no real QUIC/HTTP-3 handshake (client<->server) has been
  exercised, on this device or any other - `-test` only validates that
  xray-core's own config loader accepts the shape, not that a live QUIC
  session actually completes. That requires the production port (above),
  hence remains for Phase O (physical validation) after operator approval.
