# B8O1A - TLS/TCP gateway inbound: separate-listener audit

Answers the one open item B8O0 left unresolved: does serving VLESS+REALITY
and VLESS+TLS on the same gateway require two separate xray-core inbounds
(listen ports), or can they share one? Verified against the same pinned
source B8O0/B8K1A already cite (`github.com/xtls/xray-core`, commit
`5ca6f4b7d4dc20a881d4330e498892697627ec0c`, tag `v26.7.28`).

## Finding: two separate inbounds are required - there is no shared-listener mechanism

`infra/conf/xray.go`'s `InboundDetourConfig` is the JSON shape of one entry
in the top-level `"inbounds"` array:

```go
type InboundDetourConfig struct {
    Protocol       string           `json:"protocol"`
    PortList       *PortList        `json:"port"`
    ListenOn       *Address         `json:"listen"`
    Settings       *json.RawMessage `json:"settings"`
    Tag            string           `json:"tag"`
    StreamSetting  *StreamConfig    `json:"streamSettings"`
    SniffingConfig *SniffingConfig  `json:"sniffing"`
}
```

Its `Build()` method produces exactly one `core.InboundHandlerConfig` per
entry - one listener socket, bound to that entry's own `port`/`listen`, with
its own `StreamSetting.Build()` (the `security`/`realitySettings`/
`tlsSettings` block this whole B8O0/B8O1/B8O2 series is about). There is no
code path anywhere in this method, or in how xray-core wires
`InboundHandlerConfig`s into running listeners, that lets two JSON `inbounds`
entries share one socket or negotiate between two different
`streamSettings.security` values on the same port. A single TCP listener has
exactly one `StreamConfig`, decided once at that listener's own construction.

**Consequence:** REALITY (`security: "reality"`) and plain TLS
(`security: "tls"`) must be two separate `inbounds` array entries, each with
its own `port`, to run simultaneously - never a config toggle or a shared
listener negotiating between them. This is exactly what
`gateway/api/xray_config_renderer.py`'s `render_server_config(..., tls=...)`
does (B8O2): REALITY's own inbound is untouched, and a second inbound is
appended only when a `TlsServerConfig` is supplied - two independent
listener configs in the same rendered `config.json`, exactly as this finding
requires.

## Consequence for gateway/xray/README.md's own port allocation

REALITY already occupies its own port (`gateway/xray/README.md` documents
`2053` as the first live-proof port; the current `.env`/`AppConfig` default
used in this repo's own tests is `8444`). TLS/TCP's own inbound needs a
THIRD distinct public port, never REALITY's - `gateway/api/config.py`
enforces this explicitly (`XRAY_TLS_SERVER_PORT` must differ from
`XRAY_SERVER_PORT`). The actual production port number is an operator
choice/firewall change, not resolved by this document (see
`gateway/xray/README.md`'s own "Firewall / Oracle security-list change
required (NOT YET APPLIED)" section, which applies equally to whatever port
TLS/TCP is eventually given).

## What this does NOT resolve

- The exact production port TLS/TCP will use, and the corresponding Oracle
  security-list/firewall change - both remain NOT YET APPLIED, same as
  REALITY's own `2053` in `gateway/xray/README.md`.
- Server-side `TLSConfig` fields beyond `certificates` (e.g. `alpn`,
  `minVersion`) - B8O2's renderer emits only `certificates` (via
  `certificateFile`/`keyFile`, reusing the existing Let's Encrypt cert), the
  minimal correct shape; every other field has a safe xray-core default.
