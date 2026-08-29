# VLESS/REALITY runtime foundation (B8K0)

This directory is a **build-tooling and provenance foundation only**. It does
not integrate into the Android app yet - `TransportKind.XRAY_REALITY` remains
`NOT_IMPLEMENTED` in `TransportRegistry`, no Kotlin adapter exists, and
`VpnController`/`TransportOrchestrator` are untouched. See
`docs/B8K0_RUNTIME_AUDIT.md` for the full comparison/decision record.

## What's pinned here

- `VERSION` - exact commit/tag/license for the selected runtime, same
  discipline as `third_party/build-tunnel-wsl.sh`'s AmneziaWG pin.
- `build-xray-wsl.sh` - builds the Android AAR inside WSL2 Ubuntu, mirroring
  the existing AmneziaWG build script's structure (pinned-commit
  verification, explicit `JAVA_HOME`, fails loudly on mismatch).

No generated binary (`.aar`) is committed here, matching this repo's existing
`.gitignore` policy for `android/**/libs/` - the built artifact is copied into
`android/app/libs/` locally, exactly like the AmneziaWG AAR already is.

## Why Xray-core (not sing-box), briefly

sing-box/libbox has a more turnkey Android TUN-integration story (a
purpose-built `PlatformInterface` with `OpenTun`/`AutoDetectInterfaceControl`/
per-app-package pass-through, proven by a real shipped reference app). It was
the prior slice's tentative recommendation. Re-auditing the actual upstream
license changed that recommendation: sing-box is GPL-3.0-or-later **plus** an
additional "no derivative work may use the name or imply association with
this application without prior consent" restriction. Embedding GPL-3.0 code
into a commercial closed-source app's distributed binary is a real,
consequential legal risk (likely obligates releasing Nova's own source), not
a mere inconvenience. Xray-core itself is MPL-2.0 (file-level copyleft, the
license basis many commercial VPN products already build on) and the
community Android wrapper this foundation pins is LGPL-3.0 - both compatible
with a proprietary app linking against them without open-sourcing Nova's own
code. See the audit doc for the full comparison, including the real
technical cost of this choice (a thinner, less turnkey Android TUN/protect
integration that Nova will need to design more of itself - not a licensing
footnote, a genuine engineering gap to close in a later slice, before any
code claims VLESS/REALITY works).

## Explicitly NOT done here

- No VLESS_REALITY transport adapter, no VpnTransport implementation.
- No change to `TransportRegistry`'s production availability.
- No change to `VpnController`, `TransportOrchestrator`, or Smart Connect.
- No server-side listener, no `/v1/activate` change, no Oracle change.
- No socket-protection design finalized yet - see the audit doc's open item.
