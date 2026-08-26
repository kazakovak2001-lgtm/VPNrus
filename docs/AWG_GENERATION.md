# AmneziaWG generation invariant

```
CLIENT_AWG_GENERATION == GATEWAY_AWG_GENERATION
```

The Android client's AmneziaWG obfuscation parameters (Jc, Jmin, Jmax, S1, S2,
H1-H4, I1-I5, header protection, content padding, RandomTrailers,
DisableCookies, rekey/timing) are only meaningful if the peer on the other end
of the tunnel runs a wire-compatible `amneziawg-go`/`amneziawg-tools` build.
These are not purely local settings - several affect the on-wire packet
format and must be understood identically by both ends to complete a
handshake.

## Current pin

| Side | Status | Pinned ref |
|---|---|---|
| Android client (`third_party/amneziawg-android`) | **pinned** | `v3.1.20260814` / `5c16489e2cd9ed3a0a7a27c7445bba5238132f86` (amneziawg-go `v3.1.20260814`, amneziawg-tools `ee0f0a9a`) |
| Linux gateway (B5, not yet implemented) | **not yet built** | must use a matching `v3.1.20260814`-generation `amneziawg-go`/`amneziawg-tools` build |

## Rule for B5 (gateway)

- Build/install `amneziawg-tools` (`awg`, `awg-quick`) and `amneziawg-go` from
  the **same tagged upstream generation** as the Android client pin above -
  built from source and pinned by tag/commit, the same way the client is.
- **Do not** install an OS-repo/distro package as the protocol implementation
  unless that package is verified to be built from the identical pinned
  upstream commit. An unverified apt/distro package version is not an
  acceptable substitute - version drift here silently breaks obfuscation
  compatibility or handshake compatibility instead of failing loudly.
- If the client pin is upgraded in the future, this file and the gateway's
  pinned version must be updated together, in the same change.
