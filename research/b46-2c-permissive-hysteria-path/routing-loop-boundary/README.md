# Routing-loop-boundary proof (B46-2C clarification)

`loopcheck.go` is a research harness proving the Android routing-loop
boundary that FD-Control/`VpnService.protect(fd)` exists to prevent:

- App traffic entering the TUN must reach the local Hysteria SOCKS5
  listener (`--proxy`).
- Hysteria's own outbound QUIC UDP socket must be excluded from the
  tunnel's own routing (via the FD-protect hook), or it loops back into
  the TUN it is itself feeding and the QUIC handshake never completes.

`--full-tunnel` points the *client netns's own default route* at the TUN,
simulating an Android full-tunnel VPN capturing all outbound traffic by
default. `--serve` holds the TUN + tun2socks engine open (blocking on
SIGTERM/SIGINT) so a separately-run Hysteria client process can be observed
under that condition.

See `docs/B46_2C_PERMISSIVE_HYSTERIA_PATH.md` Part 4 (routing-loop-boundary
clarification) for the full real A/B result: with the minimal Hysteria
client's `--fwmark` protect hook active, the QUIC handshake succeeds and app
traffic still reaches it through the TUN with no interference; without it,
the QUIC handshake genuinely times out because its own packets get captured
by the TUN's default route.

Not production code. Requires root/`CAP_NET_ADMIN` (network namespaces,
`ip rule`/policy routing, raw TUN device access).
