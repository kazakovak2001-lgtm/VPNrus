# Minimal Hysteria2 SOCKS5-only client (B46-2C research prototype)

`novaminimal_main.go` is a `package main` prototype proving Hysteria2 can be
built as a SOCKS5-only client that does **not** import `app/internal/tun`
and therefore does not link `github.com/apernet/sing-tun`.

It cannot be built standalone: it imports `app/internal/socks5`, which is a
Go `internal/` package, so it must live inside the Hysteria2 module tree to
be importable. To reproduce:

```
git clone https://github.com/apernet/hysteria.git
cd hysteria
git checkout e1366b173ccf5706e1e4630fe8aa654a4b574085
mkdir -p app/novaminimal
cp <this file> app/novaminimal/main.go
cd app
go build -o novaminimal ./novaminimal
```

This does not modify any existing upstream file - it only adds one new
directory/command alongside the existing `app/cmd` CLI. See
`docs/B46_2C_PERMISSIVE_HYSTERIA_PATH.md` Part H-J for the full audit,
dependency-graph proof that `sing-tun` is absent, and the real end-to-end
QUIC proof this prototype was exercised against.

Not production code. Not wired into Nova's release build.
