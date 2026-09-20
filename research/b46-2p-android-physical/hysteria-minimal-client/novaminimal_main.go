// Command novaminimal is the B46-2P extension of the B46-2C research
// prototype: a minimal Hysteria2 SOCKS5-only client, deliberately built
// WITHOUT importing app/internal/tun (and therefore without importing
// github.com/apernet/sing-tun). It is not production code and is not wired
// into Nova's release build.
//
// B46-2P additively extends the B46-2C prototype
// (research/b46-2c-permissive-hysteria-path/hysteria-minimal-client/novaminimal_main.go)
// with two new, real capabilities the physical Android test needs and the
// host-side research prototype did not:
//
//  1. --protect-path <unix-socket-path>: a REAL Android VpnService.protect(fd)
//     analog, using the exact same wire protocol Nova's production
//     RealShadowsocksVpnProtectBridge already proves physically
//     (android/app/src/main/java/net/pocvpn/client/vpn/shadowsocks/ShadowsocksVpnProtectBridge.kt):
//     connect to the Unix-domain SOCK_STREAM socket, send one payload byte
//     plus one SCM_RIGHTS ancillary fd (the QUIC socket's own fd), then read
//     a single response byte (0x00 = protect() succeeded, anything else =
//     failed). Fails closed (returns an error, which fails client
//     construction) on dial failure, sendmsg failure, timeout, or a
//     non-zero response byte. This is the ONLY mechanism used for the
//     Android acceptance test - --protect-stub and --fwmark (B46-2C) remain
//     for host-side research reproducibility only and are not used on
//     Android.
//  2. --config-file <path>: reads server/auth/sni/insecure/obfsSalamander/
//     socksListen/protectPath from a JSON file instead of argv, so neither
//     the auth password nor the obfsSalamander password ever appears in
//     argv, environment, process title, or logcat (both are redacted out
//     of any logged error text - see redact()). The Android acceptance
//     child is launched with ONLY --config-file - no --auth flag is used
//     on Android.
//
// No existing upstream Hysteria file is modified by this file's presence;
// see README.md for exact grafting instructions.
package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/apernet/hysteria/app/v2/internal/socks5"
	"github.com/apernet/hysteria/core/v2/client"
	"github.com/apernet/hysteria/extras/v2/obfs"
)

const protectRPCTimeout = 5 * time.Second

// protectFD is the Android VpnService.protect() analog: called on every raw
// outbound QUIC UDP socket's file descriptor immediately after creation, so
// the platform can exclude it from the VPN's own routing (preventing a
// routing loop).
var protectFD func(fd int) error

// authSecret and obfsSecret are redacted out of any error text before it is
// logged (Part B requirement: never expose auth/obfs/config-file contents
// in logs). PRE-MERGE HARDENING CORRECTION (2026-09-20, manual review,
// round 3): obfsSecret was missing here - only authSecret was ever
// redacted, despite obfsSalamander being an equally secret-shaped value
// (see novaminimalConfig's own doc comment, which already said so).
var authSecret string
var obfsSecret string

func redact(s string) string {
	out := s
	if authSecret != "" {
		out = strings.ReplaceAll(out, authSecret, "***REDACTED***")
	}
	if obfsSecret != "" {
		out = strings.ReplaceAll(out, obfsSecret, "***REDACTED***")
	}
	return out
}

func logf(format string, args ...interface{}) {
	log.Print(redact(fmt.Sprintf(format, args...)))
}

type saltedConnFactory struct {
	obfsPassword string
}

func (f *saltedConnFactory) New(addr net.Addr) (net.PacketConn, error) {
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	if protectFD != nil {
		rc, err := conn.SyscallConn()
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("SyscallConn: %w", err)
		}
		var protectErr error
		if ctrlErr := rc.Control(func(fd uintptr) {
			protectErr = protectFD(int(fd))
		}); ctrlErr != nil {
			conn.Close()
			return nil, fmt.Errorf("fd control: %w", ctrlErr)
		}
		if protectErr != nil {
			conn.Close()
			return nil, fmt.Errorf("protect fd: %w", protectErr)
		}
	}
	if f.obfsPassword == "" {
		return conn, nil
	}
	return obfs.WrapPacketConnSalamander(conn, []byte(f.obfsPassword))
}

// novaminimalConfig is the --config-file schema. Deliberately has NO
// String()/MarshalJSON override that would be safe to log wholesale - the
// caller must never log this struct directly. Auth is the one field that
// must never reach argv, env, process title, or logcat.
type novaminimalConfig struct {
	Server         string `json:"server"`
	Auth           string `json:"auth"`
	SNI            string `json:"sni"`
	Insecure       bool   `json:"insecure"`
	ObfsSalamander string `json:"obfsSalamander"`
	SocksListen    string `json:"socksListen"`
	ProtectPath    string `json:"protectPath"`
}

// redactedSummary is the only safe-to-log representation of a config: never
// includes Auth or ObfsSalamander (also secret-shaped).
func (c novaminimalConfig) redactedSummary() string {
	return fmt.Sprintf("server=%s sni=%s insecure=%v socksListen=%s protectPath=%s authSet=%v obfsSet=%v",
		c.Server, c.SNI, c.Insecure, c.SocksListen, c.ProtectPath, c.Auth != "", c.ObfsSalamander != "")
}

func loadConfigFile(path string) (novaminimalConfig, error) {
	var cfg novaminimalConfig
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("read config file: %w", err)
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parse config file: %w", err)
	}
	if cfg.Server == "" {
		return cfg, errors.New("config file: server is required")
	}
	return cfg, nil
}

// protectViaUnixSocket implements the real SCM_RIGHTS FD-control RPC to the
// Android VpnService side, reusing exactly the wire protocol
// RealShadowsocksVpnProtectBridge already proves physically: connect, send
// one payload byte plus one ancillary fd (the fd to protect), read one
// response byte. 0x00 = success. Anything else, or any error/timeout, is a
// failure (fail-closed) - the caller must not use the socket unless this
// returns nil.
func protectViaUnixSocket(socketPath string, fd int) error {
	conn, err := net.DialTimeout("unix", socketPath, protectRPCTimeout)
	if err != nil {
		return fmt.Errorf("dial protect socket: %w", err)
	}
	defer conn.Close()

	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return errors.New("protect socket is not a unix connection")
	}
	if err := uc.SetDeadline(time.Now().Add(protectRPCTimeout)); err != nil {
		return fmt.Errorf("set protect socket deadline: %w", err)
	}

	rights := syscall.UnixRights(fd)
	payload := []byte{0x01}
	n, oobn, err := uc.WriteMsgUnix(payload, rights, nil)
	if err != nil {
		return fmt.Errorf("sendmsg fd via SCM_RIGHTS: %w", err)
	}
	if n != len(payload) || oobn != len(rights) {
		return fmt.Errorf("short sendmsg: wrote %d/%d bytes, %d/%d oob bytes", n, len(payload), oobn, len(rights))
	}

	resp := make([]byte, 1)
	nr, err := uc.Read(resp)
	if err != nil {
		return fmt.Errorf("read protect ack: %w", err)
	}
	if nr != 1 {
		return fmt.Errorf("short protect ack read: %d bytes", nr)
	}
	if resp[0] != 0x00 {
		return fmt.Errorf("protect() rejected: ack=0x%02x", resp[0])
	}
	return nil
}

func main() {
	serverAddr := flag.String("server", "", "Hysteria2 server address (host:port) - overridden by --config-file if both are set")
	auth := flag.String("auth", "", "auth password (research/host use only - never use on Android, use --config-file instead)")
	sni := flag.String("sni", "", "TLS server name")
	insecure := flag.Bool("insecure", false, "skip TLS verification (research only)")
	obfsPassword := flag.String("obfs-salamander", "", "salamander obfuscation password (optional)")
	socksListen := flag.String("socks-listen", "127.0.0.1:0", "local SOCKS5 listen address")
	protectStub := flag.Bool("protect-stub", false, "B46-2C host-research only: exercise the FD-protect hook with a no-op implementation. Never used on Android.")
	fwmark := flag.Int("fwmark", 0, "B46-2C host-research only: SO_MARK policy-routing analog. Never used on Android.")
	protectPath := flag.String("protect-path", "", "B46-2P: real Android VpnService.protect(fd) analog via SCM_RIGHTS over this Unix-domain socket path. Used on Android.")
	configFile := flag.String("config-file", "", "B46-2P: JSON config file (server/auth/sni/insecure/obfsSalamander/socksListen/protectPath). Required on Android - never pass --auth on Android.")
	flag.Parse()

	if *configFile != "" {
		cfg, err := loadConfigFile(*configFile)
		if err != nil {
			log.Fatalf("config-file: %v", err)
		}
		*serverAddr = cfg.Server
		authSecret = cfg.Auth
		*auth = cfg.Auth
		*sni = cfg.SNI
		*insecure = cfg.Insecure
		*obfsPassword = cfg.ObfsSalamander
		obfsSecret = cfg.ObfsSalamander
		if cfg.SocksListen != "" {
			*socksListen = cfg.SocksListen
		}
		*protectPath = cfg.ProtectPath
		logf("loaded config-file: %s", cfg.redactedSummary())
	} else {
		if *auth != "" {
			authSecret = *auth
		}
		if *obfsPassword != "" {
			obfsSecret = *obfsPassword
		}
	}

	if *serverAddr == "" {
		log.Fatal("--server (or config-file's \"server\") is required")
	}

	switch {
	case *protectPath != "":
		path := *protectPath
		protectFD = func(fd int) error {
			if err := protectViaUnixSocket(path, fd); err != nil {
				return err
			}
			log.Printf("FD_PROTECT_SCM_RIGHTS: protect() succeeded via %s for fd=%d", path, fd)
			return nil
		}
	case *protectStub:
		protectFD = func(fd int) error {
			if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
				return err
			}
			log.Printf("FD_PROTECT_STUB: called on fd=%d", fd)
			return nil
		}
	case *fwmark != 0:
		mark := *fwmark
		protectFD = func(fd int) error {
			if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_MARK, mark); err != nil {
				return err
			}
			log.Printf("FD_PROTECT_MARK: set SO_MARK=%#x on fd=%d", mark, fd)
			return nil
		}
	}

	udpAddr, err := net.ResolveUDPAddr("udp", *serverAddr)
	if err != nil {
		log.Fatalf("resolve server addr: %v", redact(err.Error()))
	}

	hyConfig := &client.Config{
		ServerAddr: udpAddr,
		Auth:       *auth,
		TLSConfig: client.TLSConfig{
			ServerName:         *sni,
			InsecureSkipVerify: *insecure,
		},
		ConnFactory: &saltedConnFactory{obfsPassword: *obfsPassword},
	}
	_ = tls.VersionTLS13 // documents the min TLS version enforced inside core/client

	hyClient, info, err := client.NewClient(hyConfig)
	if err != nil {
		log.Fatalf("hysteria client construction/handshake failed: %v", redact(err.Error()))
	}
	log.Printf("connected: udpEnabled=%v tx=%d", info.UDPEnabled, info.Tx)

	listener, err := net.Listen("tcp", *socksListen)
	if err != nil {
		log.Fatalf("socks5 listen: %v", err)
	}
	log.Printf("SOCKS5_LISTENING addr=%s", listener.Addr())

	srv := &socks5.Server{
		HyClient: hyClient,
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := srv.Serve(listener); err != nil && !errors.Is(err, net.ErrClosed) {
			log.Printf("socks5 serve error: %v", redact(err.Error()))
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	log.Print("shutting down")
	_ = listener.Close()
	_ = hyClient.Close()

	if *configFile != "" {
		_ = os.Remove(*configFile)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		log.Print("shutdown timed out")
	}
}
