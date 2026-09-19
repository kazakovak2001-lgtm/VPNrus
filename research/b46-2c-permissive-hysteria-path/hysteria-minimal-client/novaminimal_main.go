// Command novaminimal is a B46-2C research prototype: a minimal Hysteria2
// SOCKS5-only client, deliberately built WITHOUT importing app/internal/tun
// (and therefore without importing github.com/apernet/sing-tun). It is not
// production code and is not wired into Nova's release build.
//
// Architecture under test: Android VpnService TUN -> MIT tun2socks bridge ->
// 127.0.0.1:<socks> -> this minimal SOCKS5-only Hysteria2 child -> Hysteria2
// QUIC -> Nova Hysteria gateway. This binary implements only the last two
// hops (SOCKS5 listener -> QUIC), the same architecture as the real
// production Hysteria2 client, but without the CLI's tun2socks/sing-tun-only
// integration path.
package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/apernet/hysteria/app/v2/internal/socks5"
	"github.com/apernet/hysteria/core/v2/client"
	"github.com/apernet/hysteria/extras/v2/obfs"
)

// protectFD is the Android VpnService.protect() analog: called on every raw
// outbound QUIC UDP socket's file descriptor immediately after creation, so
// the platform can exclude it from the VPN's own routing (preventing a
// routing loop). In this host-side research build it is a stub that only
// proves the hook point exists and is exercised on the real code path; the
// real Android integration would JNI-call VpnService.protect(fd) here.
var protectFD func(fd int) error

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

func main() {
	serverAddr := flag.String("server", "", "Hysteria2 server address (host:port)")
	auth := flag.String("auth", "", "auth password")
	sni := flag.String("sni", "", "TLS server name")
	insecure := flag.Bool("insecure", false, "skip TLS verification (research only)")
	obfsPassword := flag.String("obfs-salamander", "", "salamander obfuscation password (optional)")
	socksListen := flag.String("socks-listen", "127.0.0.1:0", "local SOCKS5 listen address")
	protectStub := flag.Bool("protect-stub", false, "exercise the FD-protect hook with a no-op implementation (proves the call path)")
	flag.Parse()

	if *serverAddr == "" {
		log.Fatal("--server is required")
	}

	if *protectStub {
		protectFD = func(fd int) error {
			// A no-op "protect": in the real Android build this becomes a
			// JNI call into VpnService.protect(fd). Here we only prove the
			// call path is exercised (verified via FD_PROTECT_STUB log line
			// below and via the syscall.SetsockoptInt no-op call itself,
			// which fails loudly if the fd is somehow invalid).
			if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
				return err
			}
			log.Printf("FD_PROTECT_STUB: called on fd=%d", fd)
			return nil
		}
	}

	udpAddr, err := net.ResolveUDPAddr("udp", *serverAddr)
	if err != nil {
		log.Fatalf("resolve server addr: %v", err)
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
		log.Fatalf("hysteria client construction/handshake failed: %v", err)
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
			log.Printf("socks5 serve error: %v", err)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	log.Print("shutting down")
	_ = listener.Close()
	_ = hyClient.Close()

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
