// Command hysteria-server-prototype is a B46-4P research prototype.
//
// It exists to answer ONE narrow technical question: can a standalone
// Hysteria2 server binary be built directly against the upstream
// github.com/apernet/hysteria/core/v2/server public library API, without
// importing app/cmd, app/internal/tun, github.com/apernet/sing-tun, or
// github.com/sagernet/sing at all - at either the source or compiled-binary
// level?
//
// This is a prototype for a licensing-evidence experiment, not a production
// artifact. It is not wired into any Nova deployment, build, or release
// process. See docs/B46_4P_HYSTERIA2_LICENSING_REVIEW.md section 7A and
// docs/B46_4P_HYSTERIA2_SERVER_ONLY_PROTOTYPE.md for the full evidence this
// binary was built to produce.
//
// It deliberately does NOT import:
//   - github.com/apernet/hysteria/app/v2/... (the upstream CLI, which is
//     where app/cmd/client.go and app/internal/tun live)
//   - github.com/apernet/sing-tun
//   - github.com/sagernet/sing
//
// It imports only github.com/apernet/hysteria/core/v2/server (MIT), plus
// the Go standard library, for a minimal config -> create -> listen ->
// serve -> graceful-close lifecycle.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	hyserver "github.com/apernet/hysteria/core/v2/server"
)

// fixedPasswordAuthenticator is a minimal Authenticator implementation for
// this prototype only: it accepts a single, prototype-supplied password.
// This is NOT Nova's production auth.type:http design (gateway/hysteria's
// real integration reuses hysteria_auth_backend.py via extras/v2/auth) -
// wiring that in is explicitly out of scope for this build-graph
// experiment, which only needs the server to accept a connection at all.
type fixedPasswordAuthenticator struct {
	password string
}

func (a *fixedPasswordAuthenticator) Authenticate(addr net.Addr, auth string, tx uint64) (ok bool, id string) {
	if auth != a.password {
		return false, ""
	}
	return true, "prototype-client"
}

// generateEphemeralSelfSignedCert creates a throwaway, in-memory-only
// ECDSA/TLS certificate for LOCAL TEST USE ONLY. It is never written to
// disk, never reused across runs, and must never be treated as a
// production certificate. Used only when no real cert/key path is given
// via -cert/-key.
func generateEphemeralSelfSignedCert(host string) (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate serial: %w", err)
	}
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{host},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create certificate: %w", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}, nil
}

func main() {
	listenAddr := flag.String("listen", "127.0.0.1:0", "local UDP listen address (LOCAL TEST ONLY - never a production address/port)")
	password := flag.String("password", "", "auth password for this run (random if empty)")
	runFor := flag.Duration("run-for", 0, "if nonzero, shut down automatically after this duration instead of waiting for a signal (for automated evidence capture)")
	flag.Parse()

	host, _, err := net.SplitHostPort(*listenAddr)
	if err != nil || host == "" {
		host = "127.0.0.1"
	}
	if host != "127.0.0.1" && host != "localhost" && host != "::1" {
		log.Fatalf("refusing to bind non-loopback host %q - this prototype is for local evidence capture only", host)
	}

	pw := *password
	if pw == "" {
		buf := make([]byte, 16)
		if _, err := rand.Read(buf); err != nil {
			log.Fatalf("generate random password: %v", err)
		}
		pw = base64.RawURLEncoding.EncodeToString(buf)
	}

	cert, err := generateEphemeralSelfSignedCert(host)
	if err != nil {
		log.Fatalf("generate ephemeral test certificate: %v", err)
	}

	packetConn, err := net.ListenPacket("udp", *listenAddr)
	if err != nil {
		log.Fatalf("listen udp: %v", err)
	}

	cfg := &hyserver.Config{
		TLSConfig: hyserver.TLSConfig{
			Certificates: []tls.Certificate{cert},
		},
		Conn:          packetConn,
		Authenticator: &fixedPasswordAuthenticator{password: pw},
	}

	srv, err := hyserver.NewServer(cfg)
	if err != nil {
		log.Fatalf("hyserver.NewServer: %v", err)
	}

	log.Printf("PROTOTYPE_LISTENING addr=%s", packetConn.LocalAddr())

	serveErrCh := make(chan error, 1)
	go func() {
		serveErrCh <- srv.Serve()
	}()

	// Give Serve() a brief moment to actually enter its accept loop before
	// declaring the server "alive" for evidence-capture purposes.
	time.Sleep(200 * time.Millisecond)
	select {
	case err := <-serveErrCh:
		log.Fatalf("server exited immediately: %v", err)
	default:
		log.Print("PROTOTYPE_ALIVE")
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	if *runFor > 0 {
		select {
		case <-time.After(*runFor):
			log.Printf("PROTOTYPE_AUTO_SHUTDOWN after=%s", *runFor)
		case <-sigCh:
			log.Print("PROTOTYPE_SIGNAL_SHUTDOWN")
		}
	} else {
		<-sigCh
		log.Print("PROTOTYPE_SIGNAL_SHUTDOWN")
	}

	if err := srv.Close(); err != nil {
		log.Printf("server close error: %v", err)
	}

	select {
	case err := <-serveErrCh:
		if err != nil && !errors.Is(err, net.ErrClosed) {
			log.Printf("Serve() returned: %v", err)
		}
	case <-time.After(5 * time.Second):
		log.Print("PROTOTYPE_SHUTDOWN_TIMEOUT")
	}

	log.Print("PROTOTYPE_SHUTDOWN_COMPLETE")
}
