// Nova B46-4A - hardened local SOCKS5 server for the Hysteria2 child.
//
// Derived from apernet/hysteria app/internal/socks5/server.go at the pinned
// commit e1366b173ccf5706e1e4630fe8aa654a4b574085 (MIT, Copyright 2023 Toby -
// see ../UPSTREAM-LICENSE.md). That package is `internal` to the upstream app
// module, so it is copied here rather than imported. Every deviation from the
// upstream file is marked "NOVA B46-4A":
//
//  1. Authentication is mandatory: Serve refuses to run without AuthFunc, so
//     the listener can never offer the no-auth method.
//  2. UDP ASSOCIATE must declare the exact client UDP address, and it must be
//     127.0.0.1 with a non-zero port. Anything else (0.0.0.0, port 0, another
//     IP, a domain, IPv6) is refused with "connection not allowed".
//  3. The UDP relay is pinned to that declared address BEFORE any datagram is
//     read. The upstream "first UDP sender becomes the client" rule is gone,
//     so another local process can no longer take over an association by
//     racing the legitimate client's first packet.
//
// TCP CONNECT handling is unchanged apart from the mandatory authentication.
package main

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"net"

	"github.com/txthinking/socks5"

	"github.com/apernet/hysteria/core/v2/client"
)

const udpBufferSize = 4096

// NOVA B46-4A: returned by Serve when no AuthFunc is configured.
var errSocksAuthRequired = errors.New("socks5: authentication is mandatory (AuthFunc is nil)")

// Server is a SOCKS5 server using a Hysteria client as outbound.
type Server struct {
	HyClient    client.Client
	AuthFunc    func(username, password string) bool // NOVA B46-4A: required, never nil
	DisableUDP  bool
	EventLogger EventLogger
}

type EventLogger interface {
	TCPRequest(addr net.Addr, reqAddr string)
	TCPError(addr net.Addr, reqAddr string, err error)
	UDPRequest(addr net.Addr)
	UDPError(addr net.Addr, err error)
}

// NOVA B46-4A: constant-time credential check for the per-session local SOCKS
// credentials. Both comparisons always run, so the result does not reveal
// which half was wrong. Empty expected credentials never match.
func newCredentialAuthFunc(username, password string) func(string, string) bool {
	wantUser := []byte(username)
	wantPass := []byte(password)
	return func(u, p string) bool {
		if len(wantUser) == 0 || len(wantPass) == 0 {
			return false
		}
		userOK := subtle.ConstantTimeCompare([]byte(u), wantUser)
		passOK := subtle.ConstantTimeCompare([]byte(p), wantPass)
		return userOK&passOK == 1
	}
}

func (s *Server) Serve(listener net.Listener) error {
	// NOVA B46-4A: fail closed - never serve anonymous SOCKS.
	if s.AuthFunc == nil {
		return errSocksAuthRequired
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go s.dispatch(conn)
	}
}

func (s *Server) dispatch(conn net.Conn) {
	ok, _ := s.negotiate(conn)
	if !ok {
		_ = conn.Close()
		return
	}
	// Negotiation ok, get and handle the request
	req, err := socks5.NewRequestFrom(conn)
	if err != nil {
		_ = conn.Close()
		return
	}
	switch req.Cmd {
	case socks5.CmdConnect: // TCP
		s.handleTCP(conn, req)
	case socks5.CmdUDP: // UDP
		if s.DisableUDP {
			_ = sendSimpleReply(conn, socks5.RepCommandNotSupported)
			_ = conn.Close()
			return
		}
		s.handleUDP(conn, req)
	default:
		_ = sendSimpleReply(conn, socks5.RepCommandNotSupported)
		_ = conn.Close()
	}
}

func (s *Server) negotiate(conn net.Conn) (bool, error) {
	req, err := socks5.NewNegotiationRequestFrom(conn)
	if err != nil {
		return false, err
	}
	var serverMethod byte
	if s.AuthFunc != nil {
		serverMethod = socks5.MethodUsernamePassword
	} else {
		serverMethod = socks5.MethodNone
	}
	// Look for the supported method in the client request
	supported := false
	for _, m := range req.Methods {
		if m == serverMethod {
			supported = true
			break
		}
	}
	if !supported {
		// No supported method found, reject the client
		rep := socks5.NewNegotiationReply(socks5.MethodUnsupportAll)
		_, err := rep.WriteTo(conn)
		return false, err
	}
	// OK, send the method we chose
	rep := socks5.NewNegotiationReply(serverMethod)
	_, err = rep.WriteTo(conn)
	if err != nil {
		return false, err
	}
	// If we chose the username/password method, authenticate the client
	if serverMethod == socks5.MethodUsernamePassword {
		req, err := socks5.NewUserPassNegotiationRequestFrom(conn)
		if err != nil {
			return false, err
		}
		ok := s.AuthFunc(string(req.Uname), string(req.Passwd))
		if ok {
			rep := socks5.NewUserPassNegotiationReply(socks5.UserPassStatusSuccess)
			_, err := rep.WriteTo(conn)
			if err != nil {
				return false, err
			}
		} else {
			rep := socks5.NewUserPassNegotiationReply(socks5.UserPassStatusFailure)
			_, err := rep.WriteTo(conn)
			return false, err
		}
	}
	return true, nil
}

func (s *Server) handleTCP(conn net.Conn, req *socks5.Request) {
	defer conn.Close()

	addr := req.Address()

	// TCP request & error log
	if s.EventLogger != nil {
		s.EventLogger.TCPRequest(conn.RemoteAddr(), addr)
	}
	var closeErr error
	defer func() {
		if s.EventLogger != nil {
			s.EventLogger.TCPError(conn.RemoteAddr(), addr, closeErr)
		}
	}()

	// Dial
	rConn, err := s.HyClient.TCP(addr)
	if err != nil {
		_ = sendSimpleReply(conn, socks5.RepHostUnreachable)
		closeErr = err
		return
	}
	defer rConn.Close()

	// Send reply and start relaying
	_ = sendSimpleReply(conn, socks5.RepSuccess)
	copyErrChan := make(chan error, 2)
	go func() {
		_, err := io.Copy(rConn, conn)
		copyErrChan <- err
	}()
	go func() {
		_, err := io.Copy(conn, rConn)
		copyErrChan <- err
	}()
	closeErr = <-copyErrChan
}

// NOVA B46-4A: errUDPClientNotDeclared reports a UDP ASSOCIATE whose declared
// client address is not an exact, non-zero 127.0.0.1 endpoint.
var errUDPClientNotDeclared = errors.New("socks5: UDP ASSOCIATE must declare 127.0.0.1 with a non-zero port")

// NOVA B46-4A: declaredUDPClient returns the client UDP address declared in
// the UDP ASSOCIATE request (RFC 1928 DST.ADDR/DST.PORT). Only IPv4
// 127.0.0.1 with a non-zero port is accepted - never the all-zeros
// "unknown yet" form, another address, a domain name or IPv6.
func declaredUDPClient(req *socks5.Request) (*net.UDPAddr, error) {
	if req.Atyp != socks5.ATYPIPv4 || len(req.DstAddr) != net.IPv4len || len(req.DstPort) != 2 {
		return nil, errUDPClientNotDeclared
	}
	ip := net.IP(req.DstAddr)
	port := int(binary.BigEndian.Uint16(req.DstPort))
	if !ip.Equal(net.IPv4(127, 0, 0, 1)) || port == 0 {
		return nil, errUDPClientNotDeclared
	}
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}, nil
}

func (s *Server) handleUDP(conn net.Conn, req *socks5.Request) {
	defer conn.Close()

	// UDP request & error log
	if s.EventLogger != nil {
		s.EventLogger.UDPRequest(conn.RemoteAddr())
	}
	var closeErr error
	defer func() {
		if s.EventLogger != nil {
			s.EventLogger.UDPError(conn.RemoteAddr(), closeErr)
		}
	}()

	// NOVA B46-4A: the client must declare its exact UDP source up front.
	clientAddr, err := declaredUDPClient(req)
	if err != nil {
		_ = sendSimpleReply(conn, socks5.RepNotAllowed)
		closeErr = err
		return
	}

	// Start UDP relay server
	// SOCKS5 UDP requires the server to return the UDP bind address and port in the reply.
	// We bind to the same address that our TCP server listens on (but a different port).
	host, _, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		// Is this even possible?
		_ = sendSimpleReply(conn, socks5.RepServerFailure)
		closeErr = err
		return
	}
	udpAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, "0"))
	if err != nil {
		_ = sendSimpleReply(conn, socks5.RepServerFailure)
		closeErr = err
		return
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		_ = sendSimpleReply(conn, socks5.RepServerFailure)
		closeErr = err
		return
	}
	defer udpConn.Close()

	// HyClient UDP session
	hyUDP, err := s.HyClient.UDP()
	if err != nil {
		_ = sendSimpleReply(conn, socks5.RepServerFailure)
		closeErr = err
		return
	}
	defer hyUDP.Close()

	// Send reply
	_ = sendUDPReply(conn, udpConn.LocalAddr().(*net.UDPAddr))

	// UDP relay & SOCKS5 connection holder
	errChan := make(chan error, 2)
	go func() {
		err := s.udpServer(udpConn, hyUDP, clientAddr)
		errChan <- err
	}()
	go func() {
		_, err := io.Copy(io.Discard, conn)
		errChan <- err
	}()
	closeErr = <-errChan
}

// NOVA B46-4A: clientAddr is the address declared in UDP ASSOCIATE. It is
// fixed before the first datagram is read; datagrams from any other source
// are dropped, and replies only ever go to clientAddr.
func (s *Server) udpServer(udpConn *net.UDPConn, hyUDP client.HyUDPConn, clientAddr *net.UDPAddr) error {
	// remote -> local, started immediately because the client is already known.
	go func() {
		for {
			bs, from, err := hyUDP.Receive()
			if err != nil {
				// Close the UDP conn so that the local -> remote direction will exit
				_ = udpConn.Close()
				return
			}
			atyp, addr, port, err := socks5.ParseAddress(from)
			if err != nil {
				continue
			}
			if atyp == socks5.ATYPDomain {
				// socks5.ParseAddress adds a leading byte for domains,
				// but socks5.NewDatagram will add it again as it expects a raw domain.
				// So we must remove it here.
				addr = addr[1:]
			}
			d := socks5.NewDatagram(atyp, addr, port, bs)
			_, _ = udpConn.WriteToUDP(d.Bytes(), clientAddr)
		}
	}()

	buf := make([]byte, udpBufferSize)
	// local -> remote
	for {
		n, cAddr, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			return err
		}
		if !clientAddr.IP.Equal(cAddr.IP) || clientAddr.Port != cAddr.Port {
			// Not our declared client, ignore
			continue
		}
		d, err := socks5.NewDatagramFromBytes(buf[:n])
		if err != nil || d.Frag != 0 {
			// Ignore bad packets
			// Also we don't support SOCKS5 UDP fragmentation for now
			continue
		}
		// Send to remote
		_ = hyUDP.Send(d.Data, d.Address())
	}
}

// sendSimpleReply sends a SOCKS5 reply with the given reply code.
// It does not contain bind address or port, so it's not suitable for successful UDP requests.
func sendSimpleReply(conn net.Conn, rep byte) error {
	p := socks5.NewReply(rep, socks5.ATYPIPv4, []byte{0x00, 0x00, 0x00, 0x00}, []byte{0x00, 0x00})
	_, err := p.WriteTo(conn)
	return err
}

// sendUDPReply sends a SOCKS5 reply with the given reply code and bind address/port.
func sendUDPReply(conn net.Conn, addr *net.UDPAddr) error {
	var atyp byte
	var bndAddr, bndPort []byte
	if ip4 := addr.IP.To4(); ip4 != nil {
		atyp = socks5.ATYPIPv4
		bndAddr = ip4
	} else {
		atyp = socks5.ATYPIPv6
		bndAddr = addr.IP
	}
	bndPort = make([]byte, 2)
	binary.BigEndian.PutUint16(bndPort, uint16(addr.Port))
	p := socks5.NewReply(socks5.RepSuccess, atyp, bndAddr, bndPort)
	_, err := p.WriteTo(conn)
	return err
}
