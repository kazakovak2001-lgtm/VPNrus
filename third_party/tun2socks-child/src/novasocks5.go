// Nova B46-4A - "novasocks5": the tun2socks proxy protocol the Hysteria2
// tun2socks child uses to reach the local Hysteria2 SOCKS5 listener.
//
// Derived from xjasonlyu/tun2socks proxy/socks5/socks5.go at the pinned commit
// 5d9fac67bb1095a5d2bd959216f85e6434524731 (MIT, Copyright (c) 2019 Jason Lyu -
// see ../UPSTREAM-LICENSE), plus the two helpers it needs from the upstream
// module's internal proxy/internal/utils package. It is registered through the
// public proxy.RegisterProtocol API; no upstream file is modified. Every
// deviation from upstream is marked "NOVA B46-4A":
//
//  1. Credentials are captured by the registering closure (see
//     registerNovaSocks5), never carried in the proxy URL, so they cannot
//     reach the engine's "[STACK] device <-> proxy" log line or a URL parse
//     error.
//  2. DialUDP binds its UDP socket to 127.0.0.1:0 BEFORE the handshake and
//     declares that exact address in UDP ASSOCIATE (RFC 1928 DST.ADDR/PORT),
//     instead of declaring 0.0.0.0:0 and binding 0.0.0.0 afterwards. The
//     Hysteria2 side pins its relay to this declared address.
//  3. ReadFrom accepts a datagram only if its real network source is the
//     negotiated relay address; anything else is dropped before the SOCKS UDP
//     header is even decoded.
//  4. The relay address must be 127.0.0.1 with a non-zero port.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"time"

	"github.com/xjasonlyu/tun2socks/v2/dialer"
	M "github.com/xjasonlyu/tun2socks/v2/metadata"
	"github.com/xjasonlyu/tun2socks/v2/proxy"
	"github.com/xjasonlyu/tun2socks/v2/transport/socks5"
)

// novaSocks5Scheme is the proxy URL scheme registered with tun2socks.
const novaSocks5Scheme = "novasocks5"

// From upstream proxy/internal/utils (not importable from this module).
const (
	tcpConnectTimeout  = 5 * time.Second
	tcpKeepAlivePeriod = 30 * time.Second
)

func setKeepAlive(c net.Conn) {
	if tcp, ok := c.(*net.TCPConn); ok {
		_ = tcp.SetKeepAlive(true)
		_ = tcp.SetKeepAlivePeriod(tcpKeepAlivePeriod)
	}
}

func serializeSocksAddr(m *M.Metadata) socks5.Addr {
	return socks5.SerializeAddr("", m.DstIP, m.DstPort)
}

var loopbackV4 = net.IPv4(127, 0, 0, 1)

var _ proxy.Proxy = (*novaSocks5)(nil)

type novaSocks5 struct {
	addr string
	user string
	pass string
}

// NOVA B46-4A: newNovaSocks5 fails closed unless addr is 127.0.0.1:<non-zero>
// and both credentials are present.
func newNovaSocks5(addr, user, pass string) (*novaSocks5, error) {
	if err := validateLoopbackSocksAddr(addr); err != nil {
		return nil, err
	}
	if user == "" || pass == "" {
		return nil, errors.New("novasocks5: credentials are required")
	}
	return &novaSocks5{addr: addr, user: user, pass: pass}, nil
}

// validateLoopbackSocksAddr accepts only "127.0.0.1:<1-65535>".
func validateLoopbackSocksAddr(addr string) error {
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		return fmt.Errorf("novasocks5: invalid socks address: %w", err)
	}
	if ap.Addr() != netip.AddrFrom4([4]byte{127, 0, 0, 1}) || ap.Port() == 0 {
		return errors.New("novasocks5: socks address must be 127.0.0.1 with a non-zero port")
	}
	return nil
}

// registerNovaSocks5 registers the "novasocks5" scheme with credentials
// captured in the closure. The URL handed to the engine therefore only ever
// holds "novasocks5://127.0.0.1:<port>"; any userinfo in it is rejected.
func registerNovaSocks5(user, pass string) {
	proxy.RegisterProtocol(novaSocks5Scheme, func(u *url.URL) (proxy.Proxy, error) {
		if u.User != nil {
			return nil, errors.New("novasocks5: credentials must not be in the proxy URL")
		}
		return newNovaSocks5(u.Host, user, pass)
	})
}

func (ss *novaSocks5) socksUser() *socks5.User {
	return &socks5.User{Username: ss.user, Password: ss.pass}
}

func (ss *novaSocks5) DialContext(ctx context.Context, metadata *M.Metadata) (c net.Conn, err error) {
	c, err = dialer.DialContext(ctx, "tcp", ss.addr)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", ss.addr, err)
	}
	setKeepAlive(c)

	defer func() {
		if err != nil && c != nil {
			c.Close()
		}
	}()

	_, err = socks5.ClientHandshake(c, serializeSocksAddr(metadata), socks5.CmdConnect, ss.socksUser())
	return
}

func (ss *novaSocks5) DialUDP(*M.Metadata) (_ net.PacketConn, err error) {
	// NOVA B46-4A: bind the loopback UDP socket first so its exact address
	// can be declared in UDP ASSOCIATE.
	pc, err := dialer.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen packet: %w", err)
	}
	defer func() {
		if err != nil {
			pc.Close()
		}
	}()
	local, ok := pc.LocalAddr().(*net.UDPAddr)
	if !ok || !local.IP.Equal(loopbackV4) || local.Port == 0 {
		return nil, fmt.Errorf("novasocks5: unexpected local UDP address %v", pc.LocalAddr())
	}

	ctx, cancel := context.WithTimeout(context.Background(), tcpConnectTimeout)
	defer cancel()

	c, err := dialer.DialContext(ctx, "tcp", ss.addr)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", ss.addr, err)
	}
	setKeepAlive(c)

	defer func() {
		if err != nil {
			c.Close()
		}
	}()

	// The UDP ASSOCIATE request is used to establish an association within
	// the UDP relay process to handle UDP datagrams. The DST.ADDR and
	// DST.PORT fields contain the address and port that the client expects
	// to use to send UDP datagrams on for the association. RFC1928
	// NOVA B46-4A: declare the real bound address, never 0.0.0.0:0.
	declared := socks5.SerializeAddr("", netip.AddrFrom4([4]byte{127, 0, 0, 1}), uint16(local.Port))
	addr, err := socks5.ClientHandshake(c, declared, socks5.CmdUDPAssociate, ss.socksUser())
	if err != nil {
		return nil, fmt.Errorf("client handshake: %w", err)
	}

	bindAddr := addr.UDPAddr()
	if bindAddr == nil {
		return nil, fmt.Errorf("invalid UDP binding address: %#v", addr)
	}
	if bindAddr.IP.IsUnspecified() { /* e.g. "0.0.0.0" or "::" */
		bindAddr.IP = loopbackV4
	}
	// NOVA B46-4A: the relay must be a concrete loopback endpoint.
	if !bindAddr.IP.Equal(loopbackV4) || bindAddr.Port == 0 {
		return nil, fmt.Errorf("novasocks5: relay address %v is not 127.0.0.1:<non-zero>", bindAddr)
	}

	go func() {
		io.Copy(io.Discard, c)
		c.Close()
		// A UDP association terminates when the TCP connection that the UDP
		// ASSOCIATE request arrived on terminates. RFC1928
		pc.Close()
	}()

	return &novaPacketConn{PacketConn: pc, rAddr: bindAddr, tcpConn: c}, nil
}

type novaPacketConn struct {
	net.PacketConn

	rAddr   *net.UDPAddr
	tcpConn net.Conn
}

func (pc *novaPacketConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	var packet []byte
	if ma, ok := addr.(*M.Addr); ok {
		packet, err = socks5.EncodeUDPPacket(serializeSocksAddr(ma.Metadata()), b)
	} else {
		packet, err = socks5.EncodeUDPPacket(socks5.ParseAddr(addr), b)
	}

	if err != nil {
		return n, err
	}
	return pc.PacketConn.WriteTo(packet, pc.rAddr)
}

// isFromRelay reports whether a datagram's real network source is the
// negotiated relay endpoint.
func (pc *novaPacketConn) isFromRelay(from net.Addr) bool {
	u, ok := from.(*net.UDPAddr)
	return ok && u.IP.Equal(pc.rAddr.IP) && u.Port == pc.rAddr.Port
}

func (pc *novaPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		n, from, err := pc.PacketConn.ReadFrom(b)
		if err != nil {
			return 0, nil, err
		}
		// NOVA B46-4A: drop anything not sent by the negotiated relay.
		if !pc.isFromRelay(from) {
			continue
		}

		addr, payload, err := socks5.DecodeUDPPacket(b[:n])
		if err != nil {
			return 0, nil, err
		}

		udpAddr := addr.UDPAddr()
		if udpAddr == nil {
			return 0, nil, fmt.Errorf("convert %s to UDPAddr is nil", addr)
		}

		// due to DecodeUDPPacket is mutable, record addr length
		copy(b, payload)
		return n - len(addr) - 3, udpAddr, nil
	}
}

func (pc *novaPacketConn) Close() error {
	pc.tcpConn.Close()
	return pc.PacketConn.Close()
}
