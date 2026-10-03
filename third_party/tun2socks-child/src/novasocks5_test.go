package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	M "github.com/xjasonlyu/tun2socks/v2/metadata"
	"github.com/xjasonlyu/tun2socks/v2/proxy"
)

const tUser = "nova-user"
const tPass = "fedcba9876543210fedcba9876543210"

// fakeSocksServer is a minimal SOCKS5 server for the client-side tests. It
// authenticates with tUser/tPass, answers CONNECT with success, and answers
// UDP ASSOCIATE with the address of its own loopback relay socket. Before it
// replies to UDP ASSOCIATE it sends one probe datagram from the relay to the
// declared client address - which only arrives if the client had already
// bound that socket when it sent the request.
type fakeSocksServer struct {
	ln       net.Listener
	relay    *net.UDPConn
	declared chan *net.UDPAddr
}

func newFakeSocksServer(t *testing.T) *fakeSocksServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	s := &fakeSocksServer{ln: ln, relay: relay, declared: make(chan *net.UDPAddr, 4)}
	t.Cleanup(func() { _ = ln.Close(); _ = relay.Close() })
	go s.serve()
	return s
}

func (s *fakeSocksServer) addr() string { return s.ln.Addr().String() }

func (s *fakeSocksServer) serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(c)
	}
}

func (s *fakeSocksServer) handle(c net.Conn) {
	defer c.Close()
	buf := make([]byte, 512)
	if _, err := io.ReadFull(c, buf[:2]); err != nil {
		return
	}
	methods := make([]byte, buf[1])
	_, _ = io.ReadFull(c, methods)
	offered := false
	for _, m := range methods {
		offered = offered || m == 0x02
	}
	if !offered {
		_, _ = c.Write([]byte{0x05, 0xFF})
		return
	}
	_, _ = c.Write([]byte{0x05, 0x02})
	_, _ = io.ReadFull(c, buf[:2])
	user := make([]byte, buf[1])
	_, _ = io.ReadFull(c, user)
	_, _ = io.ReadFull(c, buf[:1])
	pass := make([]byte, buf[0])
	_, _ = io.ReadFull(c, pass)
	if string(user) != tUser || string(pass) != tPass {
		_, _ = c.Write([]byte{0x01, 0x01})
		return
	}
	_, _ = c.Write([]byte{0x01, 0x00})

	if _, err := io.ReadFull(c, buf[:4]); err != nil {
		return
	}
	cmd, atyp := buf[1], buf[3]
	if atyp != 0x01 {
		return
	}
	_, _ = io.ReadFull(c, buf[4:10])
	dst := &net.UDPAddr{IP: net.IP(append([]byte(nil), buf[4:8]...)), Port: int(binary.BigEndian.Uint16(buf[8:10]))}
	switch cmd {
	case 0x01: // CONNECT
		_, _ = c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		_, _ = io.Copy(c, c)
	case 0x03: // UDP ASSOCIATE
		s.declared <- dst
		_, _ = s.relay.WriteToUDP(udpPacket("probe"), dst)
		r := s.relay.LocalAddr().(*net.UDPAddr)
		rep := []byte{0x05, 0x00, 0x00, 0x01}
		rep = append(rep, r.IP.To4()...)
		rep = binary.BigEndian.AppendUint16(rep, uint16(r.Port))
		_, _ = c.Write(rep)
		_, _ = io.Copy(io.Discard, c)
	}
}

// udpPacket builds a SOCKS5 UDP datagram claiming to come from 9.9.9.9:53.
func udpPacket(payload string) []byte {
	return append([]byte{0, 0, 0, 0x01, 9, 9, 9, 9, 0, 53}, payload...)
}

func dialUDP(t *testing.T, s *fakeSocksServer, user, pass string) (*novaPacketConn, error) {
	t.Helper()
	p, err := newNovaSocks5(s.addr(), user, pass)
	if err != nil {
		t.Fatal(err)
	}
	pc, err := p.DialUDP(&M.Metadata{})
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { _ = pc.Close() })
	return pc.(*novaPacketConn), nil
}

func readPayload(t *testing.T, pc *novaPacketConn) (string, net.Addr) {
	t.Helper()
	_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	b := make([]byte, 512)
	n, from, err := pc.ReadFrom(b)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	return string(b[:n]), from
}

func TestUDPSocketBindsLoopbackAndIsDeclaredBeforeAssociate(t *testing.T) {
	s := newFakeSocksServer(t)
	pc, err := dialUDP(t, s, tUser, tPass)
	if err != nil {
		t.Fatal(err)
	}
	local := pc.LocalAddr().(*net.UDPAddr)
	if !local.IP.Equal(net.IPv4(127, 0, 0, 1)) || local.IP.IsUnspecified() {
		t.Fatalf("UDP socket bound to %v, want 127.0.0.1", local)
	}
	declared := <-s.declared
	if !declared.IP.Equal(local.IP) || declared.Port != local.Port {
		t.Fatalf("declared %v, but socket is bound to %v", declared, local)
	}
	// The probe was sent to the declared address BEFORE the server replied,
	// so receiving it proves the socket existed when ASSOCIATE was sent.
	if got, from := readPayload(t, pc); got != "probe" || from.String() != "9.9.9.9:53" {
		t.Fatalf("probe not received before reply: %q from %v", got, from)
	}
}

func TestRelayResponseParsedAndWritesGoToRelay(t *testing.T) {
	s := newFakeSocksServer(t)
	pc, err := dialUDP(t, s, tUser, tPass)
	if err != nil {
		t.Fatal(err)
	}
	if !pc.rAddr.IP.Equal(net.IPv4(127, 0, 0, 1)) || pc.rAddr.Port != s.relay.LocalAddr().(*net.UDPAddr).Port {
		t.Fatalf("relay parsed as %v, server relay is %v", pc.rAddr, s.relay.LocalAddr())
	}
	if _, err := pc.WriteTo([]byte("hello"), &net.UDPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 53}); err != nil {
		t.Fatal(err)
	}
	_ = s.relay.SetReadDeadline(time.Now().Add(2 * time.Second))
	b := make([]byte, 512)
	n, from, err := s.relay.ReadFromUDP(b)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(b[:n]), "hello") || from.Port != pc.LocalAddr().(*net.UDPAddr).Port {
		t.Fatalf("relay got %q from %v", b[:n], from)
	}
}

func TestOnlyRelayDatagramsAccepted(t *testing.T) {
	s := newFakeSocksServer(t)
	pc, err := dialUDP(t, s, tUser, tPass)
	if err != nil {
		t.Fatal(err)
	}
	readPayload(t, pc) // drain the probe
	local := pc.LocalAddr().(*net.UDPAddr)

	attacker, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer attacker.Close()
	_, _ = attacker.WriteToUDP(udpPacket("injected"), local)
	time.Sleep(50 * time.Millisecond)
	_, _ = s.relay.WriteToUDP(udpPacket("from-relay"), local)

	if got, _ := readPayload(t, pc); got != "from-relay" {
		t.Fatalf("got %q, injected datagram was not dropped", got)
	}
	if pc.isFromRelay(attacker.LocalAddr()) {
		t.Fatal("attacker address treated as relay")
	}
}

func TestAuthenticationRequiredAndChecked(t *testing.T) {
	s := newFakeSocksServer(t)
	if _, err := dialUDP(t, s, tUser, "wrong-password"); err == nil {
		t.Fatal("wrong password accepted for UDP ASSOCIATE")
	}
	p, err := newNovaSocks5(s.addr(), tUser, tPass)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c, err := p.DialContext(ctx, &M.Metadata{DstIP: netip.MustParseAddr("1.2.3.4"), DstPort: 80})
	if err != nil {
		t.Fatalf("authenticated CONNECT failed: %v", err)
	}
	_ = c.Close()

	bad, _ := newNovaSocks5(s.addr(), tUser, "nope")
	if _, err := bad.DialContext(ctx, &M.Metadata{DstIP: netip.MustParseAddr("1.2.3.4"), DstPort: 80}); err == nil {
		t.Fatal("wrong password accepted for CONNECT")
	}
}

func TestConstructionFailsClosed(t *testing.T) {
	for _, tc := range [][3]string{
		{"127.0.0.1:1080", "", tPass},
		{"127.0.0.1:1080", tUser, ""},
		{"127.0.0.1:0", tUser, tPass},
		{"0.0.0.0:1080", tUser, tPass},
		{"10.0.0.1:1080", tUser, tPass},
		{"[::1]:1080", tUser, tPass},
		{"localhost:1080", tUser, tPass},
	} {
		if _, err := newNovaSocks5(tc[0], tc[1], tc[2]); err == nil {
			t.Fatalf("accepted %q", tc)
		}
	}
}

func TestCredentialsNeverInLogsOrProxyURL(t *testing.T) {
	hdr := controlHeader{MTU: 1400, SocksAddr: "127.0.0.1:43210", SocksUser: tUser, SocksPass: tPass}
	line := startedLogLine(4242, hdr)
	u := proxyURL(hdr)
	for _, s := range []string{line, u} {
		if strings.Contains(s, tPass) || strings.Contains(s, tUser) {
			t.Fatalf("credential leaked into %q", s)
		}
	}
	if !strings.Contains(line, "protocol=novasocks5") || !strings.Contains(line, "socksAddr=127.0.0.1:43210") || !strings.Contains(line, "authenticated=true") {
		t.Fatalf("unexpected start line %q", line)
	}
	if u != "novasocks5://127.0.0.1:43210" {
		t.Fatalf("unexpected proxy URL %q", u)
	}
	for _, bad := range []controlHeader{
		{MTU: 1400, SocksAddr: "127.0.0.1:43210", SocksUser: tUser},
		{MTU: 1400, SocksAddr: "0.0.0.0:43210", SocksUser: tUser, SocksPass: tPass},
	} {
		err := validateHeader(bad)
		if err == nil || strings.Contains(err.Error(), tPass) {
			t.Fatalf("validateHeader(%+v) = %v", bad, err)
		}
	}
}

func TestSuccessAckCarriesSocksAuthCapabilityMarker(t *testing.T) {
	b, err := json.Marshal(ackResponse{OK: true, PID: 7, SocksAuth: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"socksAuth":true`) {
		t.Fatalf("ack %s lacks the socksAuth marker", b)
	}
	failed, _ := json.Marshal(ackResponse{OK: false, Error: "x"})
	if strings.Contains(string(failed), "socksAuth") {
		t.Fatalf("failure ack must not claim the capability: %s", failed)
	}
}

func TestRegisteredProtocolUsesCapturedCredentialsAndRejectsURLUserinfo(t *testing.T) {
	registerNovaSocks5(tUser, tPass)
	ok, _ := url.Parse("novasocks5://127.0.0.1:43210")
	p, err := proxy.Parse(ok)
	if err != nil {
		t.Fatal(err)
	}
	ns := p.(*novaSocks5)
	if ns.user != tUser || ns.pass != tPass || ns.addr != "127.0.0.1:43210" {
		t.Fatalf("unexpected proxy %+v", ns)
	}
	withCreds, _ := url.Parse("novasocks5://a:b@127.0.0.1:43210")
	if _, err := proxy.Parse(withCreds); err == nil {
		t.Fatal("userinfo in proxy URL must be rejected")
	}
}
