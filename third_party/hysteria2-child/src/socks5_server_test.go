package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/apernet/hysteria/core/v2/client"
)

// --- fakes -----------------------------------------------------------------

type sentDatagram struct {
	data []byte
	addr string
}

type fakeHyUDP struct {
	sent     chan sentDatagram
	incoming chan sentDatagram
	closed   chan struct{}
}

func newFakeHyUDP() *fakeHyUDP {
	return &fakeHyUDP{
		sent:     make(chan sentDatagram, 16),
		incoming: make(chan sentDatagram, 16),
		closed:   make(chan struct{}),
	}
}

func (f *fakeHyUDP) Receive() ([]byte, string, error) {
	select {
	case d := <-f.incoming:
		return d.data, d.addr, nil
	case <-f.closed:
		return nil, "", io.EOF
	}
}

func (f *fakeHyUDP) Send(b []byte, addr string) error {
	f.sent <- sentDatagram{data: append([]byte(nil), b...), addr: addr}
	return nil
}

func (f *fakeHyUDP) Close() error {
	select {
	case <-f.closed:
	default:
		close(f.closed)
	}
	return nil
}

type fakeHyClient struct {
	udp *fakeHyUDP
}

func (c *fakeHyClient) TCP(addr string) (net.Conn, error) {
	a, b := net.Pipe()
	go func() { _, _ = io.Copy(b, b) }() // echo
	return a, nil
}

func (c *fakeHyClient) UDP() (client.HyUDPConn, error) { return c.udp, nil }
func (c *fakeHyClient) Close() error                  { return nil }

const testUser = "nova-user"
const testPass = "0123456789abcdef0123456789abcdef"

func startServer(t *testing.T) (string, *fakeHyUDP) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udp := newFakeHyUDP()
	srv := &Server{HyClient: &fakeHyClient{udp: udp}, AuthFunc: newCredentialAuthFunc(testUser, testPass)}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = ln.Close(); _ = udp.Close() })
	return ln.Addr().String(), udp
}

// --- raw SOCKS5 client helpers ---------------------------------------------

func readFull(t *testing.T, c net.Conn, n int) []byte {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	b := make([]byte, n)
	if _, err := io.ReadFull(c, b); err != nil {
		t.Fatalf("read %d bytes: %v", n, err)
	}
	return b
}

// handshake returns the open conn and the user/pass status byte (0 = success).
func handshake(t *testing.T, addr, user, pass string) (net.Conn, byte) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_, _ = c.Write([]byte{0x05, 0x01, 0x02})
	if rep := readFull(t, c, 2); rep[1] != 0x02 {
		t.Fatalf("server did not choose username/password: %x", rep)
	}
	msg := []byte{0x01, byte(len(user))}
	msg = append(msg, user...)
	msg = append(msg, byte(len(pass)))
	msg = append(msg, pass...)
	_, _ = c.Write(msg)
	// A malformed user/pass packet (e.g. zero-length username) makes the
	// server close the connection without a status reply - also a rejection.
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	status := make([]byte, 2)
	if _, err := io.ReadFull(c, status); err != nil {
		return c, 0xFF
	}
	return c, status[1]
}

func authed(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, status := handshake(t, addr, testUser, testPass)
	if status != 0x00 {
		t.Fatalf("valid credentials rejected: status=%d", status)
	}
	return c
}

// associate sends UDP ASSOCIATE declaring ip:port and returns (reply code, relay addr).
func associate(t *testing.T, c net.Conn, ip net.IP, port int) (byte, *net.UDPAddr) {
	t.Helper()
	req := []byte{0x05, 0x03, 0x00, 0x01}
	req = append(req, ip.To4()...)
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	_, _ = c.Write(req)
	rep := readFull(t, c, 10)
	return rep[1], &net.UDPAddr{IP: net.IP(rep[4:8]), Port: int(binary.BigEndian.Uint16(rep[8:10]))}
}

func datagram(payload string) []byte {
	// RSV RSV FRAG ATYP=IPv4 1.2.3.4:53 payload
	return append([]byte{0, 0, 0, 0x01, 1, 2, 3, 4, 0, 53}, payload...)
}

func listenLoopbackUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func expectSent(t *testing.T, udp *fakeHyUDP, want string) {
	t.Helper()
	select {
	case d := <-udp.sent:
		if string(d.data) != want {
			t.Fatalf("relayed %q, want %q", d.data, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("expected %q to be relayed", want)
	}
}

func expectNothingSent(t *testing.T, udp *fakeHyUDP) {
	t.Helper()
	select {
	case d := <-udp.sent:
		t.Fatalf("unexpected relayed datagram %q", d.data)
	case <-time.After(300 * time.Millisecond):
	}
}

// --- authentication ----------------------------------------------------------

func TestValidCredentialsAccepted(t *testing.T) {
	addr, _ := startServer(t)
	authed(t, addr)
}

func TestNoAuthMethodRejected(t *testing.T) {
	addr, _ := startServer(t)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = c.Write([]byte{0x05, 0x01, 0x00}) // offers only "no authentication"
	if rep := readFull(t, c, 2); rep[1] != 0xFF {
		t.Fatalf("anonymous client not rejected: %x", rep)
	}
}

func TestWrongCredentialsRejected(t *testing.T) {
	addr, _ := startServer(t)
	for _, cred := range [][2]string{{testUser, "wrong"}, {"wrong", testPass}, {testUser, testPass + "x"}} {
		_, status := handshake(t, addr, cred[0], cred[1])
		if status == 0x00 {
			t.Fatalf("wrong credentials accepted: %q", cred)
		}
	}
}

func TestEmptyCredentialsRejected(t *testing.T) {
	addr, _ := startServer(t)
	if _, status := handshake(t, addr, "", ""); status == 0x00 {
		t.Fatal("empty credentials accepted")
	}
	if newCredentialAuthFunc("", "")("", "") {
		t.Fatal("empty expected credentials must never match")
	}
	if newCredentialAuthFunc("u", "")("u", "") || newCredentialAuthFunc("", "p")("", "p") {
		t.Fatal("half-empty expected credentials must never match")
	}
}

func TestServeRefusesWithoutAuthFunc(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if err := (&Server{HyClient: &fakeHyClient{udp: newFakeHyUDP()}}).Serve(ln); !errors.Is(err, errSocksAuthRequired) {
		t.Fatalf("Serve without AuthFunc returned %v", err)
	}
}

func TestTCPConnectStillWorksWhenAuthenticated(t *testing.T) {
	addr, _ := startServer(t)
	c := authed(t, addr)
	_, _ = c.Write([]byte{0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0, 80})
	if rep := readFull(t, c, 10); rep[1] != 0x00 {
		t.Fatalf("CONNECT failed: %x", rep)
	}
	_, _ = c.Write([]byte("ping"))
	if got := readFull(t, c, 4); string(got) != "ping" {
		t.Fatalf("echo got %q", got)
	}
}

// --- UDP ASSOCIATE declaration ----------------------------------------------

func TestAssociateLoopbackNonZeroAccepted(t *testing.T) {
	addr, _ := startServer(t)
	rep, relay := associate(t, authed(t, addr), net.IPv4(127, 0, 0, 1), 40000)
	if rep != 0x00 {
		t.Fatalf("valid declaration rejected: rep=%d", rep)
	}
	if !relay.IP.Equal(net.IPv4(127, 0, 0, 1)) || relay.Port == 0 {
		t.Fatalf("relay must be a concrete loopback address, got %v", relay)
	}
}

func TestAssociateRejectsUndeclaredOrForeignAddresses(t *testing.T) {
	addr, _ := startServer(t)
	cases := []struct {
		name string
		ip   net.IP
		port int
	}{
		{"unspecified ip", net.IPv4zero, 40000},
		{"zero port", net.IPv4(127, 0, 0, 1), 0},
		{"all zeros", net.IPv4zero, 0},
		{"non-loopback", net.IPv4(10, 0, 0, 1), 40000},
		{"other loopback", net.IPv4(127, 0, 0, 2), 40000},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep, _ := associate(t, authed(t, addr), tc.ip, tc.port)
			if rep != 0x02 {
				t.Fatalf("expected RepNotAllowed (2), got %d", rep)
			}
		})
	}
}

func TestAssociateRejectsDomainAndIPv6(t *testing.T) {
	addr, _ := startServer(t)
	for _, req := range [][]byte{
		append([]byte{0x05, 0x03, 0x00, 0x03, 9}, append([]byte("localhost"), 0x9c, 0x40)...),
		append(append([]byte{0x05, 0x03, 0x00, 0x04}, net.IPv6loopback...), 0x9c, 0x40),
	} {
		c := authed(t, addr)
		_, _ = c.Write(req)
		if rep := readFull(t, c, 10); rep[1] != 0x02 {
			t.Fatalf("expected RepNotAllowed for %x, got %d", req[3], rep[1])
		}
	}
}

// --- UDP relay pinning --------------------------------------------------------

func TestAttackerFirstPacketDoesNotBecomeClient(t *testing.T) {
	addr, udp := startServer(t)
	client := listenLoopbackUDP(t)
	attacker := listenLoopbackUDP(t)
	ctrl := authed(t, addr)
	rep, relay := associate(t, ctrl, net.IPv4(127, 0, 0, 1), client.LocalAddr().(*net.UDPAddr).Port)
	if rep != 0x00 {
		t.Fatalf("associate failed: %d", rep)
	}

	// Attacker wins the race to the relay port.
	_, _ = attacker.WriteToUDP(datagram("attacker"), relay)
	expectNothingSent(t, udp)

	// The declared client is still the client.
	_, _ = client.WriteToUDP(datagram("legit"), relay)
	expectSent(t, udp, "legit")

	// Replies go to the declared client only, never to the attacker.
	udp.incoming <- sentDatagram{data: []byte("reply"), addr: "1.2.3.4:53"}
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 512)
	n, _, err := client.ReadFromUDP(buf)
	if err != nil || !bytes.HasSuffix(buf[:n], []byte("reply")) {
		t.Fatalf("declared client did not get the reply: n=%d err=%v", n, err)
	}
	_ = attacker.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if n, _, err := attacker.ReadFromUDP(buf); err == nil {
		t.Fatalf("attacker received %d bytes", n)
	}
}

func TestDeclaredClientPacketsAccepted(t *testing.T) {
	addr, udp := startServer(t)
	client := listenLoopbackUDP(t)
	_, relay := associate(t, authed(t, addr), net.IPv4(127, 0, 0, 1), client.LocalAddr().(*net.UDPAddr).Port)
	for _, p := range []string{"one", "two", "three"} {
		_, _ = client.WriteToUDP(datagram(p), relay)
		expectSent(t, udp, p)
	}
}

func TestOtherSourcesRejectedAfterClientIsActive(t *testing.T) {
	addr, udp := startServer(t)
	client := listenLoopbackUDP(t)
	other := listenLoopbackUDP(t)
	_, relay := associate(t, authed(t, addr), net.IPv4(127, 0, 0, 1), client.LocalAddr().(*net.UDPAddr).Port)
	_, _ = client.WriteToUDP(datagram("legit"), relay)
	expectSent(t, udp, "legit")
	_, _ = other.WriteToUDP(datagram("injected"), relay)
	expectNothingSent(t, udp)
}

// --- config validation / redaction --------------------------------------------

func TestValidateLocalSocks(t *testing.T) {
	ok := []string{"127.0.0.1:0", "127.0.0.1:41080"}
	for _, l := range ok {
		if err := validateLocalSocks(l, "u", "p"); err != nil {
			t.Fatalf("%s: %v", l, err)
		}
	}
	bad := [][3]string{
		{"0.0.0.0:0", "u", "p"},
		{":0", "u", "p"},
		{"[::1]:0", "u", "p"},
		{"192.168.1.2:0", "u", "p"},
		{"localhost:0", "u", "p"},
		{"127.0.0.1:0", "", "p"},
		{"127.0.0.1:0", "u", ""},
		{"not-an-address", "u", "p"},
	}
	for _, b := range bad {
		if err := validateLocalSocks(b[0], b[1], b[2]); err == nil {
			t.Fatalf("accepted %q", b)
		}
	}
}

func TestSocksPasswordNeverInSummaryAndRedacted(t *testing.T) {
	cfg := novaminimalConfig{Server: "h:443", SocksListen: "127.0.0.1:0", SocksUsername: testUser, SocksPassword: testPass}
	s := cfg.redactedSummary()
	if strings.Contains(s, testPass) || strings.Contains(s, testUser) || !strings.Contains(s, "socksAuthSet=true") {
		t.Fatalf("summary leaks or misses flag: %s", s)
	}
	socksSecret = testPass
	defer func() { socksSecret = "" }()
	if strings.Contains(redact("err with "+testPass), testPass) {
		t.Fatal("redact did not mask the SOCKS password")
	}
}
