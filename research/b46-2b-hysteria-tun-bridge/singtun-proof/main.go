// B46-2B synthetic proof — NOT production code, NOT Android code.
//
// **Dependency correction pass (third pass on this proof, following a
// direct review of PR #89's race-enabled run)**: this proof previously
// pinned `github.com/apernet/sing-tun@299f04629986` (the exact version
// Hysteria2 itself vendors, per B46-2A/Section 3 of the architecture doc).
// A `go build -race` run of that version's TCP path found a REAL,
// reproducible internal data race in that dependency's own
// `stack_system_nat.go` `TCPNat.LookupBack` (`session.LastActive` written
// outside its own lock). Because the Nova bridge runs IN-PROCESS with the
// VpnService while Hysteria2 remains a separate CHILD PROCESS (the process
// boundary this document's architecture doc Section 13 pins), the bridge
// does NOT need to share Hysteria2's exact `sing-tun` build — an
// independent, justified, PINNED version choice is acceptable, and this
// pass makes one: **`github.com/sagernet/sing-tun` at commit
// `fbc0c3dff312e91f512756ad843af74dd209577c`** (current upstream `dev` HEAD
// as of this pass, pinned to this exact commit, never a floating branch).
// Verified directly: that commit's `TCPSession` carries its own
// `sync.Mutex` and `LookupBack`'s `session.refresh()` locks it before
// touching `LastActive` — the race is structurally fixed upstream, not
// patched around locally. Confirmed by re-running this exact proof under
// `go build -race`: **zero race reports**, twice in a row.
//
// This pass also found two further, real, non-obvious API differences from
// the superseded apernet fork, both discovered by actually running this
// proof, not by reading the API alone:
//
//  1. The current SagerNet `acceptLoop`/`UDPNat` no longer force-closes a
//     flow's `conn` after the handler method returns (unlike the apernet
//     fork's `SetLinger(0)`+`Close()` immediately after `NewConnection`
//     returns) — `NewConnectionEx`/`NewPacketConnectionEx` are invoked in
//     their OWN goroutine by the caller and the HANDLER now owns the
//     connection's full lifecycle (an `onClose` callback replaces the old
//     "must block or get RST'd" contract entirely). This is a genuine
//     improvement, not merely a rename.
//  2. `systemUDPPacketWriter4.WritePacket` calls `buffer.ExtendHeader()` IN
//     PLACE on the caller-supplied buffer (unlike the apernet fork, which
//     allocated its OWN internal buffer and copied the caller's payload in)
//     — a caller must pre-reserve front headroom on the buffer it passes to
//     `WritePacket`, or the call panics ("buffer overflow ... need 28").
//     See `udpWriteHeadroom` below.
//
// Also verified directly in this pass: `EXP_ExternalConfiguration` is a
// real, first-class `Options` field (used in this exact upstream commit's
// own integration test) meaning "an external owner already configured this
// TUN's address/route" — a materially better fit for Android's
// `VpnService.Builder` ownership model than the apernet fork ever exposed;
// and this dependency's own `tun_linux.go` explicitly special-cases
// `/dev/tun` as an Android TUN path (`androidTunPath`), evidence of more
// Android-conscious development than the fork it replaces.
//
// FD OWNERSHIP MODEL (unchanged from the prior pass — see
// docs/B46_2B_HYSTERIA_TUN_BRIDGE_ARCHITECTURE.md Section 8 for the full
// writeup and the Android-side equivalent using
// ParcelFileDescriptor.dup()+detachFd()): this program plays the
// "VpnService.Builder.establish()" role by opening /dev/net/tun directly
// and configuring the real interface; a SEPARATE, independent fd is then
// created via `unix.Dup(originalFd)` and ONLY THAT DUPLICATE is ever
// passed to `tun.Options.FileDescriptor` — the original is closed, by this
// program, LAST, only after the bridge (`sing-tun` Stack + Tun) has been
// stopped.
package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"time"
	"unsafe"

	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"golang.org/x/sys/unix"
)

const (
	ifName      = "novab46btun0"
	tunPrefix   = "198.18.55.1/30" // interface's own P2P-style address, per sing-tun's NewSystem contract
	testDestIP  = "203.0.113.9"    // arbitrary, unrelated, routed only via the tun device
	testTCPPort = 9000
	testUDPPort = 9001
	echoTCPPort = 19081 // stands in for Hysteria2's local SOCKS5/relay listener
	echoUDPPort = 19082 // stands in for a controlled UDP echo target reached through that listener

	// See the file header's finding (2): systemUDPPacketWriter4.WritePacket
	// extends the caller's buffer IN PLACE by IPv4(20)+UDP(8)=28 bytes
	// (observed directly via the panic this pass reproduced and fixed).
	// 128 is generously more than that, covering IPv6/vnet-header variants
	// without needing to probe the writer's exact FrontHeadroom (which the
	// concrete *UDPNatConn type returned to the handler does not itself
	// expose — verified by reading udp_nat.go directly).
	udpWriteHeadroom = 128
)

const ifrSize = unix.IFNAMSIZ + 64

// openTun plays the "external owner creates the TUN" role — exactly what
// VpnService.Builder.establish() does on Android, just via a raw ioctl
// instead of the Android framework. Returns the ORIGINAL fd — the caller
// must duplicate it before handing anything to sing-tun (see the ownership
// model in this file's header doc).
func openTun(name string) (int, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR, 0)
	if err != nil {
		return -1, fmt.Errorf("open /dev/net/tun: %w", err)
	}
	var ifr [ifrSize]byte
	copy(ifr[:unix.IFNAMSIZ], name)
	// IFF_TUN | IFF_NO_PI, little-endian uint16 at offset IFNAMSIZ
	const IFF_TUN = 0x0001
	const IFF_NO_PI = 0x1000
	flags := uint16(IFF_TUN | IFF_NO_PI)
	ifr[unix.IFNAMSIZ] = byte(flags)
	ifr[unix.IFNAMSIZ+1] = byte(flags >> 8)
	const TUNSETIFF = 0x400454ca
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(TUNSETIFF), uintptr(unsafe.Pointer(&ifr[0]))); errno != 0 {
		unix.Close(fd)
		return -1, fmt.Errorf("TUNSETIFF: %w", errno)
	}
	return fd, nil
}

type tcpObservation struct {
	source      string
	destination string
}

type udpObservation struct {
	source      string
	destination string
}

type proofHandler struct {
	tcpSeen chan tcpObservation
	udpSeen chan udpObservation
}

var _ tun.Handler = (*proofHandler)(nil)

// JudgeFlow: the current SagerNet Handler interface requires a flow-level
// admission decision before any TCP/UDP callback fires — ActionAccept lets
// every flow through to NewConnectionEx/NewPacketConnectionEx, matching
// this proof's own scope (it is not exercising the newer per-flow
// filtering/tracking capabilities this API also exposes).
func (h *proofHandler) JudgeFlow(network uint8, source netip.AddrPort, destination netip.AddrPort, firstPacket []byte) tun.FlowVerdict {
	return tun.FlowVerdict{Action: tun.ActionAccept}
}

// NewDNSPacket: only invoked when Options.DNSMode hijacks DNS, which this
// proof does not configure — present only to satisfy the Handler interface.
func (h *proofHandler) NewDNSPacket(payload []byte, source M.Socksaddr, destination M.Socksaddr, writer N.PacketWriter) {
}

// NewConnectionEx: per this file's header finding (1), the current
// SagerNet acceptLoop no longer force-closes `conn` after this method
// returns — it is called in its own goroutine and the caller (this
// handler) now owns the connection's full lifecycle, including closing it.
func (h *proofHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	defer conn.Close()
	select {
	case h.tcpSeen <- tcpObservation{source: source.String(), destination: destination.String()}:
	default:
	}
	upstream, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", echoTCPPort))
	if err != nil {
		if onClose != nil {
			onClose(err)
		}
		return
	}
	defer upstream.Close()
	done := make(chan struct{}, 2)
	go func() { io.Copy(upstream, conn); done <- struct{}{} }()
	go func() { io.Copy(conn, upstream); done <- struct{}{} }()
	<-done
	<-done
	if onClose != nil {
		onClose(nil)
	}
}

// NewPacketConnectionEx proves the FULL UDP round trip: reads the real
// inbound datagram off the tun-side flow, forwards it to a controlled
// local UDP echo target, and writes the echo response back through
// sing-tun's own WritePacket path — with the required pre-reserved
// headroom (this file's header finding (2)).
func (h *proofHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	defer conn.Close()
	select {
	case h.udpSeen <- udpObservation{source: source.String(), destination: destination.String()}:
	default:
	}

	inBuf := buf.NewPacket()
	defer inBuf.Release()
	if _, err := conn.ReadPacket(inBuf); err != nil {
		if onClose != nil {
			onClose(err)
		}
		return
	}
	payload := append([]byte(nil), inBuf.Bytes()...)

	upstream, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", echoUDPPort))
	if err != nil {
		if onClose != nil {
			onClose(err)
		}
		return
	}
	defer upstream.Close()
	if _, err := upstream.Write(payload); err != nil {
		if onClose != nil {
			onClose(err)
		}
		return
	}
	upstream.SetReadDeadline(time.Now().Add(2 * time.Second))
	respBytes := make([]byte, 2048)
	n, err := upstream.Read(respBytes)
	if err != nil {
		if onClose != nil {
			onClose(err)
		}
		return
	}

	outBuf := buf.NewSize(udpWriteHeadroom + n)
	defer outBuf.Release()
	outBuf.Resize(udpWriteHeadroom, 0)
	outBuf.Write(respBytes[:n])
	if err := conn.WritePacket(outBuf, destination); err != nil {
		if onClose != nil {
			onClose(err)
		}
		return
	}
	if onClose != nil {
		onClose(nil)
	}
}

func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}

func must(err error) {
	if err != nil {
		fmt.Println("FAIL setup:", err)
		os.Exit(1)
	}
}

func main() {
	// Cleanup any stale interface from a previous aborted run.
	_ = runCmd("ip", "link", "del", ifName)

	originalFd, err := openTun(ifName)
	if err != nil {
		fmt.Println("FAIL: openTun:", err)
		os.Exit(1)
	}
	// Ownership split: `originalFd` stays owned by the "VpnService" role
	// (this main function) and is closed by it, LAST, after the bridge has
	// been fully stopped. `bridgeFd` is an independent duplicate handed
	// exclusively to sing-tun, which owns and closes it via its Tun.Close().
	bridgeFd, err := unix.Dup(originalFd)
	if err != nil {
		unix.Close(originalFd)
		fmt.Println("FAIL: dup tun fd for bridge ownership transfer:", err)
		os.Exit(1)
	}
	fmt.Printf("OK: split ownership — original fd=%d (VpnService role, closed last), bridge fd=%d (sing-tun role)\n", originalFd, bridgeFd)

	must(runCmd("ip", "addr", "add", tunPrefix, "dev", ifName))
	must(runCmd("ip", "link", "set", ifName, "up"))
	must(runCmd("ip", "route", "add", testDestIP+"/32", "dev", ifName))

	prefix := netip.MustParsePrefix(tunPrefix)
	options := tun.Options{
		Name:           ifName,
		FileDescriptor: bridgeFd, // <-- the load-bearing line: sing-tun never opens the device itself
		MTU:            1500,
		Inet4Address:   []netip.Prefix{prefix},
		// This program (the "VpnService" role) already configured the
		// address/route above — EXP_ExternalConfiguration tells sing-tun
		// not to also try to manage them, matching how a real Android
		// VpnService.Builder already owns that configuration.
		EXP_ExternalConfiguration: true,
	}

	t, err := tun.New(options)
	if err != nil {
		fmt.Println("FAIL: tun.New with externally-supplied fd:", err)
		// Failure-path cleanup: close whichever fds this attempt owns —
		// never double-close, never leak.
		unix.Close(bridgeFd)
		unix.Close(originalFd)
		os.Exit(1)
	}
	fmt.Println("OK: sing-tun accepted the duplicate fd via Options.FileDescriptor, did not open its own device")

	handler := &proofHandler{
		tcpSeen: make(chan tcpObservation, 8),
		udpSeen: make(chan udpObservation, 8),
	}
	stack, err := tun.NewStack("system", tun.StackOptions{
		Context:    context.Background(),
		Tun:        t,
		TunOptions: options,
		Handler:    handler,
		UDPTimeout: 30 * time.Second,
		Logger:     nopLogger{},
	})
	if err != nil {
		fmt.Println("FAIL: NewStack:", err)
		// tun.New succeeded but stack construction failed - the Tun object
		// is still ours to close exactly once; the duplicate fd it wraps
		// must not be leaked.
		_ = t.Close()
		unix.Close(originalFd)
		os.Exit(1)
	}
	if err := stack.Start(); err != nil {
		fmt.Println("FAIL: stack.Start:", err)
		_ = stack.Close()
		_ = t.Close()
		unix.Close(originalFd)
		os.Exit(1)
	}

	tcpEcho := startTCPEcho(echoTCPPort)
	defer tcpEcho.Close()
	udpEcho := startUDPEcho(echoUDPPort)
	defer udpEcho.Close()

	time.Sleep(300 * time.Millisecond)

	tcpOK, tcpObs := proveTCP(handler)
	udpObserved, udpRoundTripOK, udpObs := proveUDPRoundTrip(handler)

	fmt.Printf("\n=== RESULT === tcpObserved=%v(%+v) tcpRoundTrip=%v udpObserved=%v(%+v) udpRoundTrip=%v\n",
		tcpObs != nil, tcpObs, tcpOK, udpObserved, udpObs, udpRoundTripOK)

	// Bridge-stop-before-original-close ordering, matching the documented
	// cleanup model: stop the stack (stops accepting new flows), close the
	// Tun (closes ONLY the duplicate fd), THEN close the original — never
	// the other way around, and never double-closed.
	_ = stack.Close()
	_ = t.Close()
	if err := unix.Close(originalFd); err != nil {
		fmt.Println("WARN: closing original fd:", err)
	}
	_ = runCmd("ip", "link", "del", ifName)

	if !tcpOK || !udpObserved || !udpRoundTripOK {
		os.Exit(1)
	}
}

func startTCPEcho(port int) net.Listener {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		fmt.Println("FAIL: echo listen:", err)
		os.Exit(1)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						if _, werr := c.Write(buf[:n]); werr != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}(c)
		}
	}()
	return ln
}

type udpEcho struct{ conn *net.UDPConn }

func (u udpEcho) Close() error { return u.conn.Close() }

func startUDPEcho(port int) udpEcho {
	addr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", port))
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		fmt.Println("FAIL: udp echo listen:", err)
		os.Exit(1)
	}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = conn.WriteToUDP(buf[:n], from)
		}
	}()
	return udpEcho{conn}
}

// proveTCP requires BOTH a real byte-exact round trip AND a genuine
// handler observation with the expected metadata — a send/receive success
// alone is never treated as sufficient.
func proveTCP(h *proofHandler) (bool, *tcpObservation) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", testDestIP, testTCPPort), 3*time.Second)
	if err != nil {
		fmt.Println("TCP FAIL: dial through tun:", err)
		return false, nil
	}
	defer conn.Close()
	payload := []byte("b46-2b-tcp-proof")
	if _, err := conn.Write(payload); err != nil {
		fmt.Println("TCP FAIL: write:", err)
		return false, nil
	}
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	respBuf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, respBuf); err != nil {
		fmt.Println("TCP FAIL: read:", err)
		return false, nil
	}
	roundTripOK := string(respBuf) == string(payload)

	var obs *tcpObservation
	select {
	case o := <-h.tcpSeen:
		obs = &o
	case <-time.After(2 * time.Second):
		fmt.Println("TCP FAIL: handler never observed NewConnectionEx")
		return false, nil
	}
	expectedDest := fmt.Sprintf("%s:%d", testDestIP, testTCPPort)
	if obs.destination != expectedDest {
		fmt.Printf("TCP FAIL: handler observed wrong destination: got %q want %q\n", obs.destination, expectedDest)
		return false, obs
	}
	fmt.Printf("TCP OK: round trip match=%v, handler observed source=%s destination=%s\n", roundTripOK, obs.source, obs.destination)
	return roundTripOK, obs
}

// proveUDPRoundTrip requires, deterministically (channel-synchronized, no
// sleep-and-hope): (1) the handler actually observed NewPacketConnectionEx,
// (2) the observed destination is EXACTLY the expected test IP:port, and
// (3) the real payload sent by the client comes back byte-for-byte through
// sing-tun's own WritePacket path. A send() alone is never treated as
// success.
func proveUDPRoundTrip(h *proofHandler) (observed bool, roundTrip bool, obs *udpObservation) {
	c, err := net.DialTimeout("udp", fmt.Sprintf("%s:%d", testDestIP, testUDPPort), 2*time.Second)
	if err != nil {
		fmt.Println("UDP FAIL: dial through tun:", err)
		return false, false, nil
	}
	defer c.Close()
	payload := []byte("b46-2b-udp-proof")
	if _, err := c.Write(payload); err != nil {
		fmt.Println("UDP FAIL: write:", err)
		return false, false, nil
	}

	select {
	case o := <-h.udpSeen:
		obs = &o
	case <-time.After(2 * time.Second):
		fmt.Println("UDP FAIL: handler never observed NewPacketConnectionEx")
		return false, false, nil
	}
	expectedDest := fmt.Sprintf("%s:%d", testDestIP, testUDPPort)
	if obs.destination != expectedDest {
		fmt.Printf("UDP FAIL: handler observed wrong destination: got %q want %q\n", obs.destination, expectedDest)
		return true, false, obs
	}
	if obs.source == "" {
		fmt.Println("UDP FAIL: handler observed empty source metadata")
		return true, false, obs
	}

	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	respBuf := make([]byte, len(payload))
	if _, err := io.ReadFull(c, respBuf); err != nil {
		fmt.Println("UDP FAIL: no round-trip echo received back through tun:", err)
		return true, false, obs
	}
	roundTrip = string(respBuf) == string(payload)
	fmt.Printf("UDP OK: handler observed source=%s destination=%s, round trip match=%v\n", obs.source, obs.destination, roundTrip)
	return true, roundTrip, obs
}

type nopLogger struct{}

func (nopLogger) Trace(args ...any) {}
func (nopLogger) Debug(args ...any) {}
func (nopLogger) Info(args ...any)  {}
func (nopLogger) Warn(args ...any)  {}
func (nopLogger) Error(args ...any) {}
func (nopLogger) Fatal(args ...any) {}
func (nopLogger) Panic(args ...any) {}
