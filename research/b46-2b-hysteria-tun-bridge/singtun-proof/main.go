// B46-2B synthetic proof — NOT production code, NOT Android code.
//
// Proves the single critical assumption behind Option A
// (NOVA_SING_TUN_ADAPTER): that the exact `apernet/sing-tun` dependency
// Hysteria2 itself already vendors (pinned to the same pseudo-version
// B46-2A built against, v0.2.6-0.20250920121535-299f04629986) can consume
// an EXTERNALLY created, EXTERNALLY OWNED TUN file descriptor via
// `tun.Options.FileDescriptor` — never calling its own device-open path —
// and correctly demultiplex real TCP and UDP flows arriving on that fd,
// forwarding both directions to a local target.
//
// FD OWNERSHIP MODEL (corrected in the B46-2B review pass — see
// docs/B46_2B_HYSTERIA_TUN_BRIDGE_ARCHITECTURE.md Section 8 for the full
// writeup and the Android-side equivalent using
// ParcelFileDescriptor.dup()+detachFd()):
//
//   - This program plays the "VpnService.Builder.establish()" role: it
//     opens /dev/net/tun directly (TUNSETIFF) and configures the real
//     interface's address/route. That original fd is analogous to the
//     ParcelFileDescriptor VpnService keeps for the whole session — it is
//     NEVER handed to sing-tun directly.
//   - A SEPARATE, independent fd is created via `unix.Dup(originalFd)` —
//     analogous to Android's `ParcelFileDescriptor.dup()` followed by
//     `detachFd()` — and ONLY THAT DUPLICATE is passed to
//     `tun.Options.FileDescriptor`. `sing-tun`'s own `NativeTun.Close()`
//     (verified directly in tun_linux.go: `common.Close(t.tunFile)`) closes
//     whatever fd number it was given — so if the ORIGINAL fd were handed
//     to it directly, sing-tun would end up owning the same close
//     responsibility the "VpnService" role also believes it owns, making a
//     double-close possible. Duplicating first means sing-tun exclusively
//     owns and closes the DUPLICATE (a distinct kernel-level fd number,
//     backed by the same underlying open-file description — closing one
//     never closes the other), while this program's "VpnService" role
//     exclusively owns and closes the ORIGINAL, only AFTER the bridge
//     (sing-tun Stack + Tun) has been stopped. No object ever believes it
//     owns the same close responsibility as another.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"sync"
	"time"
	"unsafe"

	tun "github.com/apernet/sing-tun"
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

// tcpObservation and udpObservation are delivered over channels, never read
// via a shared mutable field from outside the goroutine that owns them —
// this is the "no data race, no sleep+hope" fix from the B46-2B review.
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

// NewConnection MUST block until the flow's relay is finished: sing-tun's
// System-stack acceptLoop calls SetLinger(0) and closes `conn` the instant
// this method returns (stack_system.go's acceptLoop, verified directly —
// not documented anywhere). A fire-and-forget handler (spawn goroutines,
// return nil immediately) gets its connection RST'd before any data
// relays — a genuine, non-obvious API-contract finding this proof
// surfaced, not something assumed from an example. Any real Nova bridge
// implementation must relay synchronously here, exactly like this proof
// does.
func (h *proofHandler) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	select {
	case h.tcpSeen <- tcpObservation{source: metadata.Source.String(), destination: metadata.Destination.String()}:
	default:
	}
	upstream, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", echoTCPPort))
	if err != nil {
		return err
	}
	defer upstream.Close()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); io.Copy(upstream, conn) }()
	go func() { defer wg.Done(); io.Copy(conn, upstream) }()
	wg.Wait()
	return nil
}

// NewPacketConnection proves the FULL UDP round trip (not merely demux):
// it reads the real datagram off the externally-owned TUN fd via sing-tun,
// forwards it to a controlled local UDP echo target, and writes the echo
// response back through sing-tun's own WritePacket path (verified directly
// in stack_system.go's systemUDPPacketWriter4: the `destination` argument
// becomes the reply packet's fabricated source address, so it must be the
// ORIGINAL virtual destination — metadata.Destination — not the source, or
// the real client socket would see a reply from the wrong address and
// silently drop it).
func (h *proofHandler) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata M.Metadata) error {
	select {
	case h.udpSeen <- udpObservation{source: metadata.Source.String(), destination: metadata.Destination.String()}:
	default:
	}
	defer conn.Close()

	inBuf := buf.NewPacket()
	defer inBuf.Release()
	if _, err := conn.ReadPacket(inBuf); err != nil {
		return fmt.Errorf("bridge: read inbound UDP packet: %w", err)
	}
	payload := append([]byte(nil), inBuf.Bytes()...)

	upstream, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", echoUDPPort))
	if err != nil {
		return fmt.Errorf("bridge: dial local UDP target: %w", err)
	}
	defer upstream.Close()
	if _, err := upstream.Write(payload); err != nil {
		return fmt.Errorf("bridge: forward UDP payload: %w", err)
	}
	upstream.SetReadDeadline(time.Now().Add(2 * time.Second))
	respBytes := make([]byte, 2048)
	n, err := upstream.Read(respBytes)
	if err != nil {
		return fmt.Errorf("bridge: read UDP echo response: %w", err)
	}

	outBuf := buf.NewPacket()
	defer outBuf.Release()
	outBuf.Write(respBytes[:n])
	if err := conn.WritePacket(outBuf, metadata.Destination); err != nil {
		return fmt.Errorf("bridge: write UDP response back through tun: %w", err)
	}
	return nil
}

func (h *proofHandler) NewError(ctx context.Context, err error) {
	if errors.Is(err, io.EOF) {
		return
	}
	fmt.Printf("[bridge] handler error: %v\n", err)
}

func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
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
	// exclusively to sing-tun, which owns and closes it via
	// NativeTun.Close() — see the file header doc for the full model.
	bridgeFd, err := unix.Dup(originalFd)
	if err != nil {
		unix.Close(originalFd)
		fmt.Println("FAIL: dup tun fd for bridge ownership transfer:", err)
		os.Exit(1)
	}
	fmt.Printf("OK: split ownership — original fd=%d (VpnService role, closed last), bridge fd=%d (sing-tun role, closed by NativeTun.Close())\n", originalFd, bridgeFd)

	must(runCmd("ip", "addr", "add", tunPrefix, "dev", ifName))
	must(runCmd("ip", "link", "set", ifName, "up"))
	must(runCmd("ip", "route", "add", testDestIP+"/32", "dev", ifName))

	prefix := netip.MustParsePrefix(tunPrefix)
	options := tun.Options{
		Name:           ifName,
		FileDescriptor: bridgeFd, // <-- only the DUPLICATE crosses into sing-tun, never the original
		MTU:            1500,
		Inet4Address:   []netip.Prefix{prefix},
	}

	t, err := tun.New(options)
	if err != nil {
		fmt.Println("FAIL: tun.New with externally-supplied fd:", err)
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
		UDPTimeout: 30,
		Logger:     nopLogger{},
	})
	if err != nil {
		fmt.Println("FAIL: NewStack:", err)
		os.Exit(1)
	}
	if err := stack.Start(); err != nil {
		fmt.Println("FAIL: stack.Start:", err)
		os.Exit(1)
	}

	tcpEcho := startTCPEcho(echoTCPPort)
	defer tcpEcho.Close()
	udpEcho := startUDPEcho(echoUDPPort)
	defer udpEcho.Close()

	time.Sleep(300 * time.Millisecond)

	tcpOK, tcpObs := proveTCP(handler)
	udpOK, udpRoundTripOK, udpObs := proveUDPRoundTrip(handler)

	fmt.Printf("\n=== RESULT === tcpObserved=%v(%+v) tcpRoundTrip=%v udpObserved=%v(%+v) udpRoundTrip=%v\n",
		tcpObs != nil, tcpObs, tcpOK, udpObs != nil, udpObs, udpRoundTripOK)

	// Bridge-stop-before-original-close ordering, matching the documented
	// cleanup model: stop the stack (stops accepting new flows), close the
	// Tun (closes ONLY the duplicate fd, via sing-tun's own Close()), THEN
	// close the original — never the other way around.
	_ = stack.Close()
	_ = t.Close()
	if err := unix.Close(originalFd); err != nil {
		fmt.Println("WARN: closing original fd:", err)
	}
	_ = runCmd("ip", "link", "del", ifName)

	if !tcpOK || !udpOK || !udpRoundTripOK {
		os.Exit(1)
	}
}

func must(err error) {
	if err != nil {
		fmt.Println("FAIL setup:", err)
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
// alone (without checking the handler actually saw the flow) is exactly
// the class of weak proof the B46-2B review flagged for the UDP path, so
// this function is held to the same bar even though it already blocked on
// real I/O before this correction pass.
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
		fmt.Println("TCP FAIL: handler never observed NewConnection")
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
// sleep-and-hope): (1) the handler actually observed NewPacketConnection,
// (2) the observed destination is EXACTLY the expected test IP:port, and
// (3) the real payload sent by the client comes back byte-for-byte via
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
		fmt.Println("UDP FAIL: handler never observed NewPacketConnection")
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
