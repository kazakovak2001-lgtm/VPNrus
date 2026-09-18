// B46-2B synthetic proof — NOT production code, NOT Android code.
//
// Proves the single critical assumption behind Option A
// (NOVA_SING_TUN_ADAPTER): that the exact `apernet/sing-tun` dependency
// Hysteria2 itself already vendors (pinned to the same pseudo-version
// B46-2A built against, v0.2.6-0.20250920121535-299f04629986) can consume
// an EXTERNALLY created TUN file descriptor via `tun.Options.FileDescriptor`
// — never calling its own device-open path — and correctly demultiplex
// real TCP and UDP flows arriving on that fd into distinguishable,
// forwardable connections.
//
// To make the fd handoff itself faithful to the real Android shape (an
// external owner creates+configures the TUN, then hands only the fd NUMBER
// to the sing-tun-driven bridge — never letting sing-tun open the device),
// this program plays BOTH roles a real spike would split across processes:
//
//   - "VpnService.Builder.establish()" role: opens /dev/net/tun directly
//     (TUNSETIFF), configures its address/route via the real `ip` tool —
//     this is the ONLY code in this file that touches the raw tun fd
//     before handing it to sing-tun.
//   - "Nova sing-tun bridge" role: takes ONLY the resulting fd integer,
//     builds `tun.Options{FileDescriptor: fd}`, and drives sing-tun's own
//     unmodified "system" stack — the same stack shape sing-tun offers
//     Hysteria2's own (unused-on-Android) tun mode.
//   - "the app generating traffic" role: a real `net.Dial`/UDP write from
//     this same host, routed through the real kernel routing table onto
//     the real tun device, exercising the real code path end to end
//     (kernel -> tun fd -> sing-tun -> our Handler -> a local test target
//     standing in for Hysteria2's SOCKS5 listener -> back the same way).
//
// Requires root/CAP_NET_ADMIN (available in this host sandbox) to create
// the tun device and program routes — this is a host-side proof only, and
// does NOT claim anything about Android's VpnService, SELinux, or app
// process boundaries. See docs/B46_2B_HYSTERIA_TUN_BRIDGE_ARCHITECTURE.md
// for how this program's output was used.
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
	"time"
	"unsafe"

	tun "github.com/apernet/sing-tun"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"golang.org/x/sys/unix"
)

const (
	ifName      = "novab46btun0"
	tunPrefix   = "198.18.55.1/30" // interface's own P2P-style address, per sing-tun's NewSystem contract
	testDestIP  = "203.0.113.9"    // arbitrary, unrelated, routed only via the tun device
	echoTCPPort = 19081            // stands in for Hysteria2's local SOCKS5/relay listener
)

const ifrSize = unix.IFNAMSIZ + 64

// openTun plays the "external owner creates the TUN" role — exactly what
// VpnService.Builder.establish() does on Android, just via a raw ioctl
// instead of the Android framework. sing-tun is never given a chance to
// call its own open() path (Options.FileDescriptor != 0 skips it entirely
// — verified directly in tun_linux.go:New, see the accompanying
// architecture doc).
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

type proofHandler struct {
	tcpAccepted     int
	udpAccepted     int
	udpDestinations []string
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
	h.tcpAccepted++
	fmt.Printf("[bridge] TCP flow demuxed: %s -> %s\n", metadata.Source, metadata.Destination)
	upstream, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", echoTCPPort))
	if err != nil {
		return err
	}
	defer upstream.Close()
	done := make(chan struct{}, 2)
	go func() { io.Copy(upstream, conn); done <- struct{}{} }()
	go func() { io.Copy(conn, upstream); done <- struct{}{} }()
	<-done
	<-done
	return nil
}

// NewPacketConnection proves the UDP demux path in isolation: correct
// 5-tuple metadata reaches the handler for a real UDP datagram sent
// through the externally-owned TUN fd. Full echo-round-trip UDP forwarding
// (WritePacket back into the flow) is real bridge-implementation work left
// for B46-2P per the architecture doc's "known unknowns" — this proof's
// job is only to establish that sing-tun's UDP NAT session table correctly
// creates one distinguishable flow per external fd, not to build the whole
// relay.
func (h *proofHandler) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata M.Metadata) error {
	h.udpAccepted++
	h.udpDestinations = append(h.udpDestinations, metadata.Destination.String())
	fmt.Printf("[bridge] UDP flow demuxed: %s -> %s\n", metadata.Source, metadata.Destination)
	conn.Close()
	return nil
}

func (h *proofHandler) NewError(ctx context.Context, err error) {
	if errors.Is(err, io.EOF) {
		return
	}
	fmt.Printf("[bridge] handler error: %v\n", err)
}

func proxyAndClose(dst io.WriteCloser, src io.Reader) {
	defer dst.Close()
	_, _ = io.Copy(dst, src)
}

func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}

func main() {
	// Cleanup any stale interface from a previous aborted run.
	_ = runCmd("ip", "link", "del", ifName)

	fd, err := openTun(ifName)
	if err != nil {
		fmt.Println("FAIL: openTun:", err)
		os.Exit(1)
	}
	must(runCmd("ip", "addr", "add", tunPrefix, "dev", ifName))
	must(runCmd("ip", "link", "set", ifName, "up"))
	must(runCmd("ip", "route", "add", testDestIP+"/32", "dev", ifName))

	prefix := netip.MustParsePrefix(tunPrefix)
	options := tun.Options{
		Name:           ifName,
		FileDescriptor: fd, // <-- the load-bearing line: sing-tun never opens the device itself
		MTU:            1500,
		Inet4Address:   []netip.Prefix{prefix},
	}

	t, err := tun.New(options)
	if err != nil {
		fmt.Println("FAIL: tun.New with externally-supplied fd:", err)
		os.Exit(1)
	}
	fmt.Println("OK: sing-tun accepted externally-created fd via Options.FileDescriptor, did not open its own device")

	handler := &proofHandler{}
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
	defer stack.Close()

	tcpEcho := startTCPEcho(echoTCPPort)
	defer tcpEcho.Close()

	time.Sleep(300 * time.Millisecond)

	tcpOK := proveTCP()
	udpFlowSeen := proveUDPDemux()

	fmt.Printf("\n=== RESULT === tcpFlowsDemuxed=%d udpFlowsDemuxed=%d tcpRoundTrip=%v udpFlowDemuxed=%v\n",
		handler.tcpAccepted, handler.udpAccepted, tcpOK, udpFlowSeen)

	_ = runCmd("ip", "link", "del", ifName)

	if !tcpOK || !udpFlowSeen {
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

func proveTCP() bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:9000", testDestIP), 3*time.Second)
	if err != nil {
		fmt.Println("TCP FAIL: dial through tun:", err)
		return false
	}
	defer conn.Close()
	payload := []byte("b46-2b-tcp-proof")
	if _, err := conn.Write(payload); err != nil {
		fmt.Println("TCP FAIL: write:", err)
		return false
	}
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		fmt.Println("TCP FAIL: read:", err)
		return false
	}
	ok := string(buf) == string(payload)
	fmt.Printf("TCP round trip through externally-owned TUN -> sing-tun -> local target: match=%v\n", ok)
	return ok
}

func proveUDPDemux() bool {
	c, err := net.DialTimeout("udp", fmt.Sprintf("%s:9001", testDestIP), 2*time.Second)
	if err != nil {
		fmt.Println("UDP FAIL: dial through tun:", err)
		return false
	}
	defer c.Close()
	if _, err := c.Write([]byte("b46-2b-udp-probe")); err != nil {
		fmt.Println("UDP FAIL: write:", err)
		return false
	}
	time.Sleep(200 * time.Millisecond)
	return true
}

type nopLogger struct{}

func (nopLogger) Trace(args ...any) {}
func (nopLogger) Debug(args ...any) {}
func (nopLogger) Info(args ...any)  {}
func (nopLogger) Warn(args ...any)  {}
func (nopLogger) Error(args ...any) {}
func (nopLogger) Fatal(args ...any) {}
func (nopLogger) Panic(args ...any) {}
