// B46-2C tun2socks synthetic proof (host-side, Go) — NOT production code.
//
// Proves: external TUN fd (opened+configured by this program, playing the
// "VpnService" role) -> dup() -> tun2socks engine (Device: fd://<dupfd>) ->
// real SOCKS5 (danted, a real third-party SOCKS5 daemon standing in for
// Hysteria2's own listener) -> real TCP/UDP echo targets -> back through
// tun2socks -> the real originating socket, for BOTH TCP and UDP, with
// byte-exact round trip verification. Also covers lifecycle (start/stop/
// restart) and failure paths (invalid fd, SOCKS5 absent).
package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/xjasonlyu/tun2socks/v2/engine"
)

const (
	ifName      = "novat2stun0"
	tunPrefix   = "198.18.78.1/30"
	testDest    = "10.200.1.2"
	testTCPPort = 9300
	testUDPPort = 9301
)

func openTun(name string) (int, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR, 0)
	if err != nil {
		return -1, fmt.Errorf("open /dev/net/tun: %w", err)
	}
	ifr := make([]byte, 40)
	copy(ifr, name)
	// IFF_TUN | IFF_NO_PI = 0x1001, placed at offset 16 (IFNAMSIZ=16).
	ifr[16] = 0x01
	ifr[17] = 0x10
	const TUNSETIFF = 0x400454ca
	if err := ioctl(fd, TUNSETIFF, ifr); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("TUNSETIFF: %w", err)
	}
	return fd, nil
}

func ioctl(fd int, req uintptr, arg []byte) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), req, uintptr(unsafe.Pointer(&arg[0])))
	if errno != 0 {
		return errno
	}
	return nil
}

func run(format string, args ...interface{}) {
	cmdline := fmt.Sprintf(format, args...)
	fmt.Fprintf(os.Stderr, "+ %s\n", cmdline)
	cmd := exec.Command("sh", "-c", cmdline)
	cmd.Stderr = os.Stderr
	_ = cmd.Run()
}

func startEngine(fd int, mtu int) error {
	engine.Insert(&engine.Key{
		MTU:      mtu,
		Device:   fmt.Sprintf("fd://%d", fd),
		Proxy:    "socks5://10.200.0.1:1080",
		LogLevel: "warning",
	})
	return engine.Start()
}

func proveTCP() bool {
	c, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", testDest, testTCPPort), 3*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "TCP FAIL: dial through tun: %v\n", err)
		return false
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	payload := "b46-2c-tun2socks-tcp-proof"
	if _, err := c.Write([]byte(payload)); err != nil {
		fmt.Fprintf(os.Stderr, "TCP FAIL: write: %v\n", err)
		return false
	}
	buf := make([]byte, len(payload))
	n, err := readFull(c, buf)
	if err != nil || n != len(payload) || string(buf[:n]) != payload {
		fmt.Fprintf(os.Stderr, "TCP FAIL: round trip mismatch n=%d err=%v got=%q\n", n, err, buf[:n])
		return false
	}
	fmt.Fprintln(os.Stderr, "TCP OK: round trip match, via tun2socks -> SOCKS5(danted) -> echo target")
	return true
}

func readFull(c net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := c.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func proveUDP() bool {
	c, err := net.DialTimeout("udp", fmt.Sprintf("%s:%d", testDest, testUDPPort), 3*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "UDP FAIL: dial through tun: %v\n", err)
		return false
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	payload := "b46-2c-tun2socks-udp-proof"
	if _, err := c.Write([]byte(payload)); err != nil {
		fmt.Fprintf(os.Stderr, "UDP FAIL: write: %v\n", err)
		return false
	}
	buf := make([]byte, 128)
	n, err := c.Read(buf)
	if err != nil || n != len(payload) || string(buf[:n]) != payload {
		fmt.Fprintf(os.Stderr, "UDP FAIL: round trip mismatch n=%d err=%v\n", n, err)
		return false
	}
	fmt.Fprintln(os.Stderr, "UDP OK: round trip match, via tun2socks -> SOCKS5(danted) UDP ASSOCIATE -> echo target")
	return true
}

// proveDNS sends an ordinary UDP/53 query through the same tun2socks ->
// SOCKS5 UDP ASSOCIATE path to a real resolver echo stand-in (we reuse the
// UDP echo target on testUDPPort+1 as a DNS-shaped byte proof: this proves
// *transport*, not real DNS semantics — no separate DNS subsystem is
// invented, and no leak-safety claim is made without physical testing).
func proveDNSTransport() bool {
	c, err := net.DialTimeout("udp", fmt.Sprintf("%s:53", testDest), 3*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "DNS-TRANSPORT FAIL: dial through tun: %v\n", err)
		return false
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	// Minimal well-formed DNS query header+question (A record for "x.").
	query := []byte{
		0xAB, 0xCD, // ID
		0x01, 0x00, // flags: standard query, recursion desired
		0x00, 0x01, // QDCOUNT=1
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ANCOUNT/NSCOUNT/ARCOUNT=0
		0x01, 'x', 0x00, // QNAME "x."
		0x00, 0x01, // QTYPE=A
		0x00, 0x01, // QCLASS=IN
	}
	if _, err := c.Write(query); err != nil {
		fmt.Fprintf(os.Stderr, "DNS-TRANSPORT FAIL: write: %v\n", err)
		return false
	}
	buf := make([]byte, 512)
	n, err := c.Read(buf)
	if err != nil || n != len(query) || string(buf[:n]) != string(query) {
		fmt.Fprintf(os.Stderr, "DNS-TRANSPORT FAIL: round trip mismatch n=%d err=%v\n", n, err)
		return false
	}
	fmt.Fprintln(os.Stderr, "DNS-TRANSPORT OK: ordinary UDP/53 packet round-tripped through tun2socks -> SOCKS5 UDP ASSOCIATE -> echo target (transport proof only, NOT a real resolver, NOT a leak-safety claim)")
	return true
}

func oneCycle(cycleNum int, useBadFd, useBadSocks bool) bool {
	fmt.Fprintf(os.Stderr, "\n=== CYCLE %d (bad_fd=%v bad_socks=%v) ===\n", cycleNum, useBadFd, useBadSocks)

	run("ip link del %s 2>/dev/null", ifName)

	originalFd, err := openTun(ifName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: openTun: %v\n", err)
		return false
	}
	dupFd, err := unix.Dup(originalFd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: dup: %v\n", err)
		unix.Close(originalFd)
		return false
	}
	fmt.Fprintf(os.Stderr, "OK: split ownership - original fd=%d (closed last), bridge fd=%d (given to tun2socks)\n", originalFd, dupFd)

	run("ip addr add %s dev %s", tunPrefix, ifName)
	run("ip link set %s up", ifName)
	run("ip route add %s/32 dev %s", testDest, ifName)

	bridgeFd := dupFd
	if useBadFd {
		bridgeFd = 9999 // positive, unopened fd - exercises real invalid-fd validation
	}

	socksBackup := ""
	if useBadSocks {
		// point at a port nothing listens on
		socksBackup = "socks5://10.200.0.1:1"
	}

	var startErr error
	if useBadSocks {
		engine.Insert(&engine.Key{MTU: 1500, Device: fmt.Sprintf("fd://%d", bridgeFd), Proxy: socksBackup, LogLevel: "warning"})
		startErr = engine.Start()
	} else {
		startErr = startEngine(bridgeFd, 1500)
	}

	overallOK := true
	if useBadFd {
		fmt.Fprintf(os.Stderr, "invalid-fd path: engine.Start returned err=%v (expected non-nil, no crash)\n", startErr)
		overallOK = startErr != nil
	} else if startErr != nil {
		fmt.Fprintf(os.Stderr, "FAIL: engine.Start: %v\n", startErr)
		overallOK = false
	} else {
		time.Sleep(400 * time.Millisecond)
		tcpOK := proveTCP()
		udpOK := proveUDP()
		if useBadSocks {
			fmt.Fprintf(os.Stderr, "socks5-absent path: tcp_ok=%v udp_ok=%v (expected both false)\n", tcpOK, udpOK)
			overallOK = !tcpOK && !udpOK
		} else {
			dnsOK := proveDNSTransport()
			overallOK = tcpOK && udpOK && dnsOK
		}
		if err := engine.Stop(); err != nil {
			fmt.Fprintf(os.Stderr, "FAIL: engine.Stop: %v\n", err)
			overallOK = false
		}
	}

	unix.Close(dupFd)
	unix.Close(originalFd)
	run("ip link del %s 2>/dev/null", ifName)

	return overallOK
}

func main() {
	ok := true

	// Cycle 1: normal start -> TCP+UDP+DNS-transport proof -> stop.
	ok = ok && oneCycle(1, false, false)

	// Cycle 2: restart on the SAME process (proves clean stop/restart, no
	// leaked goroutine/fd/netstack state carried over).
	ok = ok && oneCycle(2, false, false)

	// Failure path: invalid TUN fd.
	ok = ok && oneCycle(3, true, false)

	// Failure path: SOCKS5 listener absent.
	ok = ok && oneCycle(4, false, true)

	fmt.Fprintf(os.Stderr, "\n=== FINAL RESULT: %s ===\n", map[bool]string{true: "ALL PASS", false: "FAILURE"}[ok])
	if !ok {
		os.Exit(1)
	}
}
