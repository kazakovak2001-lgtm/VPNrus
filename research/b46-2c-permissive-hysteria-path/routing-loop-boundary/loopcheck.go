// loopcheck is a B46-2C research harness proving the Android routing-loop
// boundary: TUN app-traffic must reach the local Hysteria SOCKS5 listener,
// while Hysteria's own outbound QUIC UDP socket must be excluded from the
// TUN's own routing (the FD-Control/protect(fd) boundary) so it never loops
// back into the TUN it is itself feeding. NOT production code.
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/xjasonlyu/tun2socks/v2/engine"
)

func openTun(name string) (int, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR, 0)
	if err != nil {
		return -1, fmt.Errorf("open /dev/net/tun: %w", err)
	}
	ifr := make([]byte, 40)
	copy(ifr, name)
	ifr[16] = 0x01
	ifr[17] = 0x10
	const TUNSETIFF = 0x400454ca
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), TUNSETIFF, uintptr(unsafe.Pointer(&ifr[0]))); errno != 0 {
		unix.Close(fd)
		return -1, fmt.Errorf("TUNSETIFF: %w", errno)
	}
	return fd, nil
}

func run(format string, args ...interface{}) {
	cmdline := fmt.Sprintf(format, args...)
	fmt.Fprintf(os.Stderr, "+ %s\n", cmdline)
	cmd := exec.Command("sh", "-c", cmdline)
	cmd.Stderr = os.Stderr
	_ = cmd.Run()
}

func main() {
	ifName := flag.String("if", "novaloopchk0", "TUN interface name")
	tunPrefix := flag.String("tun-prefix", "198.18.79.1/30", "TUN address/prefix")
	proxy := flag.String("proxy", "127.0.0.1:11090", "local Hysteria SOCKS5 address")
	tcpDest := flag.String("tcp-dest", "10.200.1.2:9300", "app-traffic TCP echo target, reached THROUGH the tunnel")
	udpDest := flag.String("udp-dest", "10.200.1.2:9301", "app-traffic UDP echo target, reached THROUGH the tunnel")
	timeout := flag.Duration("timeout", 6*time.Second, "per-probe timeout")
	fullTunnel := flag.Bool("full-tunnel", false, "point the client netns's own default route at the TUN (simulates a full-tunnel VPN; the routing-loop-boundary proof needs this)")
	serve := flag.Bool("serve", false, "after setup, block on SIGTERM/SIGINT instead of immediately running the app-traffic proof and exiting (used to hold the TUN+full-tunnel route up while a separate process, e.g. the Hysteria client, is observed)")
	flag.Parse()

	run("ip link del %s 2>/dev/null", *ifName)
	originalFd, err := openTun(*ifName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: openTun: %v\n", err)
		os.Exit(2)
	}
	dupFd, err := unix.Dup(originalFd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: dup: %v\n", err)
		os.Exit(2)
	}
	run("ip addr add %s dev %s", *tunPrefix, *ifName)
	run("ip link set %s up", *ifName)
	if *fullTunnel {
		// Simulate a full-tunnel VPN: the client netns's OWN default route
		// (table "main") now points into the TUN, exactly like Android
		// routes 0.0.0.0/0 through VpnService's TUN. Anything NOT excluded
		// via fwmark/protect (set up separately, see the routing-loop-
		// boundary proof) will be captured here - including, if protect is
		// missing, Hysteria's own outbound QUIC socket.
		run("ip route del default 2>/dev/null")
		run("ip route add default dev %s", *ifName)
	}

	engine.Insert(&engine.Key{
		MTU:      1500,
		Device:   fmt.Sprintf("fd://%d", dupFd),
		Proxy:    fmt.Sprintf("socks5://%s", *proxy),
		LogLevel: "warning",
	})
	cleanup := func() {
		engine.Stop()
		if *fullTunnel {
			run("ip route del default dev %s 2>/dev/null", *ifName)
			run("ip route add default via 10.200.0.1 dev veth1")
		}
		run("ip link del %s 2>/dev/null", *ifName)
	}

	if err := engine.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: engine.Start: %v\n", err)
		cleanup()
		os.Exit(2)
	}

	if *serve {
		fmt.Println("LOOPCHECK_SERVING")
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		<-sigCh
		cleanup()
		return
	}

	tcpOK := proveTCP(*tcpDest, *timeout)
	udpOK := proveUDP(*udpDest, *timeout)
	cleanup()

	fmt.Printf("LOOPCHECK_RESULT tcp=%v udp=%v\n", tcpOK, udpOK)
	if !tcpOK || !udpOK {
		os.Exit(1)
	}
}

func proveTCP(dest string, timeout time.Duration) bool {
	c, err := net.DialTimeout("tcp", dest, timeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "TCP FAIL: dial %s through tun: %v\n", dest, err)
		return false
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(timeout))
	payload := "b46-2c-loopcheck-tcp"
	if _, err := c.Write([]byte(payload)); err != nil {
		fmt.Fprintf(os.Stderr, "TCP FAIL: write: %v\n", err)
		return false
	}
	buf := make([]byte, len(payload))
	total := 0
	for total < len(buf) {
		n, err := c.Read(buf[total:])
		total += n
		if err != nil {
			fmt.Fprintf(os.Stderr, "TCP FAIL: read: %v\n", err)
			return false
		}
	}
	if string(buf) != payload {
		fmt.Fprintf(os.Stderr, "TCP FAIL: mismatch got=%q\n", buf)
		return false
	}
	fmt.Fprintln(os.Stderr, "TCP OK: app traffic reached local Hysteria SOCKS5 through the TUN and round-tripped via real QUIC to the real server and back")
	return true
}

func proveUDP(dest string, timeout time.Duration) bool {
	c, err := net.DialTimeout("udp", dest, timeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "UDP FAIL: dial %s through tun: %v\n", dest, err)
		return false
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(timeout))
	payload := "b46-2c-loopcheck-udp"
	if _, err := c.Write([]byte(payload)); err != nil {
		fmt.Fprintf(os.Stderr, "UDP FAIL: write: %v\n", err)
		return false
	}
	buf := make([]byte, 128)
	n, err := c.Read(buf)
	if err != nil || string(buf[:n]) != payload {
		fmt.Fprintf(os.Stderr, "UDP FAIL: mismatch/err n=%d err=%v\n", n, err)
		return false
	}
	fmt.Fprintln(os.Stderr, "UDP OK: app traffic reached local Hysteria SOCKS5 through the TUN and round-tripped via real QUIC to the real server and back")
	return true
}
