// Command tun2socks-child is the B46-3B process-isolated tun2socks bridge:
// a PLAIN Go executable (package main, no cgo, no JNI, no gomobile), built
// with the ordinary `go build` toolchain for GOOS=android GOARCH=arm64 and
// exec()'d as a child OS process by the Nova app - never dlopen()'d into
// the app's own process. This is the direct answer to B46-3A's physical
// finding (docs/B46_3A_HYSTERIA_NATIVE_BRIDGE_COEXISTENCE.md): two
// independent Go runtimes sharing ONE Android process corrupted each
// other's GC state and crashed. Running the tun2socks Go runtime in its
// own OS process, with its own separate address space, structurally
// prevents that class of bug - Xray's Go runtime (in the app process) and
// this Go runtime (in a distinct process) never share memory.
//
// Wraps the SAME pinned engine as B46-2P/B46-2C/B46-3A, unmodified:
// github.com/xjasonlyu/tun2socks/v2, MIT, commit
// 5d9fac67bb1095a5d2bd959216f85e6434524731 /
// v2.0.0-20260913205830-5d9fac67bb10.
//
// Wire protocol (one Unix-domain stream socket, path given as argv[1] -
// never a secret, so argv is fine here unlike a credential): reuses the
// EXACT SCM_RIGHTS shape already proven by
// RealShadowsocksVpnProtectBridge.kt (Android side) and
// research/b46-2p-android-physical/hysteria-minimal-client/novaminimal_main.go's
// own protectViaUnixSocket (Go side) - just with the roles/payload swapped:
// here the PARENT (Nova app) is the client-role sender (accepts the
// connection the child makes, then sends), and the payload carries a small
// JSON control header (MTU + local SOCKS5 address, neither secret) plus
// ONE ancillary fd (the duplicated TUN fd, never the VpnService's original -
// see the ownership contract below).
//
//  1. Child connects to the Unix-domain socket at argv[1].
//  2. Child reads exactly ONE message: an oob-carried fd (SCM_RIGHTS) plus
//     a JSON control header terminated by '\n' in the regular payload.
//  3. Child validates fd/MTU/SOCKS address, starts the real tun2socks
//     engine, and opens a SECOND short-lived connection to write back one
//     newline-terminated JSON ack line ({"ok":true,"pid":...} or
//     {"ok":false,"error":"..."}) - JSON rather than the protect bridge's
//     single sentinel byte specifically so the parent learns this
//     process's real PID from the one place that can authoritatively
//     report it (see ackResponse's own doc comment).
//  4. Child blocks until SIGTERM/SIGINT, then calls the real, ordered
//     engine.Stop() and exits 0 - deterministic termination, never left
//     running headless. If the control connection itself closes first
//     (parent process died), that is treated the same as a stop signal.
//
// FD OWNERSHIP CONTRACT (load-bearing, reused verbatim from B46-2C/B46-2P/
// B46-3A): the fd this process receives over SCM_RIGHTS is ALREADY a
// duplicate the Android side made (`ParcelFileDescriptor.dup(original
// .fileDescriptor).detachFd()`) - this process takes ownership of exactly
// that fd number and the real tun2socks engine closes it on Stop(). The
// Android VpnService's original ParcelFileDescriptor is never sent here.
//
// Not production code. Not wired into Nova's release transport selection.
// See docs/B46_3B_HYSTERIA_PROCESS_ISOLATION.md.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/xjasonlyu/tun2socks/v2/engine"
)

const (
	controlDialTimeout = 5 * time.Second
	controlReadTimeout = 5 * time.Second
	ancillaryBufSize   = 32 // one fd (4 or 8 bytes of cmsg header + fd) - generous headroom.
)

// controlHeader is the non-secret JSON control payload sent alongside the
// SCM_RIGHTS fd. Neither field is a credential - MTU is a plain integer,
// SocksAddr is a loopback address/port the parent itself already bound.
type controlHeader struct {
	MTU       int    `json:"mtu"`
	SocksAddr string `json:"socksAddr"`
}

// ackResponse is the second, short-lived connection's payload - JSON, not a
// single sentinel byte, specifically so the parent learns this process's
// REAL os-level PID from the one place that can authoritatively report it
// (os.Getpid() inside the child itself - java.lang.Process on Android has
// no public pid() accessor, confirmed via javap against this project's own
// compileSdk android.jar, see B45AProcessLauncher's own doc comment).
type ackResponse struct {
	OK    bool   `json:"ok"`
	PID   int    `json:"pid,omitempty"`
	Error string `json:"error,omitempty"`
}

func main() {
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: tun2socks-child <control-unix-socket-path>")
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	controlPath := flag.Arg(0)

	fd, hdr, err := receiveStartRequest(controlPath)
	if err != nil {
		log.Printf("B46_3B_CHILD_START_FAILED: %v", err)
		os.Exit(1)
	}

	if err := startEngine(fd, hdr); err != nil {
		log.Printf("B46_3B_CHILD_START_FAILED: engine start: %v", err)
		_ = sendAck(controlPath, ackResponse{OK: false, Error: err.Error()})
		os.Exit(1)
	}

	log.Printf("B46_3B_CHILD_STARTED: pid=%d mtu=%d socksAddr=%s", os.Getpid(), hdr.MTU, hdr.SocksAddr)
	if err := sendAck(controlPath, ackResponse{OK: true, PID: os.Getpid()}); err != nil {
		// The engine is running but the ack couldn't be delivered - the
		// parent will treat this as a start failure and may retry/kill us;
		// fail closed by shutting the engine back down rather than leaving
		// an orphaned, un-acked tunnel running.
		log.Printf("B46_3B_CHILD_ACK_FAILED: %v", err)
		_ = engine.Stop()
		os.Exit(1)
	}

	waitForStopSignal()
	log.Printf("B46_3B_CHILD_STOPPING: pid=%d", os.Getpid())
	if err := engine.Stop(); err != nil {
		log.Printf("B46_3B_CHILD_STOP_ERROR: %v", err)
	}
	log.Printf("B46_3B_CHILD_STOPPED: pid=%d", os.Getpid())
}

// receiveStartRequest connects to the parent's control socket and reads the
// ONE startup message: a newline-terminated JSON controlHeader plus exactly
// one ancillary fd. Never panics on malformed input - always returns a
// plain error.
func receiveStartRequest(controlPath string) (int, controlHeader, error) {
	var hdr controlHeader

	conn, err := net.DialTimeout("unix", controlPath, controlDialTimeout)
	if err != nil {
		return -1, hdr, fmt.Errorf("dial control socket: %w", err)
	}
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		conn.Close()
		return -1, hdr, errors.New("control socket is not a unix connection")
	}
	defer uc.Close()
	if err := uc.SetDeadline(time.Now().Add(controlReadTimeout)); err != nil {
		return -1, hdr, fmt.Errorf("set control socket deadline: %w", err)
	}

	raw, err := uc.File()
	if err != nil {
		return -1, hdr, fmt.Errorf("get raw control fd: %w", err)
	}
	defer raw.Close()

	payload := make([]byte, 4096)
	oob := make([]byte, ancillaryBufSize)
	n, oobn, _, _, err := syscall.Recvmsg(int(raw.Fd()), payload, oob, 0)
	if err != nil {
		return -1, hdr, fmt.Errorf("recvmsg: %w", err)
	}
	if n == 0 {
		return -1, hdr, errors.New("recvmsg: empty payload")
	}

	if err := json.Unmarshal(payload[:n], &hdr); err != nil {
		return -1, hdr, fmt.Errorf("parse control header: %w", err)
	}

	scms, err := syscall.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return -1, hdr, fmt.Errorf("parse socket control message: %w", err)
	}
	var fd int = -1
	for _, scm := range scms {
		fds, err := syscall.ParseUnixRights(&scm)
		if err != nil {
			continue
		}
		if len(fds) > 0 {
			fd = fds[0]
			break
		}
	}
	if fd < 0 {
		return -1, hdr, errors.New("no ancillary fd received")
	}
	return fd, hdr, nil
}

// startEngine validates the received fd/header (fail-closed, never a
// panic) and starts the real tun2socks engine - byte-for-byte the same
// engine.Insert/engine.Start call shape B46-2P/B46-3A already used.
func startEngine(fd int, hdr controlHeader) error {
	if fd < 0 {
		return errors.New("invalid fd")
	}
	if hdr.MTU <= 0 {
		return errors.New("invalid mtu")
	}
	if hdr.SocksAddr == "" {
		return errors.New("empty socks address")
	}

	engine.Insert(&engine.Key{
		MTU:      hdr.MTU,
		Device:   fmt.Sprintf("fd://%d", fd),
		Proxy:    "socks5://" + hdr.SocksAddr,
		LogLevel: "warning",
	})
	return engine.Start()
}

// sendAck opens a SECOND short-lived connection to the parent's control
// socket (the first one was already consumed/closed by receiveStartRequest)
// and writes one newline-terminated JSON ackResponse line.
func sendAck(controlPath string, resp ackResponse) error {
	conn, err := net.DialTimeout("unix", controlPath, controlDialTimeout)
	if err != nil {
		return fmt.Errorf("dial control socket for ack: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(controlReadTimeout))

	encoded, err := json.Marshal(resp)
	if err != nil {
		return fmt.Errorf("marshal ack: %w", err)
	}
	w := bufio.NewWriter(conn)
	if _, err := w.Write(append(encoded, '\n')); err != nil {
		return fmt.Errorf("write ack: %w", err)
	}
	return w.Flush()
}

func waitForStopSignal() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	<-sigCh
}
