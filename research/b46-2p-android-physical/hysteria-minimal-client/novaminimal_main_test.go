// B46-2P - real Go-level test of protectViaUnixSocket's SCM_RIGHTS wire
// protocol, exercised against a real net.Listen("unix", ...) fake server
// (standing in for Android's RealB46HysteriaVpnProtectBridge - same wire
// protocol, verified independently on the Kotlin side by
// B46HysteriaRuntimeTest's FD-protect tests). This is real cross-process fd
// passing over a real Unix-domain socket, not a mock - only the "Android"
// side is a test double.
//
// To run (after grafting alongside novaminimal_main.go per README.md):
//
//	cd app && go test ./novaminimal/...
package main

import (
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// fakeAndroidProtectServer accepts exactly one connection, reads the
// payload byte + ancillary fd via SCM_RIGHTS, and replies with the given
// ack byte. Returns the received fd (still open in this process - SCM_RIGHTS
// duplicates on receive) so the test can assert against it.
func fakeAndroidProtectServer(t *testing.T, socketPath string, ack byte, delay time.Duration) <-chan int {
	l, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	received := make(chan int, 1)
	go func() {
		defer l.Close()
		conn, err := l.Accept()
		if err != nil {
			received <- -1
			return
		}
		defer conn.Close()
		uc := conn.(*net.UnixConn)

		buf := make([]byte, 1)
		oob := make([]byte, 32)
		n, oobn, _, _, err := uc.ReadMsgUnix(buf, oob)
		if err != nil || n != 1 {
			received <- -1
			return
		}
		scms, err := unix.ParseSocketControlMessage(oob[:oobn])
		if err != nil || len(scms) == 0 {
			received <- -1
			return
		}
		fds, err := unix.ParseUnixRights(&scms[0])
		if err != nil || len(fds) == 0 {
			received <- -1
			return
		}

		if delay > 0 {
			time.Sleep(delay)
		}
		_, _ = uc.Write([]byte{ack})
		received <- fds[0]
	}()
	return received
}

func TestProtectViaUnixSocket_Success(t *testing.T) {
	socketPath := t.TempDir() + "/protect.sock"
	received := fakeAndroidProtectServer(t, socketPath, 0x00, 0)

	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer conn.Close()

	rc, _ := conn.SyscallConn()
	var fd int
	_ = rc.Control(func(f uintptr) { fd = int(f) })

	if err := protectViaUnixSocket(socketPath, fd); err != nil {
		t.Fatalf("expected success, got: %v", err)
	}

	select {
	case gotFd := <-received:
		if gotFd < 0 {
			t.Fatal("fake Android server never received a valid fd")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("fake Android server never completed")
	}
}

func TestProtectViaUnixSocket_NegativeAckFailsClosed(t *testing.T) {
	socketPath := t.TempDir() + "/protect.sock"
	fakeAndroidProtectServer(t, socketPath, 0xFF, 0)

	conn, _ := net.ListenUDP("udp", nil)
	defer conn.Close()
	rc, _ := conn.SyscallConn()
	var fd int
	_ = rc.Control(func(f uintptr) { fd = int(f) })

	err := protectViaUnixSocket(socketPath, fd)
	if err == nil {
		t.Fatal("expected an error on a negative (0xFF) ack, got nil")
	}
}

func TestProtectViaUnixSocket_TimeoutFailsClosed(t *testing.T) {
	socketPath := t.TempDir() + "/protect.sock"
	// Server accepts and reads the fd, but never replies within the RPC timeout.
	fakeAndroidProtectServer(t, socketPath, 0x00, protectRPCTimeout+2*time.Second)

	conn, _ := net.ListenUDP("udp", nil)
	defer conn.Close()
	rc, _ := conn.SyscallConn()
	var fd int
	_ = rc.Control(func(f uintptr) { fd = int(f) })

	err := protectViaUnixSocket(socketPath, fd)
	if err == nil {
		t.Fatal("expected a timeout error, got nil")
	}
}

func TestProtectViaUnixSocket_NoListenerFailsClosed(t *testing.T) {
	socketPath := t.TempDir() + "/does-not-exist.sock"

	conn, _ := net.ListenUDP("udp", nil)
	defer conn.Close()
	rc, _ := conn.SyscallConn()
	var fd int
	_ = rc.Control(func(f uintptr) { fd = int(f) })

	err := protectViaUnixSocket(socketPath, fd)
	if err == nil {
		t.Fatal("expected a dial error when nothing is listening, got nil")
	}
}

// PRE-MERGE HARDENING CORRECTION (2026-09-20, manual review, round 3):
// authSecret/obfsSecret are package-level vars redact() reads - save and
// restore them around each test so these tests never leak state into any
// other test in this file/package (Go test binaries run all tests in one
// process by default).
func withSecrets(t *testing.T, auth, obfs string, fn func()) {
	t.Helper()
	prevAuth, prevObfs := authSecret, obfsSecret
	authSecret, obfsSecret = auth, obfs
	defer func() { authSecret, obfsSecret = prevAuth, prevObfs }()
	fn()
}

// 5. auth redaction
func TestRedact_AuthOnly(t *testing.T) {
	withSecrets(t, "super-secret-auth-value", "", func() {
		in := "hysteria client construction/handshake failed: auth failed for super-secret-auth-value on connect"
		out := redact(in)
		if strings.Contains(out, "super-secret-auth-value") {
			t.Fatalf("redact() must remove the auth secret, got: %q", out)
		}
		if !strings.Contains(out, "***REDACTED***") {
			t.Fatalf("expected a redaction marker in output, got: %q", out)
		}
	})
}

// 6. obfs redaction
func TestRedact_ObfsOnly(t *testing.T) {
	withSecrets(t, "", "super-secret-obfs-value", func() {
		in := "salamander handshake failed using psk super-secret-obfs-value: timeout"
		out := redact(in)
		if strings.Contains(out, "super-secret-obfs-value") {
			t.Fatalf("redact() must remove the obfs secret, got: %q", out)
		}
	})
}

// 7. auth + obfs simultaneous redaction
func TestRedact_AuthAndObfsSimultaneously(t *testing.T) {
	withSecrets(t, "super-secret-auth-value", "super-secret-obfs-value", func() {
		in := "failed: auth=super-secret-auth-value obfs=super-secret-obfs-value both present in one error"
		out := redact(in)
		if strings.Contains(out, "super-secret-auth-value") {
			t.Fatalf("redact() must remove the auth secret when both are set, got: %q", out)
		}
		if strings.Contains(out, "super-secret-obfs-value") {
			t.Fatalf("redact() must remove the obfs secret when both are set, got: %q", out)
		}
	})
}

func TestRedact_NoSecretsSetIsANoOp(t *testing.T) {
	withSecrets(t, "", "", func() {
		in := "plain error text with nothing secret in it"
		if got := redact(in); got != in {
			t.Fatalf("expected redact() to be a no-op with no secrets set, got: %q", got)
		}
	})
}
