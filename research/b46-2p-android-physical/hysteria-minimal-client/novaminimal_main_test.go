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
