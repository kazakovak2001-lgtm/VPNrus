// host_proof is a throwaway, non-Android host proof for the B46-3B
// tun2socks-child wire protocol (SCM_RIGHTS fd transfer + JSON control
// header + JSON ack with real child PID). NOT shipped/committed as part
// of the app - lives only under research/ for provenance, never built into
// the APK. Run manually in a real Linux environment with a real TUN
// device (WSL2 Ubuntu, root) to validate the protocol before deploying to
// the physical Android device, where round-trips are much slower to debug.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"syscall"
	"time"
	"unsafe"
)

type controlHeader struct {
	MTU       int    `json:"mtu"`
	SocksAddr string `json:"socksAddr"`
}

type ackResponse struct {
	OK    bool   `json:"ok"`
	PID   int    `json:"pid,omitempty"`
	Error string `json:"error,omitempty"`
}

const (
	ifReqSize = 40
	tunSetIff = 0x400454ca
	iffTun    = 0x0001
	iffNoPi   = 0x1000
)

func openTun(name string) (*os.File, error) {
	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	var ifr [ifReqSize]byte
	copy(ifr[:16], name)
	*(*uint16)(unsafe.Pointer(&ifr[16])) = iffTun | iffNoPi
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(tunSetIff), uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		f.Close()
		return nil, errno
	}
	return f, nil
}

func main() {
	childPath := flag.String("child", "", "path to tun2socks-child binary")
	flag.Parse()
	if *childPath == "" {
		log.Fatal("missing -child")
	}

	tun, err := openTun("b46b3proof0")
	if err != nil {
		log.Fatalf("openTun: %v", err)
	}
	defer tun.Close()
	log.Printf("real TUN device open: fd=%d name=b46b3proof0", tun.Fd())

	controlPath := "/tmp/b46-3b-proof.sock"
	os.Remove(controlPath)
	ln, err := net.Listen("unix", controlPath)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	defer os.Remove(controlPath)

	cmd := exec.Command(*childPath, controlPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		log.Fatalf("start child: %v", err)
	}
	log.Printf("spawned child, launcher-side pid=%d", cmd.Process.Pid)

	// Connection 1: send header + ancillary fd.
	conn1, err := ln.Accept()
	if err != nil {
		log.Fatalf("accept 1: %v", err)
	}
	uc1 := conn1.(*net.UnixConn)
	hdr := controlHeader{MTU: 1500, SocksAddr: "127.0.0.1:1"}
	payload, _ := json.Marshal(hdr)
	rights := syscall.UnixRights(int(tun.Fd()))
	n, oobn, err := uc1.WriteMsgUnix(payload, rights, nil)
	if err != nil {
		log.Fatalf("WriteMsgUnix: %v", err)
	}
	log.Printf("sent header+fd: %d payload bytes, %d oob bytes", n, oobn)
	uc1.Close()

	// Connection 2: read the JSON ack.
	conn2, err := ln.Accept()
	if err != nil {
		log.Fatalf("accept 2: %v", err)
	}
	conn2.SetDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4096)
	n2, err := conn2.Read(buf)
	conn2.Close()
	if err != nil {
		log.Fatalf("read ack: %v", err)
	}
	var ack ackResponse
	if err := json.Unmarshal(buf[:n2], &ack); err != nil {
		log.Fatalf("parse ack %q: %v", buf[:n2], err)
	}
	fmt.Printf("PROOF_ACK: ok=%v pid=%d error=%q\n", ack.OK, ack.PID, ack.Error)

	if ack.OK {
		fmt.Printf("PROOF_REAL_CHILD_PID=%d LAUNCHER_PID=%d SAME_PROCESS=%v\n", ack.PID, cmd.Process.Pid, ack.PID == cmd.Process.Pid)
	}

	time.Sleep(500 * time.Millisecond)
	log.Printf("sending SIGTERM to child pid=%d", cmd.Process.Pid)
	cmd.Process.Signal(syscall.SIGTERM)
	err = cmd.Wait()
	fmt.Printf("PROOF_CHILD_EXIT: err=%v\n", err)
}
