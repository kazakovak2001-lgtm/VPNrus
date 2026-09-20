// Command native builds the Nova tun2socks native bridge as a Go
// -buildmode=c-archive artifact (B46-3A). It is a thin cgo export layer
// around the exact xjasonlyu/tun2socks engine lifecycle already reviewed
// and pinned in B46-2P/B46-2C (github.com/xjasonlyu/tun2socks/v2, MIT,
// commit 5d9fac67bb1095a5d2bd959216f85e6434524731 / pseudo-version
// v2.0.0-20260913205830-5d9fac67bb10). It does not implement any IP/TCP/UDP
// stack of its own and does not modify the tun2socks engine.
//
// Unlike the B46-2P AAR (research/b46-2p-android-physical/tun2socks-bridge),
// this is NOT built with `gomobile bind`. It is built with the plain Go
// toolchain's `-buildmode=c-archive`, which emits a standard C ABI
// (a .h header + a .a static archive) and pulls in only the ordinary Go
// runtime - no go.Seq/go.Universe/go.error bridging classes, no
// gomobile-generated Java, no second libgojni.so. A small JNI shim
// (../jni/nova_tun2socks_jni.c) links against this archive and is the only
// piece exposed to the JVM, as net.pocvpn.client.vpn.hysteria.NativeTun2SocksBridge.
//
// Not production code. Not wired into Nova's release transport selection.
// See docs/B46_3A_HYSTERIA_NATIVE_BRIDGE_COEXISTENCE.md.
package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"fmt"
	"sync"
	"unsafe"

	"github.com/xjasonlyu/tun2socks/v2/engine"
)

var (
	mu      sync.Mutex
	started bool
)

// Error codes returned across the C ABI. Kept small and stable - the JNI
// shim maps these to a typed Kotlin result, never a crash.
const (
	novaOK                 C.int = 0
	novaErrAlreadyStarted  C.int = -1
	novaErrInvalidFD       C.int = -2
	novaErrInvalidMTU      C.int = -3
	novaErrEmptySocksAddr  C.int = -4
	novaErrEngineStartFail C.int = -5
	novaErrEngineStopFail  C.int = -6
)

// NovaTun2SocksStart starts the real tun2socks engine against fd (which
// must already be a duplicate of the Android VpnService's TUN fd - the
// caller owns and closes the original; this library owns and closes the
// duplicate on Stop - see B46-2C's FD ownership contract, reused verbatim
// here), using the given MTU and pointing outbound SOCKS5 traffic at
// socksAddr (host:port, NUL-terminated C string). Never panics on bad
// input; returns a negative error code instead.
//
//export NovaTun2SocksStart
func NovaTun2SocksStart(fd C.int, mtu C.int, socksAddr *C.char) C.int {
	mu.Lock()
	defer mu.Unlock()

	if started {
		return novaErrAlreadyStarted
	}
	if fd < 0 {
		return novaErrInvalidFD
	}
	if mtu <= 0 {
		return novaErrInvalidMTU
	}
	if socksAddr == nil {
		return novaErrEmptySocksAddr
	}
	addr := C.GoString(socksAddr)
	if addr == "" {
		return novaErrEmptySocksAddr
	}

	engine.Insert(&engine.Key{
		MTU:      int(mtu),
		Device:   fmt.Sprintf("fd://%d", int(fd)),
		Proxy:    "socks5://" + addr,
		LogLevel: "warning",
	})
	if err := engine.Start(); err != nil {
		return novaErrEngineStartFail
	}
	started = true
	return novaOK
}

// NovaTun2SocksStop performs the real, ordered tun2socks shutdown
// (engine.Stop() - closes the device, then the stack, and waits).
// Idempotent: calling it when not started is a harmless no-op.
//
//export NovaTun2SocksStop
func NovaTun2SocksStop() C.int {
	mu.Lock()
	defer mu.Unlock()
	if !started {
		return novaOK
	}
	err := engine.Stop()
	started = false
	if err != nil {
		return novaErrEngineStopFail
	}
	return novaOK
}

// NovaTun2SocksIsStarted reports whether the bridge is currently believed
// to be running. Diagnostic only - never used to gate a production
// decision. Returns 1 (true) or 0 (false).
//
//export NovaTun2SocksIsStarted
func NovaTun2SocksIsStarted() C.int {
	mu.Lock()
	defer mu.Unlock()
	if started {
		return 1
	}
	return 0
}

// NovaTun2SocksLastErrorString is a small debug helper that turns one of
// the novaErr* codes above into a static, allocation-free-on-the-Go-side
// human string. The caller must free the returned pointer with
// NovaTun2SocksFreeString.
//
//export NovaTun2SocksLastErrorString
func NovaTun2SocksLastErrorString(code C.int) *C.char {
	var msg string
	switch code {
	case novaOK:
		msg = "ok"
	case novaErrAlreadyStarted:
		msg = "bridge already started"
	case novaErrInvalidFD:
		msg = "invalid fd"
	case novaErrInvalidMTU:
		msg = "invalid mtu"
	case novaErrEmptySocksAddr:
		msg = "empty socks address"
	case novaErrEngineStartFail:
		msg = "engine start failed"
	case novaErrEngineStopFail:
		msg = "engine stop failed"
	default:
		msg = "unknown error"
	}
	return C.CString(msg)
}

// NovaTun2SocksFreeString frees a string returned by
// NovaTun2SocksLastErrorString. Required because CGO-allocated C strings
// are not managed by either runtime's GC.
//
//export NovaTun2SocksFreeString
func NovaTun2SocksFreeString(s *C.char) {
	C.free(unsafe.Pointer(s))
}

func main() {}
