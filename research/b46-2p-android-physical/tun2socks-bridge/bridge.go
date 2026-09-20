// Package bridge is the B46-2P Android AAR wrapper around the real
// xjasonlyu/tun2socks engine (github.com/xjasonlyu/tun2socks/v2, MIT,
// commit 5d9fac67bb1095a5d2bd959216f85e6434524731 / pseudo-version
// v2.0.0-20260913205830-5d9fac67bb10, matching the exact pin audited in
// B46-2C, docs/B46_2C_PERMISSIVE_HYSTERIA_PATH.md Part A/G). It is not
// production code and is not wired into Nova's release build (see
// docs/B46_2P_HYSTERIA2_ANDROID_PHYSICAL_VALIDATION.md).
//
// This wraps the real engine.Insert/engine.Start/engine.Stop lifecycle
// already proven host-side in
// research/b46-2c-permissive-hysteria-path/tun2socks-proof/main.go. It does
// not implement any IP/TCP/UDP stack of its own - all packet processing is
// the real gVisor-backed tun2socks engine.
//
// Built via:
//
//	gomobile bind -target=android/arm64 -androidapi 26 -o b46-tun2socks.aar .
//
// FD OWNERSHIP CONTRACT (load-bearing, see B46-2C Part B): the caller
// (B46HysteriaVpnService) must pass a DUPLICATE of the original
// VpnService-owned TUN fd, never the original. StartBridge takes ownership
// of exactly the fd number it is given and the underlying tun2socks engine
// will close that fd on Stop() - the caller must not also close that same
// fd number itself.
package bridge

import (
	"errors"
	"fmt"
	"sync"

	"github.com/xjasonlyu/tun2socks/v2/engine"
)

var (
	mu      sync.Mutex
	started bool
)

// StartBridge starts the real tun2socks engine against fd (which must
// already be a duplicate of the VpnService's TUN fd - see the ownership
// contract above), using the given MTU and pointing outbound SOCKS5 traffic
// at socksAddr (host:port, e.g. "127.0.0.1:41080", the local Hysteria2
// child's SOCKS5 listener). Returns a non-nil error on failure; never
// panics on a bad fd (proven in the B46-2C proof's Cycle 3).
func StartBridge(fd int, mtu int, socksAddr string) error {
	mu.Lock()
	defer mu.Unlock()
	if started {
		return errors.New("bridge already started - call StopBridge first")
	}
	if fd < 0 {
		return fmt.Errorf("invalid fd %d", fd)
	}
	if mtu <= 0 {
		return fmt.Errorf("invalid mtu %d", mtu)
	}
	if socksAddr == "" {
		return errors.New("socksAddr must not be empty")
	}

	engine.Insert(&engine.Key{
		MTU:      mtu,
		Device:   fmt.Sprintf("fd://%d", fd),
		Proxy:    "socks5://" + socksAddr,
		LogLevel: "warning",
	})
	if err := engine.Start(); err != nil {
		return fmt.Errorf("engine.Start: %w", err)
	}
	started = true
	return nil
}

// StopBridge performs the real, ordered tun2socks shutdown
// (engine.Stop() - closes the device, then the stack, and waits). Safe to
// call when not started (no-op, no error).
func StopBridge() error {
	mu.Lock()
	defer mu.Unlock()
	if !started {
		return nil
	}
	err := engine.Stop()
	started = false
	if err != nil {
		return fmt.Errorf("engine.Stop: %w", err)
	}
	return nil
}

// IsStarted reports whether the bridge is currently believed to be running.
// Diagnostic only - never used to gate a production decision.
func IsStarted() bool {
	mu.Lock()
	defer mu.Unlock()
	return started
}
