package main

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	M "github.com/xjasonlyu/tun2socks/v2/metadata"
)

func resetCounters() {
	dataPlaneTxBytes.Store(0)
	dataPlaneRxBytes.Store(0)
}

func TestTCPConnectCountsPayloadOnlyAfterHandshake(t *testing.T) {
	resetCounters()
	s := newFakeSocksServer(t)
	p, err := newNovaSocks5(s.addr(), tUser, tPass)
	if err != nil {
		t.Fatal(err)
	}
	md := &M.Metadata{DstIP: netip.AddrFrom4([4]byte{1, 1, 1, 1}), DstPort: 443}
	c, err := p.DialContext(context.Background(), md)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if dataPlaneTxBytes.Load() != 0 || dataPlaneRxBytes.Load() != 0 {
		t.Fatalf("handshake bytes counted: tx=%d rx=%d", dataPlaneTxBytes.Load(), dataPlaneRxBytes.Load())
	}
	if _, err := c.Write([]byte("0123456789")); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(c, make([]byte, 10)); err != nil {
		t.Fatal(err)
	}
	if dataPlaneTxBytes.Load() != 10 || dataPlaneRxBytes.Load() != 10 {
		t.Fatalf("want tx=10 rx=10, got tx=%d rx=%d", dataPlaneTxBytes.Load(), dataPlaneRxBytes.Load())
	}
}

func TestFailedHandshakeCountsNothing(t *testing.T) {
	resetCounters()
	s := newFakeSocksServer(t)
	p, _ := newNovaSocks5(s.addr(), tUser, "wrong-password")
	if _, err := p.DialContext(context.Background(), &M.Metadata{DstIP: netip.AddrFrom4([4]byte{1, 1, 1, 1}), DstPort: 443}); err == nil {
		t.Fatal("expected auth failure")
	}
	if dataPlaneTxBytes.Load() != 0 || dataPlaneRxBytes.Load() != 0 {
		t.Fatalf("failed dial counted bytes: tx=%d rx=%d", dataPlaneTxBytes.Load(), dataPlaneRxBytes.Load())
	}
}

func TestUDPCountsDecodedPayloadNotSocksHeader(t *testing.T) {
	resetCounters()
	s := newFakeSocksServer(t)
	pc, err := dialUDP(t, s, tUser, tPass)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := readPayload(t, pc); got != "probe" {
		t.Fatalf("got %q", got)
	}
	if _, err := pc.WriteTo([]byte("hello"), &net.UDPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 53}); err != nil {
		t.Fatal(err)
	}
	if dataPlaneRxBytes.Load() != int64(len("probe")) || dataPlaneTxBytes.Load() != int64(len("hello")) {
		t.Fatalf("want tx=5 rx=5, got tx=%d rx=%d", dataPlaneTxBytes.Load(), dataPlaneRxBytes.Load())
	}
}

func TestStatsStreamIsMonotonicCountersOnlyAndStops(t *testing.T) {
	resetCounters()
	dataPlaneTxBytes.Store(100)
	dataPlaneRxBytes.Store(200)
	client, server := net.Pipe()
	defer server.Close()
	stop := make(chan struct{})
	tick := make(chan time.Time)
	done := make(chan error, 1)
	go func() { done <- writeStats(client, 4242, stop, tick) }()

	r := bufio.NewReader(server)
	var lines []statsLine
	for i := 0; i < 3; i++ {
		raw, err := r.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]any
		if err := json.Unmarshal([]byte(raw), &fields); err != nil {
			t.Fatal(err)
		}
		if len(fields) != 5 {
			t.Fatalf("stats line must carry only type/pid/seq/tx/rx: %s", raw)
		}
		var line statsLine
		_ = json.Unmarshal([]byte(raw), &line)
		lines = append(lines, line)
		if i < 2 {
			dataPlaneRxBytes.Add(1)
			tick <- time.Now()
		}
	}
	for i, l := range lines {
		if l.Type != "stats" || l.PID != 4242 || l.Seq != uint64(i+1) || l.Tx != 100 || l.Rx != int64(200+i) {
			t.Fatalf("line %d = %+v", i, l)
		}
	}
	close(stop)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reporter did not stop")
	}
}

func TestStatsStreamEndsOnWriteFailure(t *testing.T) {
	client, server := net.Pipe()
	server.Close()
	if err := writeStats(client, 1, make(chan struct{}), make(chan time.Time)); err == nil || !strings.Contains(err.Error(), "write") {
		t.Fatalf("want write error, got %v", err)
	}
}

func TestSuccessAckCarriesStatsCapabilityMarker(t *testing.T) {
	b, _ := json.Marshal(ackResponse{OK: true, PID: 7, SocksAuth: true, Stats: true})
	if !strings.Contains(string(b), `"stats":true`) {
		t.Fatalf("ack %s lacks the stats marker", b)
	}
	failed, _ := json.Marshal(ackResponse{OK: false, Error: "x"})
	if strings.Contains(string(failed), "stats") {
		t.Fatalf("failure ack must not claim the capability: %s", failed)
	}
}
