// Nova H2-GATE - data-plane byte counters and the stats stream to the parent.
//
// The counters measure payload relayed between the tun2socks netstack (fed by
// the TUN fd) and the local Hysteria2 SOCKS5 listener: TCP bytes after the
// SOCKS handshake and UDP datagram payloads, excluding SOCKS framing. tx is
// TUN -> SOCKS, rx is SOCKS -> TUN. They never include TCP ACKs (same caveat
// as the Xray VLESS-outbound totals, ROADMAP "Known limitation M1").
//
// Stats stream: after a successful ack the child opens a THIRD connection to
// the same app-private control socket and writes one JSON line per
// statsInterval: {"type":"stats","pid":..,"seq":..,"tx":..,"rx":..}. The
// stream carries counters only - never addresses, credentials or payload.
// If the parent never accepts it or the write fails, reporting stops; the
// parent then sees no fresh stats and treats the data plane as unverified,
// never as healthy.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sync/atomic"
	"time"
)

const statsInterval = time.Second

var (
	dataPlaneTxBytes atomic.Int64
	dataPlaneRxBytes atomic.Int64
)

// countingConn counts payload on an already-handshaken SOCKS CONNECT stream.
type countingConn struct {
	net.Conn
}

func (c *countingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		dataPlaneRxBytes.Add(int64(n))
	}
	return n, err
}

func (c *countingConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		dataPlaneTxBytes.Add(int64(n))
	}
	return n, err
}

type statsLine struct {
	Type string `json:"type"`
	PID  int    `json:"pid"`
	Seq  uint64 `json:"seq"`
	Tx   int64  `json:"tx"`
	Rx   int64  `json:"rx"`
}

func encodeStatsLine(pid int, seq uint64) ([]byte, error) {
	encoded, err := json.Marshal(statsLine{Type: "stats", PID: pid, Seq: seq, Tx: dataPlaneTxBytes.Load(), Rx: dataPlaneRxBytes.Load()})
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

// runStatsReporter blocks until the stream fails or stop is closed.
func runStatsReporter(controlPath string, pid int, stop <-chan struct{}) {
	conn, err := net.DialTimeout("unix", controlPath, controlDialTimeout)
	if err != nil {
		log.Printf("H2_GATE_STATS_UNAVAILABLE: dial: %v", err)
		return
	}
	defer conn.Close()
	if err := writeStats(conn, pid, stop, time.NewTicker(statsInterval).C); err != nil {
		log.Printf("H2_GATE_STATS_STOPPED: %v", err)
	}
}

func writeStats(conn net.Conn, pid int, stop <-chan struct{}, tick <-chan time.Time) error {
	var seq uint64
	for {
		seq++
		line, err := encodeStatsLine(pid, seq)
		if err != nil {
			return fmt.Errorf("encode: %w", err)
		}
		_ = conn.SetWriteDeadline(time.Now().Add(controlReadTimeout))
		if _, err := conn.Write(line); err != nil {
			return fmt.Errorf("write: %w", err)
		}
		select {
		case <-stop:
			return nil
		case <-tick:
		}
	}
}
