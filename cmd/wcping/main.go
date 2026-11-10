// Command wcping measures round-trip latency to a WideConnect peer.
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/TCOxAV/WideConnect/internal/client"
	"github.com/TCOxAV/WideConnect/internal/identity"
	"github.com/TCOxAV/WideConnect/protocol"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:7777", "peer address")
	configDir := flag.String("config", "", "config directory (default: user config dir)")
	count := flag.Int("n", 10, "number of pings")
	interval := flag.Duration("i", 200*time.Millisecond, "interval between pings")
	flag.Parse()

	dir := *configDir
	if dir == "" {
		var err error
		dir, err = identity.DefaultDir()
		if err != nil {
			log.Fatalf("config: %v", err)
		}
	}
	id, err := identity.LoadOrCreate(dir)
	if err != nil {
		log.Fatalf("identity: %v", err)
	}
	paired, err := identity.OpenPairedStore(dir)
	if err != nil {
		log.Fatalf("paired store: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := client.Dial(ctx, *addr, id, paired)
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer conn.Close()
	fmt.Printf("connected to %q (platform=%d caps=%#x)\n", conn.Peer.Name, conn.Peer.Platform, conn.Peer.Caps)
	fmt.Printf("PING %s\n", *addr)

	var min, max, total time.Duration
	received := 0

	for i := 0; i < *count; i++ {
		payload := make([]byte, 8)
		start := time.Now()
		binary.BigEndian.PutUint64(payload, uint64(start.UnixNano()))

		conn.SetDeadline(time.Now().Add(2 * time.Second))
		if err := conn.Send(protocol.Frame{Type: protocol.TypePing, Payload: payload}); err != nil {
			log.Fatalf("write: %v", err)
		}

		f, err := conn.Receive()
		rtt := time.Since(start) // monotonic clock, safe against wall-clock jumps
		if err != nil {
			log.Fatalf("read: %v", err)
		}
		if f.Type != protocol.TypePong || !bytes.Equal(f.Payload, payload) {
			log.Fatalf("bad reply: type=%#x payload=%v", f.Type, f.Payload)
		}

		received++
		total += rtt
		if received == 1 || rtt < min {
			min = rtt
		}
		if rtt > max {
			max = rtt
		}
		fmt.Printf("seq=%d rtt=%v\n", i+1, rtt)

		if i < *count-1 {
			time.Sleep(*interval)
		}
	}

	fmt.Printf("\n%d pings: min=%v avg=%v max=%v\n", received, min, total/time.Duration(received), max)
}
