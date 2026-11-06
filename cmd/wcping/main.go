// Command wcping measures round-trip latency to a WideConnect peer.
package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"time"

	"github.com/TCOxAV/WideConnect/protocol"
)

// handshake sends our HELLO, then reads and returns the peer's.
func handshake(conn net.Conn, r *bufio.Reader) (protocol.Hello, error) {
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	defer conn.SetDeadline(time.Time{})

	id, err := protocol.NewDeviceID()
	if err != nil {
		return protocol.Hello{}, err
	}

	name, err := os.Hostname()
	if err != nil || name == "" {
		name = "wcping"
	}
	if len(name) > protocol.MaxNameLen {
		name = name[:protocol.MaxNameLen]
	}

	platform := protocol.PlatformUnknown
	switch runtime.GOOS {
	case "linux":
		platform = protocol.PlatformLinux
	case "windows":
		platform = protocol.PlatformWindows
	}

	payload, err := protocol.Hello{DeviceID: id, Platform: platform, Name: name}.Marshal()
	if err != nil {
		return protocol.Hello{}, err
	}
	if err := protocol.WriteFrame(conn, protocol.Frame{Type: protocol.TypeHello, Payload: payload}); err != nil {
		return protocol.Hello{}, fmt.Errorf("sending hello: %w", err)
	}

	f, err := protocol.ReadFrame(r)
	if err != nil {
		return protocol.Hello{}, fmt.Errorf("reading hello: %w", err)
	}
	if f.Type != protocol.TypeHello {
		return protocol.Hello{}, fmt.Errorf("expected HELLO, got type %#x", f.Type)
	}
	return protocol.UnmarshalHello(f.Payload)
}

func main() {
	addr := flag.String("addr", "127.0.0.1:7777", "peer address")
	count := flag.Int("n", 10, "number of pings")
	interval := flag.Duration("i", 200*time.Millisecond, "interval between pings")
	flag.Parse()

	conn, err := net.DialTimeout("tcp", *addr, 3*time.Second)
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}
	r := bufio.NewReader(conn)

	peer, err := handshake(conn, r)
	if err != nil {
		log.Fatalf("handshake: %v", err)
	}
	fmt.Printf("connected to %q (platform=%d caps=%#x)\n", peer.Name, peer.Platform, peer.Caps)
	fmt.Printf("PING %s\n", *addr)

	var min, max, total time.Duration
	received := 0

	for i := 0; i < *count; i++ {
		payload := make([]byte, 8)
		start := time.Now()
		binary.BigEndian.PutUint64(payload, uint64(start.UnixNano()))

		conn.SetDeadline(time.Now().Add(2 * time.Second))
		if err := protocol.WriteFrame(conn, protocol.Frame{Type: protocol.TypePing, Payload: payload}); err != nil {
			log.Fatalf("write: %v", err)
		}

		f, err := protocol.ReadFrame(r)
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
