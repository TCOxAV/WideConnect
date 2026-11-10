// Package client connects to WideConnect peers and authenticates them.
package client

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"runtime"
	"time"

	"github.com/TCOxAV/WideConnect/internal/identity"
	"github.com/TCOxAV/WideConnect/protocol"
)

const handshakeTimeout = 5 * time.Second

// Conn is an authenticated WideConnect connection.
type Conn struct {
	net.Conn
	reader *bufio.Reader
	Peer   protocol.Hello
}

// Send writes one protocol frame to the peer.
func (c *Conn) Send(frame protocol.Frame) error {
	return protocol.WriteFrame(c.Conn, frame)
}

// Receive reads one protocol frame from the peer.
func (c *Conn) Receive() (protocol.Frame, error) {
	return protocol.ReadFrame(c.reader)
}

// Dial connects, exchanges HELLO, and completes mutual authentication.
// Both identities must already trust each other in their paired stores.
func Dial(ctx context.Context, addr string, id identity.Identity, paired *identity.PairedStore) (*Conn, error) {
	if paired == nil {
		return nil, fmt.Errorf("client: paired store is required")
	}
	dialer := net.Dialer{Timeout: 3 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("client: dialing peer: %w", err)
	}
	if tcp, ok := conn.(*net.TCPConn); ok {
		if err := tcp.SetNoDelay(true); err != nil {
			conn.Close()
			return nil, fmt.Errorf("client: enabling TCP_NODELAY: %w", err)
		}
	}
	stopCancel := context.AfterFunc(ctx, func() {
		conn.Close()
	})
	defer stopCancel()

	c := &Conn{Conn: conn, reader: bufio.NewReader(conn)}
	if err := conn.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("client: setting handshake deadline: %w", err)
	}

	if err := c.exchangeHello(id); err != nil {
		conn.Close()
		if ctx.Err() != nil {
			return nil, fmt.Errorf("client: handshake canceled: %w", ctx.Err())
		}
		return nil, err
	}
	if err := authenticate(c, id, paired); err != nil {
		conn.Close()
		if ctx.Err() != nil {
			return nil, fmt.Errorf("client: handshake canceled: %w", ctx.Err())
		}
		return nil, err
	}
	if !stopCancel() {
		conn.Close()
		return nil, fmt.Errorf("client: handshake canceled: %w", ctx.Err())
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		conn.Close()
		return nil, fmt.Errorf("client: clearing handshake deadline: %w", err)
	}
	return c, nil
}

func (c *Conn) exchangeHello(id identity.Identity) error {
	name, err := os.Hostname()
	if err != nil || name == "" {
		name = "wideconnect-client"
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

	payload, err := (protocol.Hello{
		DeviceID: id.DeviceID,
		Platform: platform,
		Name:     name,
	}).Marshal()
	if err != nil {
		return fmt.Errorf("client: encoding HELLO: %w", err)
	}
	if err := c.Send(protocol.Frame{Type: protocol.TypeHello, Payload: payload}); err != nil {
		return fmt.Errorf("client: sending HELLO: %w", err)
	}

	frame, err := c.Receive()
	if err != nil {
		return fmt.Errorf("client: reading HELLO: %w", err)
	}
	if frame.Type != protocol.TypeHello {
		return fmt.Errorf("client: expected HELLO, got type %#x", byte(frame.Type))
	}
	c.Peer, err = protocol.UnmarshalHello(frame.Payload)
	if err != nil {
		return fmt.Errorf("client: decoding HELLO: %w", err)
	}
	return nil
}
