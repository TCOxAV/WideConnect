// Package server accepts WideConnect TCP connections and dispatches frames.
package server

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/TCOxAV/WideConnect/internal/identity"
	"github.com/TCOxAV/WideConnect/protocol"
)

// handshakeTimeout is how long a new peer has to complete the HELLO exchange.
const handshakeTimeout = 5 * time.Second

// Server listens for WideConnect peers.
type Server struct {
	addr         string
	id           identity.Identity
	helloPayload []byte // our own HELLO, encoded once at startup
	wg           sync.WaitGroup
}

// New returns a Server that will listen on addr (e.g. ":7777").
func New(addr string, id identity.Identity) *Server {
	return &Server{addr: addr, id: id}
}

// session wraps a connection with a write lock, so several goroutines
// (ping replies, notifications, file chunks...) can send safely.
type session struct {
	conn net.Conn
	mu   sync.Mutex
}

func (s *session) send(f protocol.Frame) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return protocol.WriteFrame(s.conn, f)
}

// buildHello creates this device's identity.
// TODO: persist the DeviceID on disk so it survives restarts (needed for pairing).
// buildHello creates this device's HELLO payload from its persistent identity.
func buildHello(id identity.Identity) ([]byte, error) {
	name, err := os.Hostname()
	if err != nil || name == "" {
		name = "wideconnect"
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

	h := protocol.Hello{
		DeviceID: id.DeviceID,
		Platform: platform,
		Caps:     protocol.CapNotify | protocol.CapFiles | protocol.CapScreen,
		Name:     name,
	}
	payload, err := h.Marshal()
	if err != nil { // e.g. hostname with invalid UTF-8
		h.Name = "wideconnect"
		return h.Marshal()
	}
	return payload, nil
}

// ListenAndServe blocks until ctx is cancelled, then closes the listener
// and all connections and waits for handlers to finish.
func (s *Server) ListenAndServe(ctx context.Context) error {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", s.addr)
	if err != nil {
		return err
	}
	return s.Serve(ctx, ln)
}

// Serve accepts connections on ln until ctx is cancelled.
// It takes ownership of ln and closes it on shutdown.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	payload, err := buildHello(s.id)
	if err != nil {
		ln.Close()
		return fmt.Errorf("build hello: %w", err)
	}
	s.helloPayload = payload

	log.Printf("listening on %s", ln.Addr())

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				s.wg.Wait()
				return nil
			}
			log.Printf("accept: %v", err)
			time.Sleep(50 * time.Millisecond)
			continue
		}

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConn(ctx, conn)
		}()
	}
}

// handshake expects the peer's HELLO first, then replies with ours.
func (s *Server) handshake(sess *session, r io.Reader) (protocol.Hello, error) {
	sess.conn.SetDeadline(time.Now().Add(handshakeTimeout))
	defer sess.conn.SetDeadline(time.Time{}) // clear for normal operation

	f, err := protocol.ReadFrame(r)
	if err != nil {
		return protocol.Hello{}, fmt.Errorf("reading hello: %w", err)
	}
	if f.Type != protocol.TypeHello {
		return protocol.Hello{}, fmt.Errorf("expected HELLO, got type %#x", f.Type)
	}

	peer, err := protocol.UnmarshalHello(f.Payload)
	if err != nil {
		return protocol.Hello{}, fmt.Errorf("bad hello: %w", err)
	}

	reply := protocol.Frame{Type: protocol.TypeHello, Payload: s.helloPayload}
	if err := sess.send(reply); err != nil {
		return protocol.Hello{}, fmt.Errorf("sending hello: %w", err)
	}
	return peer, nil
}

func (s *Server) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	remote := conn.RemoteAddr()
	log.Printf("[%s] connected", remote)
	defer log.Printf("[%s] disconnected", remote)

	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(30 * time.Second)
	}

	// Closing the conn is how we unblock a pending read on shutdown.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-done:
		}
	}()

	sess := &session{conn: conn}
	r := bufio.NewReader(conn)

	peer, err := s.handshake(sess, r)
	if err != nil {
		if ctx.Err() == nil {
			log.Printf("[%s] handshake failed: %v", remote, err)
		}
		return
	}
	log.Printf("[%s] handshake ok: name=%q platform=%d caps=%#x",
		remote, peer.Name, peer.Platform, peer.Caps)

	for {
		f, err := protocol.ReadFrame(r)
		if err != nil {
			if !errors.Is(err, io.EOF) && ctx.Err() == nil {
				log.Printf("[%s] read: %v", remote, err)
			}
			return
		}

		switch f.Type {
		case protocol.TypePing:
			pong := protocol.Frame{Type: protocol.TypePong, Payload: f.Payload}
			if err := sess.send(pong); err != nil {
				log.Printf("[%s] write: %v", remote, err)
				return
			}
		default:
			log.Printf("[%s] unhandled frame type %#x", remote, f.Type)
		}
	}
}
