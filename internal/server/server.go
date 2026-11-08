// Package server accepts WideConnect TCP connections and dispatches frames.
package server

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TCOxAV/WideConnect/internal/identity"
	"github.com/TCOxAV/WideConnect/protocol"
)

// handshakeTimeout is how long a new peer has to complete the HELLO exchange.
const handshakeTimeout = 5 * time.Second
const authenticationTimeout = 5 * time.Second

// Server listens for WideConnect peers.
type Server struct {
	addr         string
	id           identity.Identity
	paired       *identity.PairedStore
	helloPayload []byte // our own HELLO, encoded once at startup
	wg           sync.WaitGroup
}

// New returns a Server that will listen on addr (e.g. ":7777")
// and identify itself to peers as id. A nil paired store means the server
// will not authenticate peers until a store is injected.
func New(addr string, id identity.Identity) *Server {
	return NewWithPairedStore(addr, id, nil)
}

// NewWithPairedStore returns a Server that verifies peers against paired.
// A nil store fails closed for authentication attempts.
func NewWithPairedStore(addr string, id identity.Identity, paired *identity.PairedStore) *Server {
	return &Server{addr: addr, id: id, paired: paired}
}

// session wraps a connection with a write lock, so several goroutines
// (ping replies, notifications, file chunks...) can send safely, and
// tracks how far the connection has progressed.
type session struct {
	conn  net.Conn
	mu    sync.Mutex
	state atomic.Uint32 // holds a State; the zero value is StateConnected
}

func (s *session) send(f protocol.Frame) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return protocol.WriteFrame(s.conn, f)
}

// State returns the session's current state.
func (s *session) State() State {
	return State(s.state.Load())
}

// advance moves the session forward by exactly one state. It returns false,
// changing nothing, if the session is not currently in from, or if to is
// not the very next state. States never move backwards or skip ahead.
func (s *session) advance(from, to State) bool {
	if to != from+1 || to > StateAuthenticated {
		return false
	}
	return s.state.CompareAndSwap(uint32(from), uint32(to))
}

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

// dispatch handles one frame that has already passed the state check.
// A returned error means the connection should be closed.
func (s *Server) dispatch(sess *session, remote net.Addr, peer protocol.Hello, r io.Reader, f protocol.Frame) error {
	switch f.Type {
	case protocol.TypePing:
		return sess.send(protocol.Frame{Type: protocol.TypePong, Payload: f.Payload})
	case protocol.TypePong:
		return nil
	case protocol.TypeAuthChallenge:
		return s.authenticate(sess, r, peer, f)
	case protocol.TypeAuthResponse:
		return errors.New("unexpected AUTH_RESPONSE")
	default:
		// Allowed in this state, but not implemented yet.
		log.Printf("[%s] unhandled frame type %#x in state %s", remote, f.Type, sess.State())
		return nil
	}
}

// authenticate completes the mutual challenge exchange after the peer has
// sent its AUTH_CHALLENGE. The server sends its own challenge and signs the
// peer's challenge, then verifies the peer's signature against the stored key.
func (s *Server) authenticate(sess *session, r io.Reader, peer protocol.Hello, incoming protocol.Frame) error {
	if sess.State() != StateGreeted {
		return fmt.Errorf("authentication is invalid in state %s", sess.State())
	}
	if s.paired == nil {
		return errors.New("authentication unavailable: paired store is not configured")
	}
	if peer.DeviceID == s.id.DeviceID {
		return errors.New("authentication rejected: self-connection")
	}
	paired, ok := s.paired.Lookup(peer.DeviceID)
	if !ok || identity.DeviceIDFromPublicKey(paired.PublicKey[:]) != peer.DeviceID {
		return errors.New("authentication rejected: peer is not paired")
	}
	peerChallenge, err := protocol.UnmarshalAuthChallenge(incoming.Payload)
	if err != nil {
		return fmt.Errorf("authentication: bad challenge: %w", err)
	}

	if err := sess.conn.SetDeadline(time.Now().Add(authenticationTimeout)); err != nil {
		return fmt.Errorf("authentication: setting deadline: %w", err)
	}
	defer sess.conn.SetDeadline(time.Time{})

	var challenge protocol.AuthChallenge
	if _, err := rand.Read(challenge.Challenge[:]); err != nil {
		return fmt.Errorf("authentication: generating challenge: %w", err)
	}
	if err := sess.send(protocol.Frame{Type: protocol.TypeAuthChallenge, Payload: challenge.Marshal()}); err != nil {
		return fmt.Errorf("authentication: sending challenge: %w", err)
	}

	message := protocol.AuthMessage(peerChallenge.Challenge, s.id.DeviceID, peer.DeviceID)
	signature := s.id.Sign(message)
	if err := sess.send(protocol.Frame{Type: protocol.TypeAuthResponse, Payload: signature}); err != nil {
		return fmt.Errorf("authentication: sending response: %w", err)
	}

	responseFrame, err := protocol.ReadFrame(r)
	if err != nil {
		return fmt.Errorf("authentication: reading response: %w", err)
	}
	if responseFrame.Type != protocol.TypeAuthResponse {
		return fmt.Errorf("authentication: expected AUTH_RESPONSE, got %#x", byte(responseFrame.Type))
	}
	response, err := protocol.UnmarshalAuthResponse(responseFrame.Payload)
	if err != nil {
		return fmt.Errorf("authentication: bad response: %w", err)
	}
	message = protocol.AuthMessage(challenge.Challenge, peer.DeviceID, s.id.DeviceID)
	if !ed25519.Verify(paired.PublicKey[:], message, response.Signature[:]) {
		return errors.New("authentication rejected: invalid signature")
	}
	if !sess.advance(StateGreeted, StateAuthenticated) {
		return errors.New("authentication: could not enter authenticated state")
	}
	return nil
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
	if !sess.advance(StateConnected, StateGreeted) {
		log.Printf("[%s] internal error: could not enter %s", remote, StateGreeted)
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

		if st := sess.State(); !allowed(st, f.Type) {
			log.Printf("[%s] frame type %#x not allowed in state %s; closing", remote, f.Type, st)
			return
		}

		if err := s.dispatch(sess, remote, peer, r, f); err != nil {
			log.Printf("[%s] write: %v", remote, err)
			return
		}
	}
}
