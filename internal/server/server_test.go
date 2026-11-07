package server

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/TCOxAV/WideConnect/internal/identity"
	"github.com/TCOxAV/WideConnect/protocol"
)

// startServer runs a server on a random local port. The returned stop
// function shuts it down and waits for Serve to return; it is also
// registered with t.Cleanup, and is safe to call more than once.
// startServer runs a server with a fresh throwaway identity on a random
// local port.
func startServer(t *testing.T) (addr string, stop func()) {
	t.Helper()
	id, err := identity.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	return startServerWithID(t, id)
}

// startServerWithID runs a server that identifies itself as id. The returned
// stop function shuts it down and waits for Serve to return; it is also
// registered with t.Cleanup, and is safe to call more than once.
func startServerWithID(t *testing.T, id identity.Identity) (addr string, stop func()) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- New("", id).Serve(ctx, ln) }()

	var once sync.Once
	stop = func() {
		once.Do(func() {
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("Serve returned: %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Error("server did not shut down in time")
			}
		})
	}
	t.Cleanup(stop)
	return ln.Addr().String(), stop
}

// testConnect dials addr with a safety deadline so a bug can't hang the test.
func testConnect(t *testing.T, addr string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	return conn, bufio.NewReader(conn)
}

// clientHandshake sends a HELLO and returns the server's HELLO.
// It returns errors instead of calling t.Fatal so goroutines can use it.
func clientHandshake(conn net.Conn, r *bufio.Reader) (protocol.Hello, error) {
	id, err := protocol.NewDeviceID()
	if err != nil {
		return protocol.Hello{}, err
	}
	payload, err := protocol.Hello{
		DeviceID: id,
		Platform: protocol.PlatformAndroid,
		Caps:     protocol.CapNotify,
		Name:     "test-client",
	}.Marshal()
	if err != nil {
		return protocol.Hello{}, err
	}
	if err := protocol.WriteFrame(conn, protocol.Frame{Type: protocol.TypeHello, Payload: payload}); err != nil {
		return protocol.Hello{}, err
	}

	f, err := protocol.ReadFrame(r)
	if err != nil {
		return protocol.Hello{}, err
	}
	if f.Type != protocol.TypeHello {
		return protocol.Hello{}, fmt.Errorf("got frame type %#x, want HELLO", f.Type)
	}
	return protocol.UnmarshalHello(f.Payload)
}

// clientPing sends a PING and checks the PONG echoes the payload.
func clientPing(conn net.Conn, r *bufio.Reader, payload []byte) error {
	if err := protocol.WriteFrame(conn, protocol.Frame{Type: protocol.TypePing, Payload: payload}); err != nil {
		return err
	}
	f, err := protocol.ReadFrame(r)
	if err != nil {
		return err
	}
	if f.Type != protocol.TypePong {
		return fmt.Errorf("got frame type %#x, want PONG", f.Type)
	}
	if !bytes.Equal(f.Payload, payload) {
		return fmt.Errorf("pong payload %v, want %v", f.Payload, payload)
	}
	return nil
}

// expectClosed fails the test unless the server closes the connection.
// A read timeout does not count: that means the server left it open.
func expectClosed(t *testing.T, r *bufio.Reader) {
	t.Helper()
	f, err := protocol.ReadFrame(r)
	if err == nil {
		t.Fatalf("expected connection to be closed, got frame type %#x", f.Type)
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatal("server left the connection open; expected it to close")
	}
}

func TestHandshakeAndPing(t *testing.T) {
	addr, _ := startServer(t)
	conn, r := testConnect(t, addr)

	srv, err := clientHandshake(conn, r)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if srv.Name == "" {
		t.Error("server HELLO has an empty name")
	}
	if want := protocol.CapNotify | protocol.CapFiles | protocol.CapScreen; !srv.Has(want) {
		t.Errorf("server caps = %#x, want at least %#x", srv.Caps, want)
	}

	for i := 0; i < 3; i++ {
		payload := []byte{byte(i), 1, 2, 3, 4, 5, 6, 7}
		if err := clientPing(conn, r, payload); err != nil {
			t.Fatalf("ping %d: %v", i, err)
		}
	}
}

func TestPingBeforeHelloRejected(t *testing.T) {
	addr, _ := startServer(t)
	conn, r := testConnect(t, addr)

	err := protocol.WriteFrame(conn, protocol.Frame{Type: protocol.TypePing, Payload: make([]byte, 8)})
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	expectClosed(t, r)
}

func TestGarbageRejected(t *testing.T) {
	addr, _ := startServer(t)
	conn, r := testConnect(t, addr)

	if _, err := conn.Write([]byte("this is not a WideConnect frame")); err != nil {
		t.Fatalf("write: %v", err)
	}
	expectClosed(t, r)
}

func TestMalformedHelloRejected(t *testing.T) {
	addr, _ := startServer(t)
	conn, r := testConnect(t, addr)

	// Correct frame type, but the payload is far too short to be a HELLO.
	err := protocol.WriteFrame(conn, protocol.Frame{Type: protocol.TypeHello, Payload: []byte{1, 2, 3}})
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	expectClosed(t, r)
}

func TestShutdownClosesConnections(t *testing.T) {
	addr, stop := startServer(t)
	conn, r := testConnect(t, addr)

	if _, err := clientHandshake(conn, r); err != nil {
		t.Fatalf("handshake: %v", err)
	}

	stop() // cancels the context and waits for Serve to return
	expectClosed(t, r)
}

func TestConcurrentClients(t *testing.T) {
	addr, _ := startServer(t)

	const clients = 8
	errs := make(chan error, clients)
	var wg sync.WaitGroup

	for i := 0; i < clients; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
			if err != nil {
				errs <- fmt.Errorf("client %d dial: %w", id, err)
				return
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			r := bufio.NewReader(conn)

			if _, err := clientHandshake(conn, r); err != nil {
				errs <- fmt.Errorf("client %d handshake: %w", id, err)
				return
			}
			for j := 0; j < 20; j++ {
				payload := []byte{byte(id), byte(j), 0, 0, 0, 0, 0, 0}
				if err := clientPing(conn, r, payload); err != nil {
					errs <- fmt.Errorf("client %d ping %d: %w", id, j, err)
					return
				}
			}
		}(i)
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func TestHelloCarriesServerIdentity(t *testing.T) {
	id, err := identity.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	addr, _ := startServerWithID(t, id)
	conn, r := testConnect(t, addr)

	srv, err := clientHandshake(conn, r)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if srv.DeviceID != id.DeviceID {
		t.Errorf("server advertised id %x, want %s", srv.DeviceID, id)
	}
}

func TestIdentityStableAcrossRestart(t *testing.T) {
	dir := t.TempDir() // plays the role of ~/.config/wideconnect

	// First "run" of the daemon.
	id1, err := identity.LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("identity (run 1): %v", err)
	}
	addr1, stop1 := startServerWithID(t, id1)
	conn1, r1 := testConnect(t, addr1)
	srv1, err := clientHandshake(conn1, r1)
	if err != nil {
		t.Fatalf("handshake (run 1): %v", err)
	}
	stop1()

	// Second "run": reload from the same directory, as a restart would.
	id2, err := identity.LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("identity (run 2): %v", err)
	}
	addr2, _ := startServerWithID(t, id2)
	conn2, r2 := testConnect(t, addr2)
	srv2, err := clientHandshake(conn2, r2)
	if err != nil {
		t.Fatalf("handshake (run 2): %v", err)
	}

	if srv1.DeviceID != srv2.DeviceID {
		t.Errorf("device id changed across restart: %x -> %x", srv1.DeviceID, srv2.DeviceID)
	}
}
