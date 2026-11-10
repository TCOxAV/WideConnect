package client_test

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/TCOxAV/WideConnect/internal/client"
	"github.com/TCOxAV/WideConnect/internal/identity"
	"github.com/TCOxAV/WideConnect/internal/server"
	"github.com/TCOxAV/WideConnect/protocol"
)

func newTestIdentity(t *testing.T) identity.Identity {
	t.Helper()
	id, err := identity.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatalf("load identity: %v", err)
	}
	return id
}

func newTestStore(t *testing.T) *identity.PairedStore {
	t.Helper()
	store, err := identity.OpenPairedStore(t.TempDir())
	if err != nil {
		t.Fatalf("open paired store: %v", err)
	}
	return store
}

func addTrustedPeer(t *testing.T, store *identity.PairedStore, id identity.Identity, name string) {
	t.Helper()
	if err := store.Add(identity.PairedDevice{
		DeviceID:  id.DeviceID,
		Name:      name,
		PublicKey: id.PublicKey,
	}); err != nil {
		t.Fatalf("add trusted peer: %v", err)
	}
}

func runTestServer(t *testing.T, id identity.Identity, paired *identity.PairedStore) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- server.NewWithPairedStore("", id, paired).Serve(ctx, listener)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("server stopped: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("server did not stop")
		}
	})
	return listener.Addr().String()
}

func TestDialAuthenticatesBothDevices(t *testing.T) {
	clientID, serverID := newTestIdentity(t), newTestIdentity(t)
	clientStore, serverStore := newTestStore(t), newTestStore(t)
	addTrustedPeer(t, clientStore, serverID, "server")
	addTrustedPeer(t, serverStore, clientID, "client")
	addr := runTestServer(t, serverID, serverStore)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := client.Dial(ctx, addr, clientID, clientStore)
	if err != nil {
		t.Fatalf("dial and authenticate: %v", err)
	}
	defer conn.Close()
	if conn.Peer.DeviceID != serverID.DeviceID {
		t.Fatalf("peer id = %x, want %x", conn.Peer.DeviceID, serverID.DeviceID)
	}

	payload := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	if err := conn.Send(protocol.Frame{Type: protocol.TypePing, Payload: payload}); err != nil {
		t.Fatalf("send authenticated ping: %v", err)
	}
	frame, err := conn.Receive()
	if err != nil {
		t.Fatalf("read pong: %v", err)
	}
	if frame.Type != protocol.TypePong || string(frame.Payload) != string(payload) {
		t.Fatalf("pong = %#v, want payload %v", frame, payload)
	}
}

func TestDialRejectsUnpairedServer(t *testing.T) {
	clientID, serverID := newTestIdentity(t), newTestIdentity(t)
	clientStore, serverStore := newTestStore(t), newTestStore(t)
	addTrustedPeer(t, serverStore, clientID, "client")
	addr := runTestServer(t, serverID, serverStore)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := client.Dial(ctx, addr, clientID, clientStore)
	if err == nil {
		conn.Close()
		t.Fatal("Dial succeeded without trusting the server")
	}
}

func TestDialRejectsUnpairedClient(t *testing.T) {
	clientID, serverID := newTestIdentity(t), newTestIdentity(t)
	clientStore, serverStore := newTestStore(t), newTestStore(t)
	addTrustedPeer(t, clientStore, serverID, "server")
	addr := runTestServer(t, serverID, serverStore)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := client.Dial(ctx, addr, clientID, clientStore)
	if err == nil {
		conn.Close()
		t.Fatal("Dial succeeded without the server trusting the client")
	}
}

func TestDialStopsWhenContextCanceledDuringAuthentication(t *testing.T) {
	clientID, serverID := newTestIdentity(t), newTestIdentity(t)
	clientStore := newTestStore(t)
	addTrustedPeer(t, clientStore, serverID, "server")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { listener.Close() })

	challengeReceived := make(chan struct{})
	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()

		if _, err := protocol.ReadFrame(conn); err != nil {
			serverDone <- err
			return
		}
		hello, err := (protocol.Hello{DeviceID: serverID.DeviceID, Name: "test-server"}).Marshal()
		if err != nil {
			serverDone <- err
			return
		}
		if err := protocol.WriteFrame(conn, protocol.Frame{Type: protocol.TypeHello, Payload: hello}); err != nil {
			serverDone <- err
			return
		}
		challenge, err := protocol.ReadFrame(conn)
		if err != nil {
			serverDone <- err
			return
		}
		if challenge.Type != protocol.TypeAuthChallenge {
			serverDone <- errors.New("client did not send AUTH_CHALLENGE")
			return
		}
		close(challengeReceived)
		_, _ = protocol.ReadFrame(conn)
		serverDone <- nil
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dialDone := make(chan error, 1)
	go func() {
		conn, err := client.Dial(ctx, listener.Addr().String(), clientID, clientStore)
		if conn != nil {
			conn.Close()
		}
		dialDone <- err
	}()

	select {
	case <-challengeReceived:
	case <-time.After(2 * time.Second):
		t.Fatal("client did not reach authentication")
	}
	cancel()

	select {
	case err := <-dialDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Dial error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Dial did not stop after context cancellation")
	}
	if err := <-serverDone; err != nil {
		t.Errorf("stalled peer: %v", err)
	}
}
