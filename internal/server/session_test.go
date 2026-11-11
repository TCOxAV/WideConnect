package server

import (
	"testing"

	"github.com/TCOxAV/WideConnect/protocol"
)

func TestAllowedMatrix(t *testing.T) {
	// Columns: Connected, Greeted, Authenticated.
	cases := []struct {
		name string
		typ  protocol.MsgType
		want [3]bool
	}{
		{"HELLO", protocol.TypeHello, [3]bool{true, false, false}},
		{"PING", protocol.TypePing, [3]bool{false, true, true}},
		{"PONG", protocol.TypePong, [3]bool{false, true, true}},
		{"ERROR", protocol.TypeError, [3]bool{false, true, true}},
		{"PAIR_REQUEST", protocol.TypePairRequest, [3]bool{false, true, true}},
		{"PAIR_RESPONSE", protocol.TypePairResponse, [3]bool{false, true, true}},
		{"PAIR_REVEAL", protocol.TypePairReveal, [3]bool{false, true, true}},
		{"PAIR_DECISION", protocol.TypePairDecision, [3]bool{false, true, true}},
		{"AUTH_CHALLENGE", protocol.TypeAuthChallenge, [3]bool{false, true, true}},
		{"AUTH_RESPONSE", protocol.TypeAuthResponse, [3]bool{false, true, true}},
		{"NOTIFY", protocol.TypeNotify, [3]bool{false, false, true}},
		{"FILE_META", protocol.TypeFileMeta, [3]bool{false, false, true}},
		{"FILE_CHUNK", protocol.TypeFileChunk, [3]bool{false, false, true}},
		{"SCREEN", protocol.TypeScreen, [3]bool{false, false, true}},
	}

	for _, c := range cases {
		for s := StateConnected; s <= StateAuthenticated; s++ {
			if got := allowed(s, c.typ); got != c.want[s] {
				t.Errorf("allowed(%s, %s) = %v, want %v", s, c.name, got, c.want[s])
			}
		}
	}
}

func TestAllowedRejectsUnknownTypes(t *testing.T) {
	for _, typ := range []protocol.MsgType{0x00, 0x04, 0x46, 0x99, 0xFE} {
		for s := StateConnected; s <= StateAuthenticated; s++ {
			if allowed(s, typ) {
				t.Errorf("allowed(%s, %#x) = true, want false for an unknown type", s, byte(typ))
			}
		}
	}
}

func TestAdvanceOnlyOneStepForward(t *testing.T) {
	var s session
	if s.State() != StateConnected {
		t.Fatalf("new session state = %s, want connected", s.State())
	}

	// Cannot skip ahead, and cannot advance from the wrong state.
	if s.advance(StateConnected, StateAuthenticated) {
		t.Error("skipping Greeted was allowed")
	}
	if s.advance(StateGreeted, StateAuthenticated) {
		t.Error("advancing from a state we are not in was allowed")
	}
	if s.State() != StateConnected {
		t.Fatalf("failed advances changed the state to %s", s.State())
	}

	if !s.advance(StateConnected, StateGreeted) {
		t.Fatal("Connected -> Greeted was refused")
	}
	if s.advance(StateConnected, StateGreeted) {
		t.Error("advancing twice from Connected was allowed")
	}

	if !s.advance(StateGreeted, StateAuthenticated) {
		t.Fatal("Greeted -> Authenticated was refused")
	}
	if s.State() != StateAuthenticated {
		t.Errorf("state = %s, want authenticated", s.State())
	}

	// No going backwards, and nothing after Authenticated.
	if s.advance(StateAuthenticated, StateGreeted) {
		t.Error("moving backwards was allowed")
	}
	if s.advance(StateAuthenticated, StateAuthenticated+1) {
		t.Error("advancing past Authenticated was allowed")
	}
}

func TestStateString(t *testing.T) {
	want := map[State]string{
		StateConnected:     "connected",
		StateGreeted:       "greeted",
		StateAuthenticated: "authenticated",
		State(42):          "unknown",
	}
	for s, str := range want {
		if s.String() != str {
			t.Errorf("State(%d).String() = %q, want %q", uint32(s), s.String(), str)
		}
	}
}

// The tests below run against a real server.

func TestFeatureFramesRejectedBeforeAuth(t *testing.T) {
	types := map[string]protocol.MsgType{
		"NOTIFY":     protocol.TypeNotify,
		"FILE_META":  protocol.TypeFileMeta,
		"FILE_CHUNK": protocol.TypeFileChunk,
		"SCREEN":     protocol.TypeScreen,
	}

	for name, typ := range types {
		t.Run(name, func(t *testing.T) {
			addr, _ := startServer(t)
			conn, r := testConnect(t, addr)

			if _, err := clientHandshake(conn, r); err != nil {
				t.Fatalf("handshake: %v", err)
			}
			err := protocol.WriteFrame(conn, protocol.Frame{Type: typ, Payload: []byte("x")})
			if err != nil {
				t.Fatalf("write: %v", err)
			}
			expectClosed(t, r)
		})
	}
}

func TestSecondHelloRejected(t *testing.T) {
	addr, _ := startServer(t)
	conn, r := testConnect(t, addr)

	if _, err := clientHandshake(conn, r); err != nil {
		t.Fatalf("handshake: %v", err)
	}

	payload, err := protocol.Hello{Name: "again"}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := protocol.WriteFrame(conn, protocol.Frame{Type: protocol.TypeHello, Payload: payload}); err != nil {
		t.Fatalf("write: %v", err)
	}
	expectClosed(t, r)
}

func TestUnknownTypeRejected(t *testing.T) {
	addr, _ := startServer(t)
	conn, r := testConnect(t, addr)

	if _, err := clientHandshake(conn, r); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if err := protocol.WriteFrame(conn, protocol.Frame{Type: 0x99, Payload: nil}); err != nil {
		t.Fatalf("write: %v", err)
	}
	expectClosed(t, r)
}

// Pairing frames are allowed once greeted. They are not handled yet (that
// arrives with the pairing flow), so for now the server ignores them and the
// connection must stay usable. This test will change when pairing is built.
func TestPairFramesAllowedWhenGreeted(t *testing.T) {
	addr, _ := startServer(t)
	conn, r := testConnect(t, addr)

	if _, err := clientHandshake(conn, r); err != nil {
		t.Fatalf("handshake: %v", err)
	}

	req := protocol.PairRequest{Commitment: [protocol.CommitmentSize]byte{1, 2, 3}}
	if err := protocol.WriteFrame(conn, protocol.Frame{Type: protocol.TypePairRequest, Payload: req.Marshal()}); err != nil {
		t.Fatalf("write: %v", err)
	}

	// The connection is still open and answers pings.
	if err := clientPing(conn, r, []byte{1, 2, 3, 4, 5, 6, 7, 8}); err != nil {
		t.Fatalf("ping after pair frame: %v", err)
	}
}

func TestAuthChallengeFailsClosedWhenPeerIsNotPaired(t *testing.T) {
	addr, _ := startServer(t)
	conn, r := testConnect(t, addr)

	if _, err := clientHandshake(conn, r); err != nil {
		t.Fatalf("handshake: %v", err)
	}

	challenge := protocol.AuthChallenge{Challenge: [protocol.ChallengeSize]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}}
	if err := protocol.WriteFrame(conn, protocol.Frame{Type: protocol.TypeAuthChallenge, Payload: challenge.Marshal()}); err != nil {
		t.Fatalf("write: %v", err)
	}

	expectClosed(t, r)
}

func TestMalformedPingRejected(t *testing.T) {
	addr, _ := startServer(t)
	conn, r := testConnect(t, addr)
	if _, err := clientHandshake(conn, r); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if err := protocol.WriteFrame(conn, protocol.Frame{
		Type:    protocol.TypePing,
		Payload: make([]byte, 9),
	}); err != nil {
		t.Fatalf("write malformed ping: %v", err)
	}
	expectClosed(t, r)
}
