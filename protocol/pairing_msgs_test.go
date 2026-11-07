package protocol

import (
	"bytes"
	"errors"
	"testing"
)

func TestPairMessageTypeCodes(t *testing.T) {
	want := map[MsgType]byte{
		TypePairRequest:   0x40,
		TypePairResponse:  0x41,
		TypePairReveal:    0x42,
		TypePairDecision:  0x43,
		TypeAuthChallenge: 0x44,
		TypeAuthResponse:  0x45,
	}
	for typ, code := range want {
		if byte(typ) != code {
			t.Errorf("type = %#x, want %#x", byte(typ), code)
		}
	}
}

func TestMessageTypesAreUnique(t *testing.T) {
	all := []MsgType{
		TypeHello, TypePing, TypePong, TypeNotify, TypeFileMeta,
		TypeFileChunk, TypeScreen, TypeError,
		TypePairRequest, TypePairResponse, TypePairReveal,
		TypePairDecision, TypeAuthChallenge, TypeAuthResponse,
	}
	seen := make(map[MsgType]bool)
	for _, typ := range all {
		if seen[typ] {
			t.Errorf("duplicate message type %#x", byte(typ))
		}
		seen[typ] = true
	}
}

func TestPairRequestRoundTrip(t *testing.T) {
	want := PairRequest{Commitment: filled32(0x11)}
	b := want.Marshal()
	if len(b) != CommitmentSize {
		t.Fatalf("len = %d, want %d", len(b), CommitmentSize)
	}
	got, err := UnmarshalPairRequest(b)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestPairResponseRoundTrip(t *testing.T) {
	want := PairResponse{PublicKey: filled32(0x22), Nonce: filled16(0x33)}
	b := want.Marshal()
	if len(b) != 48 {
		t.Fatalf("len = %d, want 48", len(b))
	}
	// Layout check: key first, then nonce.
	if !bytes.Equal(b[:32], bytes.Repeat([]byte{0x22}, 32)) ||
		!bytes.Equal(b[32:], bytes.Repeat([]byte{0x33}, 16)) {
		t.Errorf("unexpected layout: %x", b)
	}
	got, err := UnmarshalPairResponse(b)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestPairRevealRoundTrip(t *testing.T) {
	want := PairReveal{PublicKey: filled32(0x44), Nonce: filled16(0x55)}
	got, err := UnmarshalPairReveal(want.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestAuthChallengeRoundTrip(t *testing.T) {
	want := AuthChallenge{Challenge: filled16(0x66)}
	got, err := UnmarshalAuthChallenge(want.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestAuthResponseRoundTrip(t *testing.T) {
	var want AuthResponse
	for i := range want.Signature {
		want.Signature[i] = byte(i)
	}
	b := want.Marshal()
	if len(b) != SignatureSize {
		t.Fatalf("len = %d, want %d", len(b), SignatureSize)
	}
	got, err := UnmarshalAuthResponse(b)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestPairDecisionRoundTrip(t *testing.T) {
	for _, accept := range []bool{true, false} {
		b := PairDecision{Accept: accept}.Marshal()
		if len(b) != 1 {
			t.Fatalf("len = %d, want 1", len(b))
		}
		got, err := UnmarshalPairDecision(b)
		if err != nil {
			t.Fatal(err)
		}
		if got.Accept != accept {
			t.Errorf("Accept = %v, want %v", got.Accept, accept)
		}
	}
}

func TestPairDecisionRejectsOtherValues(t *testing.T) {
	for _, v := range []byte{2, 3, 0x80, 0xff} {
		if _, err := UnmarshalPairDecision([]byte{v}); !errors.Is(err, ErrBadDecision) {
			t.Errorf("value %#x: err = %v, want ErrBadDecision", v, err)
		}
	}
}

func TestPairMessagesRejectWrongLengths(t *testing.T) {
	cases := []struct {
		name   string
		size   int
		decode func([]byte) error
	}{
		{"PairRequest", CommitmentSize, func(b []byte) error { _, err := UnmarshalPairRequest(b); return err }},
		{"PairResponse", 48, func(b []byte) error { _, err := UnmarshalPairResponse(b); return err }},
		{"PairReveal", 48, func(b []byte) error { _, err := UnmarshalPairReveal(b); return err }},
		{"PairDecision", 1, func(b []byte) error { _, err := UnmarshalPairDecision(b); return err }},
		{"AuthChallenge", ChallengeSize, func(b []byte) error { _, err := UnmarshalAuthChallenge(b); return err }},
		{"AuthResponse", SignatureSize, func(b []byte) error { _, err := UnmarshalAuthResponse(b); return err }},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for _, n := range []int{0, c.size - 1, c.size + 1, c.size * 2} {
				if err := c.decode(make([]byte, n)); !errors.Is(err, ErrBadPayloadLength) {
					t.Errorf("len %d: err = %v, want ErrBadPayloadLength", n, err)
				}
			}
			if err := c.decode(make([]byte, c.size)); err != nil {
				t.Errorf("correct length %d: unexpected error %v", c.size, err)
			}
		})
	}
}

func TestVerifyReveal(t *testing.T) {
	pub, nonce := filled32(0x0A), filled16(0xA1)
	req := PairRequest{Commitment: Commitment(pub, nonce)}

	if !VerifyReveal(req, PairReveal{PublicKey: pub, Nonce: nonce}) {
		t.Error("an honest reveal was rejected")
	}

	badKey := pub
	badKey[0] ^= 1
	if VerifyReveal(req, PairReveal{PublicKey: badKey, Nonce: nonce}) {
		t.Error("a reveal with a different public key was accepted")
	}

	badNonce := nonce
	badNonce[0] ^= 1
	if VerifyReveal(req, PairReveal{PublicKey: pub, Nonce: badNonce}) {
		t.Error("a reveal with a different nonce was accepted")
	}
}

func TestPairMessageThroughFrames(t *testing.T) {
	// Encode a message, send it as a real frame, and decode it on the other side.
	want := PairResponse{PublicKey: filled32(0x77), Nonce: filled16(0x88)}

	var buf bytes.Buffer
	if err := WriteFrame(&buf, Frame{Type: TypePairResponse, Payload: want.Marshal()}); err != nil {
		t.Fatal(err)
	}
	f, err := ReadFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != TypePairResponse {
		t.Fatalf("type = %#x, want %#x", byte(f.Type), byte(TypePairResponse))
	}
	got, err := UnmarshalPairResponse(f.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
}