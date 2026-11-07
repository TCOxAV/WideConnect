package protocol

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Fixed inputs shared by the known-answer tests. The expected outputs below
// were computed with an independent implementation (Python hashlib), so they
// check the Go code against something other than itself. The Flutter client
// must reproduce exactly these values.

func filled32(b byte) [32]byte {
	var a [32]byte
	for i := range a {
		a[i] = b
	}
	return a
}

func filled16(b byte) [16]byte {
	var a [16]byte
	for i := range a {
		a[i] = b
	}
	return a
}

var (
	kaPubA   = filled32(0x0A)
	kaPubB   = filled32(0x0B)
	kaNonceA = filled16(0xA1)
	kaNonceB = filled16(0xB2)
)

func TestCommitmentKnownAnswer(t *testing.T) {
	const want = "c306e36aa18bb73edfeeb5fba85d62230f157214737425a0bdfc5bec53c31ed9"

	got := Commitment(kaPubA, kaNonceA)
	if hex.EncodeToString(got[:]) != want {
		t.Errorf("Commitment = %x, want %s", got, want)
	}
}

func TestCommitmentDependsOnBothInputs(t *testing.T) {
	base := Commitment(kaPubA, kaNonceA)

	if Commitment(kaPubB, kaNonceA) == base {
		t.Error("changing the public key did not change the commitment")
	}
	if Commitment(kaPubA, kaNonceB) == base {
		t.Error("changing the nonce did not change the commitment")
	}
}

func TestSASCodeKnownAnswer(t *testing.T) {
	if got := SASCode(kaPubA, kaPubB, kaNonceA, kaNonceB); got != "151254" {
		t.Errorf("SASCode = %q, want %q", got, "151254")
	}
}

func TestSASCodeOrderMatters(t *testing.T) {
	// Swapping the roles (B's key first) must give a different, known code.
	// If both sides disagree on who is initiator, the codes will not match
	// and the user will reject the pairing, which is the safe outcome.
	if got := SASCode(kaPubB, kaPubA, kaNonceA, kaNonceB); got != "901406" {
		t.Errorf("swapped SASCode = %q, want %q", got, "901406")
	}
}

func TestSASCodeZeroPadded(t *testing.T) {
	// This nonceB produces a numeric value below 100, which must still be
	// shown as 6 characters.
	nonceB := filled16(0xB2)
	nonceB[14], nonceB[15] = 0x05, 0x87

	got := SASCode(kaPubA, kaPubB, kaNonceA, nonceB)
	if got != "000098" {
		t.Errorf("SASCode = %q, want %q", got, "000098")
	}
}

func TestSASCodeFormat(t *testing.T) {
	for i := 0; i < 200; i++ {
		nonceB := filled16(byte(i))
		code := SASCode(kaPubA, kaPubB, kaNonceA, nonceB)
		if len(code) != 6 {
			t.Fatalf("code %q has length %d, want 6", code, len(code))
		}
		for _, c := range code {
			if c < '0' || c > '9' {
				t.Fatalf("code %q contains non-digit %q", code, c)
			}
		}
	}
}

func TestSASCodeSensitiveToEveryInput(t *testing.T) {
	base := SASCode(kaPubA, kaPubB, kaNonceA, kaNonceB)

	// Flip one bit in each input in turn. A 6-digit code can collide by
	// chance (1 in a million), but not for all four of these fixed inputs.
	pubA, pubB := kaPubA, kaPubB
	nonceA, nonceB := kaNonceA, kaNonceB
	pubA[0] ^= 1
	pubB[0] ^= 1
	nonceA[0] ^= 1
	nonceB[0] ^= 1

	variants := map[string]string{
		"pubA":   SASCode(pubA, kaPubB, kaNonceA, kaNonceB),
		"pubB":   SASCode(kaPubA, pubB, kaNonceA, kaNonceB),
		"nonceA": SASCode(kaPubA, kaPubB, nonceA, kaNonceB),
		"nonceB": SASCode(kaPubA, kaPubB, kaNonceA, nonceB),
	}
	for name, code := range variants {
		if code == base {
			t.Errorf("changing %s did not change the code (%s)", name, code)
		}
	}
}

func TestSASCodeBothSidesAgree(t *testing.T) {
	// Each side calls SASCode with the same arguments in the same order.
	a := SASCode(kaPubA, kaPubB, kaNonceA, kaNonceB)
	b := SASCode(kaPubA, kaPubB, kaNonceA, kaNonceB)
	if a != b {
		t.Errorf("sides computed different codes: %q vs %q", a, b)
	}
}

func TestAuthMessageLayout(t *testing.T) {
	challenge := filled16(0xC3)
	signer := filled16(0x51)
	verifier := filled16(0x7E)

	want := []byte("WC-AUTH-v1")
	want = append(want, bytes.Repeat([]byte{0xC3}, 16)...)
	want = append(want, bytes.Repeat([]byte{0x51}, 16)...)
	want = append(want, bytes.Repeat([]byte{0x7E}, 16)...)

	got := AuthMessage(challenge, signer, verifier)
	if !bytes.Equal(got, want) {
		t.Errorf("AuthMessage = %x, want %x", got, want)
	}
	if len(got) != 10+16+16+16 {
		t.Errorf("len = %d, want 58", len(got))
	}
}

func TestAuthMessageBindsRoles(t *testing.T) {
	challenge := filled16(0xC3)
	x := filled16(0x51)
	y := filled16(0x7E)

	// A signature made as x-for-y must not be valid as y-for-x.
	if bytes.Equal(AuthMessage(challenge, x, y), AuthMessage(challenge, y, x)) {
		t.Error("swapping signer and verifier produced the same message")
	}
	// A different challenge must change the message (replay protection).
	if bytes.Equal(AuthMessage(challenge, x, y), AuthMessage(filled16(0xC4), x, y)) {
		t.Error("changing the challenge did not change the message")
	}
}
