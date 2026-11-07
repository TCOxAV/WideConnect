package protocol

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// Sizes of the values used by pairing and authentication.
// See docs/PAIRING.md.
const (
	PublicKeySize  = 32 // Ed25519 public key
	NonceSize      = 16 // pairing nonce
	CommitmentSize = 32 // SHA-256 output
	ChallengeSize  = 16 // authentication challenge
	SignatureSize  = 64 // Ed25519 signature

	sasLabel  = "WC-PAIR-v1"
	authLabel = "WC-AUTH-v1"
)

// Commitment returns SHA-256(pub || nonce). The initiator sends this before
// seeing the responder's key, so it cannot grind keys to force a chosen code.
func Commitment(pub [PublicKeySize]byte, nonce [NonceSize]byte) [CommitmentSize]byte {
	h := sha256.New()
	h.Write(pub[:])
	h.Write(nonce[:])
	var out [CommitmentSize]byte
	copy(out[:], h.Sum(nil))
	return out
}

// SASCode returns the 6-digit code both users compare during pairing.
// A is the initiator and B the responder; both sides must pass the
// arguments in this same order.
//
//	h    = SHA-256("WC-PAIR-v1" || pubA || pubB || nonceA || nonceB)
//	code = (first 4 bytes of h, big-endian uint32) mod 1,000,000, zero-padded
func SASCode(pubA, pubB [PublicKeySize]byte, nonceA, nonceB [NonceSize]byte) string {
	h := sha256.New()
	h.Write([]byte(sasLabel))
	h.Write(pubA[:])
	h.Write(pubB[:])
	h.Write(nonceA[:])
	h.Write(nonceB[:])
	sum := h.Sum(nil)

	n := binary.BigEndian.Uint32(sum[:4]) % 1_000_000
	return fmt.Sprintf("%06d", n)
}

// AuthMessage returns the bytes a device signs to prove its identity:
//
//	"WC-AUTH-v1" || challenge || signerID || verifierID
//
// challenge is the value the verifier sent. Including both device IDs ties
// the signature to this pair of devices, so it cannot be reused elsewhere.
func AuthMessage(challenge [ChallengeSize]byte, signerID, verifierID [DeviceIDSize]byte) []byte {
	msg := make([]byte, 0, len(authLabel)+ChallengeSize+2*DeviceIDSize)
	msg = append(msg, authLabel...)
	msg = append(msg, challenge[:]...)
	msg = append(msg, signerID[:]...)
	msg = append(msg, verifierID[:]...)
	return msg
}
