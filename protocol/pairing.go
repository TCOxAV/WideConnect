package protocol

import (
	"crypto/sha256"
	"encoding/binary"
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
	var input [PublicKeySize + NonceSize]byte
	copy(input[:PublicKeySize], pub[:])
	copy(input[PublicKeySize:], nonce[:])
	return sha256.Sum256(input[:])
}

// SASCode returns the 6-digit code both users compare during pairing.
// A is the initiator and B the responder; both sides must pass the
// arguments in this same order.
//
//	h    = SHA-256("WC-PAIR-v1" || pubA || pubB || nonceA || nonceB)
//	code = (first 4 bytes of h, big-endian uint32) mod 1,000,000, zero-padded
func SASCode(pubA, pubB [PublicKeySize]byte, nonceA, nonceB [NonceSize]byte) string {
	var input [len(sasLabel) + 2*PublicKeySize + 2*NonceSize]byte
	offset := copy(input[:], sasLabel)
	offset += copy(input[offset:], pubA[:])
	offset += copy(input[offset:], pubB[:])
	offset += copy(input[offset:], nonceA[:])
	copy(input[offset:], nonceB[:])
	sum := sha256.Sum256(input[:])

	n := binary.BigEndian.Uint32(sum[:4]) % 1_000_000
	var code [6]byte
	for i := len(code) - 1; i >= 0; i-- {
		code[i] = '0' + byte(n%10)
		n /= 10
	}
	return string(code[:])
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
