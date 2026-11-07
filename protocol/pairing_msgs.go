package protocol

import (
	"crypto/subtle"
	"errors"
)

// Message types used by pairing and authentication. See docs/PAIRING.md.
const (
	TypePairRequest   MsgType = 0x40
	TypePairResponse  MsgType = 0x41
	TypePairReveal    MsgType = 0x42
	TypePairDecision  MsgType = 0x43
	TypeAuthChallenge MsgType = 0x44
	TypeAuthResponse  MsgType = 0x45
)

var (
	ErrBadPayloadLength = errors.New("protocol: payload has wrong length")
	ErrBadDecision      = errors.New("protocol: invalid pair decision value")
)

const keyNonceSize = PublicKeySize + NonceSize

func checkLen(b []byte, want int) error {
	if len(b) != want {
		return ErrBadPayloadLength
	}
	return nil
}

func marshalKeyNonce(pub [PublicKeySize]byte, nonce [NonceSize]byte) []byte {
	out := make([]byte, 0, keyNonceSize)
	out = append(out, pub[:]...)
	out = append(out, nonce[:]...)
	return out
}

func unmarshalKeyNonce(b []byte) (pub [PublicKeySize]byte, nonce [NonceSize]byte, err error) {
	if err = checkLen(b, keyNonceSize); err != nil {
		return pub, nonce, err
	}
	copy(pub[:], b[:PublicKeySize])
	copy(nonce[:], b[PublicKeySize:])
	return pub, nonce, nil
}

// PairRequest (0x40): the initiator's commitment, sent first.
// Layout: commitment (32).
type PairRequest struct {
	Commitment [CommitmentSize]byte
}

func (m PairRequest) Marshal() []byte {
	out := make([]byte, CommitmentSize)
	copy(out, m.Commitment[:])
	return out
}

func UnmarshalPairRequest(b []byte) (PairRequest, error) {
	var m PairRequest
	if err := checkLen(b, CommitmentSize); err != nil {
		return m, err
	}
	copy(m.Commitment[:], b)
	return m, nil
}

// PairResponse (0x41): the responder's public key and nonce.
// Layout: public key (32) || nonce (16).
type PairResponse struct {
	PublicKey [PublicKeySize]byte
	Nonce     [NonceSize]byte
}

func (m PairResponse) Marshal() []byte {
	return marshalKeyNonce(m.PublicKey, m.Nonce)
}

func UnmarshalPairResponse(b []byte) (PairResponse, error) {
	pub, nonce, err := unmarshalKeyNonce(b)
	return PairResponse{PublicKey: pub, Nonce: nonce}, err
}

// PairReveal (0x42): the initiator opens its commitment.
// Layout: public key (32) || nonce (16).
type PairReveal struct {
	PublicKey [PublicKeySize]byte
	Nonce     [NonceSize]byte
}

func (m PairReveal) Marshal() []byte {
	return marshalKeyNonce(m.PublicKey, m.Nonce)
}

func UnmarshalPairReveal(b []byte) (PairReveal, error) {
	pub, nonce, err := unmarshalKeyNonce(b)
	return PairReveal{PublicKey: pub, Nonce: nonce}, err
}

// VerifyReveal reports whether reveal opens the commitment in req.
// The responder MUST abort the pairing if this returns false.
func VerifyReveal(req PairRequest, reveal PairReveal) bool {
	got := Commitment(reveal.PublicKey, reveal.Nonce)
	return subtle.ConstantTimeCompare(got[:], req.Commitment[:]) == 1
}

// PairDecision (0x43): whether this side's user accepted the pairing.
// Layout: 1 byte, 1 = accept, 0 = reject. Any other value is invalid.
type PairDecision struct {
	Accept bool
}

func (m PairDecision) Marshal() []byte {
	if m.Accept {
		return []byte{1}
	}
	return []byte{0}
}

func UnmarshalPairDecision(b []byte) (PairDecision, error) {
	if err := checkLen(b, 1); err != nil {
		return PairDecision{}, err
	}
	switch b[0] {
	case 0:
		return PairDecision{Accept: false}, nil
	case 1:
		return PairDecision{Accept: true}, nil
	default:
		return PairDecision{}, ErrBadDecision
	}
}

// AuthChallenge (0x44): fresh random bytes the peer must sign.
// Layout: challenge (16).
type AuthChallenge struct {
	Challenge [ChallengeSize]byte
}

func (m AuthChallenge) Marshal() []byte {
	out := make([]byte, ChallengeSize)
	copy(out, m.Challenge[:])
	return out
}

func UnmarshalAuthChallenge(b []byte) (AuthChallenge, error) {
	var m AuthChallenge
	if err := checkLen(b, ChallengeSize); err != nil {
		return m, err
	}
	copy(m.Challenge[:], b)
	return m, nil
}

// AuthResponse (0x45): Ed25519 signature over AuthMessage(...).
// Layout: signature (64).
type AuthResponse struct {
	Signature [SignatureSize]byte
}

func (m AuthResponse) Marshal() []byte {
	out := make([]byte, SignatureSize)
	copy(out, m.Signature[:])
	return out
}

func UnmarshalAuthResponse(b []byte) (AuthResponse, error) {
	var m AuthResponse
	if err := checkLen(b, SignatureSize); err != nil {
		return m, err
	}
	copy(m.Signature[:], b)
	return m, nil
}