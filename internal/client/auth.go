package client

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/TCOxAV/WideConnect/internal/identity"
	"github.com/TCOxAV/WideConnect/protocol"
)

func authenticate(conn *Conn, id identity.Identity, paired *identity.PairedStore) error {
	if conn.Peer.DeviceID == id.DeviceID {
		return errors.New("client: authentication rejected: peer is this device")
	}
	trustedPeer, ok := paired.Lookup(conn.Peer.DeviceID)
	if !ok || identity.DeviceIDFromPublicKey(trustedPeer.PublicKey[:]) != conn.Peer.DeviceID {
		return errors.New("client: authentication rejected: peer is not paired")
	}

	var challenge protocol.AuthChallenge
	if _, err := rand.Read(challenge.Challenge[:]); err != nil {
		return fmt.Errorf("client: generating challenge: %w", err)
	}
	if err := conn.Send(protocol.Frame{Type: protocol.TypeAuthChallenge, Payload: challenge.Marshal()}); err != nil {
		return fmt.Errorf("client: sending challenge: %w", err)
	}

	frame, err := conn.Receive()
	if err != nil {
		return fmt.Errorf("client: reading peer challenge: %w", err)
	}
	if frame.Type != protocol.TypeAuthChallenge {
		return fmt.Errorf("client: expected AUTH_CHALLENGE, got type %#x", byte(frame.Type))
	}
	peerChallenge, err := protocol.UnmarshalAuthChallenge(frame.Payload)
	if err != nil {
		return fmt.Errorf("client: decoding peer challenge: %w", err)
	}

	frame, err = conn.Receive()
	if err != nil {
		return fmt.Errorf("client: reading peer signature: %w", err)
	}
	if frame.Type != protocol.TypeAuthResponse {
		return fmt.Errorf("client: expected AUTH_RESPONSE, got type %#x", byte(frame.Type))
	}
	response, err := protocol.UnmarshalAuthResponse(frame.Payload)
	if err != nil {
		return fmt.Errorf("client: decoding peer signature: %w", err)
	}
	message := protocol.AuthMessage(challenge.Challenge, conn.Peer.DeviceID, id.DeviceID)
	if !ed25519.Verify(trustedPeer.PublicKey[:], message, response.Signature[:]) {
		return errors.New("client: authentication rejected: invalid peer signature")
	}

	message = protocol.AuthMessage(peerChallenge.Challenge, id.DeviceID, conn.Peer.DeviceID)
	signature := id.Sign(message)
	if err := conn.Send(protocol.Frame{Type: protocol.TypeAuthResponse, Payload: signature}); err != nil {
		return fmt.Errorf("client: sending signature: %w", err)
	}

	var confirmation [8]byte
	binary.BigEndian.PutUint64(confirmation[:], uint64(time.Now().UnixNano()))
	if err := conn.Send(protocol.Frame{Type: protocol.TypePing, Payload: confirmation[:]}); err != nil {
		return fmt.Errorf("client: confirming authentication: %w", err)
	}
	frame, err = conn.Receive()
	if err != nil {
		return fmt.Errorf("client: reading authentication confirmation: %w", err)
	}
	if frame.Type != protocol.TypePong || !bytes.Equal(frame.Payload, confirmation[:]) {
		return errors.New("client: peer did not confirm authentication")
	}
	return nil
}
