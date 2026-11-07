package server

import "github.com/TCOxAV/WideConnect/protocol"

// State is how far a connection has progressed. See docs/PAIRING.md.
type State uint32

const (
	// StateConnected: TCP is up, no HELLO yet. Only HELLO is valid.
	StateConnected State = iota
	// StateGreeted: HELLO exchanged. Pairing, auth and ping are valid.
	StateGreeted
	// StateAuthenticated: the peer proved it is a paired device.
	// Everything except a second HELLO is valid.
	StateAuthenticated
)

func (s State) String() string {
	switch s {
	case StateConnected:
		return "connected"
	case StateGreeted:
		return "greeted"
	case StateAuthenticated:
		return "authenticated"
	default:
		return "unknown"
	}
}

// allowed reports whether a frame of type t may arrive while in state s.
// Unknown message types are never allowed: a new feature must be added here
// on purpose. A frame that is not allowed closes the connection.
func allowed(s State, t protocol.MsgType) bool {
	switch t {
	case protocol.TypeHello:
		return s == StateConnected

	case protocol.TypePing, protocol.TypePong, protocol.TypeError,
		protocol.TypePairRequest, protocol.TypePairResponse,
		protocol.TypePairReveal, protocol.TypePairDecision,
		protocol.TypeAuthChallenge, protocol.TypeAuthResponse:
		return s == StateGreeted || s == StateAuthenticated

	case protocol.TypeNotify, protocol.TypeFileMeta,
		protocol.TypeFileChunk, protocol.TypeScreen:
		return s == StateAuthenticated

	default:
		return false
	}
}
