// Package pairing runs the device pairing handshake described in
// docs/PAIRING.md: commitment, reveal, a 6-digit code both users compare,
// and a decision from each side. A device is saved to the paired store only
// when BOTH sides accept.
//
// Pairing proves nothing about who holds the private keys; the first
// authentication after pairing does that, by signing a challenge.
package pairing

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/TCOxAV/WideConnect/internal/identity"
	"github.com/TCOxAV/WideConnect/protocol"
)

const (
	// DefaultStepTimeout is how long to wait for each protocol message.
	DefaultStepTimeout = 10 * time.Second
	// DefaultDecisionTimeout is how long a human has to compare the code
	// and accept or reject. No answer counts as a rejection.
	DefaultDecisionTimeout = 60 * time.Second
)

var (
	ErrRejectedLocally    = errors.New("pairing: rejected by this device")
	ErrRejectedByPeer     = errors.New("pairing: rejected by the other device")
	ErrDecisionTimeout    = errors.New("pairing: no decision before the timeout")
	ErrCommitmentMismatch = errors.New("pairing: reveal does not match the commitment")
	ErrIdentityMismatch   = errors.New("pairing: public key does not match the peer's device id")
	ErrSelfPairing        = errors.New("pairing: peer is using our own public key")
	ErrUnexpectedFrame    = errors.New("pairing: unexpected frame")
	ErrBadParams          = errors.New("pairing: invalid parameters")
)

// Transport is the connection the pairing messages travel over.
// Send must not block indefinitely: pairing messages are tiny, so a normal
// TCP connection satisfies this.
type Transport interface {
	Send(protocol.Frame) error
	Recv() (protocol.Frame, error)
	SetReadDeadline(time.Time) error
}

type connTransport struct {
	conn net.Conn
	r    io.Reader
	mu   sync.Mutex // serializes writes
}

// NewConnTransport wraps a net.Conn. Frames are read from r, which lets the
// caller pass the bufio.Reader it already uses for this connection; if r is
// nil, frames are read directly from conn.
func NewConnTransport(conn net.Conn, r io.Reader) Transport {
	if r == nil {
		r = conn
	}
	return &connTransport{conn: conn, r: r}
}

func (c *connTransport) Send(f protocol.Frame) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return protocol.WriteFrame(c.conn, f)
}

func (c *connTransport) Recv() (protocol.Frame, error) {
	return protocol.ReadFrame(c.r)
}

func (c *connTransport) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

// Store receives a device once both sides have accepted it.
// *identity.PairedStore satisfies it.
type Store interface {
	Add(identity.PairedDevice) error
}

// Params configures one pairing attempt.
type Params struct {
	// Identity is this device's identity.
	Identity identity.Identity
	// Peer is the HELLO the other device sent. Its DeviceID must equal
	// SHA-256 of the public key the peer presents during pairing.
	Peer protocol.Hello
	// Store is where the peer is saved on success. Required.
	Store Store
	// Confirm shows the 6-digit code to the user and returns their decision.
	// It should return promptly when ctx is done. Required.
	Confirm func(ctx context.Context, code string) bool
	// StepTimeout and DecisionTimeout default to the package defaults.
	StepTimeout     time.Duration
	DecisionTimeout time.Duration
}

// Result describes a completed pairing.
type Result struct {
	Device identity.PairedDevice
	Code   string
}

func (p *Params) normalize() error {
	if p.Confirm == nil {
		return fmt.Errorf("%w: Confirm is required", ErrBadParams)
	}
	if p.Store == nil {
		return fmt.Errorf("%w: Store is required", ErrBadParams)
	}
	if p.StepTimeout <= 0 {
		p.StepTimeout = DefaultStepTimeout
	}
	if p.DecisionTimeout <= 0 {
		p.DecisionTimeout = DefaultDecisionTimeout
	}
	return nil
}

// checkPeerKey rejects a peer that presents our own key, or a key that
// does not belong to the device ID it claimed in its HELLO.
func (p Params) checkPeerKey(pub [protocol.PublicKeySize]byte) error {
	if pub == p.Identity.PublicKey {
		return ErrSelfPairing
	}
	if identity.DeviceIDFromPublicKey(pub[:]) != p.Peer.DeviceID {
		return ErrIdentityMismatch
	}
	return nil
}

// ask shows the code to the user, waiting at most DecisionTimeout.
// If the user does not answer in time it returns ErrDecisionTimeout, even
// when Confirm ignores its context or answers late.
func (p Params) ask(ctx context.Context, code string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, p.DecisionTimeout)
	defer cancel()

	res := make(chan bool, 1)
	go func() { res <- p.Confirm(ctx, code) }()

	select {
	case ok := <-res:
		if err := ctx.Err(); err != nil {
			return false, ctxErr(err) // an answer that came too late does not count
		}
		return ok, nil
	case <-ctx.Done():
		return false, ctxErr(ctx.Err())
	}
}

func ctxErr(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return ErrDecisionTimeout
	}
	return err
}

// finish saves the peer. It is only called after both sides accepted.
func (p Params) finish(pub [protocol.PublicKeySize]byte, code string) (Result, error) {
	dev := identity.PairedDevice{
		DeviceID:  p.Peer.DeviceID,
		Name:      p.Peer.Name,
		PublicKey: pub,
		PairedAt:  time.Now(),
	}
	if err := p.Store.Add(dev); err != nil {
		return Result{Code: code}, fmt.Errorf("pairing: saving device: %w", err)
	}
	return Result{Device: dev, Code: code}, nil
}

func newNonce() ([protocol.NonceSize]byte, error) {
	var n [protocol.NonceSize]byte
	if _, err := rand.Read(n[:]); err != nil {
		return n, fmt.Errorf("pairing: generating nonce: %w", err)
	}
	return n, nil
}

func send(t Transport, typ protocol.MsgType, payload []byte) error {
	return t.Send(protocol.Frame{Type: typ, Payload: payload})
}

// recvType waits up to d for one frame, which must have type want.
func recvType(t Transport, want protocol.MsgType, d time.Duration) (protocol.Frame, error) {
	if err := t.SetReadDeadline(time.Now().Add(d)); err != nil {
		return protocol.Frame{}, err
	}
	defer t.SetReadDeadline(time.Time{})

	f, err := t.Recv()
	if err != nil {
		return protocol.Frame{}, err
	}
	if f.Type != want {
		return protocol.Frame{}, fmt.Errorf("%w: got type %#x, want %#x", ErrUnexpectedFrame, byte(f.Type), byte(want))
	}
	return f, nil
}

func recvDecision(t Transport, d time.Duration) (protocol.PairDecision, error) {
	f, err := recvType(t, protocol.TypePairDecision, d)
	if err != nil {
		return protocol.PairDecision{}, err
	}
	return protocol.UnmarshalPairDecision(f.Payload)
}

// Initiate runs the pairing handshake as the initiator (side A).
// On any error the caller should close the connection.
func Initiate(ctx context.Context, t Transport, p Params) (Result, error) {
	if err := p.normalize(); err != nil {
		return Result{}, err
	}
	pubA := p.Identity.PublicKey

	nonceA, err := newNonce()
	if err != nil {
		return Result{}, err
	}

	// 1. Commit to our key and nonce before seeing the peer's.
	req := protocol.PairRequest{Commitment: protocol.Commitment(pubA, nonceA)}
	if err := send(t, protocol.TypePairRequest, req.Marshal()); err != nil {
		return Result{}, fmt.Errorf("pairing: sending request: %w", err)
	}

	// 2. Receive the responder's key and nonce.
	f, err := recvType(t, protocol.TypePairResponse, p.StepTimeout)
	if err != nil {
		return Result{}, fmt.Errorf("pairing: waiting for response: %w", err)
	}
	resp, err := protocol.UnmarshalPairResponse(f.Payload)
	if err != nil {
		return Result{}, fmt.Errorf("pairing: bad response: %w", err)
	}
	if err := p.checkPeerKey(resp.PublicKey); err != nil {
		return Result{}, err
	}

	// 3. Open our commitment.
	reveal := protocol.PairReveal{PublicKey: pubA, Nonce: nonceA}
	if err := send(t, protocol.TypePairReveal, reveal.Marshal()); err != nil {
		return Result{}, fmt.Errorf("pairing: sending reveal: %w", err)
	}

	// 4. Both users compare the code. The initiator decides and sends first.
	code := protocol.SASCode(pubA, resp.PublicKey, nonceA, resp.Nonce)
	accept, askErr := p.ask(ctx, code)
	if err := send(t, protocol.TypePairDecision, protocol.PairDecision{Accept: accept}.Marshal()); err != nil {
		return Result{Code: code}, fmt.Errorf("pairing: sending decision: %w", err)
	}
	if askErr != nil {
		return Result{Code: code}, askErr
	}
	if !accept {
		return Result{Code: code}, ErrRejectedLocally
	}

	// 5. We accepted, so the responder answers. Its user may take a while.
	peer, err := recvDecision(t, p.DecisionTimeout+p.StepTimeout)
	if err != nil {
		return Result{Code: code}, fmt.Errorf("pairing: waiting for decision: %w", err)
	}
	if !peer.Accept {
		return Result{Code: code}, ErrRejectedByPeer
	}
	return p.finish(resp.PublicKey, code)
}

// Respond runs the pairing handshake as the responder (side B). req is the
// PAIR_REQUEST the caller already read from the connection.
// On any error the caller should close the connection.
func Respond(ctx context.Context, t Transport, p Params, req protocol.PairRequest) (Result, error) {
	if err := p.normalize(); err != nil {
		return Result{}, err
	}
	pubB := p.Identity.PublicKey

	nonceB, err := newNonce()
	if err != nil {
		return Result{}, err
	}

	// 2. Answer with our key and nonce.
	resp := protocol.PairResponse{PublicKey: pubB, Nonce: nonceB}
	if err := send(t, protocol.TypePairResponse, resp.Marshal()); err != nil {
		return Result{}, fmt.Errorf("pairing: sending response: %w", err)
	}

	// 3. The initiator opens its commitment; it must match.
	f, err := recvType(t, protocol.TypePairReveal, p.StepTimeout)
	if err != nil {
		return Result{}, fmt.Errorf("pairing: waiting for reveal: %w", err)
	}
	reveal, err := protocol.UnmarshalPairReveal(f.Payload)
	if err != nil {
		return Result{}, fmt.Errorf("pairing: bad reveal: %w", err)
	}
	if !protocol.VerifyReveal(req, reveal) {
		return Result{}, ErrCommitmentMismatch
	}
	if err := p.checkPeerKey(reveal.PublicKey); err != nil {
		return Result{}, err
	}

	// 4. Show the code, then read the initiator's decision.
	code := protocol.SASCode(reveal.PublicKey, pubB, reveal.Nonce, nonceB)
	accept, askErr := p.ask(ctx, code)

	peer, err := recvDecision(t, p.DecisionTimeout+p.StepTimeout)
	if err != nil {
		return Result{Code: code}, fmt.Errorf("pairing: waiting for decision: %w", err)
	}
	if !peer.Accept {
		// The initiator rejected, so the pairing is over and no answer is sent.
		switch {
		case askErr != nil:
			return Result{Code: code}, askErr
		case !accept:
			return Result{Code: code}, ErrRejectedLocally
		default:
			return Result{Code: code}, ErrRejectedByPeer
		}
	}

	// 5. The initiator accepted, so it is waiting for our answer.
	if err := send(t, protocol.TypePairDecision, protocol.PairDecision{Accept: accept}.Marshal()); err != nil {
		return Result{Code: code}, fmt.Errorf("pairing: sending decision: %w", err)
	}
	if askErr != nil {
		return Result{Code: code}, askErr
	}
	if !accept {
		return Result{Code: code}, ErrRejectedLocally
	}
	return p.finish(reveal.PublicKey, code)
}
