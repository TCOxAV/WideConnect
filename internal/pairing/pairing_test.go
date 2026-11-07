package pairing

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"github.com/TCOxAV/WideConnect/internal/identity"
	"github.com/TCOxAV/WideConnect/protocol"
)

const testTimeout = 2 * time.Second

// device is a simulated peer with its own identity and paired store.
type device struct {
	id    identity.Identity
	store *identity.PairedStore
	hello protocol.Hello
}

func newDevice(t *testing.T, name string) device {
	t.Helper()
	id, err := identity.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	st, err := identity.OpenPairedStore(t.TempDir())
	if err != nil {
		t.Fatalf("paired store: %v", err)
	}
	return device{
		id:    id,
		store: st,
		hello: protocol.Hello{DeviceID: id.DeviceID, Platform: protocol.PlatformLinux, Name: name},
	}
}

type confirmFn func(ctx context.Context, code string) bool

func decide(accept bool) confirmFn {
	return func(context.Context, string) bool { return accept }
}

func mustNotConfirm(t *testing.T) confirmFn {
	return func(context.Context, string) bool {
		t.Error("Confirm was called, but the handshake should have failed first")
		return false
	}
}

// paramsFor builds the Params that self uses when pairing with peer.
func paramsFor(self, peer device, confirm confirmFn) Params {
	return Params{
		Identity:        self.id,
		Peer:            peer.hello,
		Store:           self.store,
		Confirm:         confirm,
		StepTimeout:     testTimeout,
		DecisionTimeout: testTimeout,
	}
}

func recordCode(c confirmFn, ch chan string) confirmFn {
	return func(ctx context.Context, code string) bool {
		select {
		case ch <- code:
		default:
		}
		return c(ctx, code)
	}
}

func drain(ch chan string) string {
	select {
	case s := <-ch:
		return s
	default:
		return ""
	}
}

func newPipe(t *testing.T) (Transport, Transport) {
	t.Helper()
	ca, cb := net.Pipe()
	t.Cleanup(func() { ca.Close(); cb.Close() })
	return NewConnTransport(ca, nil), NewConnTransport(cb, nil)
}

func sendFrame(tr Transport, typ protocol.MsgType, payload []byte) {
	_ = tr.Send(protocol.Frame{Type: typ, Payload: payload})
}

type outcome struct {
	res  Result
	err  error
	code string // the code this side showed its user
}

// runPairing runs a full pairing between a (initiator) and b (responder)
// over an in-memory pipe. tweak, if not nil, can adjust either side's Params.
func runPairing(t *testing.T, a, b device, confA, confB confirmFn, tweak func(pa, pb *Params)) (outA, outB outcome) {
	t.Helper()
	ca, cb := net.Pipe()
	t.Cleanup(func() { ca.Close(); cb.Close() })
	ta, tb := NewConnTransport(ca, nil), NewConnTransport(cb, nil)

	codeA, codeB := make(chan string, 1), make(chan string, 1)
	pa := paramsFor(a, b, recordCode(confA, codeA))
	pb := paramsFor(b, a, recordCode(confB, codeB))
	if tweak != nil {
		tweak(&pa, &pb)
	}

	doneB := make(chan outcome, 1)
	go func() {
		var out outcome
		defer func() { cb.Close(); doneB <- out }()

		// Play the part of the server: read the first frame, then hand over.
		f, err := tb.Recv()
		if err != nil {
			out.err = err
			return
		}
		req, err := protocol.UnmarshalPairRequest(f.Payload)
		if err != nil {
			out.err = err
			return
		}
		out.res, out.err = Respond(context.Background(), tb, pb, req)
	}()

	res, err := Initiate(context.Background(), ta, pa)
	ca.Close() // unblocks the other side if we stopped early
	outA = outcome{res: res, err: err}
	outB = <-doneB

	outA.code, outB.code = drain(codeA), drain(codeB)
	return outA, outB
}

func assertNothingPaired(t *testing.T, devs ...device) {
	t.Helper()
	for i, d := range devs {
		if n := len(d.store.List()); n != 0 {
			t.Errorf("device %d store has %d entries, want 0", i, n)
		}
	}
}

func TestBothAccept(t *testing.T) {
	a, b := newDevice(t, "laptop"), newDevice(t, "phone")
	outA, outB := runPairing(t, a, b, decide(true), decide(true), nil)

	if outA.err != nil || outB.err != nil {
		t.Fatalf("errors: initiator=%v responder=%v", outA.err, outB.err)
	}
	if len(outA.code) != 6 || outA.code != outB.code {
		t.Errorf("codes shown to users: %q and %q, want the same 6 digits", outA.code, outB.code)
	}

	// Each side now trusts the other, with the right key and name.
	if !a.store.IsPaired(b.id.DeviceID, b.id.PublicKey) {
		t.Error("initiator did not store the responder")
	}
	if !b.store.IsPaired(a.id.DeviceID, a.id.PublicKey) {
		t.Error("responder did not store the initiator")
	}
	if got, _ := a.store.Lookup(b.id.DeviceID); got.Name != "phone" {
		t.Errorf("stored name = %q, want %q", got.Name, "phone")
	}
	if got, _ := b.store.Lookup(a.id.DeviceID); got.Name != "laptop" {
		t.Errorf("stored name = %q, want %q", got.Name, "laptop")
	}

	// The returned results describe the other device.
	if outA.res.Device.DeviceID != b.id.DeviceID || outA.res.Device.PublicKey != b.id.PublicKey {
		t.Error("initiator result does not describe the responder")
	}
	if outB.res.Device.DeviceID != a.id.DeviceID || outB.res.Code != outB.code {
		t.Error("responder result is wrong")
	}
}

func TestInitiatorRejects(t *testing.T) {
	a, b := newDevice(t, "laptop"), newDevice(t, "phone")
	outA, outB := runPairing(t, a, b, decide(false), decide(true), nil)

	if !errors.Is(outA.err, ErrRejectedLocally) {
		t.Errorf("initiator err = %v, want ErrRejectedLocally", outA.err)
	}
	if !errors.Is(outB.err, ErrRejectedByPeer) {
		t.Errorf("responder err = %v, want ErrRejectedByPeer", outB.err)
	}
	assertNothingPaired(t, a, b)
}

func TestResponderRejects(t *testing.T) {
	a, b := newDevice(t, "laptop"), newDevice(t, "phone")
	outA, outB := runPairing(t, a, b, decide(true), decide(false), nil)

	if !errors.Is(outA.err, ErrRejectedByPeer) {
		t.Errorf("initiator err = %v, want ErrRejectedByPeer", outA.err)
	}
	if !errors.Is(outB.err, ErrRejectedLocally) {
		t.Errorf("responder err = %v, want ErrRejectedLocally", outB.err)
	}
	assertNothingPaired(t, a, b)
}

func TestBothReject(t *testing.T) {
	a, b := newDevice(t, "laptop"), newDevice(t, "phone")
	outA, outB := runPairing(t, a, b, decide(false), decide(false), nil)

	if !errors.Is(outA.err, ErrRejectedLocally) || !errors.Is(outB.err, ErrRejectedLocally) {
		t.Errorf("errors: initiator=%v responder=%v, want ErrRejectedLocally for both", outA.err, outB.err)
	}
	assertNothingPaired(t, a, b)
}

func TestDecisionTimeoutCountsAsRejection(t *testing.T) {
	a, b := newDevice(t, "laptop"), newDevice(t, "phone")

	// A's user answers "yes", but only after the deadline has passed.
	late := func(ctx context.Context, _ string) bool {
		<-ctx.Done()
		return true
	}
	short := func(pa, pb *Params) {
		pa.DecisionTimeout = 50 * time.Millisecond
		pb.DecisionTimeout = 50 * time.Millisecond
	}

	outA, outB := runPairing(t, a, b, late, decide(true), short)

	if !errors.Is(outA.err, ErrDecisionTimeout) {
		t.Errorf("initiator err = %v, want ErrDecisionTimeout", outA.err)
	}
	if !errors.Is(outB.err, ErrRejectedByPeer) {
		t.Errorf("responder err = %v, want ErrRejectedByPeer", outB.err)
	}
	assertNothingPaired(t, a, b)
}

func TestConfirmThatIgnoresContext(t *testing.T) {
	a, b := newDevice(t, "laptop"), newDevice(t, "phone")

	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	stuck := func(context.Context, string) bool {
		<-release // never looks at ctx
		return true
	}
	short := func(pa, pb *Params) { pa.DecisionTimeout = 50 * time.Millisecond }

	outA, _ := runPairing(t, a, b, stuck, decide(true), short)

	if !errors.Is(outA.err, ErrDecisionTimeout) {
		t.Errorf("initiator err = %v, want ErrDecisionTimeout", outA.err)
	}
	assertNothingPaired(t, a, b)
}

type failingStore struct{ err error }

func (f failingStore) Add(identity.PairedDevice) error { return f.err }

func TestStoreFailureIsReported(t *testing.T) {
	a, b := newDevice(t, "laptop"), newDevice(t, "phone")
	errDisk := errors.New("disk full")

	outA, outB := runPairing(t, a, b, decide(true), decide(true), func(pa, pb *Params) {
		pa.Store = failingStore{errDisk}
	})

	if !errors.Is(outA.err, errDisk) {
		t.Errorf("initiator err = %v, want it to wrap the store error", outA.err)
	}
	if outB.err != nil {
		t.Errorf("responder err = %v, want nil", outB.err)
	}
}

func TestBadParams(t *testing.T) {
	a, b := newDevice(t, "laptop"), newDevice(t, "phone")
	good := paramsFor(a, b, decide(true))

	noConfirm := good
	noConfirm.Confirm = nil
	noStore := good
	noStore.Store = nil

	for name, p := range map[string]Params{"no Confirm": noConfirm, "no Store": noStore} {
		t.Run(name, func(t *testing.T) {
			ta, _ := newPipe(t) // nothing reads from it: validation must fail before any I/O
			if _, err := Initiate(context.Background(), ta, p); !errors.Is(err, ErrBadParams) {
				t.Errorf("Initiate err = %v, want ErrBadParams", err)
			}
			if _, err := Respond(context.Background(), ta, p, protocol.PairRequest{}); !errors.Is(err, ErrBadParams) {
				t.Errorf("Respond err = %v, want ErrBadParams", err)
			}
		})
	}
}

// --- Initiator against a misbehaving responder ---

func TestInitiatorRejectsSelfPairing(t *testing.T) {
	a, b := newDevice(t, "laptop"), newDevice(t, "phone")
	ta, tb := newPipe(t)

	go func() {
		if _, err := tb.Recv(); err != nil {
			return
		}
		// Reply with the initiator's own key.
		sendFrame(tb, protocol.TypePairResponse,
			protocol.PairResponse{PublicKey: a.id.PublicKey, Nonce: [protocol.NonceSize]byte{1}}.Marshal())
	}()

	_, err := Initiate(context.Background(), ta, paramsFor(a, b, mustNotConfirm(t)))
	if !errors.Is(err, ErrSelfPairing) {
		t.Errorf("err = %v, want ErrSelfPairing", err)
	}
}

func TestInitiatorRejectsKeyThatDoesNotMatchHello(t *testing.T) {
	a, b, c := newDevice(t, "laptop"), newDevice(t, "phone"), newDevice(t, "intruder")
	ta, tb := newPipe(t)

	go func() {
		if _, err := tb.Recv(); err != nil {
			return
		}
		// The peer said it is b in its HELLO, but presents c's key.
		sendFrame(tb, protocol.TypePairResponse,
			protocol.PairResponse{PublicKey: c.id.PublicKey, Nonce: [protocol.NonceSize]byte{1}}.Marshal())
	}()

	_, err := Initiate(context.Background(), ta, paramsFor(a, b, mustNotConfirm(t)))
	if !errors.Is(err, ErrIdentityMismatch) {
		t.Errorf("err = %v, want ErrIdentityMismatch", err)
	}
}

func TestInitiatorRejectsWrongFrameType(t *testing.T) {
	a, b := newDevice(t, "laptop"), newDevice(t, "phone")
	ta, tb := newPipe(t)

	go func() {
		if _, err := tb.Recv(); err != nil {
			return
		}
		sendFrame(tb, protocol.TypePong, nil)
	}()

	_, err := Initiate(context.Background(), ta, paramsFor(a, b, mustNotConfirm(t)))
	if !errors.Is(err, ErrUnexpectedFrame) {
		t.Errorf("err = %v, want ErrUnexpectedFrame", err)
	}
}

func TestInitiatorRejectsMalformedResponse(t *testing.T) {
	a, b := newDevice(t, "laptop"), newDevice(t, "phone")
	ta, tb := newPipe(t)

	go func() {
		if _, err := tb.Recv(); err != nil {
			return
		}
		sendFrame(tb, protocol.TypePairResponse, []byte{1, 2, 3, 4, 5})
	}()

	_, err := Initiate(context.Background(), ta, paramsFor(a, b, mustNotConfirm(t)))
	if !errors.Is(err, protocol.ErrBadPayloadLength) {
		t.Errorf("err = %v, want ErrBadPayloadLength", err)
	}
}

func TestInitiatorTimesOutWaitingForResponse(t *testing.T) {
	a, b := newDevice(t, "laptop"), newDevice(t, "phone")
	ta, tb := newPipe(t)

	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	go func() {
		if _, err := tb.Recv(); err != nil {
			return
		}
		<-stop // read the request, then say nothing
	}()

	p := paramsFor(a, b, mustNotConfirm(t))
	p.StepTimeout = 50 * time.Millisecond
	_, err := Initiate(context.Background(), ta, p)
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("err = %v, want a deadline error", err)
	}
}

func TestInitiatorRejectsBadDecisionByte(t *testing.T) {
	a, b := newDevice(t, "laptop"), newDevice(t, "phone")
	ta, tb := newPipe(t)

	go func() {
		if _, err := tb.Recv(); err != nil { // request
			return
		}
		sendFrame(tb, protocol.TypePairResponse,
			protocol.PairResponse{PublicKey: b.id.PublicKey, Nonce: [protocol.NonceSize]byte{2}}.Marshal())
		if _, err := tb.Recv(); err != nil { // reveal
			return
		}
		if _, err := tb.Recv(); err != nil { // initiator's decision
			return
		}
		sendFrame(tb, protocol.TypePairDecision, []byte{7})
	}()

	_, err := Initiate(context.Background(), ta, paramsFor(a, b, decide(true)))
	if !errors.Is(err, protocol.ErrBadDecision) {
		t.Errorf("err = %v, want ErrBadDecision", err)
	}
	assertNothingPaired(t, a, b)
}

// --- Responder against a misbehaving initiator ---
//
// Here the test plays the initiator by hand. As the real server would, it
// passes the already-read PAIR_REQUEST straight to Respond.

func TestResponderRejectsCommitmentMismatch(t *testing.T) {
	a, b := newDevice(t, "laptop"), newDevice(t, "phone")
	ta, tb := newPipe(t)

	pub, nonce := a.id.PublicKey, [protocol.NonceSize]byte{9}
	req := protocol.PairRequest{Commitment: protocol.Commitment(pub, nonce)}

	go func() {
		if _, err := ta.Recv(); err != nil { // the response
			return
		}
		cheat := nonce
		cheat[0] ^= 1 // reveal a different nonce than the one committed to
		sendFrame(ta, protocol.TypePairReveal, protocol.PairReveal{PublicKey: pub, Nonce: cheat}.Marshal())
	}()

	_, err := Respond(context.Background(), tb, paramsFor(b, a, mustNotConfirm(t)), req)
	if !errors.Is(err, ErrCommitmentMismatch) {
		t.Errorf("err = %v, want ErrCommitmentMismatch", err)
	}
	assertNothingPaired(t, a, b)
}

func TestResponderRejectsKeyThatDoesNotMatchHello(t *testing.T) {
	a, b, c := newDevice(t, "laptop"), newDevice(t, "phone"), newDevice(t, "intruder")
	ta, tb := newPipe(t)

	// An honest reveal, but with c's key while the HELLO said the peer is a.
	pub, nonce := c.id.PublicKey, [protocol.NonceSize]byte{9}
	req := protocol.PairRequest{Commitment: protocol.Commitment(pub, nonce)}

	go func() {
		if _, err := ta.Recv(); err != nil {
			return
		}
		sendFrame(ta, protocol.TypePairReveal, protocol.PairReveal{PublicKey: pub, Nonce: nonce}.Marshal())
	}()

	_, err := Respond(context.Background(), tb, paramsFor(b, a, mustNotConfirm(t)), req)
	if !errors.Is(err, ErrIdentityMismatch) {
		t.Errorf("err = %v, want ErrIdentityMismatch", err)
	}
}

func TestResponderRejectsSelfPairing(t *testing.T) {
	a, b := newDevice(t, "laptop"), newDevice(t, "phone")
	ta, tb := newPipe(t)

	pub, nonce := b.id.PublicKey, [protocol.NonceSize]byte{9} // the responder's own key
	req := protocol.PairRequest{Commitment: protocol.Commitment(pub, nonce)}

	go func() {
		if _, err := ta.Recv(); err != nil {
			return
		}
		sendFrame(ta, protocol.TypePairReveal, protocol.PairReveal{PublicKey: pub, Nonce: nonce}.Marshal())
	}()

	_, err := Respond(context.Background(), tb, paramsFor(b, a, mustNotConfirm(t)), req)
	if !errors.Is(err, ErrSelfPairing) {
		t.Errorf("err = %v, want ErrSelfPairing", err)
	}
}

func TestResponderRejectsWrongFrameType(t *testing.T) {
	a, b := newDevice(t, "laptop"), newDevice(t, "phone")
	ta, tb := newPipe(t)

	req := protocol.PairRequest{Commitment: protocol.Commitment(a.id.PublicKey, [protocol.NonceSize]byte{9})}

	go func() {
		if _, err := ta.Recv(); err != nil {
			return
		}
		sendFrame(ta, protocol.TypePing, make([]byte, 8)) // not a reveal
	}()

	_, err := Respond(context.Background(), tb, paramsFor(b, a, mustNotConfirm(t)), req)
	if !errors.Is(err, ErrUnexpectedFrame) {
		t.Errorf("err = %v, want ErrUnexpectedFrame", err)
	}
}

func TestResponderRejectsBadDecisionByte(t *testing.T) {
	a, b := newDevice(t, "laptop"), newDevice(t, "phone")
	ta, tb := newPipe(t)

	pub, nonce := a.id.PublicKey, [protocol.NonceSize]byte{9}
	req := protocol.PairRequest{Commitment: protocol.Commitment(pub, nonce)}

	go func() {
		if _, err := ta.Recv(); err != nil {
			return
		}
		sendFrame(ta, protocol.TypePairReveal, protocol.PairReveal{PublicKey: pub, Nonce: nonce}.Marshal())
		sendFrame(ta, protocol.TypePairDecision, []byte{2})
	}()

	_, err := Respond(context.Background(), tb, paramsFor(b, a, decide(true)), req)
	if !errors.Is(err, protocol.ErrBadDecision) {
		t.Errorf("err = %v, want ErrBadDecision", err)
	}
	assertNothingPaired(t, a, b)
}

func TestConnTransport(t *testing.T) {
	ta, tb := newPipe(t)

	want := protocol.Frame{Type: protocol.TypePing, Payload: []byte{1, 2, 3}}
	go func() { _ = ta.Send(want) }()

	got, err := tb.Recv()
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if got.Type != want.Type || string(got.Payload) != string(want.Payload) {
		t.Errorf("got %+v, want %+v", got, want)
	}

	if err := tb.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := tb.Recv(); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("Recv after deadline: err = %v, want a deadline error", err)
	}
}
