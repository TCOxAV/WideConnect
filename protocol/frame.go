// Package protocol implements the WideConnect binary wire format.
// See docs/PROTOCOL.md for the specification.
package protocol

import (
	"encoding/binary"
	"errors"
	"io"
)

const (
	Magic      uint16 = 0x5743 // "WC"
	Version    uint8  = 0x01
	HeaderSize        = 8
	MaxPayload        = 16 << 20 // 16 MiB
)

// MsgType identifies what a frame's payload contains.
type MsgType uint8

const (
	TypeHello     MsgType = 0x01
	TypePing      MsgType = 0x02
	TypePong      MsgType = 0x03
	TypeNotify    MsgType = 0x10
	TypeFileMeta  MsgType = 0x20
	TypeFileChunk MsgType = 0x21
	TypeScreen    MsgType = 0x30
	TypeError     MsgType = 0xFF
)

var (
	ErrBadMagic           = errors.New("protocol: bad magic")
	ErrUnsupportedVersion = errors.New("protocol: unsupported version")
	ErrPayloadTooLarge    = errors.New("protocol: payload exceeds max size")
)

// Frame is one decoded protocol message.
type Frame struct {
	Type    MsgType
	Payload []byte
}

// WriteFrame encodes f and writes it to w in a single Write call.
// Header and payload are combined into one buffer so that, with
// TCP_NODELAY on, they leave as one packet instead of two.
func WriteFrame(w io.Writer, f Frame) error {
	if len(f.Payload) > MaxPayload {
		return ErrPayloadTooLarge
	}

	buf := make([]byte, HeaderSize+len(f.Payload))
	binary.BigEndian.PutUint16(buf[0:2], Magic)
	buf[2] = Version
	buf[3] = byte(f.Type)
	binary.BigEndian.PutUint32(buf[4:8], uint32(len(f.Payload)))
	copy(buf[HeaderSize:], f.Payload)

	_, err := w.Write(buf)
	return err
}

// ReadFrame reads and validates exactly one frame from r.
// The caller should close the connection on any error other than
// a clean io.EOF.
func ReadFrame(r io.Reader) (Frame, error) {
	var hdr [HeaderSize]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Frame{}, err
	}

	if binary.BigEndian.Uint16(hdr[0:2]) != Magic {
		return Frame{}, ErrBadMagic
	}
	if hdr[2] != Version {
		return Frame{}, ErrUnsupportedVersion
	}

	length := binary.BigEndian.Uint32(hdr[4:8])
	if length > MaxPayload {
		return Frame{}, ErrPayloadTooLarge
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return Frame{}, err
	}

	return Frame{Type: MsgType(hdr[3]), Payload: payload}, nil
}
