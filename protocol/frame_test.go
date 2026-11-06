package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	cases := []Frame{
		{Type: TypePing, Payload: []byte{1, 2, 3, 4, 5, 6, 7, 8}},
		{Type: TypeHello, Payload: []byte("laptop")},
		{Type: TypeError, Payload: nil}, // empty payload is valid
	}

	for _, want := range cases {
		var buf bytes.Buffer
		if err := WriteFrame(&buf, want); err != nil {
			t.Fatalf("WriteFrame: %v", err)
		}

		got, err := ReadFrame(&buf)
		if err != nil {
			t.Fatalf("ReadFrame: %v", err)
		}
		if got.Type != want.Type {
			t.Errorf("type = %#x, want %#x", got.Type, want.Type)
		}
		if !bytes.Equal(got.Payload, want.Payload) {
			t.Errorf("payload = %v, want %v", got.Payload, want.Payload)
		}
	}
}

func TestBadMagic(t *testing.T) {
	hdr := make([]byte, HeaderSize)
	binary.BigEndian.PutUint16(hdr[0:2], 0xBEEF)
	hdr[2] = Version

	_, err := ReadFrame(bytes.NewReader(hdr))
	if !errors.Is(err, ErrBadMagic) {
		t.Errorf("err = %v, want ErrBadMagic", err)
	}
}

func TestUnsupportedVersion(t *testing.T) {
	hdr := make([]byte, HeaderSize)
	binary.BigEndian.PutUint16(hdr[0:2], Magic)
	hdr[2] = 0x99

	_, err := ReadFrame(bytes.NewReader(hdr))
	if !errors.Is(err, ErrUnsupportedVersion) {
		t.Errorf("err = %v, want ErrUnsupportedVersion", err)
	}
}

func TestOversizeRejectedOnRead(t *testing.T) {
	hdr := make([]byte, HeaderSize)
	binary.BigEndian.PutUint16(hdr[0:2], Magic)
	hdr[2] = Version
	binary.BigEndian.PutUint32(hdr[4:8], MaxPayload+1)

	_, err := ReadFrame(bytes.NewReader(hdr))
	if !errors.Is(err, ErrPayloadTooLarge) {
		t.Errorf("err = %v, want ErrPayloadTooLarge", err)
	}
}

func TestOversizeRejectedOnWrite(t *testing.T) {
	var buf bytes.Buffer
	err := WriteFrame(&buf, Frame{Type: TypeFileChunk, Payload: make([]byte, MaxPayload+1)})
	if !errors.Is(err, ErrPayloadTooLarge) {
		t.Errorf("err = %v, want ErrPayloadTooLarge", err)
	}
	if buf.Len() != 0 {
		t.Error("nothing should be written for an oversize frame")
	}
}

func TestTruncatedPayload(t *testing.T) {
	var buf bytes.Buffer
	_ = WriteFrame(&buf, Frame{Type: TypeNotify, Payload: []byte("hello world")})

	// Chop off the last few bytes to simulate a dropped connection.
	truncated := buf.Bytes()[:buf.Len()-4]

	_, err := ReadFrame(bytes.NewReader(truncated))
	if err == nil {
		t.Error("expected an error for truncated payload, got nil")
	}
}
