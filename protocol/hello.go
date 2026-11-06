package protocol

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"unicode/utf8"
)

// Platform identifies the OS a device runs.
type Platform uint8

const (
	PlatformUnknown Platform = 0
	PlatformLinux   Platform = 1
	PlatformWindows Platform = 2
	PlatformAndroid Platform = 3
)

// Capability is a bit flag for a feature a device supports.
type Capability uint32

const (
	CapNotify Capability = 1 << iota
	CapFiles
	CapScreen
)

const (
	DeviceIDSize   = 16
	MaxNameLen     = 64
	helloFixedSize = DeviceIDSize + 1 + 4 + 1 // id + platform + caps + name length
)

var (
	ErrHelloTooShort  = errors.New("protocol: hello payload too short")
	ErrHelloMalformed = errors.New("protocol: hello payload malformed")
)

// Hello is the payload of a TypeHello frame.
//
// Layout (big-endian):
//
//	0   16  DeviceID
//	16  1   Platform
//	17  4   Capabilities bitmask
//	21  1   Name length N (max 64)
//	22  N   Name (UTF-8)
type Hello struct {
	DeviceID [DeviceIDSize]byte
	Platform Platform
	Caps     Capability
	Name     string
}

// NewDeviceID returns a random 16-byte device identifier.
func NewDeviceID() ([DeviceIDSize]byte, error) {
	var id [DeviceIDSize]byte
	_, err := rand.Read(id[:])
	return id, err
}

// Has reports whether the device advertises capability c.
func (h Hello) Has(c Capability) bool {
	return h.Caps&c == c
}

// Marshal encodes h into a frame payload.
func (h Hello) Marshal() ([]byte, error) {
	if len(h.Name) > MaxNameLen || !utf8.ValidString(h.Name) {
		return nil, ErrHelloMalformed
	}

	buf := make([]byte, helloFixedSize+len(h.Name))
	copy(buf[0:DeviceIDSize], h.DeviceID[:])
	buf[16] = byte(h.Platform)
	binary.BigEndian.PutUint32(buf[17:21], uint32(h.Caps))
	buf[21] = byte(len(h.Name))
	copy(buf[helloFixedSize:], h.Name)
	return buf, nil
}

// UnmarshalHello decodes a TypeHello payload.
func UnmarshalHello(b []byte) (Hello, error) {
	if len(b) < helloFixedSize {
		return Hello{}, ErrHelloTooShort
	}

	n := int(b[21])
	if n > MaxNameLen || len(b) != helloFixedSize+n {
		return Hello{}, ErrHelloMalformed
	}
	name := string(b[helloFixedSize:])
	if !utf8.ValidString(name) {
		return Hello{}, ErrHelloMalformed
	}

	var h Hello
	copy(h.DeviceID[:], b[0:DeviceIDSize])
	h.Platform = Platform(b[16])
	h.Caps = Capability(binary.BigEndian.Uint32(b[17:21]))
	h.Name = name
	return h, nil
}
