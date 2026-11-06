package protocol

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestHelloRoundTrip(t *testing.T) {
	id, err := NewDeviceID()
	if err != nil {
		t.Fatalf("NewDeviceID: %v", err)
	}

	want := Hello{
		DeviceID: id,
		Platform: PlatformLinux,
		Caps:     CapNotify | CapScreen,
		Name:     "tcoxav-hplaptop",
	}

	b, err := want.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	got, err := UnmarshalHello(b)
	if err != nil {
		t.Fatalf("UnmarshalHello: %v", err)
	}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestHelloEmptyAndMaxName(t *testing.T) {
	for _, name := range []string{"", strings.Repeat("a", MaxNameLen)} {
		h := Hello{Platform: PlatformAndroid, Name: name}
		b, err := h.Marshal()
		if err != nil {
			t.Fatalf("Marshal(len=%d): %v", len(name), err)
		}
		got, err := UnmarshalHello(b)
		if err != nil {
			t.Fatalf("Unmarshal(len=%d): %v", len(name), err)
		}
		if got.Name != name {
			t.Errorf("name len %d did not survive round trip", len(name))
		}
	}
}

func TestHelloUnicodeName(t *testing.T) {
	h := Hello{Name: "Pixel 8 📱"}
	b, err := h.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got, err := UnmarshalHello(b)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.Name != h.Name {
		t.Errorf("name = %q, want %q", got.Name, h.Name)
	}
}

func TestHelloMarshalRejectsBadName(t *testing.T) {
	cases := map[string]string{
		"too long":     strings.Repeat("a", MaxNameLen+1),
		"invalid utf8": "bad\xff\xfename",
	}
	for label, name := range cases {
		if _, err := (Hello{Name: name}).Marshal(); !errors.Is(err, ErrHelloMalformed) {
			t.Errorf("%s: err = %v, want ErrHelloMalformed", label, err)
		}
	}
}

func TestHelloUnmarshalTooShort(t *testing.T) {
	for _, n := range []int{0, 1, helloFixedSize - 1} {
		_, err := UnmarshalHello(make([]byte, n))
		if !errors.Is(err, ErrHelloTooShort) {
			t.Errorf("len %d: err = %v, want ErrHelloTooShort", n, err)
		}
	}
}

func TestHelloUnmarshalLengthMismatch(t *testing.T) {
	good, _ := Hello{Name: "abc"}.Marshal()

	// Trailing garbage after the name.
	extra := append(bytes.Clone(good), 0x00)
	if _, err := UnmarshalHello(extra); !errors.Is(err, ErrHelloMalformed) {
		t.Errorf("trailing byte: err = %v, want ErrHelloMalformed", err)
	}

	// Name length byte claims more than is present.
	short := bytes.Clone(good)
	short[21] = 10
	if _, err := UnmarshalHello(short); !errors.Is(err, ErrHelloMalformed) {
		t.Errorf("lying length: err = %v, want ErrHelloMalformed", err)
	}

	// Name length byte exceeds the allowed maximum.
	huge := append(bytes.Clone(good[:helloFixedSize]), make([]byte, MaxNameLen+1)...)
	huge[21] = MaxNameLen + 1
	if _, err := UnmarshalHello(huge); !errors.Is(err, ErrHelloMalformed) {
		t.Errorf("oversize name: err = %v, want ErrHelloMalformed", err)
	}
}

func TestHelloUnmarshalInvalidUTF8(t *testing.T) {
	b, _ := Hello{Name: "abc"}.Marshal()
	b[helloFixedSize] = 0xff // corrupt the first name byte
	if _, err := UnmarshalHello(b); !errors.Is(err, ErrHelloMalformed) {
		t.Errorf("err = %v, want ErrHelloMalformed", err)
	}
}

func TestHelloHas(t *testing.T) {
	h := Hello{Caps: CapNotify | CapScreen}
	if !h.Has(CapNotify) || !h.Has(CapScreen) {
		t.Error("expected Notify and Screen to be set")
	}
	if h.Has(CapFiles) {
		t.Error("Files should not be set")
	}
	if !h.Has(CapNotify | CapScreen) {
		t.Error("Has should accept a combined mask")
	}
}

func TestNewDeviceIDUnique(t *testing.T) {
	a, _ := NewDeviceID()
	b, _ := NewDeviceID()
	if a == b {
		t.Error("two generated device IDs were identical")
	}
}
