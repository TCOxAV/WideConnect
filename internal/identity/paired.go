package identity

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/TCOxAV/WideConnect/protocol"
)

const (
	pairedFileName      = "paired.json"
	pairedFormatVersion = 1
)

// ErrInvalidDevice is returned when a device cannot be added to the store.
var ErrInvalidDevice = errors.New("identity: invalid paired device")

// PairedDevice is a device the user has explicitly chosen to trust.
type PairedDevice struct {
	DeviceID  [protocol.DeviceIDSize]byte
	Name      string
	PublicKey [ed25519.PublicKeySize]byte
	PairedAt  time.Time
}

// On-disk layout. Hex strings keep the file readable and diff-friendly.
type pairedEntry struct {
	DeviceID  string    `json:"device_id"`
	Name      string    `json:"name"`
	PublicKey string    `json:"public_key"`
	PairedAt  time.Time `json:"paired_at"`
}

type pairedFile struct {
	Version int           `json:"version"`
	Devices []pairedEntry `json:"devices"`
}

// PairedStore is the persistent set of trusted devices. It is safe for
// concurrent use. A device is only trusted if its DeviceID is in the store
// AND its public key matches the stored one.
type PairedStore struct {
	dir  string
	path string

	mu      sync.RWMutex
	devices map[[protocol.DeviceIDSize]byte]PairedDevice
}

// OpenPairedStore loads paired.json from dir. A missing file is an empty
// store (nothing is written until the first Add). A corrupt or unreadable
// file is an error, never a silent reset: wiping the list would unpair
// every device without telling the user.
func OpenPairedStore(dir string) (*PairedStore, error) {
	s := &PairedStore{
		dir:     dir,
		path:    filepath.Join(dir, pairedFileName),
		devices: make(map[[protocol.DeviceIDSize]byte]PairedDevice),
	}

	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return s, nil
		}
		return nil, fmt.Errorf("identity: %w", err)
	}

	devs, err := parsePaired(s.path, data)
	if err != nil {
		return nil, err
	}
	s.devices = devs
	return s, nil
}

// validate checks the invariants every stored device must satisfy.
// The key/ID binding is what stops a peer from claiming someone else's ID.
func validate(d PairedDevice) error {
	if DeviceIDFromPublicKey(d.PublicKey[:]) != d.DeviceID {
		return fmt.Errorf("%w: device id does not match public key", ErrInvalidDevice)
	}
	if len(d.Name) > protocol.MaxNameLen {
		return fmt.Errorf("%w: name longer than %d bytes", ErrInvalidDevice, protocol.MaxNameLen)
	}
	if !utf8.ValidString(d.Name) {
		return fmt.Errorf("%w: name is not valid UTF-8", ErrInvalidDevice)
	}
	return nil
}

func parsePaired(path string, data []byte) (map[[protocol.DeviceIDSize]byte]PairedDevice, error) {
	var pf pairedFile
	if err := json.Unmarshal(data, &pf); err != nil {
		return nil, fmt.Errorf("identity: %s is corrupt: %v", path, err)
	}
	if pf.Version != pairedFormatVersion {
		return nil, fmt.Errorf("identity: %s has unsupported version %d", path, pf.Version)
	}

	devs := make(map[[protocol.DeviceIDSize]byte]PairedDevice, len(pf.Devices))
	for i, e := range pf.Devices {
		id, err := hex.DecodeString(e.DeviceID)
		if err != nil || len(id) != protocol.DeviceIDSize {
			return nil, fmt.Errorf("identity: %s: entry %d has an invalid device_id", path, i)
		}
		pub, err := hex.DecodeString(e.PublicKey)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("identity: %s: entry %d has an invalid public_key", path, i)
		}

		dev := PairedDevice{Name: e.Name, PairedAt: e.PairedAt}
		copy(dev.DeviceID[:], id)
		copy(dev.PublicKey[:], pub)

		if err := validate(dev); err != nil {
			return nil, fmt.Errorf("identity: %s: entry %d: %w", path, i, err)
		}
		if _, dup := devs[dev.DeviceID]; dup {
			return nil, fmt.Errorf("identity: %s: entry %d is a duplicate device_id", path, i)
		}
		devs[dev.DeviceID] = dev
	}
	return devs, nil
}

// Lookup returns the paired device with the given ID, if any.
func (s *PairedStore) Lookup(id [protocol.DeviceIDSize]byte) (PairedDevice, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.devices[id]
	return d, ok
}

// IsPaired reports whether a device with this ID AND this public key is trusted.
func (s *PairedStore) IsPaired(id [protocol.DeviceIDSize]byte, pub [ed25519.PublicKeySize]byte) bool {
	d, ok := s.Lookup(id)
	return ok && d.PublicKey == pub
}

// List returns all paired devices, oldest pairing first. The result is a
// copy: changing it does not affect the store.
func (s *PairedStore) List() []PairedDevice {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return sortedDevices(s.devices)
}

// Add trusts dev and saves the store. Adding a device that is already paired
// refreshes its name and pairing time (this is how re-pairing works).
// If PairedAt is zero, the current time is used. If saving fails, the
// in-memory store is left unchanged.
func (s *PairedStore) Add(dev PairedDevice) error {
	if err := validate(dev); err != nil {
		return err
	}
	if dev.PairedAt.IsZero() {
		dev.PairedAt = time.Now()
	}
	dev.PairedAt = dev.PairedAt.UTC().Truncate(time.Second)

	s.mu.Lock()
	defer s.mu.Unlock()

	next := cloneDevices(s.devices)
	next[dev.DeviceID] = dev
	if err := s.persist(next); err != nil {
		return err
	}
	s.devices = next
	return nil
}

// Remove unpairs a device. It reports whether the device was paired.
// If saving fails, the in-memory store is left unchanged.
func (s *PairedStore) Remove(id [protocol.DeviceIDSize]byte) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.devices[id]; !ok {
		return false, nil
	}
	next := cloneDevices(s.devices)
	delete(next, id)
	if err := s.persist(next); err != nil {
		return false, err
	}
	s.devices = next
	return true, nil
}

func cloneDevices(m map[[protocol.DeviceIDSize]byte]PairedDevice) map[[protocol.DeviceIDSize]byte]PairedDevice {
	out := make(map[[protocol.DeviceIDSize]byte]PairedDevice, len(m)+1)
	for k, v := range m {
		out[k] = v
	}
	return out
}

// sortedDevices returns devices ordered by pairing time, ties broken by ID,
// so the file on disk is deterministic.
func sortedDevices(m map[[protocol.DeviceIDSize]byte]PairedDevice) []PairedDevice {
	list := make([]PairedDevice, 0, len(m))
	for _, d := range m {
		list = append(list, d)
	}
	sort.Slice(list, func(i, j int) bool {
		if !list[i].PairedAt.Equal(list[j].PairedAt) {
			return list[i].PairedAt.Before(list[j].PairedAt)
		}
		return bytes.Compare(list[i].DeviceID[:], list[j].DeviceID[:]) < 0
	})
	return list
}

// persist writes devs to disk. The caller must hold s.mu for writing.
func (s *PairedStore) persist(devs map[[protocol.DeviceIDSize]byte]PairedDevice) error {
	list := sortedDevices(devs)
	pf := pairedFile{
		Version: pairedFormatVersion,
		Devices: make([]pairedEntry, 0, len(list)),
	}
	for _, d := range list {
		pf.Devices = append(pf.Devices, pairedEntry{
			DeviceID:  hex.EncodeToString(d.DeviceID[:]),
			Name:      d.Name,
			PublicKey: hex.EncodeToString(d.PublicKey[:]),
			PairedAt:  d.PairedAt,
		})
	}

	data, err := json.MarshalIndent(pf, "", "  ")
	if err != nil {
		return fmt.Errorf("identity: encoding: %w", err)
	}
	data = append(data, '\n')
	return writeFileAtomic(s.dir, s.path, data)
}

// writeFileAtomic writes data to path via a temp file in dir: write, flush
// to disk, then rename into place, so a crash can never leave a half-written
// file. The temp file is created with mode 0600.
func writeFileAtomic(dir, path string, data []byte) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("identity: creating %s: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, filepath.Base(path)+"-*.tmp")
	if err != nil {
		return fmt.Errorf("identity: creating temp file: %w", err)
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("identity: writing: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("identity: syncing: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("identity: closing: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("identity: saving: %w", err)
	}
	return nil
}
