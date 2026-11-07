// Package identity persists this device's permanent identity.
//
// Each device has a long-term Ed25519 keypair. The DeviceID is derived from
// the public key, so a peer cannot claim an ID without holding the key.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/TCOxAV/WideConnect/protocol"
)

const (
	fileName      = "identity.json"
	backupSuffix  = ".v1.bak"
	formatVersion = 2 // keypair-based identity
	legacyVersion = 1 // random device id, no keys
)

// Identity is this device's persistent identity.
//
// It contains only fixed-size arrays, so two Identity values can be compared
// with ==. The private seed is unexported: use Sign to make signatures.
type Identity struct {
	DeviceID  [protocol.DeviceIDSize]byte
	PublicKey [ed25519.PublicKeySize]byte
	seed      [ed25519.SeedSize]byte
}

// String returns the device ID as lowercase hex, handy for logs.
func (i Identity) String() string {
	return hex.EncodeToString(i.DeviceID[:])
}

// Sign signs msg with this device's private key.
func (i Identity) Sign(msg []byte) []byte {
	return ed25519.Sign(ed25519.NewKeyFromSeed(i.seed[:]), msg)
}

// DeviceIDFromPublicKey derives a DeviceID: the first 16 bytes of SHA-256(pub).
func DeviceIDFromPublicKey(pub []byte) [protocol.DeviceIDSize]byte {
	sum := sha256.Sum256(pub)
	var id [protocol.DeviceIDSize]byte
	copy(id[:], sum[:])
	return id
}

func fromSeed(seed [ed25519.SeedSize]byte) Identity {
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub := priv.Public().(ed25519.PublicKey)

	var id Identity
	id.seed = seed
	copy(id.PublicKey[:], pub)
	id.DeviceID = DeviceIDFromPublicKey(pub)
	return id
}

func generate() (Identity, error) {
	var seed [ed25519.SeedSize]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return Identity{}, fmt.Errorf("identity: generating key: %w", err)
	}
	return fromSeed(seed), nil
}

// fileFormat is the on-disk JSON layout (version 2).
// private_key holds the 32-byte Ed25519 seed; the full key is derived from it.
type fileFormat struct {
	Version    int    `json:"version"`
	DeviceID   string `json:"device_id"`
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
}

// DefaultDir returns the per-user config directory for WideConnect:
//
//	Linux:   ~/.config/wideconnect
//	Windows: %AppData%\wideconnect
func DefaultDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("identity: locating config dir: %w", err)
	}
	return filepath.Join(base, "wideconnect"), nil
}

// LoadOrCreate returns the identity stored in dir.
//
//   - No file: a new identity is created and saved.
//   - Version 2 file: loaded and checked for internal consistency.
//   - Version 1 file (random ID, no keys): the old file is kept as
//     identity.json.v1.bak and replaced by a fresh version 2 identity.
//     The device ID changes once, which is safe because v1 devices
//     could never be paired.
//
// A corrupt or unreadable file is an error, never a silent reset: a new
// identity would make every paired device treat us as a stranger.
func LoadOrCreate(dir string) (Identity, error) {
	path := filepath.Join(dir, fileName)

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return createNew(dir, path)
		}
		return Identity{}, fmt.Errorf("identity: %w", err)
	}

	var ff fileFormat
	if err := json.Unmarshal(data, &ff); err != nil {
		return Identity{}, fmt.Errorf("identity: %s is corrupt: %v", path, err)
	}

	switch ff.Version {
	case formatVersion:
		return parseV2(path, ff)

	case legacyVersion:
		raw, err := hex.DecodeString(ff.DeviceID)
		if err != nil || len(raw) != protocol.DeviceIDSize {
			return Identity{}, fmt.Errorf("identity: %s has an invalid device_id", path)
		}
		if err := os.WriteFile(path+backupSuffix, data, 0o600); err != nil {
			return Identity{}, fmt.Errorf("identity: backing up old identity: %w", err)
		}
		return createNew(dir, path)

	default:
		return Identity{}, fmt.Errorf("identity: %s has unsupported version %d", path, ff.Version)
	}
}

func createNew(dir, path string) (Identity, error) {
	id, err := generate()
	if err != nil {
		return Identity{}, err
	}
	if err := save(dir, path, id); err != nil {
		return Identity{}, err
	}
	return id, nil
}

func parseV2(path string, ff fileFormat) (Identity, error) {
	seedRaw, err := hex.DecodeString(ff.PrivateKey)
	if err != nil || len(seedRaw) != ed25519.SeedSize {
		return Identity{}, fmt.Errorf("identity: %s has an invalid private_key", path)
	}
	var seed [ed25519.SeedSize]byte
	copy(seed[:], seedRaw)
	id := fromSeed(seed)

	if ff.PublicKey != hex.EncodeToString(id.PublicKey[:]) {
		return Identity{}, fmt.Errorf("identity: %s: public_key does not match private_key", path)
	}
	if ff.DeviceID != id.String() {
		return Identity{}, fmt.Errorf("identity: %s: device_id does not match public_key", path)
	}
	return id, nil
}

// save writes id to path atomically: write a temp file, flush it to disk,
// then rename it into place, so a crash can never leave a half-written file.
func save(dir, path string, id Identity) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("identity: creating %s: %w", dir, err)
	}

	data, err := json.MarshalIndent(fileFormat{
		Version:    formatVersion,
		DeviceID:   id.String(),
		PublicKey:  hex.EncodeToString(id.PublicKey[:]),
		PrivateKey: hex.EncodeToString(id.seed[:]),
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("identity: encoding: %w", err)
	}
	data = append(data, '\n')

	tmp, err := os.CreateTemp(dir, "identity-*.tmp") // created with mode 0600
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
