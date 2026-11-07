package identity

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const goodID = "00112233445566778899aabbccddeeff"

func TestCreateThenReload(t *testing.T) {
	dir := t.TempDir()

	first, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("first LoadOrCreate: %v", err)
	}
	if first.DeviceID == [len(first.DeviceID)]byte{} {
		t.Fatal("created an all-zero device ID")
	}
	if first.PublicKey == [len(first.PublicKey)]byte{} {
		t.Fatal("created an all-zero public key")
	}

	for i := 0; i < 3; i++ {
		again, err := LoadOrCreate(dir)
		if err != nil {
			t.Fatalf("reload %d: %v", i, err)
		}
		if again != first {
			t.Fatalf("reload %d: identity changed: got %s, want %s", i, again, first)
		}
	}
}

func TestDeviceIDDerivedFromKey(t *testing.T) {
	id, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if want := DeviceIDFromPublicKey(id.PublicKey[:]); id.DeviceID != want {
		t.Errorf("DeviceID = %x, want SHA-256(pub)[:16] = %x", id.DeviceID, want)
	}
}

func TestSignAndVerify(t *testing.T) {
	dir := t.TempDir()
	id, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("WC-AUTH-v1 test message")
	sig := id.Sign(msg)
	if !ed25519.Verify(id.PublicKey[:], msg, sig) {
		t.Fatal("signature does not verify")
	}
	if ed25519.Verify(id.PublicKey[:], []byte("different message"), sig) {
		t.Error("signature verified for a different message")
	}

	// After a restart the reloaded key must still match the same public key.
	reloaded, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(id.PublicKey[:], msg, reloaded.Sign(msg)) {
		t.Error("reloaded identity signs with a different key")
	}
}

func TestCreatesMissingDirectories(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "a", "b", "wideconnect")

	if _, err := LoadOrCreate(dir); err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, fileName)); err != nil {
		t.Errorf("identity file not created: %v", err)
	}
}

func TestFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permission bits do not apply on Windows")
	}

	dir := filepath.Join(t.TempDir(), "wideconnect")
	if _, err := LoadOrCreate(dir); err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}

	di, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := di.Mode().Perm(); perm != 0o700 {
		t.Errorf("dir mode = %o, want 700", perm)
	}

	fi, err := os.Stat(filepath.Join(dir, fileName))
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("file mode = %o, want 600 (it now holds a private key)", perm)
	}
}

// expectErrorAndUntouched checks that LoadOrCreate fails on the file in dir,
// does not claim the file is missing, and leaves it unmodified.
func expectErrorAndUntouched(t *testing.T, dir, content string) {
	t.Helper()
	path := filepath.Join(dir, fileName)

	_, err := LoadOrCreate(dir)
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if errors.Is(err, fs.ErrNotExist) {
		t.Errorf("error wrongly reports a missing file: %v", err)
	}

	after, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("reading file back: %v", readErr)
	}
	if string(after) != content {
		t.Errorf("file was modified: %q", after)
	}
}

func TestRejectsBadFiles(t *testing.T) {
	cases := map[string]string{
		"empty file":        "",
		"not json":          "this is not json",
		"missing version":   `{"device_id": "` + goodID + `"}`,
		"future version":    `{"version": 3}`,
		"legacy missing id": `{"version": 1}`,
		"legacy non-hex id": `{"version": 1, "device_id": "` + strings.Repeat("z", 32) + `"}`,
		"legacy short id":   `{"version": 1, "device_id": "0011"}`,
		"v2 without keys":   `{"version": 2, "device_id": "` + goodID + `"}`,
	}

	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, fileName), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			expectErrorAndUntouched(t, dir, content)
		})
	}
}

func TestRejectsInconsistentV2(t *testing.T) {
	other, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	otherPub := strings.ToLower(hexOf(other.PublicKey[:]))

	mutations := map[string]func(m map[string]any){
		"wrong public key":    func(m map[string]any) { m["public_key"] = otherPub },
		"wrong device id":     func(m map[string]any) { m["device_id"] = goodID },
		"non-hex private key": func(m map[string]any) { m["private_key"] = strings.Repeat("z", 64) },
		"short private key":   func(m map[string]any) { m["private_key"] = "0011" },
		"missing private key": func(m map[string]any) { delete(m, "private_key") },
	}

	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if _, err := LoadOrCreate(dir); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, fileName)

			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var m map[string]any
			if err := json.Unmarshal(raw, &m); err != nil {
				t.Fatal(err)
			}
			mutate(m)
			bad, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, bad, 0o600); err != nil {
				t.Fatal(err)
			}

			expectErrorAndUntouched(t, dir, string(bad))
		})
	}
}

func TestMigratesLegacyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, fileName)
	legacy := `{"version": 1, "device_id": "` + goodID + `"}` + "\n"
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}

	id, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("migration: %v", err)
	}
	if id.String() == goodID {
		t.Error("device id should change when migrating to a keypair identity")
	}
	if id.PublicKey == [len(id.PublicKey)]byte{} {
		t.Error("migrated identity has no public key")
	}

	// The file on disk is now version 2.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var ff fileFormat
	if err := json.Unmarshal(raw, &ff); err != nil {
		t.Fatal(err)
	}
	if ff.Version != formatVersion {
		t.Errorf("file version = %d, want %d", ff.Version, formatVersion)
	}

	// The old file was preserved byte for byte.
	bak, err := os.ReadFile(path + backupSuffix)
	if err != nil {
		t.Fatalf("backup missing: %v", err)
	}
	if string(bak) != legacy {
		t.Errorf("backup = %q, want %q", bak, legacy)
	}

	// Migration happens once: later loads return the same identity.
	again, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if again != id {
		t.Error("identity changed after migration")
	}
}

func TestUnreadablePathIsError(t *testing.T) {
	dir := t.TempDir()

	// A directory where the file should be: reading it fails with
	// something other than "not exist", so we must not generate a new ID.
	if err := os.Mkdir(filepath.Join(dir, fileName), 0o700); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadOrCreate(dir); err == nil {
		t.Fatal("expected an error, got nil")
	}
}

func TestNoLeftoverTempFiles(t *testing.T) {
	dir := t.TempDir()

	if _, err := LoadOrCreate(dir); err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != fileName {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Errorf("dir contains %v, want only [%s]", names, fileName)
	}
}

func TestDifferentDirsDifferentIDs(t *testing.T) {
	a, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if a == b || a.DeviceID == b.DeviceID || a.PublicKey == b.PublicKey {
		t.Error("two fresh identities shared an ID or a key")
	}
}

func TestString(t *testing.T) {
	id, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	s := id.String()
	if len(s) != 32 {
		t.Fatalf("len = %d, want 32", len(s))
	}
	if s != strings.ToLower(s) {
		t.Errorf("%q is not lowercase", s)
	}
	for _, c := range s {
		if !strings.ContainsRune("0123456789abcdef", c) {
			t.Fatalf("%q contains non-hex character %q", s, c)
		}
	}
}

func TestDefaultDir(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)
	t.Setenv("AppData", tmp)

	dir, err := DefaultDir()
	if err != nil {
		t.Fatalf("DefaultDir: %v", err)
	}
	if filepath.Base(dir) != "wideconnect" {
		t.Errorf("dir = %q, want it to end in wideconnect", dir)
	}
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = digits[c>>4]
		out[i*2+1] = digits[c&0x0f]
	}
	return string(out)
}
