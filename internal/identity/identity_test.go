package identity

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCreateThenReload(t *testing.T) {
	dir := t.TempDir()

	first, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("first LoadOrCreate: %v", err)
	}
	if first.DeviceID == [len(first.DeviceID)]byte{} {
		t.Fatal("created an all-zero device ID")
	}

	// Every later load must return the exact same ID.
	for i := 0; i < 3; i++ {
		again, err := LoadOrCreate(dir)
		if err != nil {
			t.Fatalf("reload %d: %v", i, err)
		}
		if again != first {
			t.Fatalf("reload %d: id changed: got %s, want %s", i, again, first)
		}
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
		t.Errorf("file mode = %o, want 600", perm)
	}
}

func TestRejectsBadFiles(t *testing.T) {
	const goodID = "00112233445566778899aabbccddeeff"

	cases := map[string]string{
		"empty file":      "",
		"not json":        "this is not json",
		"missing version": `{"device_id": "` + goodID + `"}`,
		"future version":  `{"version": 2, "device_id": "` + goodID + `"}`,
		"missing id":      `{"version": 1}`,
		"non-hex id":      `{"version": 1, "device_id": "` + strings.Repeat("z", 32) + `"}`,
		"short id":        `{"version": 1, "device_id": "0011"}`,
		"long id":         `{"version": 1, "device_id": "` + goodID + `00"}`,
	}

	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, fileName)
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}

			_, err := LoadOrCreate(dir)
			if err == nil {
				t.Fatal("expected an error, got nil")
			}
			// Must not look like "file missing", or callers might treat it as first run.
			if errors.Is(err, fs.ErrNotExist) {
				t.Errorf("error wrongly reports a missing file: %v", err)
			}

			// The bad file must be left untouched, never silently replaced.
			after, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Fatalf("reading file back: %v", readErr)
			}
			if string(after) != content {
				t.Errorf("file was modified: %q", after)
			}
		})
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
	if a == b {
		t.Error("two fresh identities were identical")
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
	// Point the config dir at a temp location so the test is hermetic.
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
