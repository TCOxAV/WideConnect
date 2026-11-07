package identity

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TCOxAV/WideConnect/protocol"
)

// newPeer makes a device with a real keypair, as a peer's HELLO would describe.
func newPeer(t *testing.T, name string) PairedDevice {
	t.Helper()
	id, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	return PairedDevice{DeviceID: id.DeviceID, Name: name, PublicKey: id.PublicKey}
}

func mustOpen(t *testing.T, dir string) *PairedStore {
	t.Helper()
	s, err := OpenPairedStore(dir)
	if err != nil {
		t.Fatalf("OpenPairedStore: %v", err)
	}
	return s
}

func sameDevice(a, b PairedDevice) bool {
	return a.DeviceID == b.DeviceID && a.PublicKey == b.PublicKey &&
		a.Name == b.Name && a.PairedAt.Equal(b.PairedAt)
}

func entryFor(d PairedDevice) pairedEntry {
	return pairedEntry{
		DeviceID:  hexOf(d.DeviceID[:]),
		Name:      d.Name,
		PublicKey: hexOf(d.PublicKey[:]),
		PairedAt:  time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC),
	}
}

func fileWith(t *testing.T, entries ...pairedEntry) string {
	t.Helper()
	b, err := json.MarshalIndent(pairedFile{Version: pairedFormatVersion, Devices: entries}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return string(b) + "\n"
}

func TestOpenMissingFileIsEmpty(t *testing.T) {
	dir := t.TempDir()
	s := mustOpen(t, dir)

	if got := s.List(); len(got) != 0 {
		t.Errorf("List = %v, want empty", got)
	}
	if _, ok := s.Lookup([protocol.DeviceIDSize]byte{1}); ok {
		t.Error("Lookup found a device in an empty store")
	}
	if _, err := os.Stat(filepath.Join(dir, pairedFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("opening an empty store should not create a file, stat err = %v", err)
	}
}

func TestAddThenReload(t *testing.T) {
	dir := t.TempDir()
	s := mustOpen(t, dir)

	peer := newPeer(t, "Pixel 8 📱")
	peer.PairedAt = time.Date(2026, 11, 7, 12, 30, 45, 123456789, time.UTC)
	if err := s.Add(peer); err != nil {
		t.Fatalf("Add: %v", err)
	}

	want := peer
	want.PairedAt = peer.PairedAt.Truncate(time.Second) // stored with 1s precision

	s2 := mustOpen(t, dir) // simulates a restart
	list := s2.List()
	if len(list) != 1 || !sameDevice(list[0], want) {
		t.Fatalf("after reload got %+v, want [%+v]", list, want)
	}
	if got, ok := s2.Lookup(peer.DeviceID); !ok || !sameDevice(got, want) {
		t.Errorf("Lookup = %+v, %v", got, ok)
	}
}

func TestAddDefaultsPairedAt(t *testing.T) {
	s := mustOpen(t, t.TempDir())
	peer := newPeer(t, "phone")
	if err := s.Add(peer); err != nil {
		t.Fatal(err)
	}

	got, _ := s.Lookup(peer.DeviceID)
	if got.PairedAt.IsZero() {
		t.Fatal("PairedAt was not filled in")
	}
	if d := time.Since(got.PairedAt); d < 0 || d > time.Minute {
		t.Errorf("PairedAt is %v ago, want within the last minute", d)
	}
}

func TestAddRejectsInvalidDevices(t *testing.T) {
	good := newPeer(t, "ok")

	cases := map[string]func(d *PairedDevice){
		"id does not match key": func(d *PairedDevice) { d.DeviceID[0] ^= 0xff },
		"name too long":         func(d *PairedDevice) { d.Name = strings.Repeat("a", protocol.MaxNameLen+1) },
		"invalid utf8 name":     func(d *PairedDevice) { d.Name = "bad\xff\xfename" },
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			s := mustOpen(t, dir)

			dev := good
			mutate(&dev)
			if err := s.Add(dev); !errors.Is(err, ErrInvalidDevice) {
				t.Errorf("err = %v, want ErrInvalidDevice", err)
			}
			if len(s.List()) != 0 {
				t.Error("rejected device ended up in the store")
			}
			if _, err := os.Stat(filepath.Join(dir, pairedFileName)); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("nothing should be written for a rejected device, stat err = %v", err)
			}
		})
	}
}

func TestIsPaired(t *testing.T) {
	s := mustOpen(t, t.TempDir())
	peer := newPeer(t, "phone")
	stranger := newPeer(t, "stranger")
	if err := s.Add(peer); err != nil {
		t.Fatal(err)
	}

	if !s.IsPaired(peer.DeviceID, peer.PublicKey) {
		t.Error("paired device with its real key should be trusted")
	}
	if s.IsPaired(peer.DeviceID, stranger.PublicKey) {
		t.Error("paired ID with a different key must NOT be trusted")
	}
	if s.IsPaired(stranger.DeviceID, stranger.PublicKey) {
		t.Error("unknown device must NOT be trusted")
	}
}

func TestAddTwiceUpdates(t *testing.T) {
	dir := t.TempDir()
	s := mustOpen(t, dir)

	peer := newPeer(t, "old name")
	if err := s.Add(peer); err != nil {
		t.Fatal(err)
	}
	peer.Name = "new name"
	if err := s.Add(peer); err != nil {
		t.Fatal(err)
	}

	for label, st := range map[string]*PairedStore{"live": s, "reloaded": mustOpen(t, dir)} {
		list := st.List()
		if len(list) != 1 {
			t.Fatalf("%s: len = %d, want 1 (re-pairing must not duplicate)", label, len(list))
		}
		if list[0].Name != "new name" {
			t.Errorf("%s: name = %q, want %q", label, list[0].Name, "new name")
		}
	}
}

func TestRemove(t *testing.T) {
	dir := t.TempDir()
	s := mustOpen(t, dir)

	a := newPeer(t, "a")
	b := newPeer(t, "b")
	for _, p := range []PairedDevice{a, b} {
		if err := s.Add(p); err != nil {
			t.Fatal(err)
		}
	}

	removed, err := s.Remove(a.DeviceID)
	if err != nil || !removed {
		t.Fatalf("Remove = %v, %v; want true, nil", removed, err)
	}
	removed, err = s.Remove(a.DeviceID)
	if err != nil || removed {
		t.Fatalf("second Remove = %v, %v; want false, nil", removed, err)
	}

	list := mustOpen(t, dir).List()
	if len(list) != 1 || list[0].DeviceID != b.DeviceID {
		t.Errorf("after reload got %+v, want only b", list)
	}
}

func TestListSortedByPairedAt(t *testing.T) {
	dir := t.TempDir()
	s := mustOpen(t, dir)

	base := time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC)
	late := newPeer(t, "late")
	late.PairedAt = base.Add(2 * time.Hour)
	early := newPeer(t, "early")
	early.PairedAt = base
	mid := newPeer(t, "mid")
	mid.PairedAt = base.Add(time.Hour)

	for _, p := range []PairedDevice{late, early, mid} { // deliberately out of order
		if err := s.Add(p); err != nil {
			t.Fatal(err)
		}
	}

	for label, st := range map[string]*PairedStore{"live": s, "reloaded": mustOpen(t, dir)} {
		var names []string
		for _, d := range st.List() {
			names = append(names, d.Name)
		}
		if got := strings.Join(names, ","); got != "early,mid,late" {
			t.Errorf("%s: order = %s, want early,mid,late", label, got)
		}
	}
}

func TestListReturnsCopy(t *testing.T) {
	s := mustOpen(t, t.TempDir())
	peer := newPeer(t, "original")
	if err := s.Add(peer); err != nil {
		t.Fatal(err)
	}

	list := s.List()
	list[0].Name = "hacked"

	if got, _ := s.Lookup(peer.DeviceID); got.Name != "original" {
		t.Errorf("store was modified through List: name = %q", got.Name)
	}
}

func TestOpenRejectsBadFiles(t *testing.T) {
	good := entryFor(newPeer(t, "laptop"))
	with := func(mutate func(e *pairedEntry)) string {
		e := good
		mutate(&e)
		return fileWith(t, e)
	}

	cases := map[string]string{
		"empty file":         "",
		"not json":           "this is not json",
		"missing version":    `{"devices": []}`,
		"future version":     `{"version": 2, "devices": []}`,
		"non-hex device id":  with(func(e *pairedEntry) { e.DeviceID = strings.Repeat("z", 32) }),
		"short device id":    with(func(e *pairedEntry) { e.DeviceID = "0011" }),
		"non-hex public key": with(func(e *pairedEntry) { e.PublicKey = strings.Repeat("z", 64) }),
		"short public key":   with(func(e *pairedEntry) { e.PublicKey = "0011" }),
		"id not from key":    with(func(e *pairedEntry) { e.DeviceID = goodID }),
		"name too long":      with(func(e *pairedEntry) { e.Name = strings.Repeat("a", protocol.MaxNameLen+1) }),
		"duplicate entries":  fileWith(t, good, good),
	}

	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, pairedFileName)
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}

			_, err := OpenPairedStore(dir)
			if err == nil {
				t.Fatal("expected an error, got nil")
			}
			if errors.Is(err, os.ErrNotExist) {
				t.Errorf("error wrongly reports a missing file: %v", err)
			}

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

func TestPairedFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permission bits do not apply on Windows")
	}

	dir := filepath.Join(t.TempDir(), "wideconnect")
	s := mustOpen(t, dir)
	if err := s.Add(newPeer(t, "phone")); err != nil {
		t.Fatal(err)
	}

	di, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := di.Mode().Perm(); perm != 0o700 {
		t.Errorf("dir mode = %o, want 700", perm)
	}
	fi, err := os.Stat(filepath.Join(dir, pairedFileName))
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("file mode = %o, want 600", perm)
	}
}

func TestFailedSaveLeavesMemoryUnchanged(t *testing.T) {
	dir := t.TempDir()
	s := mustOpen(t, dir)

	// Put a directory where paired.json should go, so the final rename fails.
	path := filepath.Join(dir, pairedFileName)
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}

	peer := newPeer(t, "phone")
	if err := s.Add(peer); err == nil {
		t.Fatal("expected Add to fail when the file cannot be written")
	}
	if len(s.List()) != 0 || s.IsPaired(peer.DeviceID, peer.PublicKey) {
		t.Error("a failed save must not leave the device trusted in memory")
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != pairedFileName {
		t.Errorf("leftover files after failed save: %v", entries)
	}
}

func TestConcurrentAccess(t *testing.T) {
	dir := t.TempDir()
	s := mustOpen(t, dir)

	const n = 8
	peers := make([]PairedDevice, n)
	for i := range peers {
		peers[i] = newPeer(t, fmt.Sprintf("dev-%d", i))
	}

	errs := make(chan error, n)
	var wg sync.WaitGroup
	for _, p := range peers {
		wg.Add(1)
		go func(p PairedDevice) {
			defer wg.Done()
			if err := s.Add(p); err != nil {
				errs <- fmt.Errorf("%s: Add: %w", p.Name, err)
				return
			}
			if !s.IsPaired(p.DeviceID, p.PublicKey) {
				errs <- fmt.Errorf("%s: not paired right after Add", p.Name)
				return
			}
			_ = s.List()
		}(p)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}

	if got := len(mustOpen(t, dir).List()); got != n {
		t.Errorf("after reload len = %d, want %d", got, n)
	}
}
