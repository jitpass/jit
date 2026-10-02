// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package sealstore

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"
)

// gcloudDir builds a logged-in gcloud config dir the way SDK 587.0.0 lays
// it out (spike E1): three copies of the refresh token, an access-token
// cache, and settings.
func gcloudDir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	write := func(rel, body string, mode os.FileMode) {
		p := filepath.Join(d, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
	}
	write("credentials.db", "SQLite format 3\x00 refresh_token 1//RT", 0o600)
	write("access_tokens.db", "SQLite format 3\x00 ya29.ACCESS", 0o600)
	write("legacy_credentials/u@example.com/adc.json", `{"refresh_token":"1//RT"}`, 0o600)
	write("legacy_credentials/u@example.com/.boto", "gs_oauth2_refresh_token = 1//RT\n", 0o600)
	write("active_config", "default", 0o644)
	write("configurations/config_default", "[core]\nproject = p\n", 0o644)
	write("logs/2026.10.02/x.log", "Running [gcloud.auth.list]\n", 0o644)
	return d
}

func names(t *testing.T, blob []byte) []string {
	t.Helper()
	var out []string
	tr := tar.NewReader(bytes.NewReader(blob))
	for {
		h, err := tr.Next()
		if err != nil {
			break
		}
		out = append(out, h.Name)
	}
	return out
}

func TestPackHoldsOnlyTheSecrets(t *testing.T) {
	blob, err := Gcloud.Pack(gcloudDir(t))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"credentials.db",
		"legacy_credentials/",
		"legacy_credentials/u@example.com/",
		"legacy_credentials/u@example.com/.boto",
		"legacy_credentials/u@example.com/adc.json",
	}
	if got := names(t, blob); !reflect.DeepEqual(got, want) {
		t.Fatalf("packed %q, want %q", got, want)
	}
	if bytes.Contains(blob, []byte("ya29.ACCESS")) {
		t.Fatal("the access-token cache was packed; it is ephemeral (D3)")
	}
}

// TestPackIsCanonical is what makes "did the run change the store" a byte
// comparison (D4): the same content packs to the same bytes whatever the
// files' times.
func TestPackIsCanonical(t *testing.T) {
	d := gcloudDir(t)
	a, err := Gcloud.Pack(d)
	if err != nil {
		t.Fatal(err)
	}
	later := time.Now().Add(time.Hour)
	if err := os.Chtimes(filepath.Join(d, "credentials.db"), later, later); err != nil {
		t.Fatal(err)
	}
	b, err := Gcloud.Pack(d)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("a touched but unchanged store packed differently")
	}
	if err := os.WriteFile(filepath.Join(d, "credentials.db"), []byte("new login"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Gcloud.Pack(d)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, c) {
		t.Fatal("a changed store packed to the same bytes")
	}
}

func TestRoundTrip(t *testing.T) {
	src := gcloudDir(t)
	blob, err := Gcloud.Pack(src)
	if err != nil {
		t.Fatal(err)
	}
	dst := t.TempDir()
	if err := Gcloud.Unpack(blob, dst); err != nil {
		t.Fatal(err)
	}
	again, err := Gcloud.Pack(dst)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(blob, again) {
		t.Fatal("unpack then pack changed the store")
	}
	got, err := os.ReadFile(filepath.Join(dst, "legacy_credentials/u@example.com/.boto"))
	if err != nil || !strings.Contains(string(got), "1//RT") {
		t.Fatalf(".boto after round trip: %q, %v", got, err)
	}
	info, err := os.Stat(filepath.Join(dst, "credentials.db"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("credentials.db mode %v, %v; want 0600", info.Mode().Perm(), err)
	}
	if _, err := os.Stat(filepath.Join(dst, "access_tokens.db")); !os.IsNotExist(err) {
		t.Fatal("unpack created the ephemeral cache")
	}
}

func TestEmptyStore(t *testing.T) {
	blob, err := Gcloud.Pack(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if !Empty(blob) {
		t.Fatal("a logged-out dir did not pack to an empty store")
	}
	full, _ := Gcloud.Pack(gcloudDir(t))
	if Empty(full) {
		t.Fatal("a logged-in store reported empty")
	}
	if err := Gcloud.Unpack(blob, t.TempDir()); err != nil {
		t.Fatalf("unpacking an empty store: %v", err)
	}
}

func TestPackRefusesLinks(t *testing.T) {
	d := t.TempDir()
	if err := os.Symlink("/etc/passwd", filepath.Join(d, "credentials.db")); err != nil {
		t.Fatal(err)
	}
	if _, err := Gcloud.Pack(d); err == nil {
		t.Fatal("packed a symlinked credentials.db")
	}
}

// tarOf builds an archive with one entry, for the hostile cases Pack never
// writes.
func tarOf(t *testing.T, hdr *tar.Header, body string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	hdr.Size = int64(len(body))
	if hdr.Typeflag == tar.TypeSymlink || hdr.Typeflag == tar.TypeDir {
		hdr.Size = 0
		body = ""
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestUnpackStaysInsideTheStore(t *testing.T) {
	cases := map[string]*tar.Header{
		"parent escape":     {Name: "legacy_credentials/../../escape", Typeflag: tar.TypeReg, Mode: 0o600},
		"absolute":          {Name: "/tmp/escape", Typeflag: tar.TypeReg, Mode: 0o600},
		"outside the store": {Name: "configurations/config_default", Typeflag: tar.TypeReg, Mode: 0o600},
		"ephemeral":         {Name: "access_tokens.db", Typeflag: tar.TypeReg, Mode: 0o600},
		"symlink":           {Name: "credentials.db", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"},
	}
	for name, hdr := range cases {
		t.Run(name, func(t *testing.T) {
			dst := t.TempDir()
			if err := Gcloud.Unpack(tarOf(t, hdr, "x"), dst); err == nil {
				t.Fatalf("unpacked %q", hdr.Name)
			}
		})
	}
}

func TestUnpackWillNotOverwrite(t *testing.T) {
	blob, _ := Gcloud.Pack(gcloudDir(t))
	dst := t.TempDir()
	if err := os.WriteFile(filepath.Join(dst, "credentials.db"), []byte("planted"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Gcloud.Unpack(blob, dst); err == nil {
		t.Fatal("unpack wrote over a file already in the run dir")
	}
}

func TestPlaintextAndRemove(t *testing.T) {
	d := gcloudDir(t)
	got, err := Gcloud.Plaintext(d)
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(got)
	if want := []string{"access_tokens.db", "credentials.db", "legacy_credentials"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("plaintext %q, want %q", got, want)
	}
	if err := Gcloud.Remove(d); err != nil {
		t.Fatal(err)
	}
	if got, _ := Gcloud.Plaintext(d); len(got) != 0 {
		t.Fatalf("after Remove still %q", got)
	}
	if _, err := os.Stat(filepath.Join(d, "configurations/config_default")); err != nil {
		t.Fatal("Remove took a setting with it")
	}
	if got, err := Gcloud.Plaintext(filepath.Join(d, "missing")); err != nil || len(got) != 0 {
		t.Fatalf("absent dir: %q, %v", got, err)
	}
}

func TestLinkSkipsPrivateEntries(t *testing.T) {
	real := gcloudDir(t)
	run := t.TempDir()
	if err := Gcloud.Link(real, run); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(run)
	var got []string
	for _, e := range entries {
		if e.Type()&os.ModeSymlink == 0 {
			t.Fatalf("%s is not a symlink", e.Name())
		}
		got = append(got, e.Name())
	}
	if want := []string{"active_config", "configurations", "logs"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("linked %q, want %q", got, want)
	}
	// A write through the link lands in the real dir (spike E2).
	if err := os.WriteFile(filepath.Join(run, "configurations", "config_new"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(real, "configurations", "config_new")); err != nil {
		t.Fatal("a write through the configurations link did not reach the real dir")
	}
}

func TestLinkCreatesMissingRealDir(t *testing.T) {
	real := filepath.Join(t.TempDir(), "gcloud")
	if err := Gcloud.Link(real, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(real); err != nil || !info.IsDir() {
		t.Fatal("Link did not create the real settings dir")
	}
}

func TestAdoptCarriesSettingsBack(t *testing.T) {
	real := t.TempDir()
	if err := os.WriteFile(filepath.Join(real, "active_config"), []byte("default"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(real, "logs"), 0o755); err != nil {
		t.Fatal(err)
	}
	run := t.TempDir()
	if err := Gcloud.Link(real, run); err != nil {
		t.Fatal(err)
	}
	// The run: a new configurations dir (first run), active_config rewritten
	// by rename over its symlink, a new logs dir that real already has, and
	// the secrets.
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(run, "configurations"), 0o755))
	must(os.WriteFile(filepath.Join(run, "configurations", "config_default"), []byte("[core]"), 0o644))
	must(os.Remove(filepath.Join(run, "active_config")))
	must(os.WriteFile(filepath.Join(run, "active_config"), []byte("work"), 0o644))
	must(os.Remove(filepath.Join(run, "logs")))
	must(os.Mkdir(filepath.Join(run, "logs"), 0o755))
	must(os.WriteFile(filepath.Join(run, "credentials.db"), []byte("secret"), 0o600))
	must(os.WriteFile(filepath.Join(run, "access_tokens.db"), []byte("secret"), 0o600))

	moved, err := Gcloud.Adopt(run, real)
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(moved)
	if want := []string{"active_config", "configurations"}; !reflect.DeepEqual(moved, want) {
		t.Fatalf("moved %q, want %q", moved, want)
	}
	if b, _ := os.ReadFile(filepath.Join(real, "active_config")); string(b) != "work" {
		t.Fatalf("real active_config %q, want the run's rewrite", b)
	}
	if _, err := os.Stat(filepath.Join(real, "configurations", "config_default")); err != nil {
		t.Fatal("the new configurations dir did not reach real")
	}
	for _, secret := range []string{"credentials.db", "access_tokens.db"} {
		if _, err := os.Stat(filepath.Join(real, secret)); !os.IsNotExist(err) {
			t.Fatalf("Adopt moved %s into the real dir", secret)
		}
	}
}

func TestRunDirsAndSweep(t *testing.T) {
	base := filepath.Join(t.TempDir(), "gcloud-run")
	live, err := NewRunDir(base, 100, 5)
	if err != nil {
		t.Fatal(err)
	}
	dead, err := NewRunDir(base, 200, 6)
	if err != nil {
		t.Fatal(err)
	}
	recycled, err := NewRunDir(base, 100, 4) // same pid, older fork time
	if err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(base, "not-ours")
	if err := os.Mkdir(foreign, 0o700); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(base); info.Mode().Perm() != 0o700 {
		t.Fatalf("base mode %#o", info.Mode().Perm())
	}
	if info, _ := os.Stat(live); info.Mode().Perm() != 0o700 {
		t.Fatalf("run dir mode %#o", info.Mode().Perm())
	}
	if pid, start, ok := Owner(live); !ok || pid != 100 || start != 5 {
		t.Fatalf("Owner(%s) = %d %d %v", live, pid, start, ok)
	}

	alive := func(pid int, start int64) bool { return pid == 100 && start == 5 }
	removed, err := Sweep(base, alive)
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(removed)
	want := []string{dead, recycled}
	sort.Strings(want)
	if !reflect.DeepEqual(removed, want) {
		t.Fatalf("swept %q, want %q", removed, want)
	}
	for _, keep := range []string{live, foreign} {
		if _, err := os.Stat(keep); err != nil {
			t.Fatalf("sweep removed %s", keep)
		}
	}
	if got, err := Sweep(filepath.Join(t.TempDir(), "none"), alive); err != nil || got != nil {
		t.Fatalf("sweeping a missing base: %q, %v", got, err)
	}
}

func TestNewRunDirRefusesALooseBase(t *testing.T) {
	base := filepath.Join(t.TempDir(), "gcloud-run")
	if err := os.Mkdir(base, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRunDir(base, 1, 1); err == nil {
		t.Fatal("made a run dir under a group-readable base")
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(t.TempDir(), link); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRunDir(link, 1, 1); err == nil {
		t.Fatal("made a run dir under a symlinked base")
	}
}

// Merge folds a login the tool just wrote over a store sealed earlier: the
// new file wins, every other sealed file stays, and the result is the same
// bytes Pack would make of the union.
func TestMerge(t *testing.T) {
	layout := Layout{Secrets: []string{"cache"}}
	sealedDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(sealedDir, "cache"), 0o700); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"a.json": "old login", "reg.json": "registration"} {
		if err := os.WriteFile(filepath.Join(sealedDir, "cache", name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	sealed, err := layout.Pack(sealedDir)
	if err != nil {
		t.Fatal(err)
	}
	fresh := t.TempDir()
	if err := os.MkdirAll(filepath.Join(fresh, "cache"), 0o700); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"a.json": "new login", "b.json": "another session"} {
		if err := os.WriteFile(filepath.Join(fresh, "cache", name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	merged, err := layout.Merge(sealed, fresh)
	if err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	if err := layout.Unpack(merged, out); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"a.json": "new login", "b.json": "another session", "reg.json": "registration"} {
		if b, _ := os.ReadFile(filepath.Join(out, "cache", name)); string(b) != want {
			t.Errorf("%s = %q, want %q", name, b, want)
		}
	}
	repacked, _ := layout.Pack(out)
	if !bytes.Equal(repacked, merged) {
		t.Error("Merge is not canonical: Pack of its unpacked result differs")
	}
	if _, err := layout.Merge([]byte("not a tar"), fresh); err == nil {
		t.Error("merged over a store that is not one")
	}
}

// The read itself refuses what the walk's Lstat could not see coming: a
// symlink or a FIFO swapped in between the two. A FIFO must not block it.
func TestReadRegularNoFollow(t *testing.T) {
	d := t.TempDir()
	reg := filepath.Join(d, "reg")
	if err := os.WriteFile(reg, []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, err := readRegularNoFollow(reg); err != nil || string(b) != "ok" {
		t.Fatalf("regular file: %q, %v", b, err)
	}
	link := filepath.Join(d, "link")
	if err := os.Symlink(reg, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readRegularNoFollow(link); err == nil {
		t.Error("read through a symlink")
	}
	fifo := filepath.Join(d, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := readRegularNoFollow(fifo); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Error("read a FIFO as a store file")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reading a FIFO blocked")
	}
}
