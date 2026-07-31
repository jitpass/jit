// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestBrewManaged(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/opt/homebrew/Caskroom/jitpass/0.69.0/jit", true},
		{"/usr/local/Caskroom/jitpass/0.69.0/jit", true},        // Intel-default prefix
		{"/opt/homebrew/Cellar/jitpass/0.69.0/bin/jit", true},   // formula shape, just in case
		{"/home/linuxbrew/.linuxbrew/Cellar/jitpass/jit", true}, // custom prefix still has the segment
		{"/usr/local/bin/jit", false},                           // plain install, brew prefix but no Caskroom
		{"/opt/homebrew/bin/jit", false},                        // the symlink itself — callers pass the resolved path
		{"/Users/dev/go/bin/jit", false},                        // go install
		{"/Users/dev/src/Caskroom-notes/jit", false},            // segment match, not substring match
		{"", false},
	}
	for _, c := range cases {
		if got := brewManaged(c.path); got != c.want {
			t.Errorf("brewManaged(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestVersionNewer(t *testing.T) {
	cases := []struct {
		latest, current string
		want            bool
	}{
		{"v0.41.0", "0.40.0", true},
		{"v0.41.0", "v0.40.0", true},
		{"0.40.0", "0.40.0", false},
		{"v0.40.0", "0.40.0", false}, // v-prefix must not read as newer
		{"0.40.0", "0.41.0", false},  // never offer a downgrade
		{"v0.40.1", "0.40.0", true},
		{"v1.0.0", "0.40.0", true},
		{"v0.41.0", "dev", true},            // unparseable current is older than any tag
		{"v0.41.0", "v0.41.0+dirty", false}, // same version, build suffix ignored — --force reinstalls if wanted
		{"v0.41.0", "v0.40.0+dirty", true},  // a lower dirty build still gets the offer
		{"v0.41.0", "0.41.0", false},
	}
	for _, c := range cases {
		if got := versionNewer(c.latest, c.current); got != c.want {
			t.Errorf("versionNewer(%q, %q) = %v, want %v", c.latest, c.current, got, c.want)
		}
	}
}

func TestParseChecksums(t *testing.T) {
	in := "" +
		"abc123  jitpass_darwin_arm64.tar.gz\n" +
		"DEF456  checksums-ignored-different\n" +
		"\n" +
		"789aaa  *some_binary\n"
	got, err := parseChecksums(in)
	if err != nil {
		t.Fatalf("parseChecksums: %v", err)
	}
	if got["jitpass_darwin_arm64.tar.gz"] != "abc123" {
		t.Errorf("archive sum = %q, want abc123", got["jitpass_darwin_arm64.tar.gz"])
	}
	if got["some_binary"] != "789aaa" { // leading '*' stripped, lowercased
		t.Errorf("binary sum = %q, want 789aaa", got["some_binary"])
	}
	if got["checksums-ignored-different"] != "def456" { // hex lowercased
		t.Errorf("sum not lowercased: %q", got["checksums-ignored-different"])
	}
}

func TestParseChecksumsEmpty(t *testing.T) {
	if _, err := parseChecksums("\n\n   \n"); err == nil {
		t.Fatal("expected an error for a checksums file with no entries")
	}
}

func TestExtractBinaryFromTarGz(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "a.tar.gz")

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	// A decoy entry before the real one, to prove we walk by name not position.
	writeTar(t, tw, "LICENSE", "not the binary")
	writeTar(t, tw, "jit", "#!binary-bytes")
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(archive, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	dest := filepath.Join(dir, "out")
	if err := extractBinaryFromTarGz(archive, "jit", dest); err != nil {
		t.Fatalf("extract: %v", err)
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "#!binary-bytes" {
		t.Errorf("extracted %q, want the jit entry bytes", got)
	}
	fi, err := os.Stat(dest)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o100 == 0 {
		t.Errorf("extracted binary is not executable: mode %v", fi.Mode())
	}
}

func TestExtractBinaryFromTarGzMissing(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "a.tar.gz")
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	writeTar(t, tw, "README", "x")
	tw.Close()
	gz.Close()
	if err := os.WriteFile(archive, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := extractBinaryFromTarGz(archive, "jit", filepath.Join(dir, "out")); err == nil {
		t.Fatal("expected an error when the named entry is absent")
	}
}

func TestDisplayVersion(t *testing.T) {
	cases := map[string]string{
		"0.40.0":  "v0.40.0",
		"v0.40.0": "v0.40.0",
		"dev":     "(dev build)",
		"":        "(dev build)",
	}
	for in, want := range cases {
		if got := displayVersion(in); got != want {
			t.Errorf("displayVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDownloadToFile(t *testing.T) {
	body := []byte("the-release-archive-bytes")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "dl")
	got, err := downloadToFile(context.Background(), srv.Client(), srv.URL, dest)
	if err != nil {
		t.Fatalf("downloadToFile: %v", err)
	}
	sum := sha256.Sum256(body)
	if got != hex.EncodeToString(sum[:]) {
		t.Errorf("returned sum %q does not match the served bytes", got)
	}
	on, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(on, body) {
		t.Errorf("file on disk = %q, want the served bytes", on)
	}
}

func TestDownloadToFileHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	if _, err := downloadToFile(context.Background(), srv.Client(), srv.URL, filepath.Join(t.TempDir(), "x")); err == nil {
		t.Fatal("expected an error on a 404 response")
	}
}

func TestReplaceBinaryWritableDir(t *testing.T) {
	dir := t.TempDir() // writable, so no sudo path
	target := filepath.Join(dir, "jit")
	if err := os.WriteFile(target, []byte("OLD"), 0o755); err != nil {
		t.Fatal(err)
	}
	staged := filepath.Join(t.TempDir(), "new")
	if err := os.WriteFile(staged, []byte("NEW-BINARY"), 0o755); err != nil {
		t.Fatal(err)
	}

	usedSudo, err := replaceBinary(target, staged)
	if err != nil {
		t.Fatalf("replaceBinary: %v", err)
	}
	if usedSudo {
		t.Error("a writable target dir must not escalate to sudo")
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "NEW-BINARY" {
		t.Errorf("target holds %q, want the new binary bytes", got)
	}
	fi, _ := os.Stat(target)
	if fi.Mode().Perm()&0o100 == 0 {
		t.Errorf("replaced binary lost its exec bit: %v", fi.Mode())
	}
	// The staged temp beside the target must not be left behind.
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("expected only the target in dir, got %d entries", len(entries))
	}
}

func writeTar(t *testing.T, tw *tar.Writer, name, body string) {
	t.Helper()
	if err := tw.WriteHeader(&tar.Header{
		Name:     name,
		Mode:     0o755,
		Size:     int64(len(body)),
		Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
}

// verifyStagedSignature must refuse anything that isn't a genuine, intact,
// our-team-signed release — and it must ACCEPT a real Developer ID signature,
// which is the half that fails closed into "nobody can ever upgrade".
//
// The inline-requirement syntax is the trap: codesign's -R reads its argument
// as a FILE path unless it starts with "=", so the natural-looking string
// produces "invalid requirement specification" and rejects every binary,
// genuine ones included. That failure is indistinguishable from a real
// rejection at the call site, so it is pinned here rather than discovered by a
// user whose upgrade stopped working.
func TestVerifyStagedSignature(t *testing.T) {
	if _, err := os.Stat("/usr/bin/codesign"); err != nil {
		t.Skip("codesign unavailable")
	}
	ctx := context.Background()

	// An ad-hoc/linker-signed binary — what `go build` produces — is not a
	// Developer ID release and must be refused.
	local, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	if err := verifyStagedSignature(ctx, local); err == nil {
		t.Error("an ad-hoc signed binary passed signature verification; the upgrade path would install an unsigned build")
	}

	// A nonexistent path must also fail rather than pass vacuously.
	if err := verifyStagedSignature(ctx, filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Error("a missing file passed signature verification")
	}

	// The positive half: the requirement FORM has to match a real Developer ID
	// signature. Checked against whatever Developer-ID-signed code this machine
	// happens to have, substituting that binary's own team, since jit's own
	// signed release isn't available in a test.
	signed, team := findDeveloperIDSigned(t)
	if signed == "" {
		t.Skip("no Developer ID signed binary available to validate the requirement form")
	}
	req := signatureRequirement(team)
	out, err := exec.CommandContext(ctx, "/usr/bin/codesign", "--verify", "--strict", "-R", req, signed).CombinedOutput()
	if err != nil {
		t.Fatalf("the requirement form jit uses rejected a genuine Developer ID signature (%s, team %s): %v\n%s\n"+
			"every jit upgrade would fail closed with this form", signed, team, err, out)
	}
}

// findDeveloperIDSigned returns a Developer-ID-signed path on this machine and
// its team ID, or "" when there is none to test against.
func findDeveloperIDSigned(t *testing.T) (path, team string) {
	t.Helper()
	candidates, _ := filepath.Glob("/Applications/*.app")
	for _, c := range candidates {
		out, err := exec.Command("/usr/bin/codesign", "-dv", "--verbose=4", c).CombinedOutput()
		if err != nil {
			continue
		}
		text := string(out)
		if !strings.Contains(text, "Authority=Developer ID Application") {
			continue
		}
		for _, line := range strings.Split(text, "\n") {
			if id, ok := strings.CutPrefix(strings.TrimSpace(line), "TeamIdentifier="); ok && id != "not set" && id != "" {
				return c, id
			}
		}
	}
	return "", ""
}
