// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/sealstore"
)

func TestInRunDir(t *testing.T) {
	base := "/root/gcloud-run"
	cases := map[string]bool{
		"/root/gcloud-run/123-456-789":      true,
		"/root/gcloud-run/123-456-789/":     true,
		"/root/gcloud-run":                  false,
		"/root/gcloud-run/123-456-789/deep": false,
		"/root/elsewhere":                   false,
		"/root/gcloud-run/../escape":        false,
		"/Users/u/.config/gcloud":           false,
	}
	for cfg, want := range cases {
		if got := inRunDir(base, cfg); got != want {
			t.Errorf("inRunDir(%q) = %v, want %v", cfg, got, want)
		}
	}
}

func TestIsADCCommand(t *testing.T) {
	cases := map[string]bool{
		"auth application-default print-access-token": true,
		"--project p auth application-default login":  true,
		"auth list":                              false,
		"compute instances list":                 false,
		"config set auth application-default":    true, // conservative: grant, never unseal for it
		"run deploy -- auth application-default": false,
		"auth":                                   false,
		"storage cp gs://b/auth gs://b/application-default.txt": false,
	}
	for line, want := range cases {
		if got := isADCCommand(strings.Fields(line)); got != want {
			t.Errorf("isADCCommand(%q) = %v, want %v", line, got, want)
		}
	}
}

func TestGcloudChildEnv(t *testing.T) {
	in := []string{
		"PATH=/bin",
		"JIT_SHIM_GUARD_GCLOUD=1",
		"JIT_SHIM_GUARD_BQ=1",
		"CLOUDSDK_CONFIG=/somewhere/else",
		"HOME=/Users/u",
	}
	got := gcloudChildEnv(in, "gcloud", "/run/dir")
	want := []string{"PATH=/bin", "JIT_SHIM_GUARD_BQ=1", "HOME=/Users/u", "CLOUDSDK_CONFIG=/run/dir"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("env %q, want %q", got, want)
	}
	if got := gcloudChildEnv(in, "gcloud", ""); strings.Contains(strings.Join(got, "|"), "CLOUDSDK_CONFIG") {
		t.Fatalf("an empty run dir still set CLOUDSDK_CONFIG: %q", got)
	}
}

func TestForkAndWaitPassesTheStatusThrough(t *testing.T) {
	for script, want := range map[string]int{
		"exit 0":        0,
		"exit 3":        3,
		"kill -TERM $$": 128 + 15,
	} {
		got, err := forkAndWait("/bin/sh", []string{"-c", script}, os.Environ())
		if err != nil || got != want {
			t.Errorf("%q: status %d, %v; want %d", script, got, err, want)
		}
	}
	if _, err := forkAndWait("/nonexistent/tool", nil, os.Environ()); err == nil {
		t.Error("a tool that cannot start reported success")
	}
}

// fakeVault records reseals and can refuse them (a declined Touch ID).
type fakeVault struct {
	calls int
	err   error
}

func (f *fakeVault) reseal(_, _ string, _ []byte) error {
	f.calls++
	return f.err
}

// runFixture is a materialized run: a real settings dir and a run dir
// holding a login.
func runFixture(t *testing.T, token string) (dir, runDir string, baseline []byte) {
	t.Helper()
	dir = t.TempDir()
	runDir = t.TempDir()
	if err := os.WriteFile(filepath.Join(runDir, "credentials.db"), []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := sealstore.Gcloud.Pack(runDir)
	if err != nil {
		t.Fatal(err)
	}
	return dir, runDir, b
}

func TestResealOnlyWhenTheStoreChanged(t *testing.T) {
	dir, runDir, baseline := runFixture(t, "1//SAME")
	f := &fakeVault{}
	var out bytes.Buffer
	resealGcloudRun(&out, f, "", dir, runDir, baseline)
	if f.calls != 0 {
		t.Fatalf("an unchanged store was resealed %d times (D4: no vault write, no Touch ID)", f.calls)
	}

	if err := os.WriteFile(filepath.Join(runDir, "credentials.db"), []byte("1//NEW"), 0o600); err != nil {
		t.Fatal(err)
	}
	resealGcloudRun(&out, f, "", dir, runDir, baseline)
	if f.calls != 1 || !strings.Contains(out.String(), "sealed gcloud's login") {
		t.Fatalf("a changed store: %d reseals, output %q", f.calls, out.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "credentials.db")); !os.IsNotExist(err) {
		t.Fatal("a successful reseal left the login in the settings dir")
	}
}

// TestFailedResealKeepsTheLogin: a declined vault write must not delete the
// login the user just completed with the run dir.
func TestFailedResealKeepsTheLogin(t *testing.T) {
	dir, runDir, baseline := runFixture(t, "1//OLD")
	if err := os.WriteFile(filepath.Join(runDir, "credentials.db"), []byte("1//NEW"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	resealGcloudRun(&out, &fakeVault{err: errors.New("denied")}, "", dir, runDir, baseline)
	b, err := os.ReadFile(filepath.Join(dir, "credentials.db"))
	if err != nil || string(b) != "1//NEW" {
		t.Fatalf("after a failed reseal the settings dir holds %q, %v; want the new login", b, err)
	}
	if !strings.Contains(out.String(), "jit wrap gcloud") {
		t.Fatalf("the user was not told how to seal it: %q", out.String())
	}
}

func TestSignOutReportsAnEmptyStore(t *testing.T) {
	dir, runDir, baseline := runFixture(t, "1//OLD")
	if err := os.Remove(filepath.Join(runDir, "credentials.db")); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	f := &fakeVault{}
	resealGcloudRun(&out, f, "", dir, runDir, baseline)
	if f.calls != 1 || !strings.Contains(out.String(), "signed out") {
		t.Fatalf("sign-out: %d reseals, output %q", f.calls, out.String())
	}
}

func TestMaterializeGcloud(t *testing.T) {
	src := t.TempDir()
	if err := os.MkdirAll(filepath.Join(src, "legacy_credentials", "u@x.com"), 0o700); err != nil {
		t.Fatal(err)
	}
	for rel, body := range map[string]string{
		"credentials.db":                   "1//RT",
		"legacy_credentials/u@x.com/.boto": "1//RT",
	} {
		if err := os.WriteFile(filepath.Join(src, rel), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	blob, err := sealstore.Gcloud.Pack(src)
	if err != nil {
		t.Fatal(err)
	}
	settings := t.TempDir()
	if err := os.WriteFile(filepath.Join(settings, "active_config"), []byte("default"), 0o644); err != nil {
		t.Fatal(err)
	}
	runDir := t.TempDir()
	baseline, err := materializeGcloud(blob, settings, runDir)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(baseline, blob) {
		t.Fatal("the baseline is not the unsealed store")
	}
	if fi, err := os.Lstat(filepath.Join(runDir, "active_config")); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("settings were not linked into the run dir")
	}

	// A logged-out wrap (no store yet) materializes an empty one, so a
	// login through it is captured (D5).
	empty := t.TempDir()
	baseline, err = materializeGcloud(nil, settings, empty)
	if err != nil || !sealstore.Empty(baseline) {
		t.Fatalf("logged-out baseline: %v, empty=%v", err, sealstore.Empty(baseline))
	}
}
