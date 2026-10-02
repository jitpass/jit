// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/keystore"
	"github.com/jitpass/jit/internal/migrate"
	"github.com/jitpass/jit/internal/sealstore"
	"github.com/jitpass/jit/internal/wrap"
)

// withTestKeystore points the vault at a stand-in key and a fake launchd,
// so a test home's vault opens with no keychain and no service.
func withTestKeystore(t *testing.T) {
	t.Helper()
	orig := openKeyStore
	t.Cleanup(func() { openKeyStore = orig })
	key := countingKeychainKey{kw: newFakeKeyWrapper(), uses: new(int)}
	openKeyStore = func(r string) keystore.Store { return keystore.OpenTesting(r, key) }
	withFakeLaunchd(t)
}

// plantGcloudLogin writes a logged-in gcloud config dir under home.
func plantGcloudLogin(t *testing.T, home, token string) string {
	t.Helper()
	dir := migrate.GcloudConfigDir(home)
	for rel, body := range map[string]string{
		"credentials.db":                   "SQLite format 3\x00" + token,
		"access_tokens.db":                 "ya29.ACCESS",
		"legacy_credentials/u@x.com/.boto": "gs_oauth2_refresh_token = " + token,
		"active_config":                    "default",
		"configurations/config_default":    "[core]\naccount = u@x.com\n",
	} {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestWrapGcloudSealsTheStoreAndUndoPutsItBack(t *testing.T) {
	home := withFixtureHome(t)
	withTestKeystore(t)
	t.Setenv("SHELL", "/bin/zsh")
	// Not the machine's PATH: whether gsutil is really installed here must
	// not decide what the wrap shims.
	t.Setenv("PATH", "/usr/bin:/bin")
	putToolOnPath(t, "gcloud")
	putToolOnPath(t, "bq")
	dir := plantGcloudLogin(t, home, "1//FIRST")

	out, err := execWrap(t, "gcloud")
	if err != nil {
		t.Fatalf("jit wrap gcloud: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Wrapped gcloud, bq") || !strings.Contains(out, "moved to the vault") {
		t.Errorf("summary:\n%s", out)
	}
	shims := wrap.ShimDir(home)
	for _, tool := range []string{"gcloud", "bq"} {
		if _, err := os.Lstat(filepath.Join(shims, tool)); err != nil {
			t.Errorf("no %s shim: %v", tool, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(shims, "gsutil")); err == nil {
		t.Error("shimmed gsutil, which is not installed")
	}
	m, _ := wrap.LoadManifest(home)
	if m.Tools["gcloud"].Store != "gcloud" || m.Tools["bq"].Store != "gcloud" {
		t.Errorf("manifest %+v, want store-wraps on gcloud and bq", m.Tools)
	}
	if left, _ := sealstore.Gcloud.Plaintext(dir); len(left) != 0 {
		t.Fatalf("plaintext left after the wrap: %q", left)
	}

	out, err = execWrap(t, "undo", "bq")
	if err != nil {
		t.Fatalf("jit wrap undo bq: %v\n%s", err, out)
	}
	b, err := os.ReadFile(filepath.Join(dir, "credentials.db"))
	if err != nil || !strings.Contains(string(b), "1//FIRST") {
		t.Fatalf("undo left credentials.db %q, %v", b, err)
	}
	for _, tool := range []string{"gcloud", "bq"} {
		if _, err := os.Lstat(filepath.Join(shims, tool)); err == nil {
			t.Errorf("undo of the family left the %s shim", tool)
		}
	}
	if m, _ := wrap.LoadManifest(home); len(m.Tools) != 0 {
		t.Errorf("manifest after undo: %+v", m.Tools)
	}
}

// fakeGcloud is a stand-in tool: it reads and writes the store it was
// pointed at the way gcloud does, and reports what it saw to $OUT.
const fakeGcloud = `#!/bin/sh
case "$1" in
  peek)  cat "$CLOUDSDK_CONFIG/credentials.db" > "$OUT"; cat "$CLOUDSDK_CONFIG/active_config" >> "$OUT" ;;
  login) printf '1//NEW' > "$CLOUDSDK_CONFIG/credentials.db" ;;
  setting) echo work > "$CLOUDSDK_CONFIG/new_setting" ;;
  where) echo "$CLOUDSDK_CONFIG" > "$OUT" ;;
esac
exit ${CODE:-0}
`

func gcloudRunFixture(t *testing.T) (home, tool string) {
	t.Helper()
	home = withFixtureHome(t)
	withTestKeystore(t)
	t.Setenv("CLOUDSDK_CONFIG", "")
	plantGcloudLogin(t, home, "1//FIRST")
	v, err := openVault()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := migrate.SealGcloudStore(v, home); err != nil {
		t.Fatal(err)
	}
	tool = filepath.Join(t.TempDir(), "gcloud")
	if err := os.WriteFile(tool, []byte(fakeGcloud), 0o755); err != nil { // #nosec G306 -- a test stub must be executable
		t.Fatal(err)
	}
	return home, tool
}

func runGcloudRunForTest(t *testing.T, tool string, args ...string) (int, string) {
	t.Helper()
	var errOut bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetErr(&errOut)
	code, err := runGcloudRun(cmd, tool, args)
	if err != nil {
		t.Fatalf("gcloud-run %v: %v\n%s", args, err, errOut.String())
	}
	return code, errOut.String()
}

func TestGcloudRunUnsealsForTheRunAndLeavesNothing(t *testing.T) {
	home, tool := gcloudRunFixture(t)
	out := filepath.Join(t.TempDir(), "out")
	t.Setenv("OUT", out)

	if code, _ := runGcloudRunForTest(t, tool, "peek"); code != 0 {
		t.Fatalf("status %d", code)
	}
	saw, _ := os.ReadFile(out)
	if !strings.Contains(string(saw), "1//FIRST") || !strings.Contains(string(saw), "default") {
		t.Fatalf("the tool saw %q; want the unsealed login and the user's settings", saw)
	}

	runGcloudRunForTest(t, tool, "where")
	runDir, _ := os.ReadFile(out)
	if _, err := os.Stat(strings.TrimSpace(string(runDir))); !os.IsNotExist(err) {
		t.Fatalf("the run dir %s is still there", runDir)
	}
	root, _ := vaultRootDir()
	if entries, _ := os.ReadDir(gcloudRunBase(root)); len(entries) != 0 {
		t.Fatalf("run dirs left behind: %v", entries)
	}
	if left, _ := sealstore.Gcloud.Plaintext(migrate.GcloudConfigDir(home)); len(left) != 0 {
		t.Fatalf("plaintext in the settings dir after a run: %q", left)
	}
}

func TestGcloudRunCapturesALogin(t *testing.T) {
	home, tool := gcloudRunFixture(t)
	_, stderr := runGcloudRunForTest(t, tool, "login")
	if !strings.Contains(stderr, "sealed gcloud's login into the vault") {
		t.Errorf("stderr %q", stderr)
	}
	v, _ := openVault()
	blob, err := v.Get(migrate.GcloudStorePath)
	if err != nil || !strings.Contains(string(blob), "1//NEW") {
		t.Fatalf("the vault holds %q, %v; want the new login", blob, err)
	}
	if left, _ := sealstore.Gcloud.Plaintext(migrate.GcloudConfigDir(home)); len(left) != 0 {
		t.Fatalf("a login left plaintext in the settings dir: %q", left)
	}
}

func TestGcloudRunKeepsSettingsAndStatus(t *testing.T) {
	home, tool := gcloudRunFixture(t)
	t.Setenv("CODE", "7")
	code, stderr := runGcloudRunForTest(t, tool, "setting")
	if code != 7 {
		t.Fatalf("status %d, want the tool's 7", code)
	}
	if strings.Contains(stderr, "sealed") {
		t.Errorf("an unchanged store was resealed: %q", stderr)
	}
	b, err := os.ReadFile(filepath.Join(migrate.GcloudConfigDir(home), "new_setting"))
	if err != nil || strings.TrimSpace(string(b)) != "work" {
		t.Fatalf("a setting the run created did not reach the settings dir: %q, %v", b, err)
	}
}

// TestGcloudRunWithPlaintextBackPassesThrough covers D7: when something
// logged in without the shim, the run must not swap in the older vaulted
// login. The passthrough itself execs, so this checks the decision only.
func TestGcloudRunWithPlaintextBackIsDetected(t *testing.T) {
	home, _ := gcloudRunFixture(t)
	plantGcloudLogin(t, home, "1//OUTSIDE")
	secrets, ephemeral, err := splitPlaintext(migrate.GcloudConfigDir(home))
	if err != nil || len(secrets) != 2 || len(ephemeral) != 1 {
		t.Fatalf("secrets %q ephemeral %q, %v", secrets, ephemeral, err)
	}
}
