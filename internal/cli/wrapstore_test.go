// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/keystore"
	"github.com/jitpass/jit/internal/lineage"
	"github.com/jitpass/jit/internal/migrate"
	"github.com/jitpass/jit/internal/sealstore"
	"github.com/jitpass/jit/internal/vault"
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
	// Wrapped store rows name the sealed store, so the app can count each
	// tool's reads by the use events labelled with it.
	listed, err := execWrap(t, "list", "--format", "json")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(listed, `"store_path": "gcloud-cli/store"`) {
		t.Errorf("wrap list lacks the store path:\n%s", listed)
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
  login) printf '1//NEW' > "$CLOUDSDK_CONFIG/credentials.db"
         mkdir -p "$CLOUDSDK_CONFIG/legacy_credentials/new@x.com"
         printf '1//NEW' > "$CLOUDSDK_CONFIG/legacy_credentials/new@x.com/adc.json" ;;
  revoke) rm -rf "$CLOUDSDK_CONFIG/legacy_credentials"
          printf 'SQLite format 3 1//FIRST' > "$CLOUDSDK_CONFIG/credentials.db" ;;
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
	if _, err := migrate.GcloudStore.Seal(v, home); err != nil {
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
	code, err := runStoreRun(cmd, migrate.GcloudStore, tool, args)
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
	if entries, _ := os.ReadDir(storeRunBase(root, migrate.GcloudStore)); len(entries) != 0 {
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

// TestGcloudRunRecordsASignOut: a revoke through the wrap leaves a sealed
// store with no account in it, and the listing must say so rather than
// "login sealed". The revoked token's bytes stay in credentials.db, as
// SQLite leaves them, so only the account folders can tell.
func TestGcloudRunRecordsASignOut(t *testing.T) {
	_, tool := gcloudRunFixture(t)
	if got := storeSignedIn("gcloud"); got == nil || !*got {
		t.Fatalf("after the seal: %s, want signed in", signedInState(got))
	}
	if _, stderr := runGcloudRunForTest(t, tool, "revoke"); !strings.Contains(stderr, "gcloud is signed out") {
		t.Errorf("a revoke announced %q, want the sign-out", stderr)
	}
	if got := storeSignedIn("gcloud"); got == nil || *got {
		t.Fatalf("after a revoke: %s, want signed out", signedInState(got))
	}
	runGcloudRunForTest(t, tool, "login")
	if got := storeSignedIn("gcloud"); got == nil || !*got {
		t.Fatalf("after a new login: %s, want signed in", signedInState(got))
	}
}

func signedInState(b *bool) string {
	switch {
	case b == nil:
		return "unknown"
	case *b:
		return "signed in"
	}
	return "signed out"
}

// The app's view of a store-wrap: each wrapped row says whether the
// sealed store holds a login, and carries the store's own login command
// (a family member, its namesake's), so a signed-out row can offer to log
// in through the shim. The text table says "signed out".
func TestWrapListShowsAStoreSignedOut(t *testing.T) {
	home := withFixtureHome(t)
	withTestKeystore(t)
	t.Setenv("SHELL", "/bin/zsh")
	t.Setenv("PATH", "/usr/bin:/bin")
	putToolOnPath(t, "gcloud")
	putToolOnPath(t, "bq")
	plantGcloudLogin(t, home, "1//FIRST")
	if out, err := execWrap(t, "gcloud"); err != nil {
		t.Fatalf("jit wrap gcloud: %v\n%s", err, out)
	}
	rows := func() map[string]wrapToolJSON {
		t.Helper()
		listed, err := execWrap(t, "list", "--format", "json")
		if err != nil {
			t.Fatal(err)
		}
		var res wrapListResult
		if err := json.Unmarshal([]byte(listed), &res); err != nil {
			t.Fatal(err)
		}
		out := map[string]wrapToolJSON{}
		for _, r := range res.Tools {
			out[r.Tool] = r
		}
		return out
	}
	for _, tool := range []string{"gcloud", "bq"} {
		r := rows()[tool]
		if r.LoginCommand != "gcloud auth login" || r.StoreSignedIn == nil || !*r.StoreSignedIn {
			t.Fatalf("%s row: login %q, %s; want gcloud auth login, signed in", tool, r.LoginCommand, signedInState(r.StoreSignedIn))
		}
	}

	tool := filepath.Join(t.TempDir(), "gcloud")
	if err := os.WriteFile(tool, []byte(fakeGcloud), 0o755); err != nil { // #nosec G306 -- a test stub must be executable
		t.Fatal(err)
	}
	runGcloudRunForTest(t, tool, "revoke")
	if r := rows()["bq"]; r.StoreSignedIn == nil || *r.StoreSignedIn {
		t.Fatalf("bq row after a revoke: %s, want signed out", signedInState(r.StoreSignedIn))
	}
	if out, _ := execWrap(t, "list"); !strings.Contains(out, "signed out") || strings.Contains(out, "login sealed") {
		t.Fatalf("wrap list after a revoke:\n%s", out)
	}
}

func TestStoreSignedInUnknownBeforeAnyWrite(t *testing.T) {
	withFixtureHome(t)
	if got := storeSignedIn("gcloud"); got != nil {
		t.Fatalf("no store ever sealed: %s, want unknown", signedInState(got))
	}
	if got := storeSignedIn("nope"); got != nil {
		t.Fatalf("an unknown store: %s, want unknown", signedInState(got))
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
	secrets, ephemeral, err := splitPlaintext(migrate.GcloudStore, migrate.GcloudConfigDir(home))
	if err != nil || len(secrets) != 2 || len(ephemeral) != 1 {
		t.Fatalf("secrets %q ephemeral %q, %v", secrets, ephemeral, err)
	}
}

// writeStoreWrapManifest records the gcloud family as wrapped, or (with
// wrapped false) as nothing at all.
func writeStoreWrapManifest(t *testing.T, home string, wrapped bool) {
	t.Helper()
	body := `{"tools":{}}`
	if wrapped {
		body = `{"tools":{"gcloud":{"store":"gcloud","added_at":"2026-01-01T00:00:00Z"},"bq":{"store":"gcloud","added_at":"2026-01-01T00:00:00Z"}}}`
	}
	p := wrap.ManifestPath(home)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// A wrapped tool's sealed login is in use: `jit vault orphans` must never
// offer to prune it. Once the wrap is gone (undo keeps the vault copy and
// says so), it is a genuine orphan again.
func TestVaultOrphansSparesASealedStore(t *testing.T) {
	home := withFixtureHome(t)
	cwd := withFixtureCwd(t)
	stubUserPresence(t)
	t.Cleanup(func() { vaultOrphansPrune = false; vaultOrphansYes = false })
	writeFixtureProfile(t, cwd, "myapp", "API_KEY: kept/API_KEY\n")
	root := seedFixtureVault(t, "kept/API_KEY")
	v := &vault.Vault{Root: root, KeyWrapper: newFakeKeyWrapper(), RecipientID: "test-device"}
	if err := v.Set(migrate.GcloudStorePath, []byte("sealed")); err != nil {
		t.Fatal(err)
	}

	orphans := func() string {
		t.Helper()
		var buf bytes.Buffer
		rootCmd.SetOut(&buf)
		rootCmd.SetErr(&buf)
		rootCmd.SetArgs([]string{"vault", "orphans"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("jit vault orphans: %v", err)
		}
		return buf.String()
	}

	writeStoreWrapManifest(t, home, true)
	if out := orphans(); strings.Contains(out, "gcloud-cli") {
		t.Fatalf("a wrapped tool's sealed login was listed as an orphan:\n%s", out)
	}
	rec, err := reconcileSecrets(root, cwd, v)
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range rec.Groups {
		if g.Name == "gcloud-cli" && g.State != stateManagedElsewhere {
			t.Fatalf("status classes the sealed login %v, want managed elsewhere", g.State)
		}
	}

	writeStoreWrapManifest(t, home, false)
	if out := orphans(); !strings.Contains(out, "gcloud-cli") {
		t.Fatalf("with no wrap left, the vault copy is an orphan and must be listed:\n%s", out)
	}
}

func TestStoreWrapDoctorFindings(t *testing.T) {
	home := withFixtureHome(t)
	root, err := vaultRootDir()
	if err != nil {
		t.Fatal(err)
	}
	if got := storeWrapFindings(home, root); len(got) != 0 {
		t.Fatalf("nothing wrapped, nothing left: %+v", got)
	}

	// A folder a killed run left: its owner pid cannot be alive with that
	// fork time. Our own process's folder is a live run and must not count.
	if _, err := sealstore.NewRunDir(storeRunBase(root, migrate.GcloudStore), 999999, 1); err != nil {
		t.Fatal(err)
	}
	if got := staleRuns(storeRunBase(root, migrate.GcloudStore)); len(got) != 1 {
		t.Fatalf("stale runs %q, want the dead owner's one", got)
	}
	start, _ := lineage.ProcessStartTime(int32(os.Getpid()))
	if _, err := sealstore.NewRunDir(storeRunBase(root, migrate.GcloudStore), os.Getpid(), start); err != nil {
		t.Fatal(err)
	}
	got := storeWrapFindings(home, root)
	if len(got) != 1 || got[0].Kind != kindWrapStore || !strings.Contains(got[0].Detail, "interrupted run") {
		t.Fatalf("findings %+v, want one leftover finding", got)
	}
	// The command is the Action, so doctor's fixes (and the app's button)
	// carry it, and it is no destructive one.
	fixes := fixesFor(got[0].Kind, got[0].Action)
	if len(fixes) != 1 || fixes[0].Command != "jit service restart" || fixes[0].Destructive {
		t.Fatalf("leftover fixes %+v", fixes)
	}
	if !got[0].Kind.warning() {
		t.Error("a login on disk is advisory: gcloud still runs")
	}

	// Plaintext back in the config dir only matters while the wrap is in
	// place: unwrapped, it is simply gcloud as it always was.
	plantGcloudLogin(t, home, "1//BACK")
	if got := storeWrapFindings(home, root); len(got) != 1 {
		t.Fatalf("unwrapped plaintext was reported: %+v", got)
	}
	writeStoreWrapManifest(t, home, true)
	got = storeWrapFindings(home, root)
	if len(got) != 2 || !strings.Contains(got[1].Detail, "the login is in plaintext") {
		t.Fatalf("findings %+v, want the plaintext-back finding too", got)
	}
	fixes = fixesFor(got[1].Kind, got[1].Action)
	if len(fixes) != 1 || fixes[0].Command != "jit wrap gcloud" || fixes[0].Destructive {
		t.Fatalf("plaintext-back fixes %+v", fixes)
	}
}
