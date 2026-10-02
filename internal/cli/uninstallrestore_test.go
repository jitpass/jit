// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/keystore"
	"github.com/jitpass/jit/internal/migrate"
	"github.com/jitpass/jit/internal/sealstore"
	"github.com/jitpass/jit/internal/vault"
)

const tfvarsBefore = "region = \"eu-west-1\"\ndb_password = \"wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY\"\n"

// restoreFixture is a home with three migrations in it: a shell config, a
// project's terraform.tfvars (rewritten in place) beside a file migration
// CREATED, and a second shell config whose file was deleted afterwards.
func restoreFixture(t *testing.T) (home, root string, v *vault.Vault) {
	t.Helper()
	home = t.TempDir()
	t.Setenv("HOME", home)
	root = filepath.Join(home, "Library", "Application Support", "jitpass")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	deviceID, err := vault.EnsureDeviceID(root)
	if err != nil {
		t.Fatal(err)
	}
	v = &vault.Vault{Root: root, KeyWrapper: grantTestWrapper{}, RecipientID: deviceID}

	write := func(path, content string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(home, ".zshrc"), "export EDITOR=vim\nexport STRIPE_API_KEY=sk_test_123\n")
	if _, err := migrate.ApplyShellConfig(v, filepath.Join(home, ".zshrc")); err != nil {
		t.Fatal(err)
	}
	write(filepath.Join(home, ".bashrc"), "export GITHUB_TOKEN=ghp_0123456789abcdefghij0123456789abcdef\n")
	if _, err := migrate.ApplyShellConfig(v, filepath.Join(home, ".bashrc")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(home, ".bashrc")); err != nil {
		t.Fatal(err)
	}
	infra := filepath.Join(home, "proj", "infra")
	write(filepath.Join(infra, "terraform.tfvars"), tfvarsBefore)
	if _, err := migrate.ApplyTfvarsDir(v, infra, infra, []string{filepath.Join(infra, "terraform.tfvars")}); err != nil {
		t.Fatal(err)
	}
	write(filepath.Join(infra, "created-by-jit"), "x\n")
	if err := migrate.RecordCreatedFile(root, filepath.Join(infra, "created-by-jit")); err != nil {
		t.Fatal(err)
	}
	return home, root, v
}

func kindsByPath(plan uninstallRestorePlan) map[string]restoreKind {
	kinds := map[string]restoreKind{}
	for _, item := range plan.Restore {
		kinds[item.Path] = item.Kind
	}
	return kinds
}

func TestUninstallRestorePutsEveryKindBackItsOwnWay(t *testing.T) {
	home, root, v := restoreFixture(t)
	zshrc := filepath.Join(home, ".zshrc")
	creds := filepath.Join(home, "proj", "infra", "terraform.tfvars")
	awsConfig := filepath.Join(home, "proj", "infra", "created-by-jit")

	// Life after migration: a line added to each file, well past the grace.
	appendTo := func(path, line string) {
		t.Helper()
		f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0) // #nosec G304 -- test-controlled path
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteString(line); err != nil {
			t.Fatal(err)
		}
		_ = f.Close()
		later := time.Now().Add(time.Hour)
		if err := os.Chtimes(path, later, later); err != nil {
			t.Fatal(err)
		}
	}
	appendTo(zshrc, "alias gs='git status'\n")
	appendTo(creds, "replicas = 3\n")

	plan, err := buildUninstallRestorePlan(root, home, v)
	if err != nil {
		t.Fatal(err)
	}
	kinds := kindsByPath(plan)
	if kinds[zshrc] != restoreShell || kinds[creds] != restoreBackup || kinds[awsConfig] != restoreCreated {
		t.Fatalf("kinds = %v", kinds)
	}
	if len(plan.Gone) != 1 || plan.Gone[0] != filepath.Join(home, ".bashrc") {
		t.Errorf("Gone = %v, want the deleted ~/.bashrc", plan.Gone)
	}
	// ~/.bashrc is not coming back, so its token has no file to return to.
	if len(plan.VaultOnly) != 1 || plan.VaultOnly[0].Path != "bashrc/GITHUB_TOKEN" {
		t.Errorf("VaultOnly = %v, want only bashrc/GITHUB_TOKEN", plan.VaultOnly)
	}

	res := runUninstallRestore(v, root, home, plan, nil)
	if len(res.Failures) != 0 {
		t.Fatalf("failures: %v", res.Failures)
	}

	got, _ := os.ReadFile(zshrc) // #nosec G304 -- test-controlled path
	if want := "export EDITOR=vim\nexport STRIPE_API_KEY='sk_test_123'\nalias gs='git status'\n"; string(got) != want {
		t.Errorf("~/.zshrc = %q\nwant %q", got, want)
	}
	got, _ = os.ReadFile(creds) // #nosec G304 -- test-controlled path
	if string(got) != tfvarsBefore {
		t.Errorf("terraform.tfvars = %q, want its content from before jit", got)
	}
	kept, err := os.ReadFile(creds + keptBesideSuffix) // #nosec G304 -- test-controlled path
	if err != nil || !strings.Contains(string(kept), "replicas = 3") {
		t.Errorf("today's version was not kept beside it: %q, %v", kept, err)
	}
	if strings.Contains(string(kept), "wJalrXUtnFEMI") {
		t.Error("the kept copy holds the secret jit had moved out")
	}
	if _, err := os.Lstat(awsConfig); !os.IsNotExist(err) {
		t.Error("the file jit created is still there")
	}
	if len(plan.ProjectStores) != 1 || plan.ProjectStores[0] != filepath.Join(home, "proj", "infra", ".jit") {
		t.Errorf("ProjectStores = %v, want the tfvars project's .jit", plan.ProjectStores)
	}
	if _, err := os.Lstat(filepath.Join(home, ".bashrc")); !os.IsNotExist(err) {
		t.Error("a file the user deleted was recreated")
	}
}

// A link where the file was: refused, reported, and the link left intact.
func TestUninstallRestoreRefusesToReplaceASymlink(t *testing.T) {
	home, root, v := restoreFixture(t)
	creds := filepath.Join(home, "proj", "infra", "terraform.tfvars")
	target := filepath.Join(home, "linked-tfvars")
	if err := os.Rename(creds, target); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, creds); err != nil {
		t.Fatal(err)
	}

	plan, err := buildUninstallRestorePlan(root, home, v)
	if err != nil {
		t.Fatal(err)
	}
	res := runUninstallRestore(v, root, home, plan, nil)
	if len(res.Failures) != 1 || res.Failures[0].Path != creds {
		t.Fatalf("failures = %v, want exactly the symlinked tfvars file", res.Failures)
	}
	if info, _ := os.Lstat(creds); info == nil || info.Mode()&os.ModeSymlink == 0 {
		t.Error("the symlink was replaced")
	}
	// The rest of the batch still ran: the caller needs the whole list.
	if len(res.Restored) == 0 {
		t.Error("one failure stopped the other restores")
	}
}

func TestOnUnmountedVolume(t *testing.T) {
	if !onUnmountedVolume("/Volumes/jit-no-such-volume/proj/.env") {
		t.Error("a path under a volume that is not there must count as unmounted")
	}
	if onUnmountedVolume(filepath.Join(t.TempDir(), "gone", ".env")) {
		t.Error("a missing folder off /Volumes is a deleted project, not a volume")
	}
}

// stubUninstallSystem stands in for launchd, the keychain and Touch ID, and
// hands --restore the fixture's own vault.
func stubUninstallSystem(t *testing.T, v *vault.Vault) (keysDeleted *bool) {
	t.Helper()
	stubKeychain(t, keystore.Present)
	origLaunchctl, origDelete, origOpen, origChallenge := launchctlRun, deleteVaultKeys, uninstallOpenVault, uninstallChallenge
	t.Cleanup(func() {
		launchctlRun, deleteVaultKeys, uninstallOpenVault, uninstallChallenge = origLaunchctl, origDelete, origOpen, origChallenge
		uninstallPurge, uninstallYes, uninstallKeepBinary = false, false, false
		uninstallRestore, uninstallDryRun, uninstallFormat = false, false, "text"
	})
	deleted := false
	launchctlRun = func(...string) ([]byte, error) { return nil, nil }
	deleteVaultKeys = func(keystore.Store) error { deleted = true; return nil }
	uninstallOpenVault = func(string) (*vault.Vault, error) { return v, nil }
	uninstallChallenge = func(string) error { return nil }
	return &deleted
}

func TestUninstallRestoreEndToEndStreamsItsSteps(t *testing.T) {
	home, root, v := restoreFixture(t)
	keysDeleted := stubUninstallSystem(t, v)

	uninstallRestore, uninstallYes, uninstallKeepBinary, uninstallFormat = true, true, true, "ndjson"
	var out strings.Builder
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	if err := runUninstall(cmd, nil); err != nil {
		t.Fatalf("runUninstall: %v\n%s", err, out.String())
	}

	var steps []string
	var last map[string]any
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var ev map[string]any
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("not one JSON object per line: %q", line)
		}
		if ev["event"] == "step" {
			steps = append(steps, ev["step"].(string))
		}
		last = ev
	}
	if got := strings.Join(steps, ","); got != "auth,restore,stores,service,tools,vault" {
		t.Errorf("steps = %s", got)
	}
	if last["event"] != "done" || last["ok"] != true {
		t.Errorf("last event = %v, want done ok", last)
	}
	if !*keysDeleted {
		t.Error("the vault's key was not removed")
	}
	for _, gone := range []string{root, filepath.Join(home, ".jit"), filepath.Join(home, "proj", "infra", ".jit")} {
		if _, err := os.Lstat(gone); !os.IsNotExist(err) {
			t.Errorf("%s is still there", gone)
		}
	}
	got, _ := os.ReadFile(filepath.Join(home, "proj", "infra", "terraform.tfvars")) // #nosec G304 -- test-controlled path
	if string(got) != tfvarsBefore {
		t.Errorf("terraform.tfvars = %q", got)
	}
}

// The promise the whole flow rests on: one file that cannot be put back,
// and the vault, its key and jit are all still there.
func TestUninstallRestoreFailureDeletesNothing(t *testing.T) {
	home, root, v := restoreFixture(t)
	keysDeleted := stubUninstallSystem(t, v)
	tfvars := filepath.Join(home, "proj", "infra", "terraform.tfvars")
	target := filepath.Join(home, "linked-tfvars")
	if err := os.Rename(tfvars, target); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, tfvars); err != nil {
		t.Fatal(err)
	}

	uninstallRestore, uninstallYes, uninstallKeepBinary = true, true, true
	var out strings.Builder
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	err := runUninstall(cmd, nil)

	var exitErr *ExitError
	if !errors.As(err, &exitErr) || exitErr.Code != uninstallRestoreFailedExitCode {
		t.Fatalf("err = %v, want exit %d", err, uninstallRestoreFailedExitCode)
	}
	if *keysDeleted {
		t.Error("the key was deleted after a failed restore")
	}
	for _, kept := range []string{filepath.Join(root, "vault"), filepath.Join(home, ".jit"), filepath.Join(home, "proj", "infra", ".jit")} {
		if _, err := os.Stat(kept); err != nil {
			t.Errorf("%s is gone after a failed restore: %v", kept, err)
		}
	}
	if !strings.Contains(out.String(), "nothing was deleted") {
		t.Errorf("output does not say nothing was deleted:\n%s", out.String())
	}
}

// Sealing gcloud's store deletes credentials.db on purpose, so to the plan
// it looked Gone (and its gcp class mount-born): Remove JitPass would have
// dropped the gcloud login. It comes back as one store item, from the
// vault's current copy — the latest login, not the one from the wrap day.
func TestUninstallRestoreBringsBackTheSealedGcloudLogin(t *testing.T) {
	home, root, v := restoreFixture(t)
	dir := migrate.GcloudConfigDir(home)
	plantGcloudLogin(t, home, "1//WRAP-DAY")
	if _, err := migrate.SealGcloudStore(v, home); err != nil {
		t.Fatal(err)
	}
	// A later login through the wrap, resealed.
	run := t.TempDir()
	plantGcloudLogin(t, run, "1//LATEST")
	runStore := migrate.GcloudConfigDir(run)
	blob, err := sealstore.Gcloud.Pack(runStore)
	if err != nil {
		t.Fatal(err)
	}
	if err := migrate.ResealGcloudStore(v, home, runStore, blob); err != nil {
		t.Fatal(err)
	}

	plan, err := buildUninstallRestorePlan(root, home, v)
	if err != nil {
		t.Fatal(err)
	}
	creds := filepath.Join(dir, "credentials.db")
	if kindsByPath(plan)[creds] != restoreStore {
		t.Fatalf("kinds = %v, want the gcloud store item", kindsByPath(plan))
	}
	for _, g := range plan.Gone {
		if migrate.IsGcloudStoreFile(home, g) {
			t.Errorf("a sealed store file was planned as Gone: %s", g)
		}
	}
	for _, s := range plan.VaultOnly {
		if s.Path == migrate.GcloudStorePath {
			t.Error("the sealed login was planned as lost with the vault")
		}
	}

	res := runUninstallRestore(v, root, home, plan, nil)
	if len(res.Failures) != 0 {
		t.Fatalf("failures: %v", res.Failures)
	}
	b, err := os.ReadFile(creds) // #nosec G304 -- test-controlled path
	if err != nil || !strings.Contains(string(b), "1//LATEST") {
		t.Fatalf("credentials.db after restore: %q, %v; want the latest login", b, err)
	}

	// Already back in plaintext: nothing to write over it.
	plan, err = buildUninstallRestorePlan(root, home, v)
	if err != nil {
		t.Fatal(err)
	}
	if kindsByPath(plan)[creds] == restoreStore {
		t.Error("planned to write the vaulted login over a plaintext one")
	}
}

// writeAWSSSOSetup writes an SSO profile and its cached login into home.
func writeAWSSSOSetup(t *testing.T, home, refresh string) {
	t.Helper()
	for rel, body := range map[string]string{
		".aws/config":             "[profile dev]\nsso_session = corp\nsso_account_id = 111122223333\nsso_role_name = Developer\n\n[sso-session corp]\nsso_start_url = https://corp.awsapps.com/start\nsso_region = us-east-1\n",
		".aws/sso/cache/tok.json": `{"accessToken":"a","refreshToken":"` + refresh + `"}`,
	} {
		p := filepath.Join(home, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// rotateSealedAWSLogin stands in for an hour of use: a refresh rotated the
// token and jit aws-sso resealed it.
func rotateSealedAWSLogin(t *testing.T, v *vault.Vault, home, refresh string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "cache"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cache", "tok.json"), []byte(`{"accessToken":"b","refreshToken":"`+refresh+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	blob, err := migrate.AWSSSOLayout.Pack(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := migrate.StoreAWSSSOCache(v, home, blob); err != nil {
		t.Fatal(err)
	}
}

// Remove JitPass puts the original SSO profiles back and the CURRENT login:
// the seal-day backup's refresh token was rotated away by the first hour of
// use (design/aws-sso-sealed.md D10).
func TestUninstallRestoreBringsBackTheCurrentAWSSSOLogin(t *testing.T) {
	home, root, v := restoreFixture(t)
	t.Cleanup(migrate.SetJitExecutableForTesting("/usr/local/bin/jit"))
	writeAWSSSOSetup(t, home, "1//SEAL-DAY")
	if _, err := migrate.ApplyAWSSSO(v, home, []string{"dev"}, nil); err != nil {
		t.Fatal(err)
	}
	rotateSealedAWSLogin(t, v, home, "1//CURRENT")

	plan, err := buildUninstallRestorePlan(root, home, v)
	if err != nil {
		t.Fatal(err)
	}
	kinds := kindsByPath(plan)
	if kinds[migrate.AWSSSOCacheDir(home)] != restoreStore || kinds[migrate.AWSConfigPath(home)] != restoreBackup {
		t.Fatalf("kinds = %v", kinds)
	}
	for _, g := range plan.Gone {
		if migrate.IsAWSSSOCacheFile(home, g) {
			t.Errorf("a sealed token file was planned as Gone: %s", g)
		}
	}
	res := runUninstallRestore(v, root, home, plan, nil)
	if len(res.Failures) != 0 {
		t.Fatalf("failures: %v", res.Failures)
	}
	cfg, _ := os.ReadFile(migrate.AWSConfigPath(home)) // #nosec G304 -- test path
	if !strings.Contains(string(cfg), "sso_account_id = 111122223333") || strings.Contains(string(cfg), "aws-sso") {
		t.Fatalf("config after restore:\n%s", cfg)
	}
	tok, err := os.ReadFile(filepath.Join(migrate.AWSSSOCacheDir(home), "tok.json")) // #nosec G304 -- test path
	if err != nil || !strings.Contains(string(tok), "1//CURRENT") {
		t.Fatalf("token after restore %q, %v; want the current login", tok, err)
	}
}

// Undo restores the files from their backups, then the AWS step replaces
// the seal-day token with the current one.
func TestUndoRestoresTheCurrentAWSSSOLogin(t *testing.T) {
	home, _, v := restoreFixture(t)
	t.Cleanup(migrate.SetJitExecutableForTesting("/usr/local/bin/jit"))
	writeAWSSSOSetup(t, home, "1//SEAL-DAY")
	if _, err := migrate.ApplyAWSSSO(v, home, []string{"dev"}, nil); err != nil {
		t.Fatal(err)
	}
	rotateSealedAWSLogin(t, v, home, "1//CURRENT")
	recs, err := migrate.LoadBackupRecords(v.Root)
	if err != nil {
		t.Fatal(err)
	}
	var mine []migrate.BackupRecord
	for _, r := range migrate.LatestBackups(recs) {
		if r.OriginalPath == migrate.AWSConfigPath(home) || migrate.IsAWSSSOCacheFile(home, r.OriginalPath) {
			if err := migrate.RestoreFromBackup(v, r); err != nil {
				t.Fatal(err)
			}
			mine = append(mine, r)
		}
	}
	tok := filepath.Join(migrate.AWSSSOCacheDir(home), "tok.json")
	if b, _ := os.ReadFile(tok); !strings.Contains(string(b), "1//SEAL-DAY") { // #nosec G304 -- test path
		t.Fatalf("the backups did not restore the seal-day token: %q", b)
	}
	var out bytes.Buffer
	restoreCurrentAWSSSOLogin(&out, v, home, mine)
	if b, _ := os.ReadFile(tok); !strings.Contains(string(b), "1//CURRENT") { // #nosec G304 -- test path
		t.Fatalf("undo left the seal-day token: %q (%s)", b, out.String())
	}
}
