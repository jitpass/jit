// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/agent"
	"github.com/jitpass/jit/internal/migrate"
	"github.com/jitpass/jit/internal/mount"
	"github.com/jitpass/jit/internal/termtext"
	"github.com/jitpass/jit/internal/vault"
)

// TestVaultListRejectsUnknownFormatBeforeOpeningVault confirms an invalid
// --format value fails validation before the vault is even read — list
// runs on a bare read-only Vault and can never prompt, but a bad flag
// should still fail before any filesystem walk happens.
func TestVaultListRejectsUnknownFormatBeforeOpeningVault(t *testing.T) {
	vaultListFormat = "text"
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetArgs([]string{"vault", "list", "--format", "yaml"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected an error for an unknown --format value, got nil")
	}
	if !strings.Contains(err.Error(), `unknown --format "yaml"`) {
		t.Errorf("expected the error to name the bad value, got: %v", err)
	}
}

// TestVaultImportDeclinedConfirmationAborts confirms `jit vault import`
// aborts on a declined (empty-stdin) confirmation before ever prompting
// for the export's passphrase or reaching openVault() — the same
// declined-confirmation discipline jit migrate's own GAPS.md #17 test
// uses, and the only part of import this package can exercise
// automatically (same testing discipline as above).
func TestVaultImportDeclinedConfirmationAborts(t *testing.T) {
	vaultImportYes = false
	vaultImportStdin = false
	dir := t.TempDir()
	exportPath := filepath.Join(dir, "export.json")
	// Content doesn't need to be a real, decryptable export — declining
	// the confirmation must abort before the file is even parsed for
	// passphrase verification.
	if err := os.WriteFile(exportPath, []byte(`{"version":1,"salt":"aa","payload":"bb"}`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)                 // confirmation prompts go to stderr, capture both streams in order
	rootCmd.SetIn(strings.NewReader("")) // EOF, an empty/declined answer
	rootCmd.SetArgs([]string{"vault", "import", exportPath})

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("jit vault import declined confirmation: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Import secrets from") {
		t.Errorf("expected the confirmation prompt naming the file, got:\n%s", out)
	}
	if !strings.Contains(out, "Aborted.") {
		t.Errorf("expected the abort message, got:\n%s", out)
	}
	if strings.Contains(out, "passphrase") {
		t.Errorf("expected declining to skip the passphrase prompt entirely, got:\n%s", out)
	}
}

// TestVaultImportMissingFileFailsBeforeConfirmation confirms a nonexistent
// export file errors out immediately, before the confirmation prompt —
// there's nothing to confirm importing if the file can't even be read.
func TestVaultImportMissingFileFailsBeforeConfirmation(t *testing.T) {
	vaultImportYes = false
	vaultImportStdin = false

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetArgs([]string{"vault", "import", "/nonexistent/export.json"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected an error for a nonexistent export file, got nil")
	}
	if strings.Contains(buf.String(), "Import secrets from") {
		t.Errorf("expected no confirmation prompt for an unreadable file, got:\n%s", buf.String())
	}
}

// TestVaultImportMalformedFileFailsBeforeConfirmation confirms a file
// that isn't valid ExportEnvelope JSON errors out before confirmation too.
func TestVaultImportMalformedFileFailsBeforeConfirmation(t *testing.T) {
	vaultImportYes = false
	vaultImportStdin = false
	dir := t.TempDir()
	exportPath := filepath.Join(dir, "export.json")
	if err := os.WriteFile(exportPath, []byte("not valid json"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetArgs([]string{"vault", "import", exportPath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected an error for a malformed export file, got nil")
	}
	if strings.Contains(buf.String(), "Import secrets from") {
		t.Errorf("expected no confirmation prompt for a malformed file, got:\n%s", buf.String())
	}
}

// seedFixtureVault writes one secret into the fixture $HOME's vault so
// clean/delete have something real to act on — through the same
// vault.Vault the commands themselves construct (Root under the fixture
// home), with the package's established fakeKeyWrapper standing in for
// the keychain.
func seedFixtureVault(t *testing.T, path string) string {
	t.Helper()
	root, err := vaultRootDir()
	if err != nil {
		t.Fatalf("vaultRootDir: %v", err)
	}
	v := &vault.Vault{Root: root, KeyWrapper: newFakeKeyWrapper(), RecipientID: "test-device"}
	if err := v.Set(path, []byte("fixture-value")); err != nil {
		t.Fatalf("seeding fixture vault: %v", err)
	}
	return root
}

// TestVaultPathCompletionListsSecretsWithoutAuth drives cobra's
// __complete machinery for `jit vault get <TAB>` end to end: stored
// secret paths come back as candidates, _backups/ bookkeeping doesn't,
// the toComplete prefix filters, and the whole thing runs with no
// KeyWrapper anywhere in reach — completion must never be the thing
// that pops a Touch ID prompt.
func TestVaultPathCompletionListsSecretsWithoutAuth(t *testing.T) {
	withFixtureHome(t)
	seedFixtureVault(t, "stripe/dev-key")
	root := seedFixtureVault(t, "aws/s3-access-key")
	v := &vault.Vault{Root: root, KeyWrapper: newFakeKeyWrapper(), RecipientID: "test-device"}
	if err := v.Set("_backups/a/.env.jit-bak-1", []byte("backup-bytes")); err != nil {
		t.Fatalf("seeding backup: %v", err)
	}

	complete := func(args ...string) string {
		t.Helper()
		var buf bytes.Buffer
		rootCmd.SetOut(&buf)
		rootCmd.SetErr(&buf)
		rootCmd.SetArgs(append([]string{cobra.ShellCompRequestCmd}, args...))
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("__complete %v: %v", args, err)
		}
		return buf.String()
	}

	out := complete("vault", "get", "")
	for _, want := range []string{"aws/s3-access-key", "stripe/dev-key"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q among completions, got:\n%s", want, out)
		}
	}
	if strings.Contains(out, "_backups/") {
		t.Errorf("expected _backups/ entries hidden from completion, got:\n%s", out)
	}

	out = complete("vault", "set", "stripe/")
	if strings.Contains(out, "aws/s3-access-key") {
		t.Errorf("expected the stripe/ prefix to filter out aws paths, got:\n%s", out)
	}
	if !strings.Contains(out, "stripe/dev-key") {
		t.Errorf("expected stripe/dev-key for the stripe/ prefix, got:\n%s", out)
	}

	// Past the path argument (set's [value]) nothing should be offered,
	// including the shell's default file-name fallback.
	out = complete("vault", "set", "stripe/dev-key", "")
	if strings.Contains(out, "aws/") || strings.Contains(out, "stripe/") {
		t.Errorf("expected no path candidates for set's value argument, got:\n%s", out)
	}
}

// TestVaultPruneKeepsNewestBackupPerFile (issue #5): migrate→undo cycles
// accumulate _backups/ entries unboundedly; prune must delete every stale
// one while keeping exactly the newest per file — the record `jit migrate
// undo` restores from — and never touch real secrets or RemoveOnRestore
// records (whose empty VaultPath must not wildcard-match in the drop set).
// stubUserPresence replaces the destructive-command biometric gate with a
// no-op for the duration of a test. The real gate calls the production
// keychain / a live Touch ID prompt, which no automated test may touch (see
// internal/keychainwrap's TEST-ONLY rule); a test exercising the deletion
// itself stubs the gate, and a separate test pins that a DENIED gate aborts.
func stubUserPresence(t *testing.T) {
	t.Helper()
	prev := requireUserPresence
	requireUserPresence = func(string) error { return nil }
	t.Cleanup(func() { requireUserPresence = prev })
}

func TestVaultPruneKeepsNewestBackupPerFile(t *testing.T) {
	withFixtureHome(t)
	stubUserPresence(t)
	vaultPruneYes = true
	t.Cleanup(func() { vaultPruneYes = false })
	root := seedFixtureVault(t, "fixture/API_KEY")
	v := &vault.Vault{Root: root, KeyWrapper: newFakeKeyWrapper(), RecipientID: "test-device"}
	for _, p := range []string{"_backups/a/.env.jit-bak-1", "_backups/a/.env.jit-bak-2", "_backups/a/.env.jit-bak-3", "_backups/b/.env.jit-bak-1"} {
		if err := v.Set(p, []byte("backup-bytes")); err != nil {
			t.Fatalf("seeding backup %s: %v", p, err)
		}
	}
	index := "backups:\n" +
		"    - {original_path: /a/.env, vault_path: _backups/a/.env.jit-bak-1, unix_ts: 1}\n" +
		"    - {original_path: /a/.env, vault_path: _backups/a/.env.jit-bak-2, unix_ts: 2}\n" +
		"    - {original_path: /a/.env, vault_path: _backups/a/.env.jit-bak-3, unix_ts: 3}\n" +
		"    - {original_path: /b/.env, vault_path: _backups/b/.env.jit-bak-1, unix_ts: 1}\n" +
		"    - {original_path: /c/created-by-migrate, unix_ts: 1, remove_on_restore: true}\n"
	if err := os.WriteFile(migrate.BackupIndexPath(root), []byte(index), 0o600); err != nil {
		t.Fatalf("seeding undo index: %v", err)
	}

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs([]string{"vault", "prune"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("jit vault prune --yes: %v", err)
	}
	// "file backups", not just "backups": the wording deliberately names the
	// object class so this can't be confused with `jit vault orphans --prune`,
	// which deletes secret values instead.
	if !strings.Contains(buf.String(), "Pruned 2 stale file backups") {
		t.Errorf("expected 2 stale file backups pruned (a's two older), got:\n%s", buf.String())
	}

	ro := &vault.Vault{Root: root, RecipientID: "test-device"}
	paths, err := ro.List()
	if err != nil {
		t.Fatalf("List after prune: %v", err)
	}
	want := []string{"_backups/a/.env.jit-bak-3", "_backups/b/.env.jit-bak-1", "fixture/API_KEY"}
	if strings.Join(paths, ",") != strings.Join(want, ",") {
		t.Errorf("vault after prune = %v, want %v", paths, want)
	}

	recs, err := migrate.LoadBackupRecords(root)
	if err != nil {
		t.Fatalf("LoadBackupRecords after prune: %v", err)
	}
	if len(recs) != 3 {
		t.Errorf("undo index has %d record(s) after prune, want 3 (newest per file + the RemoveOnRestore record)", len(recs))
	}
	for _, r := range recs {
		if r.VaultPath == "_backups/a/.env.jit-bak-1" || r.VaultPath == "_backups/a/.env.jit-bak-2" {
			t.Errorf("stale record %s still in the undo index", r.VaultPath)
		}
	}

	// Idempotent: a second prune finds nothing.
	buf.Reset()
	rootCmd.SetArgs([]string{"vault", "prune"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("second jit vault prune: %v", err)
	}
	if !strings.Contains(buf.String(), "Nothing to prune") {
		t.Errorf("expected a nothing-to-prune message, got:\n%s", buf.String())
	}
}

// TestVaultRmMultipleOneGesture: `vault rm a b c` deletes every named secret
// under a SINGLE user-presence gate. The one-gesture-for-the-batch property is
// what lets a script (a test teardown, a decommissioned project) clean up N
// secrets for one approval instead of N; the count is asserted directly.
func TestVaultRmMultipleOneGesture(t *testing.T) {
	withFixtureHome(t)
	prev := requireUserPresence
	var gestures int
	requireUserPresence = func(string) error { gestures++; return nil }
	t.Cleanup(func() { requireUserPresence = prev; vaultRmYes = false })

	root := seedFixtureVault(t, "e2e/a")
	v := &vault.Vault{Root: root, KeyWrapper: newFakeKeyWrapper(), RecipientID: "test-device"}
	for _, p := range []string{"e2e/b", "e2e/c"} {
		if err := v.Set(p, []byte("val")); err != nil {
			t.Fatalf("seeding %s: %v", p, err)
		}
	}

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs([]string{"vault", "rm", "-y", "e2e/a", "e2e/b", "e2e/c"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("jit vault rm (multi): %v", err)
	}
	if gestures != 1 {
		t.Errorf("user-presence gestures = %d, want 1 for the whole batch", gestures)
	}
	ro := &vault.Vault{Root: root, RecipientID: "test-device"}
	paths, err := ro.List()
	if err != nil {
		t.Fatalf("List after rm: %v", err)
	}
	if len(paths) != 0 {
		t.Errorf("vault still holds %v after rm of all, want empty", paths)
	}
}

// TestVaultRmMultipleReportsMissing: a missing path is reported and the command
// exits non-zero, but every path that DOES exist is still removed — best-effort,
// so one stale name can't strand the rest of a cleanup.
func TestVaultRmMultipleReportsMissing(t *testing.T) {
	withFixtureHome(t)
	stubUserPresence(t)
	t.Cleanup(func() { vaultRmYes = false })

	root := seedFixtureVault(t, "e2e/a")
	v := &vault.Vault{Root: root, KeyWrapper: newFakeKeyWrapper(), RecipientID: "test-device"}
	if err := v.Set("e2e/b", []byte("val")); err != nil {
		t.Fatalf("seeding e2e/b: %v", err)
	}

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs([]string{"vault", "rm", "-y", "e2e/a", "e2e/missing", "e2e/b"})
	if err := rootCmd.Execute(); err == nil {
		t.Errorf("expected a non-zero error when a path is missing, got nil")
	}
	if !strings.Contains(buf.String(), "no secret stored at") {
		t.Errorf("missing-path report absent, got:\n%s", buf.String())
	}
	ro := &vault.Vault{Root: root, RecipientID: "test-device"}
	paths, err := ro.List()
	if err != nil {
		t.Fatalf("List after rm: %v", err)
	}
	if len(paths) != 0 {
		t.Errorf("existing paths not removed: %v", paths)
	}
}

// TestVaultOrphansListsAndPrunes: a secret no profile references is listed by
// `jit vault orphans` and deleted by `--prune`, while a secret a profile does
// reference is spared by both — even one with no recorded origin, since the
// command keys on "referenced by nothing", not on provenance.
func TestVaultOrphansListsAndPrunes(t *testing.T) {
	withFixtureHome(t)
	cwd := withFixtureCwd(t)
	stubUserPresence(t)
	t.Cleanup(func() { vaultOrphansPrune = false; vaultOrphansYes = false })

	writeFixtureProfile(t, cwd, "myapp", "API_KEY: kept/API_KEY\n")
	root := seedFixtureVault(t, "kept/API_KEY")
	v := &vault.Vault{Root: root, KeyWrapper: newFakeKeyWrapper(), RecipientID: "test-device"}
	if err := v.Set("custom_scripts-descope/DESCOPE_PROJECT_1", []byte("orphan")); err != nil {
		t.Fatalf("seeding orphan: %v", err)
	}

	// List mode: names the orphan, spares the referenced secret, deletes nothing.
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs([]string{"vault", "orphans"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("jit vault orphans: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "custom_scripts-descope") || !strings.Contains(out, "DESCOPE_PROJECT_1") {
		t.Errorf("expected the orphan listed, got:\n%s", out)
	}
	if strings.Contains(out, "kept") {
		t.Errorf("a referenced secret must never be listed as an orphan, got:\n%s", out)
	}
	if ok, _ := v.Exists("custom_scripts-descope/DESCOPE_PROJECT_1"); !ok {
		t.Error("listing must not delete the orphan")
	}

	// Prune mode: deletes the orphan, keeps the referenced secret.
	buf.Reset()
	rootCmd.SetArgs([]string{"vault", "orphans", "--prune", "--yes"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("jit vault orphans --prune: %v", err)
	}
	if !strings.Contains(buf.String(), "Deleted 1 orphaned secret") {
		t.Errorf("expected the delete count, got:\n%s", buf.String())
	}
	if ok, _ := v.Exists("custom_scripts-descope/DESCOPE_PROJECT_1"); ok {
		t.Error("prune must delete the orphan")
	}
	if ok, _ := v.Exists("kept/API_KEY"); !ok {
		t.Error("prune must keep the referenced secret")
	}
}

// TestVaultRmGroupNameDeletesWholeGroup: a bare group name expands to every
// secret under it — announced before the confirmation, one gesture for the
// lot — while an overlapping explicit member dedupes, a sibling group is
// spared, and `_backups/` never joins the expansion (its cleanup belongs to
// `jit vault prune`). Pins the fix for `jit vault rm jamf-2` costing a
// confirmation plus a Touch ID before failing with "no secret stored".
func TestVaultRmGroupNameDeletesWholeGroup(t *testing.T) {
	withFixtureHome(t)
	prev := requireUserPresence
	var gestures int
	requireUserPresence = func(string) error { gestures++; return nil }
	t.Cleanup(func() { requireUserPresence = prev; vaultRmYes = false })

	root := seedFixtureVault(t, "jamf-2/JAMF_URL")
	v := &vault.Vault{Root: root, KeyWrapper: newFakeKeyWrapper(), RecipientID: "test-device"}
	for _, p := range []string{"jamf-2/JAMF_CLIENT_ID", "jamf-2/OUTPUT_FILE", "jamf/JAMF_URL", "_backups/jamf-2/.env.jit-bak-1"} {
		if err := v.Set(p, []byte("val")); err != nil {
			t.Fatalf("seeding %s: %v", p, err)
		}
	}

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs([]string{"vault", "rm", "-y", "jamf-2", "jamf-2/JAMF_URL"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("jit vault rm (group): %v", err)
	}
	if gestures != 1 {
		t.Errorf("user-presence gestures = %d, want 1 for the whole group", gestures)
	}
	if !strings.Contains(buf.String(), "jamf-2 is a group: deleting all 3 secrets under it.") {
		t.Errorf("expected the expansion announced, got:\n%s", buf.String())
	}
	ro := &vault.Vault{Root: root, RecipientID: "test-device"}
	paths, err := ro.List()
	if err != nil {
		t.Fatalf("List after rm: %v", err)
	}
	want := []string{"_backups/jamf-2/.env.jit-bak-1", "jamf/JAMF_URL"}
	if strings.Join(paths, ",") != strings.Join(want, ",") {
		t.Errorf("vault after group rm = %v, want %v (sibling group and backup spared)", paths, want)
	}
}

// TestVaultRmUnknownNameStillReportsMissing: an argument that is neither a
// stored secret nor a group falls through the expansion untouched and keeps
// rm's established missing-path contract (reported, non-zero exit).
func TestVaultRmUnknownNameStillReportsMissing(t *testing.T) {
	withFixtureHome(t)
	stubUserPresence(t)
	t.Cleanup(func() { vaultRmYes = false })
	seedFixtureVault(t, "e2e/a")

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs([]string{"vault", "rm", "-y", "nope"})
	if err := rootCmd.Execute(); err == nil {
		t.Errorf("expected a non-zero error for an unknown name, got nil")
	}
	if !strings.Contains(buf.String(), `no secret stored at "nope"`) {
		t.Errorf("missing-path report absent, got:\n%s", buf.String())
	}
}

// TestVaultOrphansStaleMountSurvivesAndPrunes: a registered mount whose
// profile file is GONE (project directory deleted without `jit unmount`
// first) must not abort `jit vault orphans` — that stranded the exact
// recovery the command exists for. The stale registration is reported, the
// now-unreferenced secrets list as orphans, and --prune deletes the orphans
// AND clears the registration plus its .pointers companion in the same run.
func TestVaultOrphansStaleMountSurvivesAndPrunes(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)
	stubUserPresence(t)
	t.Cleanup(func() { vaultOrphansPrune = false; vaultOrphansYes = false })

	root := seedFixtureVault(t, "deadproj/API_KEY")
	mountPath := filepath.Join(home, "deadproj", ".env")
	registerFixtureMount(t, home, mountPath, filepath.Join(home, "deadproj", ".jit", "profiles", "deadproj.yaml"))

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs([]string{"vault", "orphans"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("jit vault orphans with a stale mount registered: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "[stale mounts]") || !strings.Contains(out, "deadproj/.env") {
		t.Errorf("expected the stale mount reported, got:\n%s", out)
	}
	if !strings.Contains(out, "API_KEY") {
		t.Errorf("expected the dead project's secret listed as an orphan, got:\n%s", out)
	}

	buf.Reset()
	rootCmd.SetArgs([]string{"vault", "orphans", "--prune", "--yes"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("jit vault orphans --prune with a stale mount: %v", err)
	}
	if !strings.Contains(buf.String(), "Deleted 1 orphaned secret") || !strings.Contains(buf.String(), "Cleared 1 stale mount registration") {
		t.Errorf("expected both the delete and the clear reported, got:\n%s", buf.String())
	}
	v := &vault.Vault{Root: root, RecipientID: "test-device"}
	if ok, _ := v.Exists("deadproj/API_KEY"); ok {
		t.Error("prune must delete the dead project's orphaned secret")
	}
	entries, err := mount.LoadRegistry(mount.RegistryPath(root))
	if err != nil {
		t.Fatalf("LoadRegistry after prune: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("stale registry entry still present after prune: %v", entries)
	}
}

// TestVaultOrphansUnparseableMountProfileStillAborts: the stale-mount carve-
// out is for a MISSING profile only. A profile that exists but fails to
// parse still aborts the command — --prune must never treat a secret as
// unreferenced because the manifest naming it failed to load.
func TestVaultOrphansUnparseableMountProfileStillAborts(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)
	seedFixtureVault(t, "proj/API_KEY")
	profilePath := filepath.Join(home, "proj", ".jit", "profiles", "proj.yaml")
	writeProfileAt(t, profilePath, "not: [valid")
	registerFixtureMount(t, home, filepath.Join(home, "proj", ".env"), profilePath)

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs([]string{"vault", "orphans"})
	err := rootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "loading profile") {
		t.Fatalf("expected the unparseable mount profile to abort, got: %v", err)
	}
}

// TestVaultCleanDeclinedConfirmationAborts: declining must leave every
// secret in place — and, per this package's ordering discipline, the
// listing/count shown in the prompt itself must never have cost any auth
// (clean runs entirely on the read-only vault construction).
func TestVaultCleanDeclinedConfirmationAborts(t *testing.T) {
	withFixtureHome(t)
	vaultCleanYes = false
	root := seedFixtureVault(t, "fixture/API_KEY")

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetIn(strings.NewReader(""))
	rootCmd.SetArgs([]string{"vault", "clean"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("jit vault clean (declined): %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "ALL 1 secret") {
		t.Errorf("expected the prompt to state the count, got:\n%s", out)
	}
	if !strings.Contains(out, "Aborted.") {
		t.Errorf("expected the abort message, got:\n%s", out)
	}

	v := &vault.Vault{Root: root, KeyWrapper: nil, RecipientID: "test-device"}
	if exists, err := v.Exists("fixture/API_KEY"); err != nil || !exists {
		t.Errorf("declined clean removed the secret anyway (exists=%v, err=%v)", exists, err)
	}
}

// TestVaultCleanRemovesEverySecret: --yes wipes every secret (including
// a _backups/ entry) plus the undo index, and the vault stays usable.
func TestVaultCleanRemovesEverySecret(t *testing.T) {
	withFixtureHome(t)
	stubUserPresence(t)
	vaultCleanYes = true
	t.Cleanup(func() { vaultCleanYes = false })
	root := seedFixtureVault(t, "fixture/API_KEY")
	v := &vault.Vault{Root: root, KeyWrapper: newFakeKeyWrapper(), RecipientID: "test-device"}
	if err := v.Set("_backups/env.jit-bak-1", []byte("backup-bytes")); err != nil {
		t.Fatalf("seeding backup secret: %v", err)
	}
	if err := os.WriteFile(migrate.BackupIndexPath(root), []byte("backups: []\n"), 0o600); err != nil {
		t.Fatalf("seeding undo index: %v", err)
	}

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs([]string{"vault", "clean"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("jit vault clean --yes: %v", err)
	}
	if !strings.Contains(buf.String(), "Deleted 2 secrets") {
		t.Errorf("expected the count line, got:\n%s", buf.String())
	}

	ro := &vault.Vault{Root: root, RecipientID: "test-device"}
	paths, err := ro.List()
	if err != nil {
		t.Fatalf("List after clean: %v", err)
	}
	if len(paths) != 0 {
		t.Errorf("secrets remain after clean: %v", paths)
	}
	if _, err := os.Stat(migrate.BackupIndexPath(root)); !os.IsNotExist(err) {
		t.Error("undo index still exists after clean, jit migrate undo would half-fail against deleted backup secrets")
	}
}

// TestVaultCleanDeniedPresenceGateAborts pins the security contract of the
// destructive-command biometric gate: if the fingerprint/passcode challenge
// is DENIED (or unavailable), the command must abort with that error and
// delete nothing, even past the [y/N] confirm. A same-user process on an
// unlocked session that can't produce a live human gesture must not be able
// to wipe the vault.
func TestVaultCleanDeniedPresenceGateAborts(t *testing.T) {
	withFixtureHome(t)
	prev := requireUserPresence
	requireUserPresence = func(string) error { return errors.New("the user canceled") }
	t.Cleanup(func() { requireUserPresence = prev })
	vaultCleanYes = true
	t.Cleanup(func() { vaultCleanYes = false })
	root := seedFixtureVault(t, "fixture/API_KEY")

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs([]string{"vault", "clean"})
	err := rootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "the user canceled") {
		t.Fatalf("expected a denied-presence error, got: %v", err)
	}

	ro := &vault.Vault{Root: root, RecipientID: "test-device"}
	paths, listErr := ro.List()
	if listErr != nil {
		t.Fatalf("List after aborted clean: %v", listErr)
	}
	if len(paths) == 0 {
		t.Error("secrets were deleted despite a denied biometric gate, the gate is not actually blocking")
	}
}

// TestVaultCleanEmptyVaultSaysSo: the empty state is one friendly line,
// never a confirmation prompt for deleting nothing.
func TestVaultCleanEmptyVaultSaysSo(t *testing.T) {
	withFixtureHome(t)
	vaultCleanYes = false

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs([]string{"vault", "clean"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("jit vault clean (empty): %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "already empty") {
		t.Errorf("expected the empty-state line, got:\n%s", out)
	}
	if strings.Contains(out, "[y/N]") {
		t.Errorf("an empty vault must not prompt for confirmation, got:\n%s", out)
	}
}

// TestVaultDeleteRefusesWhileMountsRegistered: destroying the vault out
// from under a live mount would permanently strand the file as decoys —
// the refusal must fire before any confirmation or deletion.
func TestVaultDeleteRefusesWhileMountsRegistered(t *testing.T) {
	withFixtureHome(t)
	vaultDeleteYes = true // even --yes must not get past the refusal
	t.Cleanup(func() { vaultDeleteYes = false })
	root := seedFixtureVault(t, "fixture/API_KEY")
	if err := mount.AddMount(mount.RegistryPath(root), mount.Entry{MountPath: "/p/.env", ProfilePath: "/p/profile.yaml"}); err != nil {
		t.Fatalf("AddMount: %v", err)
	}

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs([]string{"vault", "delete"})
	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected jit vault delete to refuse while a mount is registered")
	}
	if !strings.Contains(err.Error(), "live-mounted") {
		t.Errorf("expected the refusal to explain the live mount, got: %v", err)
	}

	v := &vault.Vault{Root: root, RecipientID: "test-device"}
	if exists, _ := v.Exists("fixture/API_KEY"); !exists {
		t.Error("the refused delete removed secrets anyway")
	}
}

// TestVaultDeleteDeclinedConfirmationAborts: declining leaves everything
// in place — the actual destruction (including the keychain MEK removal,
// which no automated test may ever exercise: see internal/keychainwrap's
// TEST-ONLY rule) is real-hardware verification territory.
func TestVaultDeleteDeclinedConfirmationAborts(t *testing.T) {
	withFixtureHome(t)
	vaultDeleteYes = false
	root := seedFixtureVault(t, "fixture/API_KEY")

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetIn(strings.NewReader(""))
	rootCmd.SetArgs([]string{"vault", "delete"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("jit vault delete (declined): %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "destroy the ENTIRE vault") {
		t.Errorf("expected the destruction prompt, got:\n%s", out)
	}
	if !strings.Contains(out, "No vault export exists") {
		t.Errorf("expected the no-backup warning (nothing was ever exported in this fixture), got:\n%s", out)
	}
	if !strings.Contains(out, "Aborted.") {
		t.Errorf("expected the abort message, got:\n%s", out)
	}
	v := &vault.Vault{Root: root, RecipientID: "test-device"}
	if exists, _ := v.Exists("fixture/API_KEY"); !exists {
		t.Error("the declined delete removed secrets anyway")
	}
}

// TestVaultCleanRefusesWhileMountsRegistered mirrors delete's refusal
// (and exists because of a real incident: a vault cleaned with 4 mounts
// registered left all four permanently stranded as decoys — and unmount
// can't run AFTER a clean, since writing the plaintext back needs the
// very secrets the clean just deleted).
func TestVaultCleanRefusesWhileMountsRegistered(t *testing.T) {
	withFixtureHome(t)
	vaultCleanYes = true // even --yes must not get past the refusal
	t.Cleanup(func() { vaultCleanYes = false })
	root := seedFixtureVault(t, "fixture/API_KEY")
	if err := mount.AddMount(mount.RegistryPath(root), mount.Entry{MountPath: "/p/.env", ProfilePath: "/p/profile.yaml"}); err != nil {
		t.Fatalf("AddMount: %v", err)
	}

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs([]string{"vault", "clean"})
	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected jit vault clean to refuse while a mount is registered")
	}
	if !strings.Contains(err.Error(), "live-mounted") {
		t.Errorf("expected the refusal to explain the live mount, got: %v", err)
	}
	v := &vault.Vault{Root: root, RecipientID: "test-device"}
	if exists, _ := v.Exists("fixture/API_KEY"); !exists {
		t.Error("the refused clean removed secrets anyway")
	}
}

// TestLockAgentAfterMEKDeletion drives the post-delete lock step against a
// real agent.Server (fake MEK fetch only — the established boundary): an
// unlocked agent must end up locked, so a cached copy of a just-deleted
// MEK can never outlive the vault and silently wrap the NEXT vault's
// writes with an orphaned key. The full `vault delete` RunE stays
// real-hardware-only per the TEST-ONLY keychain rule (it deletes the real
// production MEK); this helper is exactly the part that rule allows
// exercising.
func TestLockAgentAfterMEKDeletion(t *testing.T) {
	root := t.TempDir()
	socketPath := agent.SocketPath(root)
	server := agent.NewServer(socketPath, func() agent.MEKFetcher { return &fakeMEKFetcher{key: bytes.Repeat([]byte{0x77}, 32)} }, time.Minute)
	if err := server.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = server.Serve(ctx); close(done) }()
	defer func() { cancel(); _ = server.Close(); <-done }()

	client := agent.NewClient(socketPath)
	if _, _, err := client.Unlock(); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if st, err := client.Status(); err != nil || !st.Unlocked {
		t.Fatalf("precondition: agent should be unlocked (unlocked=%v, err=%v)", st.Unlocked, err)
	}

	var stderr bytes.Buffer
	if got := lockAgentAfterMEKDeletion(root, &stderr); got == "" {
		t.Fatalf("expected a locked-session description, got empty (stderr: %q)", stderr.String())
	}
	if st, err := client.Status(); err != nil || st.Unlocked {
		t.Errorf("agent still unlocked after lockAgentAfterMEKDeletion (unlocked=%v, err=%v)", st.Unlocked, err)
	}
}

// No agent running at all: the helper must be a silent no-op, never an
// error or a warning — most machines run `vault delete` with no agent.
func TestLockAgentAfterMEKDeletionNoAgent(t *testing.T) {
	var stderr bytes.Buffer
	if got := lockAgentAfterMEKDeletion(t.TempDir(), &stderr); got != "" {
		t.Errorf("no-agent case should return empty, got %q", got)
	}
	if stderr.Len() != 0 {
		t.Errorf("no-agent case should be silent, got: %q", stderr.String())
	}
}

// TestPrintVaultList pins GAPS.md #55's display half: jit migrate's own
// _backups/ entries are jit bookkeeping, not user secrets — a real
// three-project vault opened its listing with three unreadable
// absolute-path backup entries and counted them as "secrets." They
// collapse into the count line by default, list only under --all, and the
// closing count never lumps the two together.
func TestPrintVaultList(t *testing.T) {
	secrets := []string{"notion/NOTION_API_KEY", "wiz/WIZ_CLIENT_ID"}
	backups := []string{"_backups/Users/x/notion/.env.jit-bak-1"}

	var buf bytes.Buffer
	printVaultList(&buf, secrets, backups, false, false, false, nil, "path")
	out := buf.String()
	if strings.Contains(out, "_backups/") {
		t.Errorf("default listing must not include _backups/ entries, got:\n%s", out)
	}
	// The footer wraps to the window, and it is a paragraph rather than an
	// indented row, so its continuation starts at column 0 where unwrap
	// cannot tell it from a new row. Assert the parts instead of guessing
	// where the break lands.
	for _, want := range []string{"2 secrets stored, plus 1 encrypted file backup", "jit migrate undo", "--all"} {
		if !strings.Contains(out, want) {
			t.Errorf("count line must summarize hidden backups and how to see them, missing %q, got:\n%s", want, out)
		}
	}

	buf.Reset()
	printVaultList(&buf, secrets, backups, true, false, false, nil, "path")
	out = buf.String()
	if !strings.Contains(out, "_backups/Users/x/notion/.env.jit-bak-1") {
		t.Errorf("--all must list backup entries, got:\n%s", out)
	}
	for _, want := range []string{"2 secrets stored, plus 1 encrypted file backup", "jit migrate undo"} {
		if !strings.Contains(out, want) {
			t.Errorf("--all count line must still separate secrets from backups, missing %q, got:\n%s", want, out)
		}
	}

	buf.Reset()
	printVaultList(&buf, nil, backups, false, false, false, nil, "path")
	out = buf.String()
	for _, want := range []string{"No secrets stored yet, 1 encrypted file backup", "jit migrate undo", "--all"} {
		if !strings.Contains(out, want) {
			t.Errorf("backups-only vault needs an honest empty state, missing %q, got:\n%s", want, out)
		}
	}

	// Backups-only with --all: the backups list, and the closing line
	// still says "No secrets" rather than the old "0 secret(s)".
	buf.Reset()
	printVaultList(&buf, nil, backups, true, false, false, nil, "path")
	out = buf.String()
	if !strings.Contains(out, "_backups/Users/x/notion/.env.jit-bak-1") {
		t.Errorf("backups-only --all must list backup entries, got:\n%s", out)
	}
	if !strings.Contains(unwrap(out), "No secrets stored yet, 1 encrypted file backup kept for jit migrate undo.") {
		t.Errorf("backups-only --all count line must not say '0 secrets', got:\n%s", out)
	}

	buf.Reset()
	printVaultList(&buf, nil, nil, false, false, false, nil, "path")
	if !strings.Contains(buf.String(), "No secrets stored yet. Run jit vault set <path>") {
		t.Errorf("empty vault keeps the standard empty state, got:\n%s", buf.String())
	}
}

// TestPrintVaultListGrouped pins the terminal display: secrets collapse
// under a "prefix/ (n)" header per first path segment with keys indented,
// pathless entries stay bare lines, backups stay flat full paths even
// under --all, and the closing count line is unchanged by grouping.
func TestPrintVaultListGrouped(t *testing.T) {
	secrets := []string{
		"descope/KEY_1",
		"descope/KEY_2",
		"toplevel-secret",
		"wiz/WIZ_CLIENT_ID",
	}
	backups := []string{"_backups/Users/x/notion/.env.jit-bak-1"}

	var buf bytes.Buffer
	printVaultList(&buf, secrets, backups, true, true, false, nil, "path")
	out := buf.String()
	for _, want := range []string{
		"[descope] 2",
		"KEY_1",
		"KEY_2",
		"toplevel-secret",
		"[wiz] 1",
		"WIZ_CLIENT_ID",
		"_backups/Users/x/notion/.env.jit-bak-1",
		"4 secrets stored, plus 1 encrypted file backup kept for jit migrate undo.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("grouped listing missing %q, got:\n%s", want, out)
		}
	}
	if strings.Contains(out, "  descope/KEY_1") {
		t.Errorf("grouped keys must not repeat their prefix, got:\n%s", out)
	}
	if strings.Contains(out, "[_backups] 1") {
		t.Errorf("backups must never be grouped, got:\n%s", out)
	}
}

// TestPrintVaultListLong pins the -l annotation: each key gains its class
// and last-updated age, a secret without provenance reads "unknown", and a
// secret with no timestamp shows the class alone (never a 1970 age).
func TestPrintVaultListLong(t *testing.T) {
	secrets := []string{"jamf/API_KEY", "jamf/OLD_KEY"}
	now := time.Now().Unix()
	meta := map[string]vault.SecretInfo{
		"jamf/API_KEY": {Path: "jamf/API_KEY", Class: vault.ClassDotenv, UpdatedUnix: now - 3*24*3600},
		"jamf/OLD_KEY": {Path: "jamf/OLD_KEY"}, // no class, no timestamp (a v1 secret)
	}

	var buf bytes.Buffer
	printVaultList(&buf, secrets, nil, false, true, true, meta, "path")
	out := buf.String()

	if !strings.Contains(out, "dotenv · updated") {
		t.Errorf("-l must annotate the class and age, got:\n%s", out)
	}
	if !strings.Contains(out, "unknown") {
		t.Errorf("-l must render a provenance-less secret as \"unknown\", got:\n%s", out)
	}
	// The no-timestamp secret shows class only, never a bogus age.
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "OLD_KEY") && strings.Contains(line, "updated") {
			t.Errorf("a secret with no UpdatedUnix must not show an age, got line:\n%s", line)
		}
	}
}

// TestGroupHeaderProvenance pins the top-level group header's provenance
// note: a group whose members share one recorded Origin states it once on
// the header with the newest member's age ("dotenv · from <origin> · 2d
// ago"), a uniformly manual group reads "set directly", mixed origins say
// nothing, nested headers never restate the top-level fact, and an origin
// too long for the window is truncated, never wrapped.
func TestGroupHeaderProvenance(t *testing.T) {
	now := time.Now().Unix()
	secrets := []string{
		"jamf/CLIENT_ID", "jamf/CLIENT_SECRET",
		"manual-grp/KEY_A", "manual-grp/KEY_B",
		"mixed/ONE", "mixed/TWO",
		"nested/sub/KEY",
	}
	meta := map[string]vault.SecretInfo{
		"jamf/CLIENT_ID":     {Class: vault.ClassDotenv, Origin: "/x/scripts/jamf/.env", UpdatedUnix: now - 3*24*3600},
		"jamf/CLIENT_SECRET": {Class: vault.ClassDotenv, Origin: "/x/scripts/jamf/.env", UpdatedUnix: now - 9*24*3600},
		"manual-grp/KEY_A":   {Class: vault.ClassManual, UpdatedUnix: now - 3600},
		"manual-grp/KEY_B":   {Class: vault.ClassManual, UpdatedUnix: now - 7200},
		"mixed/ONE":          {Class: vault.ClassDotenv, Origin: "/x/a/.env", UpdatedUnix: now},
		"mixed/TWO":          {Class: vault.ClassDotenv, Origin: "/x/b/.env", UpdatedUnix: now},
		"nested/sub/KEY":     {Class: vault.ClassMCP, Origin: "/x/n/.mcp.json", UpdatedUnix: now},
	}

	var buf bytes.Buffer
	printVaultList(&buf, secrets, nil, false, true, false, meta, "path")
	out := buf.String()

	// Aligned layout (option A): every top-level name is padded to the
	// widest, so the count+class column and then the origin start at the
	// same screen column on every row. The facts are the same; only their
	// placement is shared.
	if !strings.Contains(out, "[jamf]") || !strings.Contains(out, "2 · dotenv") ||
		!strings.Contains(out, "/x/scripts/jamf/.env · 3d ago") {
		t.Errorf("uniform-origin group must carry origin + newest age on its header, got:\n%s", out)
	}
	if !strings.Contains(out, "set directly · 1h ago") {
		t.Errorf("uniformly manual group must read \"set directly\", got:\n%s", out)
	}
	// The alignment itself: the widest label here is "[manual-grp]" (12),
	// so every header's second column starts at the same offset.
	var starts []int
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "[") {
			continue
		}
		idx := strings.Index(line, "] ")
		if idx < 0 {
			continue
		}
		// column offset of the first non-space after the label
		off := idx + 2
		for off < len(line) && line[off] == ' ' {
			off++
		}
		starts = append(starts, off)
	}
	if len(starts) < 2 {
		t.Fatalf("expected several top-level headers, got:\n%s", out)
	}
	for _, s := range starts[1:] {
		if s != starts[0] {
			t.Errorf("top-level headers must share one column grid, offsets %v, got:\n%s", starts, out)
			break
		}
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "[mixed]") && strings.Contains(line, "/x/") {
			t.Errorf("mixed-origin group must not claim an origin, got line:\n%s", line)
		}
		// The nested [sub] header must not restate what [nested] already
		// carries.
		if strings.Contains(line, "[sub]") && (strings.Contains(line, "/x/") || strings.Contains(line, "ago")) {
			t.Errorf("nested header must not restate provenance, got line:\n%s", line)
		}
	}
	if !strings.Contains(out, "/x/n/.mcp.json") {
		t.Errorf("top-level header of a nested group carries the provenance, got:\n%s", out)
	}

	// An origin longer than the window is middle-truncated onto the one
	// header line, and a window too narrow for any useful origin drops it.
	long := "/very/long/prefix/" + strings.Repeat("deep/", 30) + ".env"
	buf.Reset()
	printVaultList(&buf, []string{"big/KEY"}, nil, false, true, false,
		map[string]vault.SecretInfo{"big/KEY": {Class: vault.ClassDotenv, Origin: long, UpdatedUnix: now}}, "path")
	header, _, _ := strings.Cut(buf.String(), "\n")
	if w := termtext.VisibleWidth(header); w > 80 {
		t.Errorf("header must truncate to the window, got %d columns:\n%s", w, header)
	}
	if !strings.Contains(header, "…") {
		t.Errorf("a too-long origin must be visibly truncated, got:\n%s", header)
	}
}

// TestPrintSecretsByProvenance pins --by origin: secrets bucket under their
// source file (with class + count), a distinct file makes a distinct bucket,
// and provenance-less secrets collect under "no recorded source" last.
//
// The header is the house `[Name] count · extra` motif and members flow into
// columns (design/output-style.md rules 1, 3 and 4) — this axis used to print
// a faint "path  class (n)" header over a one-per-line stack, so the same
// vault rendered two different ways depending on the --by flag.
func TestPrintSecretsByProvenance(t *testing.T) {
	secrets := []string{"jamf/CLIENT_ID", "jamf/CLIENT_SECRET", "mcp-x/TOKEN", "legacy/OLD"}
	meta := map[string]vault.SecretInfo{
		"jamf/CLIENT_ID":     {Class: vault.ClassDotenv, GroupID: "g1", Origin: "~/scripts/jamf/.env"},
		"jamf/CLIENT_SECRET": {Class: vault.ClassDotenv, GroupID: "g1", Origin: "~/scripts/jamf/.env"},
		"mcp-x/TOKEN":        {Class: vault.ClassMCP, GroupID: "g2", Origin: "~/.mcp.json"},
		"legacy/OLD":         {}, // no provenance
	}

	var buf bytes.Buffer
	printSecretsByProvenance(&buf, secrets, meta, "origin")
	out := buf.String()

	for _, want := range []string{
		"[~/scripts/jamf/.env] 2 · dotenv",
		"jamf/CLIENT_ID",
		"jamf/CLIENT_SECRET",
		"[~/.mcp.json] 1 · mcp",
		"mcp-x/TOKEN",
		"[no recorded source] 1",
		"legacy/OLD",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("--by origin output missing %q, got:\n%s", want, out)
		}
	}
	// Brackets already delimit the label, so the old parenthesized phrase
	// would now read as "[(no recorded source)]".
	if strings.Contains(out, "[(no recorded source)]") {
		t.Errorf("label must not keep its own parentheses inside the brackets, got:\n%s", out)
	}
	// The unknown bucket sorts last.
	if idx := strings.Index(out, "no recorded source"); idx >= 0 && idx < strings.Index(out, "~/.mcp.json") {
		t.Errorf("no recorded source must sort after real origins, got:\n%s", out)
	}
	// Two secrets from one origin share a row rather than stacking.
	if !strings.Contains(out, "jamf/CLIENT_ID") || !strings.Contains(out, "jamf/CLIENT_SECRET") {
		t.Errorf("both members must appear, got:\n%s", out)
	}
}

// TestPrintGroupedSecretsNests pins the tree renderer: multi-segment paths
// collapse under a shared parent with indented subtrees, while a single-level
// path renders flat exactly as before.
func TestPrintGroupedSecretsNests(t *testing.T) {
	secrets := []string{
		"custom_scripts/jamf/CLIENT_ID",
		"custom_scripts/jamf/CLIENT_SECRET",
		"custom_scripts/notion/API_KEY",
		"flat/ONLY",
	}
	var buf bytes.Buffer
	printGroupedSecrets(&buf, secrets, nil, false)
	out := buf.String()

	for _, want := range []string{
		"[custom_scripts] 3",
		"  [jamf] 2",
		"CLIENT_ID",
		"CLIENT_SECRET",
		"  [notion] 1",
		"API_KEY",
		"[flat] 1",
		"ONLY",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("nested tree missing %q, got:\n%s", want, out)
		}
	}
	// The old flat behavior (key keeping its mid-path) must be gone.
	if strings.Contains(out, "jamf/CLIENT_ID") {
		t.Errorf("nested path must not render flat, got:\n%s", out)
	}
}

func TestLooksLikeConfig(t *testing.T) {
	config := []string{"OUTPUT_FILE", "DEBUG", "AWS_REGION", "LOG_LEVEL", "HIBOB_FIELDS", "PORT"}
	secret := []string{"API_KEY", "JAMF_CLIENT_SECRET", "STRIPE_KEY", "DATABASE_URL", "AUTH_TOKEN", "WIZ_CLIENT_ID", "PRIVATE_KEY"}
	for _, n := range config {
		if !looksLikeConfig(n) {
			t.Errorf("looksLikeConfig(%q) = false, want true", n)
		}
	}
	for _, n := range secret {
		if looksLikeConfig(n) {
			t.Errorf("looksLikeConfig(%q) = true, want false (never dim a possible secret)", n)
		}
	}
}

// TestPrintDuplicateGroupNudge pins the origin-backed duplicate hint: the
// nudge fires only when groups share both their key set AND origin evidence
// (the same recorded file, or the same file's tail in two directories), it
// routes to `jit vault duplicates` rather than telling anyone to rm, and —
// the regression that motivated the rewrite — same key names from DIFFERENT
// live files stay silent, because five export scripts sharing Jamf keys are
// not stale copies of each other.
func TestPrintDuplicateGroupNudge(t *testing.T) {
	origin := func(paths []string, o string) map[string]vault.SecretInfo {
		m := map[string]vault.SecretInfo{}
		for _, p := range paths {
			m[p] = vault.SecretInfo{Origin: o}
		}
		return m
	}
	merge := func(ms ...map[string]vault.SecretInfo) map[string]vault.SecretInfo {
		out := map[string]vault.SecretInfo{}
		for _, m := range ms {
			for k, v := range m {
				out[k] = v
			}
		}
		return out
	}

	// The same file migrated into two namespaces -> nudge naming the file.
	sameFile := []string{"wiz/A", "wiz/B", "wiz-2/A", "wiz-2/B"}
	meta := merge(
		origin([]string{"wiz/A", "wiz/B"}, "/u/x/scripts/.env"),
		origin([]string{"wiz-2/A", "wiz-2/B"}, "/u/x/scripts/.env"),
	)
	var buf bytes.Buffer
	printDuplicateGroupNudge(&buf, sameFile, meta)
	if !strings.Contains(buf.String(), "wiz, wiz-2 were migrated from the same file") ||
		!strings.Contains(buf.String(), "jit vault duplicates") {
		t.Errorf("expected a same-file nudge routing to jit vault duplicates, got:\n%s", buf.String())
	}

	// Two copies of one file in different trees -> nudge naming the tail,
	// even for a single-key group (origin evidence needs no key-count floor).
	copied := []string{"mcp-caido/CAIDO_URL", "mcp-caido-2/CAIDO_URL"}
	meta = merge(
		origin([]string{"mcp-caido/CAIDO_URL"}, "/u/x/Documents/ws/.mcp.json"),
		origin([]string{"mcp-caido-2/CAIDO_URL"}, "/u/x/Desktop/Share/ws/.mcp.json"),
	)
	buf.Reset()
	printDuplicateGroupNudge(&buf, copied, meta)
	if !strings.Contains(buf.String(), "two copies of ws/.mcp.json") {
		t.Errorf("expected a copied-file nudge naming the tail, got:\n%s", buf.String())
	}

	// Same key names from different live files -> silence. This is the
	// shared-credential shape the old key-set-only nudge mislabeled.
	shared := []string{
		"export-a/JAMF_CLIENT_ID", "export-a/JAMF_CLIENT_SECRET", "export-a/JAMF_URL",
		"export-b/JAMF_CLIENT_ID", "export-b/JAMF_CLIENT_SECRET", "export-b/JAMF_URL",
	}
	meta = merge(
		origin([]string{"export-a/JAMF_CLIENT_ID", "export-a/JAMF_CLIENT_SECRET", "export-a/JAMF_URL"}, "/u/x/scripts/inventory/.env"),
		origin([]string{"export-b/JAMF_CLIENT_ID", "export-b/JAMF_CLIENT_SECRET", "export-b/JAMF_URL"}, "/u/x/scripts/computers/.env"),
	)
	buf.Reset()
	printDuplicateGroupNudge(&buf, shared, meta)
	if buf.Len() != 0 {
		t.Errorf("same keys from different files must not nudge, got:\n%s", buf.String())
	}

	// No recorded origin -> key names alone are not evidence -> silence.
	buf.Reset()
	printDuplicateGroupNudge(&buf, sameFile, map[string]vault.SecretInfo{})
	if buf.Len() != 0 {
		t.Errorf("origin-less groups must not nudge, got:\n%s", buf.String())
	}
	// The rm footgun must be gone from every nudge.
	buf.Reset()
	printDuplicateGroupNudge(&buf, sameFile, merge(
		origin([]string{"wiz/A", "wiz/B"}, "/u/x/scripts/.env"),
		origin([]string{"wiz-2/A", "wiz-2/B"}, "/u/x/scripts/.env"),
	))
	if strings.Contains(buf.String(), "vault rm") {
		t.Errorf("the nudge must never recommend rm on listing evidence, got:\n%s", buf.String())
	}
}

func TestSecretMetaSuffix(t *testing.T) {
	if got := secretMetaSuffix(vault.SecretInfo{}); got != "unknown" {
		t.Errorf("empty info suffix = %q, want %q", got, "unknown")
	}
	if got := secretMetaSuffix(vault.SecretInfo{Class: vault.ClassMCP}); got != "mcp" {
		t.Errorf("classed-but-timeless suffix = %q, want %q", got, "mcp")
	}
	got := secretMetaSuffix(vault.SecretInfo{Class: vault.ClassMCP, UpdatedUnix: time.Now().Unix()})
	if !strings.HasPrefix(got, "mcp · updated ") {
		t.Errorf("classed+timed suffix = %q, want prefix %q", got, "mcp · updated ")
	}
	// A config-shaped key name appends the hint; a secret-shaped one never does.
	if got := secretMetaSuffix(vault.SecretInfo{Path: "hibob/OUTPUT_FILE", Class: vault.ClassDotenv}); !strings.Contains(got, "likely config") {
		t.Errorf("config-named suffix = %q, want a \"likely config\" hint", got)
	}
	if got := secretMetaSuffix(vault.SecretInfo{Path: "jamf/CLIENT_SECRET", Class: vault.ClassDotenv}); strings.Contains(got, "likely config") {
		t.Errorf("secret-named suffix = %q, must not be hinted as config", got)
	}
}

// TestVaultListEndToEndWithoutAuth drives the full `jit vault list` RunE
// through rootCmd — possible at all only because list runs on a bare
// read-only Vault (no agent dial, no KeyWrapper, no device-id write), the
// regression this test pins. Also covers natural ordering end to end and
// the --format json shape.
func TestVaultListEndToEndWithoutAuth(t *testing.T) {
	withFixtureHome(t)
	vaultListFormat = "text"
	vaultListAll = false
	t.Cleanup(func() { vaultListFormat = "text" })
	seedFixtureVault(t, "descope/PROJECT_10")
	seedFixtureVault(t, "descope/PROJECT_2")

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs([]string{"vault", "list"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("jit vault list: %v", err)
	}
	out := buf.String()
	i2, i10 := strings.Index(out, "descope/PROJECT_2"), strings.Index(out, "descope/PROJECT_10")
	if i2 < 0 || i10 < 0 || i2 > i10 {
		t.Errorf("expected PROJECT_2 before PROJECT_10 (natural order), got:\n%s", out)
	}
	if !strings.Contains(unwrap(out), "2 secrets stored.") {
		t.Errorf("expected the closing count line, got:\n%s", out)
	}

	buf.Reset()
	rootCmd.SetArgs([]string{"vault", "list", "--format", "json"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("jit vault list --format json: %v", err)
	}
	var res struct {
		Secrets []struct {
			Path string `json:"path"`
		} `json:"secrets"`
		Backups []string `json:"backups"`
	}
	if err := json.Unmarshal(buf.Bytes(), &res); err != nil {
		t.Fatalf("parsing json output: %v\n%s", err, buf.String())
	}
	gotPaths := make([]string, len(res.Secrets))
	for i, s := range res.Secrets {
		gotPaths[i] = s.Path
	}
	if strings.Join(gotPaths, ",") != "descope/PROJECT_2,descope/PROJECT_10" {
		t.Errorf("json secret paths = %v, want natural order", gotPaths)
	}
	if res.Backups == nil || len(res.Backups) != 0 {
		t.Errorf("json backups = %#v, want empty non-nil array", res.Backups)
	}
}

func TestSplitBackupPaths(t *testing.T) {
	secrets, backups := splitBackupPaths([]string{
		"_backups/Users/x/.env.jit-bak-1",
		"notion/NOTION_API_KEY",
	})
	if len(secrets) != 1 || secrets[0] != "notion/NOTION_API_KEY" {
		t.Errorf("secrets = %v, want [notion/NOTION_API_KEY]", secrets)
	}
	if len(backups) != 1 || backups[0] != "_backups/Users/x/.env.jit-bak-1" {
		t.Errorf("backups = %v, want the _backups/ entry", backups)
	}
	// Never nil, even on empty input — the JSON shape's own guarantee.
	secrets, backups = splitBackupPaths(nil)
	if secrets == nil || backups == nil {
		t.Error("splitBackupPaths(nil) must return empty slices, never nil")
	}
}

// TestSecretProfileReferences drives the `jit vault get` footer's lookup:
// a global-store manifest referencing the secret comes back by name with
// the .source sidecar's recorded config file, and an unreferenced path
// returns nothing. The footer itself is stderr-TTY-gated (invisible to
// piped test output by design), so the helper is the testable surface.
func TestSecretProfileReferences(t *testing.T) {
	home := withFixtureHome(t)
	profilesDir := filepath.Join(home, ".jit", "profiles")
	if err := os.MkdirAll(profilesDir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(profilesDir, "mcp-wiz.yaml"),
		[]byte("WIZ_CLIENT_ID: mcp-wiz/WIZ_CLIENT_ID\n"), 0o600); err != nil {
		t.Fatalf("writing manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(profilesDir, "mcp-wiz.source"),
		[]byte("/Users/x/proj/.mcp.json\n"), 0o600); err != nil {
		t.Fatalf("writing sidecar: %v", err)
	}

	names, source := secretProfileReferences("mcp-wiz/WIZ_CLIENT_ID")
	if strings.Join(names, ",") != "mcp-wiz" {
		t.Errorf("names = %v, want [mcp-wiz]", names)
	}
	if source != "/Users/x/proj/.mcp.json" {
		t.Errorf("source = %q, want the sidecar's recorded config file", source)
	}

	names, source = secretProfileReferences("unreferenced/PATH")
	if len(names) != 0 || source != "" {
		t.Errorf("unreferenced path returned names=%v source=%q, want none", names, source)
	}
}

func TestConfirmPromptLeavesRestOfStdinUnread(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.SetIn(strings.NewReader("y\nhunter2-passphrase\n"))
	var errBuf bytes.Buffer
	cmd.SetErr(&errBuf)

	if !confirmPrompt(cmd, "Proceed? [y/N] ") {
		t.Fatal("confirmPrompt = false, want true for a piped y")
	}
	rest, err := io.ReadAll(cmd.InOrStdin())
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	// The line after the confirmation is the passphrase `vault import
	// --stdin` reads next — confirmPrompt buffering past its own line
	// swallowed it (a real bug: piped import always failed "wrong
	// passphrase").
	if string(rest) != "hunter2-passphrase\n" {
		t.Errorf("stdin after confirmPrompt = %q, want the untouched passphrase line", rest)
	}
}

func TestConfirmPromptDecline(t *testing.T) {
	for _, input := range []string{"n\n", "\n", ""} {
		cmd := &cobra.Command{}
		cmd.SetIn(strings.NewReader(input))
		var errBuf bytes.Buffer
		cmd.SetErr(&errBuf)
		if confirmPrompt(cmd, "Proceed? [y/N] ") {
			t.Errorf("confirmPrompt(%q) = true, want false", input)
		}
	}
}

// A malformed path must be rejected before the confirmation and the
// biometric gate. It used to reach vault.Remove, which validates -- but only
// after jit had already demanded a fingerprint for an operation it was always
// going to refuse.
func TestVaultRmRejectsBadPathBeforePrompting(t *testing.T) {
	cmd := vaultRmCmd
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	err := cmd.RunE(cmd, []string{"not a valid path!! with spaces"})
	if err == nil {
		t.Fatal("RunE succeeded on a malformed secret path, want a validation error")
	}
	if !strings.Contains(err.Error(), "must be slash-separated") {
		t.Errorf("error = %v, want the path-shape rejection", err)
	}
	// No prompt, no gate: the run never got far enough to write anything.
	if out.Len() != 0 {
		t.Errorf("output = %q, want nothing printed before the rejection", out.String())
	}
}

func TestPromptEllipsis(t *testing.T) {
	if got := promptEllipsis("short/path", 60); got != "short/path" {
		t.Errorf("promptEllipsis kept-as-is = %q, want the input unchanged", got)
	}
	long := strings.Repeat("a", 40) + "/" + strings.Repeat("b", 40)
	got := promptEllipsis(long, 30)
	if len([]rune(got)) > 30 {
		t.Errorf("promptEllipsis(%d chars) = %d runes, want <= 30", len(long), len([]rune(got)))
	}
	// Head and tail survive: they are the identifying halves of a secret path.
	if !strings.HasPrefix(got, "aaa") || !strings.HasSuffix(got, "bbb") {
		t.Errorf("promptEllipsis = %q, want the head and tail kept", got)
	}
}

// The export is the one file where jit's secrets leave their device binding:
// the vault is useless without this Mac's keychain, while the export opens
// anywhere for anyone holding it and the passphrase. So a short passphrase
// gets one line — and only a line. It must never refuse or re-prompt: an
// enforced minimum would break `--stdin` exports piping a passphrase in from
// a password manager, turning a working backup script into a broken one.
func TestWarnWeakExportPassphrase(t *testing.T) {
	cases := []struct {
		name       string
		passphrase string
		wantWarn   bool
		wantText   string
	}{
		{"one character", "x", true, "1 character"},
		{"short", "hunter2", true, "7 characters"},
		{"just under the line", "elevenchars", true, "11 characters"},
		{"at the line", "twelvechars!", false, ""},
		{"a real passphrase", "correct horse battery staple", false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := &cobra.Command{}
			var stderr bytes.Buffer
			cmd.SetErr(&stderr)

			warnWeakExportPassphrase(cmd, []byte(tc.passphrase))

			got := stderr.String()
			if !tc.wantWarn {
				if got != "" {
					t.Fatalf("warned on a passphrase that is long enough: %q", got)
				}
				return
			}
			if got == "" {
				t.Fatal("no warning for a short passphrase on a full-vault export")
			}
			if !strings.Contains(got, tc.wantText) {
				t.Errorf("warning = %q, want it to name the length %q", got, tc.wantText)
			}
			// The passphrase itself must never be echoed back — it was typed
			// hidden, and a terminal it appears in is one it can be read from.
			if strings.Contains(got, tc.passphrase) {
				t.Errorf("warning echoed the passphrase itself: %q", got)
			}
		})
	}
}
