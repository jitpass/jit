// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

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
	if !strings.Contains(buf.String(), "Pruned 2 stale backup(s)") {
		t.Errorf("expected 2 stale backups pruned (a's two older), got:\n%s", buf.String())
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
	if !strings.Contains(buf.String(), "Deleted 1 orphaned secret(s)") {
		t.Errorf("expected the delete count, got:\n%s", buf.String())
	}
	if ok, _ := v.Exists("custom_scripts-descope/DESCOPE_PROJECT_1"); ok {
		t.Error("prune must delete the orphan")
	}
	if ok, _ := v.Exists("kept/API_KEY"); !ok {
		t.Error("prune must keep the referenced secret")
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
	if !strings.Contains(out, "ALL 1 secret(s)") {
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
	if !strings.Contains(buf.String(), "Deleted 2 secret(s)") {
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
	printVaultList(&buf, secrets, backups, false, false, nil, "path")
	out := buf.String()
	if strings.Contains(out, "_backups/") {
		t.Errorf("default listing must not include _backups/ entries, got:\n%s", out)
	}
	if !strings.Contains(out, "2 secrets stored, plus 1 encrypted file backup kept for `jit migrate undo` (list with --all).") {
		t.Errorf("count line must summarize hidden backups and how to see them, got:\n%s", out)
	}

	buf.Reset()
	printVaultList(&buf, secrets, backups, true, false, nil, "path")
	out = buf.String()
	if !strings.Contains(out, "_backups/Users/x/notion/.env.jit-bak-1") {
		t.Errorf("--all must list backup entries, got:\n%s", out)
	}
	if !strings.Contains(out, "2 secrets stored, plus 1 encrypted file backup kept for `jit migrate undo`.") {
		t.Errorf("--all count line must still separate secrets from backups, got:\n%s", out)
	}

	buf.Reset()
	printVaultList(&buf, nil, backups, false, false, nil, "path")
	out = buf.String()
	if !strings.Contains(out, "No secrets stored yet, 1 encrypted file backup kept for `jit migrate undo` (list with --all).") {
		t.Errorf("backups-only vault needs an honest empty state, got:\n%s", out)
	}

	// Backups-only with --all: the backups list, and the closing line
	// still says "No secrets" rather than the old "0 secret(s)".
	buf.Reset()
	printVaultList(&buf, nil, backups, true, false, nil, "path")
	out = buf.String()
	if !strings.Contains(out, "_backups/Users/x/notion/.env.jit-bak-1") {
		t.Errorf("backups-only --all must list backup entries, got:\n%s", out)
	}
	if !strings.Contains(out, "No secrets stored yet, 1 encrypted file backup kept for `jit migrate undo`.") {
		t.Errorf("backups-only --all count line must not say '0 secrets', got:\n%s", out)
	}

	buf.Reset()
	printVaultList(&buf, nil, nil, false, false, nil, "path")
	if !strings.Contains(buf.String(), "No secrets stored yet. Run `jit vault set <path>`") {
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
	printVaultList(&buf, secrets, backups, true, true, nil, "path")
	out := buf.String()
	for _, want := range []string{
		"descope/ (2)",
		"  KEY_1",
		"  KEY_2",
		"toplevel-secret",
		"wiz/ (1)",
		"  WIZ_CLIENT_ID",
		"_backups/Users/x/notion/.env.jit-bak-1",
		"4 secrets stored, plus 1 encrypted file backup kept for `jit migrate undo`.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("grouped listing missing %q, got:\n%s", want, out)
		}
	}
	if strings.Contains(out, "  descope/KEY_1") {
		t.Errorf("grouped keys must not repeat their prefix, got:\n%s", out)
	}
	if strings.Contains(out, "_backups/ (") {
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
	printVaultList(&buf, secrets, nil, false, true, meta, "path")
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

// TestPrintSecretsByProvenance pins --by origin: secrets bucket under their
// source file (with class + count), a distinct file makes a distinct bucket,
// and provenance-less secrets collect under "(no recorded source)" last.
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
		"~/scripts/jamf/.env  dotenv (2)",
		"  jamf/CLIENT_ID",
		"  jamf/CLIENT_SECRET",
		"~/.mcp.json  mcp (1)",
		"  mcp-x/TOKEN",
		"(no recorded source) (1)",
		"  legacy/OLD",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("--by origin output missing %q, got:\n%s", want, out)
		}
	}
	// The unknown bucket sorts last.
	if idx := strings.Index(out, "(no recorded source)"); idx >= 0 && idx < strings.Index(out, "~/.mcp.json") {
		t.Errorf("(no recorded source) must sort after real origins, got:\n%s", out)
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
	printGroupedSecrets(&buf, secrets, nil)
	out := buf.String()

	for _, want := range []string{
		"custom_scripts/ (3)",
		"  jamf/ (2)",
		"    CLIENT_ID",
		"    CLIENT_SECRET",
		"  notion/ (1)",
		"    API_KEY",
		"flat/ (1)",
		"  ONLY",
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

// TestPrintDuplicateGroupNudge: identical key sets across groups trigger one
// hint, but small look-alikes (2 keys) and genuinely distinct groups don't.
func TestPrintDuplicateGroupNudge(t *testing.T) {
	// wiz/ and custom_scripts-wiz/ share five keys -> nudge.
	dup := []string{
		"wiz/A", "wiz/B", "wiz/C", "wiz/D",
		"custom_scripts-wiz/A", "custom_scripts-wiz/B", "custom_scripts-wiz/C", "custom_scripts-wiz/D",
	}
	var buf bytes.Buffer
	printDuplicateGroupNudge(&buf, dup)
	if !strings.Contains(buf.String(), "wiz/, custom_scripts-wiz/") && !strings.Contains(buf.String(), "hold the same keys") {
		t.Errorf("expected a duplicate-group nudge, got:\n%s", buf.String())
	}

	// Two-key sandboxes are below the threshold -> silence.
	buf.Reset()
	small := []string{"sandbox/DATABASE_URL", "sandbox/STRIPE_KEY", "sandbox-2/DATABASE_URL", "sandbox-2/STRIPE_KEY"}
	printDuplicateGroupNudge(&buf, small)
	if buf.Len() != 0 {
		t.Errorf("2-key look-alikes must not nudge, got:\n%s", buf.String())
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
	if !strings.Contains(out, "2 secrets stored.") {
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
