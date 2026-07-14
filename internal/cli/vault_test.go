// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package cli

import (
	"bytes"
	"context"
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
// --format value fails validation before openVault() is ever reached — the
// only part of `jit vault list` this package can exercise without a real
// Touch ID/passcode approval (this package's testing discipline: any
// RunE reaching openVault() needs manual verification on real hardware
// instead).
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
	rootCmd.SetErr(&buf)                 // confirmation prompts go to stderr — capture both streams in order
	rootCmd.SetIn(strings.NewReader("")) // EOF — an empty/declined answer
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
		t.Error("undo index still exists after clean — jit migrate undo would half-fail against deleted backup secrets")
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
	printVaultList(&buf, secrets, backups, false)
	out := buf.String()
	if strings.Contains(out, "_backups/") {
		t.Errorf("default listing must not include _backups/ entries, got:\n%s", out)
	}
	if !strings.Contains(out, "2 secret(s) stored, plus 1 encrypted file backup(s) kept for `jit migrate undo` (list with --all).") {
		t.Errorf("count line must summarize hidden backups and how to see them, got:\n%s", out)
	}

	buf.Reset()
	printVaultList(&buf, secrets, backups, true)
	out = buf.String()
	if !strings.Contains(out, "_backups/Users/x/notion/.env.jit-bak-1") {
		t.Errorf("--all must list backup entries, got:\n%s", out)
	}
	if !strings.Contains(out, "2 secret(s) stored, plus 1 encrypted file backup(s) kept for `jit migrate undo`.") {
		t.Errorf("--all count line must still separate secrets from backups, got:\n%s", out)
	}

	buf.Reset()
	printVaultList(&buf, nil, backups, false)
	out = buf.String()
	if !strings.Contains(out, "No secrets stored yet — 1 encrypted file backup(s) kept for `jit migrate undo` (list with --all).") {
		t.Errorf("backups-only vault needs an honest empty state, got:\n%s", out)
	}

	buf.Reset()
	printVaultList(&buf, nil, nil, false)
	if !strings.Contains(buf.String(), "No secrets stored yet. Run `jit vault set <path>`") {
		t.Errorf("empty vault keeps the standard empty state, got:\n%s", buf.String())
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
