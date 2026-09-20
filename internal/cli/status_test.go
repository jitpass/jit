// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jitpass/jit/internal/agent"
	"github.com/jitpass/jit/internal/guard"
	"github.com/jitpass/jit/internal/keychainwrap"
	"github.com/jitpass/jit/internal/migrate"
	"github.com/jitpass/jit/internal/mount"
	"github.com/jitpass/jit/internal/vault"
)

func execStatus(t *testing.T, args ...string) (stdout string, err error) {
	t.Helper()
	statusFormat = "text"
	statusSecretsDetail = false
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetArgs(append([]string{"status"}, args...))
	err = rootCmd.Execute()
	return buf.String(), err
}

func TestStatusEverythingEmpty(t *testing.T) {
	withFixtureHome(t)
	withFixtureCwd(t)

	out, err := execStatus(t)
	if err != nil {
		t.Fatalf("jit status: %v", err)
	}
	for _, want := range []string{
		// The jit row is the version answering, nothing more — the state of
		// each section is that section's own row to report.
		"jit      " + shortVersion(agent.Version()),
		"vault    no secrets yet",
		"service  ✗ not running",
		"secrets  none stored yet",
		"mounts   none registered",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected output to contain %q, got:\n%s", want, out)
		}
	}
}

// TestShortVersion pins goPseudoVersion against literal inputs, because the
// two places the status row is asserted — status_test.go's "jit " + …
// expectation above and status_agent_test.go's wantVersions — both BUILD the
// expected string by calling shortVersion, the production expression under
// test. Both sides of those comparisons move together, so a broken regexp
// keeps them green while `jit status` prints a build-system artifact nobody
// reads. Those two lines were shortVersion's only appearances in any test.
func TestShortVersion(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		// A released binary carries a plain version and must pass through.
		{"v0.67.0", "v0.67.0"},
		{"0.67.0", "0.67.0"},
		// Go's pseudo-version tail for a checkout with a preceding tag…
		{"v0.67.0-0.20260801120000-abcdef123456", "v0.67.0"},
		// …and the +dirty variant a modified tree produces.
		{"v0.67.0-0.20260801120000-abcdef123456+dirty", "v0.67.0"},
		// The untagged shape, where the "0." group is absent.
		{"v0.0.0-20260801120000-abcdef123456", "v0.0.0"},
		// A genuine prerelease suffix is short and meaningful: keep it.
		{"v0.67.0-rc1", "v0.67.0-rc1"},
		// Only the TAIL is a pseudo-version; the same shape mid-string is not.
		{"v0.67.0-0.20260801120000-abcdef123456-rc1", "v0.67.0-0.20260801120000-abcdef123456-rc1"},
		{"", ""},
	} {
		if got := shortVersion(tc.in); got != tc.want {
			t.Errorf("shortVersion(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestStatusVaultReportsSecretCount(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)
	plantVaultSecret(t, home, "stripe/dev-key")
	plantVaultSecret(t, home, "aws/s3-access-key")

	out, err := execStatus(t)
	if err != nil {
		t.Fatalf("jit status: %v", err)
	}
	if !strings.Contains(out, "vault    2 secrets in 2 groups") {
		t.Errorf("expected a secret count, got:\n%s", out)
	}
}

// `_backups/…` entries are migrate-undo snapshots, not secrets — folding
// them into the headline count made `jit status` disagree with
// `jit vault list` for the same vault (issue #1).
func TestStatusVaultCountExcludesBackups(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)
	plantVaultSecret(t, home, "stripe/dev-key")
	plantVaultSecret(t, home, "aws/s3-access-key")
	plantVaultSecret(t, home, "_backups/Users/x/app/.env.jit-bak-1")
	plantVaultSecret(t, home, "_backups/Users/x/app/.env.jit-bak-2")

	out, err := execStatus(t)
	if err != nil {
		t.Fatalf("jit status: %v", err)
	}
	// The backticks are hlCmds markup, stripped on the way out (cyan on a
	// terminal, plain here) — so the assertion must not contain them.
	if !strings.Contains(out, "vault    2 secrets in 2 groups · 2 file backups kept for jit migrate undo") {
		t.Errorf("expected backups excluded from the secret count and reported separately, got:\n%s", out)
	}
}

// A vault holding only undo backups is not "no secrets yet" — the
// `jit vault init` nudge would be wrong there.
func TestStatusVaultOnlyBackups(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)
	plantVaultSecret(t, home, "_backups/Users/x/app/.env.jit-bak-1")

	out, err := execStatus(t)
	if err != nil {
		t.Fatalf("jit status: %v", err)
	}
	if !strings.Contains(out, "vault    0 secrets · 1 file backup kept for jit migrate undo") {
		t.Errorf("expected a backups-only vault line, got:\n%s", out)
	}
	if strings.Contains(out, "no secrets yet") {
		t.Errorf("backups-only vault should not claim the vault is empty, got:\n%s", out)
	}
}

// plantUndoIndex writes the undo index that backs the prune nudge — the
// same YAML shape TestVaultPruneKeepsNewestBackupPerFile seeds.
func plantUndoIndex(t *testing.T, home string, records ...string) {
	t.Helper()
	root := filepath.Join(home, "Library", "Application Support", "jitpass")
	index := "backups:\n"
	for _, r := range records {
		index += "    - " + r + "\n"
	}
	if err := os.WriteFile(migrate.BackupIndexPath(root), []byte(index), 0o600); err != nil {
		t.Fatalf("seeding undo index: %v", err)
	}
}

// The prune nudge fires only when BOTH hold: the backup pile outweighs the
// vault itself (the point where "170 file backups" starts reading as a
// problem with no exit), AND prune would actually delete something. The
// second condition is the live lesson: a pile of newest-only backups kept
// the arrow pointing at a command that answered "Nothing to prune".
func TestStatusVaultPruneNudge(t *testing.T) {
	t.Run("a stale-heavy pile points at prune, with the count", func(t *testing.T) {
		home := withFixtureHome(t)
		withFixtureCwd(t)
		plantVaultSecret(t, home, "stripe/dev-key")
		plantVaultSecret(t, home, "_backups/a/.env.jit-bak-1")
		plantVaultSecret(t, home, "_backups/a/.env.jit-bak-2")
		plantUndoIndex(t, home,
			"{original_path: /a/.env, vault_path: _backups/a/.env.jit-bak-1, unix_ts: 1}",
			"{original_path: /a/.env, vault_path: _backups/a/.env.jit-bak-2, unix_ts: 2}")

		out, err := execStatus(t)
		if err != nil {
			t.Fatalf("jit status: %v", err)
		}
		if !strings.Contains(unwrap(out), "jit vault prune — deletes 1 stale backup, keeps each file's newest") {
			t.Errorf("expected a prune nudge naming the stale count, got:\n%s", out)
		}
	})

	t.Run("a pile of newest-only backups stays quiet", func(t *testing.T) {
		home := withFixtureHome(t)
		withFixtureCwd(t)
		plantVaultSecret(t, home, "stripe/dev-key")
		plantVaultSecret(t, home, "_backups/a/.env.jit-bak-1")
		plantVaultSecret(t, home, "_backups/b/.env.jit-bak-1")
		plantUndoIndex(t, home,
			"{original_path: /a/.env, vault_path: _backups/a/.env.jit-bak-1, unix_ts: 1}",
			"{original_path: /b/.env, vault_path: _backups/b/.env.jit-bak-1, unix_ts: 1}")

		out, err := execStatus(t)
		if err != nil {
			t.Fatalf("jit status: %v", err)
		}
		if strings.Contains(out, "jit vault prune") {
			t.Errorf("expected no prune nudge when every backup is already each file's newest, got:\n%s", out)
		}
	})

	t.Run("a balanced pile stays quiet even with stale backups", func(t *testing.T) {
		home := withFixtureHome(t)
		withFixtureCwd(t)
		plantVaultSecret(t, home, "stripe/dev-key")
		plantVaultSecret(t, home, "aws/s3-access-key")
		plantVaultSecret(t, home, "gcp/sa-key")
		plantVaultSecret(t, home, "_backups/a/.env.jit-bak-1")
		plantVaultSecret(t, home, "_backups/a/.env.jit-bak-2")
		plantUndoIndex(t, home,
			"{original_path: /a/.env, vault_path: _backups/a/.env.jit-bak-1, unix_ts: 1}",
			"{original_path: /a/.env, vault_path: _backups/a/.env.jit-bak-2, unix_ts: 2}")

		out, err := execStatus(t)
		if err != nil {
			t.Fatalf("jit status: %v", err)
		}
		if strings.Contains(out, "jit vault prune") {
			t.Errorf("expected no prune nudge for a modest backup pile, got:\n%s", out)
		}
	})
}

// The guard row is the prevention mode's one dashboard surface: present and
// green when the hook is fully in place, absent otherwise — like the
// sessions row, no state means no row, and the scan report owns the on-ramp.
func TestStatusGuardRow(t *testing.T) {
	t.Run("installed hook gets a row", func(t *testing.T) {
		home := withFixtureHome(t)
		withFixtureCwd(t)
		t.Setenv("ZDOTDIR", "")
		plantVaultSecret(t, home, "stripe/dev-key")
		hook := guard.HookPath(home)
		if err := os.MkdirAll(filepath.Dir(hook), 0o700); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if err := os.WriteFile(hook, []byte("# hook\n"), 0o600); err != nil {
			t.Fatalf("WriteFile hook: %v", err)
		}
		if err := os.WriteFile(filepath.Join(home, ".zshrc"), []byte(guard.RcLine()+"\n"), 0o600); err != nil {
			t.Fatalf("WriteFile zshrc: %v", err)
		}

		out, err := execStatus(t)
		if err != nil {
			t.Fatalf("jit status: %v", err)
		}
		if !strings.Contains(unwrap(out), "guard    ● zsh history hook active") {
			t.Errorf("expected a guard row for an installed hook, got:\n%s", out)
		}
	})

	t.Run("no hook, no row", func(t *testing.T) {
		home := withFixtureHome(t)
		withFixtureCwd(t)
		t.Setenv("ZDOTDIR", "")
		plantVaultSecret(t, home, "stripe/dev-key")

		out, err := execStatus(t)
		if err != nil {
			t.Fatalf("jit status: %v", err)
		}
		if strings.Contains(out, "guard    ") {
			t.Errorf("expected no guard row when the hook is not installed, got:\n%s", out)
		}
	})
}

// The three backup-nudge states: the vault's one disaster-recovery path
// (`jit vault export`) used to be entirely invisible — nothing ever
// suggested it existed, on a vault that only decrypts on this machine.
func TestStatusBackupNudgeWhenNeverExported(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)
	plantVaultSecret(t, home, "stripe/dev-key")

	out, err := execStatus(t)
	if err != nil {
		t.Fatalf("jit status: %v", err)
	}
	// Amber, not red: nothing is broken today, this is exposure to a future
	// event — red stays reserved for what is failing right now.
	if !strings.Contains(out, "backup   ○ no vault export on record") || !strings.Contains(out, "jit vault export") {
		t.Errorf("expected an amber never-exported nudge naming the command, got:\n%s", out)
	}
}

func TestStatusBackupUpToDate(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)
	plantVaultSecret(t, home, "stripe/dev-key")
	root := filepath.Join(home, "Library", "Application Support", "jitpass")
	if err := vault.RecordExport(root); err != nil {
		t.Fatalf("RecordExport: %v", err)
	}

	out, err := execStatus(t)
	if err != nil {
		t.Fatalf("jit status: %v", err)
	}
	if !strings.Contains(out, "backup   ● export up to date") {
		t.Errorf("expected an up-to-date backup line, got:\n%s", out)
	}
}

func TestStatusBackupStaleAfterNewSecret(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)
	root := filepath.Join(home, "Library", "Application Support", "jitpass")
	plantVaultSecret(t, home, "stripe/dev-key")
	if err := vault.RecordExport(root); err != nil {
		t.Fatalf("RecordExport: %v", err)
	}
	// A secret written after the export — Chtimes to a clearly-later
	// mtime rather than depending on wall-clock granularity.
	plantVaultSecret(t, home, "aws/new-key")
	later := time.Now().Add(time.Minute)
	if err := os.Chtimes(filepath.Join(root, "vault", "aws", "new-key.enc"), later, later); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}

	out, err := execStatus(t)
	if err != nil {
		t.Fatalf("jit status: %v", err)
	}
	if !strings.Contains(out, "backup   ○ secrets changed since the last export") {
		t.Errorf("expected a stale-backup nudge, got:\n%s", out)
	}
}

// TestStatusNoBackupNudgeOnEmptyVault: an empty vault has nothing worth
// exporting — nudging there would just be noise before first migrate.
func TestStatusNoBackupNudgeOnEmptyVault(t *testing.T) {
	withFixtureHome(t)
	withFixtureCwd(t)

	out, err := execStatus(t)
	if err != nil {
		t.Fatalf("jit status: %v", err)
	}
	if strings.Contains(out, "backup   ") {
		t.Errorf("expected no Backup line for an empty vault, got:\n%s", out)
	}
}

func TestStatusSecretsWiredResolveCleanly(t *testing.T) {
	home := withFixtureHome(t)
	cwd := withFixtureCwd(t)
	writeFixtureProfile(t, cwd, "aws-admin", "AWS_ACCESS_KEY_ID: aws/s3-access-key\n")
	plantVaultSecret(t, home, "aws/s3-access-key")

	out, err := execStatus(t)
	if err != nil {
		t.Fatalf("jit status: %v", err)
	}
	// The total moved to the vault row; the secrets section now carries only
	// the reconciliation it is actually about.
	if !strings.Contains(out, "vault    1 secret in 1 group") {
		t.Errorf("expected a stored-secret headline, got:\n%s", out)
	}
	if !strings.Contains(out, "Wired here") || !strings.Contains(out, "1 group via 1 profile (1 reference), all resolve.") {
		t.Errorf("expected the wired secret to resolve cleanly, got:\n%s", out)
	}
}

func TestStatusSecretsWiredButBrokenPointsAtDoctor(t *testing.T) {
	withFixtureHome(t)
	cwd := withFixtureCwd(t)
	writeFixtureProfile(t, cwd, "aws-admin", "AWS_ACCESS_KEY_ID: aws/s3-access-key\n")
	// Deliberately no plantVaultSecret call — the referenced path is missing, so
	// the wired reference is broken even though the vault is otherwise empty.

	out, err := execStatus(t)
	if err != nil {
		t.Fatalf("jit status: %v", err)
	}
	if !strings.Contains(out, "1 broken") || !strings.Contains(out, "jit doctor") {
		t.Errorf("expected a broken-reference summary pointing at doctor, got:\n%s", out)
	}
	// status itself must not fail the process over a resolvable-elsewhere
	// problem — it's a rollup, not a gate; jit doctor is what fails loud.
	if strings.Contains(out, "AWS_ACCESS_KEY_ID") {
		t.Errorf("expected status to summarize, not enumerate doctor's own per-variable detail, got:\n%s", out)
	}
}

func TestStatusMountsRegisteredButAgentNotRunning(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)
	root := filepath.Join(home, "Library", "Application Support", "jitpass")
	if err := mount.AddMount(mount.RegistryPath(root), mount.Entry{MountPath: "/tmp/fixture/.env", ProfilePath: "/tmp/fixture/profile.yaml"}); err != nil {
		t.Fatalf("AddMount: %v", err)
	}

	out, err := execStatus(t)
	if err != nil {
		t.Fatalf("jit status: %v", err)
	}
	if !strings.Contains(out, "mounts   1 registered mount · not being served (service not running)") {
		t.Errorf("expected a not-being-served mount summary, got:\n%s", out)
	}
}

// TestStatusFormatJSONMatchesTextSections confirms GAPS.md #22's JSON
// snapshot reports the exact same facts the text report does, just
// structured — plants one of everything (a secret, a resolving profile, a
// registered-but-unserved mount) and cross-checks both representations.
func TestStatusFormatJSONMatchesTextSections(t *testing.T) {
	home := withFixtureHome(t)
	cwd := withFixtureCwd(t)
	plantVaultSecret(t, home, "aws/s3-access-key")
	// The vault section now reports the master key's presence, and the real
	// probe answers from the production keychain of whatever machine runs this.
	stubKeychain(t, keychainwrap.MEKPresent)
	writeFixtureProfile(t, cwd, "aws-admin", "AWS_ACCESS_KEY_ID: aws/s3-access-key\n")
	root := filepath.Join(home, "Library", "Application Support", "jitpass")
	if err := mount.AddMount(mount.RegistryPath(root), mount.Entry{MountPath: "/tmp/fixture/.env", ProfilePath: "/tmp/fixture/profile.yaml"}); err != nil {
		t.Fatalf("AddMount: %v", err)
	}

	out, err := execStatus(t, "--format", "json")
	if err != nil {
		t.Fatalf("jit status --format json: %v", err)
	}
	var result statusResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("unmarshaling output %q: %v", out, err)
	}

	want := statusResult{
		CLI:   statusCLI{Version: agent.Version(), Build: agent.BuildID()},
		Vault: statusVault{Initialized: "yes", SecretsStored: 1},
		Agent: statusAgent{Running: false, Unlocked: false},
		Secrets: statusSecrets{
			TotalSecrets: 1, TotalGroups: 1,
			WiredGroups: 1, WiredProfiles: 1, WiredReferences: 1,
		},
		Mounts: statusMounts{Registered: 1, BeingServed: false},
	}
	if !reflect.DeepEqual(result, want) {
		t.Errorf("result = %+v, want %+v", result, want)
	}
}

func TestStatusFormatRejectsUnknownValue(t *testing.T) {
	withFixtureHome(t)
	withFixtureCwd(t)

	_, err := execStatus(t, "--format", "yaml")
	if err == nil {
		t.Fatal("expected an error for an unknown --format value, got nil")
	}
}

func TestStatusNeverTouchesKeyWrapper(t *testing.T) {
	// A nil KeyWrapper (openVaultReadOnly's shape) must never be dereferenced
	// — status, like doctor, only checks existence, never decrypts, so it
	// must never need local authentication.
	withFixtureHome(t)
	withFixtureCwd(t)

	if _, err := execStatus(t); err != nil {
		t.Fatalf("jit status with no vault/agent/profiles set up: %v", err)
	}
}

// TestAgentMissingBinaryParts covers the failure the build comparison beside
// it structurally cannot see: a service whose binary was MOVED rather than
// replaced reports the same build and version as the CLI while being unable
// to read the keychain at all, because macOS validates a caller's code
// signature against an on-disk file that no longer exists.
func TestAgentMissingBinaryParts(t *testing.T) {
	t.Run("a deleted binary is named, with the fix as the action", func(t *testing.T) {
		gone := filepath.Join(t.TempDir(), "jit")
		detail, action := agentMissingBinaryParts(gone)
		if detail == "" {
			t.Fatalf("no finding for a service running a binary that does not exist (%s)", gone)
		}
		if !strings.Contains(detail, gone) {
			t.Errorf("finding does not name the path: %q", detail)
		}
		if action != "`jit service restart` to run the current binary" {
			t.Errorf("the fix must be the action, backticked for doctor's fixes: %q", action)
		}
		if strings.Contains(detail, "`") {
			t.Errorf("the command belongs in the action, not the detail: %q", detail)
		}
	})

	t.Run("a binary that exists is silent", func(t *testing.T) {
		here := filepath.Join(t.TempDir(), "jit")
		if err := os.WriteFile(here, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatalf("write: %v", err)
		}
		if detail, action := agentMissingBinaryParts(here); detail != "" || action != "" {
			t.Errorf("reported a healthy service: %q %q", detail, action)
		}
	})

	t.Run("an unknown path is silent, not a warning", func(t *testing.T) {
		// An agent predating the field reports "". Unknown must not render as
		// missing, or every user on an older service sees a false alarm.
		if detail, _ := agentMissingBinaryParts(""); detail != "" {
			t.Errorf("treated an unknown path as missing: %q", detail)
		}
	})
}

// TestSecretsSectionEmptyRegistryNeverOffersPrune: a vault whose groups are
// referenced by nothing at all is the restored-without-its-profiles case,
// not a pile of surplus secrets. `jit vault orphans --prune` would delete
// every one of them, so this state must not name it; and the headline must
// not claim a reconciliation against the zero profiles and zero mounts it
// actually found.
func TestSecretsSectionEmptyRegistryNeverOffersPrune(t *testing.T) {
	var buf bytes.Buffer
	printSecretsSection(&buf, statusSecrets{
		TotalSecrets: 69, TotalGroups: 21,
		UnreferencedGroups: 21, UnreferencedSecrets: 69,
	})
	out := buf.String()
	if strings.Contains(out, "--prune") {
		t.Errorf("a vault nothing references must not be pointed at --prune, got:\n%s", out)
	}
	if strings.Contains(out, "reconciled against every profile and mount") {
		t.Errorf("nothing was reconciled: there are no profiles and no mounts, got:\n%s", out)
	}
	if !strings.Contains(out, "used_by") {
		t.Errorf("the diagnostic that answers 'what references this' must be offered, got:\n%s", out)
	}
	if !strings.Contains(out, ".jit/profiles") {
		t.Errorf("the reason — profiles travel separately from the vault — must be stated, got:\n%s", out)
	}
}

// The ordinary case keeps its wording and still offers the cleanup —
// orphans beside working profiles really can be surplus — but routes to the
// LISTING, not straight to the delete.
//
// This row counts what is unreferenced FROM HERE. `jit vault orphans` counts
// what is unreferenced by any profile on the machine, and on a
// project-scoped setup the two legitimately disagree: measured on a real one,
// 21 groups/69 secrets here against 16/59 machine-wide, the gap being five
// groups referenced by profiles one directory away. Naming `--prune` under
// this count implied it would delete these 69; it deletes the other 59, and
// nothing on the line let the reader see that. The listing prints its own
// count and ends with its own `--prune`, so the destructive command sits
// beside the number it actually acts on.
func TestSecretsSectionRoutesOrphansToTheListingNotThePrune(t *testing.T) {
	var buf bytes.Buffer
	printSecretsSection(&buf, statusSecrets{
		TotalSecrets: 44, TotalGroups: 21, WiredGroups: 5, WiredProfiles: 9, WiredReferences: 44,
		UnreferencedGroups: 16, UnreferencedSecrets: 59,
	})
	out := buf.String()
	if !strings.Contains(out, "reconciled against every profile and mount") {
		t.Errorf("the ordinary headline must be unchanged, got:\n%s", out)
	}
	if !strings.Contains(out, "jit vault orphans") {
		t.Errorf("the cleanup must still be reachable, got:\n%s", out)
	}
	if strings.Contains(out, "--prune") {
		t.Errorf("a count scoped to this directory must not name a delete scoped to the machine, got:\n%s", out)
	}
}
