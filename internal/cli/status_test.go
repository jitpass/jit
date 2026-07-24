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
		"jit      " + versionBuild(agent.Version(), agent.BuildID()) + " · service not running",
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

func TestStatusVaultReportsSecretCount(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)
	plantVaultSecret(t, home, "stripe/dev-key")
	plantVaultSecret(t, home, "aws/s3-access-key")

	out, err := execStatus(t)
	if err != nil {
		t.Fatalf("jit status: %v", err)
	}
	if !strings.Contains(out, "vault    2 secret(s) stored") {
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
	if !strings.Contains(out, "vault    2 secret(s) stored · 2 file backup(s) kept for `jit migrate undo`") {
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
	if !strings.Contains(out, "vault    0 secret(s) stored · 1 file backup(s) kept for `jit migrate undo`") {
		t.Errorf("expected a backups-only vault line, got:\n%s", out)
	}
	if strings.Contains(out, "no secrets yet") {
		t.Errorf("backups-only vault should not claim the vault is empty, got:\n%s", out)
	}
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
	if !strings.Contains(out, "backup   ✗ no vault export on record") || !strings.Contains(out, "jit vault export") {
		t.Errorf("expected a never-exported nudge naming the command, got:\n%s", out)
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
	if !strings.Contains(out, "secrets  1 stored in 1 group(s)") {
		t.Errorf("expected a stored-secret headline, got:\n%s", out)
	}
	if !strings.Contains(out, "Wired here") || !strings.Contains(out, "1 group(s) via 1 profile(s) (1 reference(s)), all resolve.") {
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
	if !strings.Contains(out, "mounts   1 registered · not being served (service not running)") {
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
		Vault: statusVault{SecretsStored: 1},
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
