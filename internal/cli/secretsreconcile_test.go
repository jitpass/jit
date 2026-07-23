// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// removeFixtureProfile deletes a project-local profile manifest, the inverse of
// writeFixtureProfile, so a test can move a secret from one scope to another.
func removeFixtureProfile(cwd, name string) error {
	return os.Remove(filepath.Join(cwd, ".jit", "profiles", name+".yaml"))
}

// TestStatusSecretsThreeStates plants one secret in each state — wired by a
// project-local profile, referenced only by a global profile (managed
// elsewhere), and referenced by nothing (unreferenced) — and confirms the
// reconciliation buckets each correctly. This is the distinction the retired
// `jit profile list` could never draw.
func TestStatusSecretsThreeStates(t *testing.T) {
	home := withFixtureHome(t)
	cwd := withFixtureCwd(t)

	// Wired here: a project-local profile references it.
	writeFixtureProfile(t, cwd, "aws-admin", "AWS_ACCESS_KEY_ID: aws/key1\n")
	plantVaultSecret(t, home, "aws/key1")

	// Managed elsewhere: only a GLOBAL profile (written under home) references it.
	writeFixtureProfile(t, home, "shell", "STRIPE_API_KEY: stripe/key1\n")
	plantVaultSecret(t, home, "stripe/key1")

	// Unreferenced: no profile jit can see points at it.
	plantVaultSecret(t, home, "orphan/key1")

	out, err := execStatus(t, "--format", "json")
	if err != nil {
		t.Fatalf("jit status --format json: %v", err)
	}
	var result statusResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("unmarshaling %q: %v", out, err)
	}

	s := result.Secrets
	if s.TotalSecrets != 3 || s.TotalGroups != 3 {
		t.Errorf("totals = %d secrets / %d groups, want 3 / 3", s.TotalSecrets, s.TotalGroups)
	}
	if s.WiredGroups != 1 || s.WiredProfiles != 1 || s.WiredReferences != 1 || s.WiredProblems != 0 {
		t.Errorf("wired = %d groups / %d profiles / %d refs / %d problems, want 1 / 1 / 1 / 0",
			s.WiredGroups, s.WiredProfiles, s.WiredReferences, s.WiredProblems)
	}
	if s.ManagedElsewhereGroups != 1 {
		t.Errorf("managed elsewhere = %d groups, want 1", s.ManagedElsewhereGroups)
	}
	if s.UnreferencedGroups != 1 || s.UnreferencedSecrets != 1 {
		t.Errorf("unreferenced = %d groups / %d secrets, want 1 / 1", s.UnreferencedGroups, s.UnreferencedSecrets)
	}
	// The default snapshot stays small — no per-group detail unless --secrets.
	if len(s.Groups) != 0 {
		t.Errorf("default --format json should omit per-group detail, got %d groups", len(s.Groups))
	}
}

// TestStatusSecretsScopeSplit proves the buckets are the project/elsewhere
// SPLIT, not just the union `jit vault orphans` keys on: the same secret reads
// as "wired here" when a project-local profile references it, and as "managed
// elsewhere" when only a global profile does.
func TestStatusSecretsScopeSplit(t *testing.T) {
	home := withFixtureHome(t)
	cwd := withFixtureCwd(t)
	plantVaultSecret(t, home, "aws/key1")

	// Project-local reference -> wired here.
	writeFixtureProfile(t, cwd, "aws-admin", "AWS_ACCESS_KEY_ID: aws/key1\n")
	wired := secretsJSON(t)
	if wired.WiredGroups != 1 || wired.ManagedElsewhereGroups != 0 {
		t.Fatalf("with a project profile: wired=%d elsewhere=%d, want 1/0", wired.WiredGroups, wired.ManagedElsewhereGroups)
	}

	// Remove the project profile, add an equivalent GLOBAL one -> managed
	// elsewhere, same secret.
	if err := removeFixtureProfile(cwd, "aws-admin"); err != nil {
		t.Fatalf("removing project profile: %v", err)
	}
	writeFixtureProfile(t, home, "aws-admin", "AWS_ACCESS_KEY_ID: aws/key1\n")
	elsewhere := secretsJSON(t)
	if elsewhere.WiredGroups != 0 || elsewhere.ManagedElsewhereGroups != 1 {
		t.Fatalf("with only a global profile: wired=%d elsewhere=%d, want 0/1", elsewhere.WiredGroups, elsewhere.ManagedElsewhereGroups)
	}
}

// TestStatusSecretsDetailListsGroups confirms `jit status --secrets` expands
// into the per-group reconciliation and, for the unreferenced block, reuses the
// same origin-annotated rendering as `jit vault orphans`.
func TestStatusSecretsDetailListsGroups(t *testing.T) {
	home := withFixtureHome(t)
	cwd := withFixtureCwd(t)
	writeFixtureProfile(t, cwd, "aws-admin", "AWS_ACCESS_KEY_ID: aws/key1\n")
	plantVaultSecret(t, home, "aws/key1")
	plantVaultSecret(t, home, "orphan/key1")

	out, err := execStatus(t, "--secrets")
	if err != nil {
		t.Fatalf("jit status --secrets: %v", err)
	}
	// The detail view is vault-centric: it lists each group's stored secret
	// KEYS (the env-var-name -> path mapping is what `jit profile show` prints).
	for _, want := range []string{
		"Wired here (1 group(s)",
		"aws/ (1)",
		"• key1",
		"Unreferenced here (1 group(s), 1 secret(s)):",
		"orphan/ (1)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected --secrets output to contain %q, got:\n%s", want, out)
		}
	}
}

// TestStatusSecretsToleratesUnreadableProfile is the graceful-degradation
// guard: a project profile that won't parse must not fail `jit status` (it stays
// a safe overview) nor mislabel an otherwise-referenced secret. Its references
// simply don't count, and it's tallied as a parse failure.
func TestStatusSecretsToleratesUnreadableProfile(t *testing.T) {
	home := withFixtureHome(t)
	cwd := withFixtureCwd(t)
	// A YAML sequence won't decode into the map[string]string a profile is.
	writeFixtureProfile(t, cwd, "broken", "- not\n- a map\n")
	writeFixtureProfile(t, cwd, "aws-admin", "AWS_ACCESS_KEY_ID: aws/key1\n")
	plantVaultSecret(t, home, "aws/key1")

	out, err := execStatus(t, "--format", "json")
	if err != nil {
		t.Fatalf("jit status must survive an unreadable profile, got: %v", err)
	}
	var result statusResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("unmarshaling %q: %v", out, err)
	}
	s := result.Secrets
	if s.ParseFailures != 1 {
		t.Errorf("parse failures = %d, want 1", s.ParseFailures)
	}
	// The readable profile still wires its secret.
	if s.WiredGroups != 1 || s.UnreferencedGroups != 0 {
		t.Errorf("wired=%d unreferenced=%d, want 1/0 (the broken profile mustn't strand the secret)", s.WiredGroups, s.UnreferencedGroups)
	}
}

// secretsJSON runs `jit status --format json` and returns just the Secrets
// section, for tests that assert on it repeatedly.
func secretsJSON(t *testing.T) statusSecrets {
	t.Helper()
	out, err := execStatus(t, "--format", "json")
	if err != nil {
		t.Fatalf("jit status --format json: %v", err)
	}
	var result statusResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("unmarshaling %q: %v", out, err)
	}
	return result.Secrets
}
