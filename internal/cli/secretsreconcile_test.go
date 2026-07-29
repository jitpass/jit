// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

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
	// KEYS in the house style — a bold "<group> <count>" header over the keys
	// flowed into columns, with the unreferenced block's shared origin stated
	// once rather than per key.
	for _, want := range []string{
		"Wired here",
		"[aws] 1",
		"key1",
		"Unreferenced here",
		"[orphan] 1",
		"no recorded origin",
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

// TestStatusDetectsRenamedGroupLeftovers covers the re-migration shape that
// produces most real orphans: a group is migrated once under one name, again
// under another, and the first copy is left behind holding the same keys with
// nothing pointing at it. The unreferenced copy must be linked to the live one
// by name so the reader can prune without diffing group listings by eye.
func TestStatusDetectsRenamedGroupLeftovers(t *testing.T) {
	home := withFixtureHome(t)
	cwd := withFixtureCwd(t)

	// The live group: two secrets, wired by a project-local profile.
	writeFixtureProfile(t, cwd, "wiz", "WIZ_CLIENT_ID: wiz/WIZ_CLIENT_ID\nWIZ_CLIENT_SECRET: wiz/WIZ_CLIENT_SECRET\n")
	plantVaultSecret(t, home, "wiz/WIZ_CLIENT_ID")
	plantVaultSecret(t, home, "wiz/WIZ_CLIENT_SECRET")

	// The leftover: same keys, older group name, referenced by nothing.
	plantVaultSecret(t, home, "custom_scripts-wiz/WIZ_CLIENT_ID")
	plantVaultSecret(t, home, "custom_scripts-wiz/WIZ_CLIENT_SECRET")

	// An unreferenced group that is NOT a copy must stay uncounted, so the
	// number means "already accounted for elsewhere", not "unreferenced".
	plantVaultSecret(t, home, "infra/TF_VAR_db_password")
	plantVaultSecret(t, home, "infra/TF_VAR_api_token")

	s := secretsJSON(t)
	if s.UnreferencedGroups != 2 || s.UnreferencedSecrets != 4 {
		t.Fatalf("unreferenced = %d groups / %d secrets, want 2 / 4", s.UnreferencedGroups, s.UnreferencedSecrets)
	}
	if s.DuplicateGroups != 1 || s.DuplicateSecrets != 2 {
		t.Errorf("duplicates = %d groups / %d secrets, want 1 / 2 (only the renamed copy)", s.DuplicateGroups, s.DuplicateSecrets)
	}

	out, err := execStatus(t, "--secrets")
	if err != nil {
		t.Fatalf("jit status --secrets: %v", err)
	}
	// The rollup names the count, the detail names the pairing, and neither
	// may claim the VALUES match — status never decrypts, so it can only
	// ever have compared key names.
	for _, want := range []string{
		// One of the two unreferenced groups is a copy — a strict subset, so
		// "1 of them" rather than the "all N" wording.
		"1 of them (2 secrets) have the same key names as a group still in use",
		"custom_scripts-wiz = wiz",
		"names, not values",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected --secrets output to contain %q, got:\n%s", want, out)
		}
	}
}

// TestStatusDuplicateDetectionIgnoresSingleKeyGroups guards the one way this
// heuristic could mislead expensively: single-key groups collide on generic
// names (API_KEY, OUTPUT_FILE) constantly, and calling a live-looking secret a
// "leftover" is exactly the wrong error to make in a prune recommendation.
func TestStatusDuplicateDetectionIgnoresSingleKeyGroups(t *testing.T) {
	home := withFixtureHome(t)
	cwd := withFixtureCwd(t)
	writeFixtureProfile(t, cwd, "app", "API_KEY: app/API_KEY\n")
	plantVaultSecret(t, home, "app/API_KEY")
	// Same lone key name, unrelated group — a name collision, not a copy.
	plantVaultSecret(t, home, "other-project/API_KEY")

	s := secretsJSON(t)
	if s.UnreferencedGroups != 1 {
		t.Fatalf("unreferenced groups = %d, want 1", s.UnreferencedGroups)
	}
	if s.DuplicateGroups != 0 {
		t.Errorf("duplicate groups = %d, want 0 — a single shared key name is not evidence of a copy", s.DuplicateGroups)
	}
}

// TestStatusCountsUnreferencedInsideMixedGroups covers the accounting gap
// between this rollup and `jit vault orphans`: orphans keys on individual
// paths, while the rollup buckets whole groups by their dominant state, so an
// unreferenced secret inside an otherwise-wired group is listed by one and not
// the other. Reported explicitly rather than left as an unexplained mismatch.
func TestStatusCountsUnreferencedInsideMixedGroups(t *testing.T) {
	home := withFixtureHome(t)
	cwd := withFixtureCwd(t)
	// One group, two secrets, only one of them referenced.
	writeFixtureProfile(t, cwd, "aws", "AWS_ACCESS_KEY_ID: aws/key1\n")
	plantVaultSecret(t, home, "aws/key1")
	plantVaultSecret(t, home, "aws/key2")

	s := secretsJSON(t)
	// The group is dominantly wired, so it isn't in the unreferenced bucket...
	if s.UnreferencedGroups != 0 || s.UnreferencedSecrets != 0 {
		t.Fatalf("unreferenced = %d groups / %d secrets, want 0 / 0 (the group is dominantly wired)", s.UnreferencedGroups, s.UnreferencedSecrets)
	}
	// ...but the stray member is still counted and still surfaced.
	if s.UnreferencedInMixed != 1 {
		t.Errorf("unreferenced-in-mixed = %d, want 1", s.UnreferencedInMixed)
	}
	out, err := execStatus(t)
	if err != nil {
		t.Fatalf("jit status: %v", err)
	}
	if !strings.Contains(out, "1 secret inside groups counted above as in use is unreferenced too") {
		t.Errorf("expected the mixed-group reconciliation note, got:\n%s", out)
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
