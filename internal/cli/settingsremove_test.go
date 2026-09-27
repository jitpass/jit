// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/jitpass/jit/internal/migrate"
	"github.com/jitpass/jit/internal/settings"
	"github.com/jitpass/jit/internal/vault"
)

// Removing the project a .env.bak was protected in removes its settings
// too, and the pointer file naming them (it is the project's own) does not
// hold them back as "used elsewhere" (review of #183).
func TestProjectRemovalTakesItsSettings(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)
	root, err := vaultRootDir()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(home, "code", "billing-sync")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	bak := filepath.Join(dir, ".env.bak")
	if err := os.WriteFile(bak, []byte("BILLING_URL=https://billing.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	v := &vault.Vault{Root: root, KeyWrapper: newFakeKeyWrapper(), RecipientID: "test-device"}
	res, err := migrate.ApplyEnvFile(v, dir, bak)
	if err != nil {
		t.Fatalf("ApplyEnvFile: %v", err)
	}
	if len(res.Settings) != 1 {
		t.Fatalf("Settings = %v, want the URL kept as a setting", res.Settings)
	}

	// The way `jit migrate remove <file>` resolves it: a file inside a
	// project with its own .jit/ names that project.
	targets, err := resolveRemovalTargets(dir, home, []string{bak})
	if err != nil {
		t.Fatalf("resolveRemovalTargets: %v", err)
	}
	if len(targets) != 1 || targets[0].loose {
		t.Fatalf("targets = %+v, want the project", targets)
	}
	plan, err := buildProjectRemovalPlan(root, home, targets[0].path, &vault.Vault{Root: root})
	if err != nil {
		t.Fatalf("buildProjectRemovalPlan: %v", err)
	}
	want := settings.Pointer(res.ProfileName + "/BILLING_URL")
	if !slices.Contains(plan.deletePaths, want) {
		t.Errorf("deletePaths = %v, want the setting %s", plan.deletePaths, want)
	}
}

// A setting line in a pointer file makes that file one of the setting's
// users: move-in must refuse, or the backup's restore would point at a
// setting that is gone.
func TestMoveInRefusesASettingAPointerFileNames(t *testing.T) {
	r := newMoveRig(t)
	home, _ := os.UserHomeDir()
	dir := filepath.Join(home, "code", "billing-sync")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	bak := filepath.Join(dir, ".env.bak")
	if err := os.WriteFile(bak, []byte("BILLING_URL=https://billing.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := migrate.ApplyEnvFile(r.v, dir, bak)
	if err != nil {
		t.Fatalf("ApplyEnvFile: %v", err)
	}
	_, err = execVaultMove(t, "move-in", res.ProfileName+"/BILLING_URL", "--yes")
	if err == nil {
		t.Fatal("move-in of a setting a pointer file names succeeded")
	}
	if ok, _ := settings.New(r.root).Exists(res.ProfileName + "/BILLING_URL"); !ok {
		t.Error("a refused move-in removed the setting")
	}
	if len(r.reasons) != 0 {
		t.Errorf("a refused move asked for Touch ID: %q", r.reasons)
	}
}
