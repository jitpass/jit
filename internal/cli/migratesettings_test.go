// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"os"
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/settings"
	"github.com/jitpass/jit/internal/vault"
)

// A profile protected before settings stayed plain: a URL, a secret and a
// name that says secret, all in the vault from one .env.
func oldStyleRig(t *testing.T) *moveRig {
	t.Helper()
	r := newMoveRig(t)
	meta := vault.Meta{Class: vault.ClassDotenv}
	for p, val := range map[string]string{
		"billing/BILLING_URL":             "https://billing.example.com",
		"billing/CLIENT_SECRET":           strings.Join([]string{"Qx7vK2", "mP9wLs", "4Rt8Yn", "3Bz6Hc"}, ""),
		"billing/OUTPUT_FILE_DEV_SECRETS": "dev_secrets.json",
	} {
		if err := r.v.SetWithMeta(p, []byte(val), meta); err != nil {
			t.Fatal(err)
		}
	}
	manifest := "BILLING_URL: billing/BILLING_URL\nCLIENT_SECRET: billing/CLIENT_SECRET\nOUTPUT_FILE_DEV_SECRETS: billing/OUTPUT_FILE_DEV_SECRETS\n"
	if err := os.WriteFile(r.manifest, []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	return r
}

func execMigrateSettings(t *testing.T, args ...string) (string, error) {
	t.Helper()
	migrateSettingsFormat = "text"
	return execMigrate(t, append([]string{"settings"}, args...)...)
}

// Only the setting moves; the secret and the name that says secret stay.
// One Touch ID for the run.
func TestMigrateSettingsMovesOnlySettings(t *testing.T) {
	r := oldStyleRig(t)
	out, err := execMigrateSettings(t, "--yes")
	if err != nil {
		t.Fatalf("migrate settings: %v\n%s", err, out)
	}
	if ok, _ := r.v.Exists("billing/BILLING_URL"); ok {
		t.Error("BILLING_URL is still in the vault")
	}
	if got, err := settings.New(r.root).Get("billing/BILLING_URL"); err != nil || string(got) != "https://billing.example.com" {
		t.Errorf("setting BILLING_URL = %q, %v", got, err)
	}
	for _, p := range []string{"billing/CLIENT_SECRET", "billing/OUTPUT_FILE_DEV_SECRETS"} {
		if ok, _ := r.v.Exists(p); !ok {
			t.Errorf("%s left the vault", p)
		}
	}
	if !strings.Contains(out, "stayed in the vault because the name looks like a secret") {
		t.Errorf("output does not name the check:\n%s", out)
	}
	if len(r.reasons) != 1 {
		t.Errorf("Touch ID asked %d times, want once for the run: %q", len(r.reasons), r.reasons)
	}
}

// A dry run reads (it has to, to judge) but moves nothing.
func TestMigrateSettingsDryRunMovesNothing(t *testing.T) {
	r := oldStyleRig(t)
	out, err := execMigrateSettings(t, "--yes", "--dry-run")
	if err != nil {
		t.Fatalf("migrate settings --dry-run: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Would move 1 setting") {
		t.Errorf("output = %q", out)
	}
	if ok, _ := r.v.Exists("billing/BILLING_URL"); !ok {
		t.Error("a dry run moved BILLING_URL")
	}
}

// A dry run changes nothing, the class index included: a class it recorded
// would tell the app the entries were checked, and hide the cleanup that has
// not happened (review of #183).
func TestMigrateSettingsDryRunRecordsNoClass(t *testing.T) {
	r := oldStyleRig(t)
	if _, err := execMigrateSettings(t, "--yes", "--dry-run"); err != nil {
		t.Fatalf("dry run: %v", err)
	}
	classes, err := settings.LoadClasses(r.root)
	if err != nil {
		t.Fatal(err)
	}
	if got := classes.Get("billing/BILLING_URL"); got != "" {
		t.Errorf("class after a dry run = %q, want none", got)
	}
}

// Every .env entry is read and classed, named by a profile or not, so the
// app's "may hold settings" count can reach zero; one no profile names is a
// setting left where it is, and said so (review of #183).
func TestMigrateSettingsClassesWhatItCannotMove(t *testing.T) {
	r := oldStyleRig(t)
	if err := r.v.SetWithMeta("billing/ORPHAN_URL", []byte("https://old.example.com"), vault.Meta{Class: vault.ClassDotenv}); err != nil {
		t.Fatal(err)
	}
	out, err := execMigrateSettings(t, "--yes")
	if err != nil {
		t.Fatalf("migrate settings: %v\n%s", err, out)
	}
	if ok, _ := r.v.Exists("billing/ORPHAN_URL"); !ok {
		t.Error("an entry no profile names was moved")
	}
	classes, err := settings.LoadClasses(r.root)
	if err != nil {
		t.Fatal(err)
	}
	if got := classes.Get("billing/ORPHAN_URL"); got != "setting" {
		t.Errorf("class of the unnamed entry = %q, want setting", got)
	}
	if !strings.Contains(out, "no profile names it") {
		t.Errorf("output does not say why it stayed:\n%s", out)
	}
}

// A 1Password link is never read or copied out: reading resolves the item,
// and a plain copy would cut the link (review of #183).
func TestA1PasswordLinkNeverMovesOut(t *testing.T) {
	r := oldStyleRig(t)
	if err := r.v.SetReference("billing/LINKED_URL", "op://Work/Billing/url", vault.Meta{Class: vault.ClassDotenv}); err != nil {
		t.Fatal(err)
	}
	manifest := "BILLING_URL: billing/BILLING_URL\nLINKED_URL: billing/LINKED_URL\n"
	if err := os.WriteFile(r.manifest, []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := execVaultMove(t, "move-out", "billing/LINKED_URL", "--yes"); err == nil || !strings.Contains(err.Error(), "1Password link") {
		t.Fatalf("move-out of a link = %v, want refused", err)
	}
	if len(r.reasons) != 0 {
		t.Errorf("a refused move asked for Touch ID: %q", r.reasons)
	}
	out, err := execMigrateSettings(t, "--yes")
	if err != nil {
		t.Fatalf("migrate settings: %v\n%s", err, out)
	}
	if ok, _ := settings.New(r.root).Exists("billing/LINKED_URL"); ok {
		t.Error("the cleanup wrote a 1Password link's value to disk")
	}
	if ok, _ := r.v.Exists("billing/LINKED_URL"); !ok {
		t.Error("the cleanup removed the link")
	}
}
