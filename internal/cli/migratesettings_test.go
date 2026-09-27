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
