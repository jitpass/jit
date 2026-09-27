// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/profile"
	"github.com/jitpass/jit/internal/settings"
)

// Invented values, built at run time so the leak guard does not read them as
// committed credentials.
var (
	splitSecretA = strings.Join([]string{"Qx7vK2", "mP9wLs", "4Rt8Yn", "3Bz6Hc"}, "")
	splitSecretB = strings.Join([]string{"Zq4Wx8", "Ev2Rc6", "Tb1Yn5", "Um9Ik3"}, "")
)

// The shape that started this (design/secrets-only-vault.md): a .env of one
// client secret beside a URL, a client ID, file names and flags. Only the
// secret, the second random-looking value, and the name that says secret go
// to the vault; the rest are settings, and the manifest names both kinds.
func TestApplyEnvFileKeepsOnlySecretsInTheVault(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".env")
	writeFile(t, path, strings.Join([]string{
		"BILLING_URL=https://billing.example.com",
		"BILLING_CLIENT_ID=sync-reporter",
		"BILLING_CLIENT_SECRET=" + splitSecretA,
		"SERVICE_VALUE=" + splitSecretB,
		"OUTPUT_FILE_DEV_SECRETS=dev_secrets.json",
		"KEEP_REPORTS=30",
		"REPORT_DIR=~/reports",
	}, "\n")+"\n")

	v := newTestVault(t)
	var vaulted []string
	v.OnSet = func(p string, _ []byte) { vaulted = append(vaulted, p) }
	res, err := ApplyEnvFile(v, root, path)
	if err != nil {
		t.Fatalf("ApplyEnvFile: %v", err)
	}
	if want := []string{"BILLING_URL", "BILLING_CLIENT_ID", "KEEP_REPORTS", "REPORT_DIR"}; !reflect.DeepEqual(res.Settings, want) {
		t.Errorf("Settings = %v, want %v", res.Settings, want)
	}
	if want := []string{"OUTPUT_FILE_DEV_SECRETS"}; !reflect.DeepEqual(res.Checks, want) {
		t.Errorf("Checks = %v, want %v", res.Checks, want)
	}

	p, err := profile.LoadFile(res.ProfilePath)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	ns := res.ProfileName
	for _, name := range []string{"BILLING_CLIENT_SECRET", "SERVICE_VALUE", "OUTPUT_FILE_DEV_SECRETS"} {
		if p[name] != ns+"/"+name {
			t.Errorf("manifest %s = %q, want the vault path", name, p[name])
		}
		if ok, _ := v.Exists(ns + "/" + name); !ok {
			t.Errorf("%s is not in the vault", name)
		}
	}
	for _, name := range res.Settings {
		if p[name] != settings.Pointer(ns+"/"+name) {
			t.Errorf("manifest %s = %q, want a setting pointer", name, p[name])
		}
		if ok, _ := v.Exists(ns + "/" + name); ok {
			t.Errorf("setting %s reached the vault", name)
		}
	}
	got, err := settings.New(v.Root).Get(ns + "/BILLING_URL")
	if err != nil || string(got) != "https://billing.example.com" {
		t.Errorf("setting BILLING_URL = %q, %v", got, err)
	}

	// The vault saw the three secrets and the file's backup, nothing else:
	// the agent-cache sweep hunts what the vault saw, so it never hunts a URL.
	for _, p := range vaulted {
		for _, name := range res.Settings {
			if strings.HasSuffix(p, "/"+name) {
				t.Errorf("the vault was handed setting %s (%s)", name, p)
			}
		}
	}

	// The manifest is safe to commit: no value in it.
	data, err := os.ReadFile(res.ProfilePath) // #nosec G304 -- test path
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"billing.example.com", "sync-reporter", splitSecretA} {
		if strings.Contains(string(data), value) {
			t.Errorf("manifest carries a value (%q):\n%s", value, data)
		}
	}
}

// The user's word beats the class, both ways.
func TestApplyEnvFileSplitHonoursTheUser(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".env")
	writeFile(t, path, "OUTPUT_FILE_DEV_SECRETS=dev_secrets.json\nINTERNAL_TOKEN_NAME=reporter\n")

	v := newTestVault(t)
	res, err := ApplyEnvFileSplit(v, root, path, EnvSplit{
		Setting: map[string]bool{"OUTPUT_FILE_DEV_SECRETS": true},
		Secret:  map[string]bool{"INTERNAL_TOKEN_NAME": true},
	})
	if err != nil {
		t.Fatalf("ApplyEnvFileSplit: %v", err)
	}
	if want := []string{"OUTPUT_FILE_DEV_SECRETS"}; !reflect.DeepEqual(res.Settings, want) {
		t.Errorf("Settings = %v, want %v", res.Settings, want)
	}
	if len(res.Checks) != 0 {
		t.Errorf("Checks = %v; a name the user chose is no longer one to check", res.Checks)
	}
	if ok, _ := v.Exists(res.ProfileName + "/INTERNAL_TOKEN_NAME"); !ok {
		t.Error("INTERNAL_TOKEN_NAME, named a secret, is not in the vault")
	}
}

// A backup-suffixed file becomes a pointer file, not a mount. Its setting
// lines point at the setting, and restoring it brings every value back.
func TestPointerFileWithSettingsRestores(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".env.bak")
	writeFile(t, path, "BILLING_URL=https://billing.example.com\nBILLING_CLIENT_SECRET="+splitSecretA+"\n")

	v := newTestVault(t)
	if _, err := ApplyEnvFile(v, root, path); err != nil {
		t.Fatalf("ApplyEnvFile: %v", err)
	}
	data, err := os.ReadFile(path) // #nosec G304 -- test path
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "BILLING_URL=jit://setting/") || strings.Contains(string(data), "jit://vault/jit://") {
		t.Fatalf("pointer file = %q, want a setting pointer for BILLING_URL", data)
	}
	if _, err := RestorePointerFile(v, path); err != nil {
		t.Fatalf("RestorePointerFile: %v", err)
	}
	data, _ = os.ReadFile(path) // #nosec G304 -- test path
	for _, line := range []string{"BILLING_URL=https://billing.example.com", "BILLING_CLIENT_SECRET=" + splitSecretA} {
		if !strings.Contains(string(data), line) {
			t.Errorf("restored file lacks %q:\n%s", line, data)
		}
	}
}

// A namespace whose settings our own manifest names is still ours: a
// second file in the same place must not be pushed to "<name>-2" by them.
// One whose setting another manifest owns is not.
func TestClaimNamespaceCountsSettings(t *testing.T) {
	root := t.TempDir()
	v := newTestVault(t)
	store := settings.New(v.Root)
	if err := store.Set("billing/BILLING_URL", []byte("https://billing.example.com")); err != nil {
		t.Fatal(err)
	}

	name, _, _, moved, err := claimNamespace(v, root, "billing", []string{"BILLING_URL"})
	if err != nil {
		t.Fatalf("claimNamespace: %v", err)
	}
	if name != "billing-2" || moved != "billing" {
		t.Errorf("a setting owned by no manifest here: claimed %q (moved from %q), want billing-2", name, moved)
	}

	mp, err := profile.Path(root, "billing")
	if err != nil {
		t.Fatal(err)
	}
	data, err := profile.MarshalOrdered(profile.Profile{"BILLING_URL": settings.Pointer("billing/BILLING_URL")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, mp, string(data))
	if name, _, _, _, err = claimNamespace(v, root, "billing", []string{"BILLING_URL"}); err != nil || name != "billing" {
		t.Errorf("our own setting: claimed %q, %v; want billing", name, err)
	}
}
