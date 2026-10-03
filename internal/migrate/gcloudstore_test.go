// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/sealstore"
)

// writeGcloudLogin lays out a logged-in gcloud config dir under home (spike
// E1's shape) with token as the refresh token, plus an ADC file and
// settings that sealing must leave alone.
func writeGcloudLogin(t *testing.T, root, token string) {
	t.Helper()
	files := map[string]string{
		"credentials.db":                       "SQLite format 3\x00" + token,
		"access_tokens.db":                     "SQLite format 3\x00ya29.ACCESS",
		"legacy_credentials/u@x.com/adc.json":  `{"refresh_token":"` + token + `"}`,
		"legacy_credentials/u@x.com/.boto":     "gs_oauth2_refresh_token = " + token + "\n",
		"application_default_credentials.json": `{"type":"authorized_user"}`,
		"configurations/config_default":        "[core]\naccount = u@x.com\n",
		"active_config":                        "default",
	}
	for rel, body := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSealGcloudStore(t *testing.T) {
	home := t.TempDir()
	dir := GcloudConfigDir(home)
	writeGcloudLogin(t, dir, "1//FIRST")
	v := newTestVault(t)

	res, err := SealGcloudStore(v, home)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Files) != 3 || res.LoggedOut || res.AlreadySealed {
		t.Fatalf("result %+v, want 3 files sealed", res)
	}
	left, _ := sealstore.Gcloud.Plaintext(dir)
	if len(left) != 0 {
		t.Fatalf("plaintext left after sealing: %q", left)
	}
	for _, keep := range []string{"application_default_credentials.json", "configurations/config_default", "active_config"} {
		if _, err := os.Stat(filepath.Join(dir, keep)); err != nil {
			t.Fatalf("sealing removed %s", keep)
		}
	}

	blob, err := v.Get(GcloudStorePath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(blob), "1//FIRST") || strings.Contains(string(blob), "ya29.ACCESS") {
		t.Fatal("the vaulted store is not the login without its access-token cache")
	}

	// Every plaintext file is backed up, linked so they come back together.
	recs, err := LoadBackupRecords(v.Root)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 3 {
		t.Fatalf("%d backup records, want 3", len(recs))
	}
	for _, r := range recs {
		if len(r.RestoreWith) != 2 {
			t.Fatalf("%s restores with %q, want its two partners", r.OriginalPath, r.RestoreWith)
		}
	}

	// A second seal finds nothing to move.
	again, err := SealGcloudStore(v, home)
	if err != nil || !again.AlreadySealed {
		t.Fatalf("second seal: %+v, %v", again, err)
	}
}

func TestSealGcloudStoreLoggedOut(t *testing.T) {
	home := t.TempDir()
	v := newTestVault(t)
	res, err := SealGcloudStore(v, home)
	if err != nil {
		t.Fatal(err)
	}
	if !res.LoggedOut {
		t.Fatalf("result %+v, want LoggedOut", res)
	}
	if sealed, _ := GcloudStoreSealed(v); !sealed {
		t.Fatal("a logged-out seal left no store to capture the next login into (D5)")
	}
}

// TestResealRecordsTheLatestLogin is D10: after a login through the wrap,
// undo puts back that login, not the one from the day of the wrap.
func TestResealRecordsTheLatestLogin(t *testing.T) {
	home := t.TempDir()
	dir := GcloudConfigDir(home)
	writeGcloudLogin(t, dir, "1//FIRST")
	v := newTestVault(t)
	if _, err := SealGcloudStore(v, home); err != nil {
		t.Fatal(err)
	}

	run := t.TempDir()
	writeGcloudLogin(t, run, "1//SECOND")
	blob, err := sealstore.Gcloud.Pack(run)
	if err != nil {
		t.Fatal(err)
	}
	if err := ResealGcloudStore(v, home, run, blob); err != nil {
		t.Fatal(err)
	}
	got, _ := v.Get(GcloudStorePath)
	if !strings.Contains(string(got), "1//SECOND") {
		t.Fatal("reseal did not vault the new login")
	}

	recs, err := LoadBackupRecords(v.Root)
	if err != nil {
		t.Fatal(err)
	}
	latest := LatestBackups(recs)
	var paths []string
	for _, r := range latest {
		paths = append(paths, r.OriginalPath)
		if err := RestoreFromBackup(v, r); err != nil {
			t.Fatalf("restoring %s: %v", r.OriginalPath, err)
		}
	}
	sort.Strings(paths)
	if len(paths) != 3 || !strings.HasPrefix(paths[0], dir) {
		t.Fatalf("latest backups %q, want the three store files under %s", paths, dir)
	}
	b, err := os.ReadFile(filepath.Join(dir, "credentials.db"))
	if err != nil || !strings.Contains(string(b), "1//SECOND") {
		t.Fatalf("undo restored %q, %v; want the latest login", b, err)
	}
}

func TestUnsealGcloudStore(t *testing.T) {
	home := t.TempDir()
	dir := GcloudConfigDir(home)
	writeGcloudLogin(t, dir, "1//FIRST")
	v := newTestVault(t)
	if _, err := SealGcloudStore(v, home); err != nil {
		t.Fatal(err)
	}
	files, err := UnsealGcloudStore(v, home)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 3 {
		t.Fatalf("unsealed %q, want 3 files", files)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "legacy_credentials/u@x.com/.boto"))
	if !strings.Contains(string(b), "1//FIRST") {
		t.Fatal("unseal did not put the login back")
	}
	if sealed, _ := GcloudStoreSealed(v); !sealed {
		t.Fatal("unseal dropped the vault copy")
	}
	if _, err := UnsealGcloudStore(v, home); err == nil {
		t.Fatal("unseal wrote over a plaintext store already there")
	}
}
