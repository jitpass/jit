// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/sealstore"
)

const awsSSOConfig = `# my AWS setup
[default]
region = eu-west-1

[profile dev]
sso_session = corp
sso_account_id = 111122223333
sso_role_name = Developer
region = us-east-1

[profile prod]
sso_session = corp
sso_account_id = 444455556666
sso_role_name = ReadOnly

[profile old]
sso_start_url = https://legacy.awsapps.com/start
sso_region = us-east-1
sso_account_id = 777788889999
sso_role_name = Admin

[profile static]
region = us-west-2

[sso-session corp]
sso_start_url = https://corp.awsapps.com/start
sso_region = us-east-1
sso_registration_scopes = sso:account:access
`

// awsSSOHome lays out a home the way the spike measured it (E1): a config
// with SSO profiles, a token cache with a refresh token, a client
// registration, and the CLI's role-credential cache beside an assume-role
// one that is not SSO's.
func awsSSOHome(t *testing.T, refresh string) string {
	t.Helper()
	home := t.TempDir()
	files := map[string]string{
		".aws/config": awsSSOConfig,
		".aws/sso/cache/ee0bfd2552fbd840c02cc48b6e823320543c450f.json": `{"accessToken":"a","refreshToken":"` + refresh + `","clientId":"c","clientSecret":"s"}`,
		".aws/sso/cache/1b56c55d6e723362537167a7f43960b8185b5a80.json": `{"clientId":"c","clientSecret":"s","scopes":["sso:account:access"]}`,
		".aws/cli/cache/6b17aaa4b7ddc1fd491e01d5f64d4b66d9e2b04c.json": `{"ProviderType":"sso","Credentials":{"SecretAccessKey":"x"}}`,
		".aws/cli/cache/1234assumerole.json":                           `{"ProviderType":"assume-role","Credentials":{"SecretAccessKey":"y"}}`,
	}
	for rel, body := range files {
		p := filepath.Join(home, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return home
}

func TestDiscoverAWSSSOProfiles(t *testing.T) {
	home := awsSSOHome(t, "r1")
	got, err := DiscoverAWSSSOProfiles(home)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"dev", "old", "prod"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("discovered %q, want %q", got, want)
	}
	if got, err := DiscoverAWSSSOProfiles(t.TempDir()); err != nil || got != nil {
		t.Fatalf("no config: %q, %v", got, err)
	}
}

func TestApplyAWSSSO(t *testing.T) {
	home := awsSSOHome(t, "1//R1")
	v := newTestVault(t)
	profiles, _ := DiscoverAWSSSOProfiles(home)
	res, err := ApplyAWSSSO(v, home, profiles, NewBackupTracker())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.CacheFiles) != 2 || res.RoleCaches != 1 || res.LoggedOut {
		t.Fatalf("result %+v", res)
	}

	// The user's config: role keys out, credential_process in, sso_session
	// and every other line kept.
	b, _ := os.ReadFile(AWSConfigPath(home))
	cfg := string(b)
	for _, want := range []string{
		"# my AWS setup", "[profile static]", "region = us-west-2", "[sso-session corp]",
		"sso_session = corp", "sso_start_url = https://legacy.awsapps.com/start",
		"credential_process = /usr/local/bin/jit aws-sso --profile dev",
		"credential_process = /usr/local/bin/jit aws-sso --profile old",
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("rewritten config lacks %q:\n%s", want, cfg)
		}
	}
	for _, gone := range []string{"sso_account_id", "sso_role_name"} {
		if strings.Contains(cfg, gone) {
			t.Errorf("rewritten config still has %s:\n%s", gone, cfg)
		}
	}
	if again, _ := DiscoverAWSSSOProfiles(home); len(again) != 0 {
		t.Errorf("a sealed profile was discovered again: %q", again)
	}

	// The sealed config: the original definitions, session included.
	sb, err := os.ReadFile(AWSSSOSealedConfigPath(v.Root))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"[profile dev]", "sso_account_id = 111122223333", "[profile old]", "sso_role_name = Admin", "[sso-session corp]", "sso_registration_scopes"} {
		if !strings.Contains(string(sb), want) {
			t.Errorf("sealed config lacks %q:\n%s", want, sb)
		}
	}
	if strings.Contains(string(sb), "[profile static]") {
		t.Error("a profile that was not sealed was copied into the sealed config")
	}

	// The token cache: in the vault, off the disk; the assume-role cache
	// is not SSO's to delete.
	blob, err := v.Get(AWSSSOStorePath)
	if err != nil || !strings.Contains(string(blob), "1//R1") {
		t.Fatalf("vault holds %q, %v", blob, err)
	}
	if files, _ := awsSSOCacheFiles(home); len(files) != 0 {
		t.Errorf("token cache left on disk: %q", files)
	}
	if _, err := os.Stat(filepath.Join(home, ".aws/cli/cache/6b17aaa4b7ddc1fd491e01d5f64d4b66d9e2b04c.json")); !os.IsNotExist(err) {
		t.Error("the SSO role-credential cache was left")
	}
	if _, err := os.Stat(filepath.Join(home, ".aws/cli/cache/1234assumerole.json")); err != nil {
		t.Error("an assume-role cache was deleted")
	}

	// Backups: the config and both cache files, linked to come back together.
	recs, _ := LoadBackupRecords(v.Root)
	byPath := map[string]BackupRecord{}
	for _, r := range recs {
		byPath[r.OriginalPath] = r
	}
	if r, ok := byPath[AWSConfigPath(home)]; !ok || len(r.RestoreWith) != 2 {
		t.Errorf("config backup %+v, want it linked to the two cache files", r)
	}
	for _, f := range res.CacheFiles {
		if r, ok := byPath[f]; !ok || !containsPath(r.RestoreWith, AWSConfigPath(home)) {
			t.Errorf("cache backup for %s: %+v", f, r)
		}
	}
}

func containsPath(list []string, p string) bool {
	for _, x := range list {
		if x == p {
			return true
		}
	}
	return false
}

// A second migration (a profile added later) keeps what was sealed first,
// in the vault and in the sealed config.
func TestApplyAWSSSOAgainMerges(t *testing.T) {
	home := awsSSOHome(t, "1//R1")
	v := newTestVault(t)
	if _, err := ApplyAWSSSO(v, home, []string{"dev"}, nil); err != nil {
		t.Fatal(err)
	}
	// A new session's login, then the second profile.
	other := filepath.Join(AWSSSOCacheDir(home), "aaaa.json")
	if err := os.WriteFile(other, []byte(`{"accessToken":"b","refreshToken":"1//R2"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyAWSSSO(v, home, []string{"prod"}, nil); err != nil {
		t.Fatal(err)
	}
	blob, _ := v.Get(AWSSSOStorePath)
	if !strings.Contains(string(blob), "1//R1") || !strings.Contains(string(blob), "1//R2") {
		t.Fatal("the second migration lost the first login or the new one")
	}
	sb, _ := os.ReadFile(AWSSSOSealedConfigPath(v.Root))
	if strings.Count(string(sb), "[profile dev]") != 1 || strings.Count(string(sb), "[profile prod]") != 1 || strings.Count(string(sb), "[sso-session corp]") != 1 {
		t.Fatalf("sealed config after two migrations:\n%s", sb)
	}
}

func TestCaptureAndUnsealAWSSSO(t *testing.T) {
	home := awsSSOHome(t, "1//R1")
	v := newTestVault(t)
	profiles, _ := DiscoverAWSSSOProfiles(home)
	if _, err := ApplyAWSSSO(v, home, profiles, nil); err != nil {
		t.Fatal(err)
	}
	if got, err := CaptureAWSSSOLogin(v, home); err != nil || got {
		t.Fatalf("nothing to capture: %v, %v", got, err)
	}

	// `aws sso login` on the rewritten profile writes a fresh token.
	tok := filepath.Join(AWSSSOCacheDir(home), "ee0bfd2552fbd840c02cc48b6e823320543c450f.json")
	if err := os.WriteFile(tok, []byte(`{"accessToken":"a2","refreshToken":"1//NEW"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := CaptureAWSSSOLogin(v, home); err != nil || !got {
		t.Fatalf("capture: %v, %v", got, err)
	}
	if files, _ := awsSSOCacheFiles(home); len(files) != 0 {
		t.Fatalf("captured login left on disk: %q", files)
	}
	blob, _ := v.Get(AWSSSOStorePath)
	if !strings.Contains(string(blob), "1//NEW") || strings.Contains(string(blob), "1//R1") {
		t.Fatal("capture did not replace the old token with the new login")
	}
	if !strings.Contains(string(blob), "sso:account:access") {
		t.Fatal("capture dropped the client registration it did not replace")
	}

	// Unseal without overwrite keeps a file already there; with it, the
	// vault's copy wins (undo's seal-day copy replaced by the live one).
	if err := os.WriteFile(tok, []byte(`seal-day`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := UnsealAWSSSOCache(v, home, false); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(tok); string(b) != "seal-day" {
		t.Fatalf("unseal without overwrite replaced %q", b)
	}
	if _, err := UnsealAWSSSOCache(v, home, true); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(tok); !strings.Contains(string(b), "1//NEW") {
		t.Fatalf("unseal with overwrite left %q", b)
	}
	if files, _ := awsSSOCacheFiles(home); len(files) != 2 {
		t.Fatalf("unsealed %q, want the token and the registration", files)
	}
	if !IsAWSSSOCacheFile(home, tok) || IsAWSSSOCacheFile(home, AWSConfigPath(home)) {
		t.Error("IsAWSSSOCacheFile")
	}
	if !sealstore.Empty(mustPack(t, t.TempDir())) {
		t.Error("an empty sso dir did not pack empty")
	}
}

func mustPack(t *testing.T, dir string) []byte {
	t.Helper()
	b, err := AWSSSOLayout.Pack(dir)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestApplyAWSSSORefusesANonSSOProfile(t *testing.T) {
	home := awsSSOHome(t, "r")
	v := newTestVault(t)
	if _, err := ApplyAWSSSO(v, home, []string{"static"}, nil); err == nil {
		t.Fatal("sealed a profile with no SSO role")
	}
	if b, _ := os.ReadFile(AWSConfigPath(home)); string(b) != awsSSOConfig {
		t.Fatal("a refused migration changed the config")
	}
}

// The listing's prompt-free view of the sealed login: signed in after
// sealing a login, signed out once only the registration is left, unknown
// before anything was sealed.
func TestAWSSSOSignedInState(t *testing.T) {
	home := awsSSOHome(t, "1//R1")
	v := newTestVault(t)
	if _, known := AWSSSOSignedIn(v.Root); known {
		t.Fatal("state known before anything was sealed")
	}
	profiles, _ := DiscoverAWSSSOProfiles(home)
	if _, err := ApplyAWSSSO(v, home, profiles, nil); err != nil {
		t.Fatal(err)
	}
	if in, known := AWSSSOSignedIn(v.Root); !in || !known {
		t.Fatalf("after sealing a login: signedIn %v known %v", in, known)
	}
	regOnly := t.TempDir()
	if err := os.MkdirAll(filepath.Join(regOnly, "cache"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(regOnly, "cache", "reg.json"), []byte(`{"clientId":"c","clientSecret":"s"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := StoreAWSSSOCache(v, home, mustPack(t, regOnly)); err != nil {
		t.Fatal(err)
	}
	if in, known := AWSSSOSignedIn(v.Root); in || !known {
		t.Fatalf("after sign-out: signedIn %v known %v", in, known)
	}
}
