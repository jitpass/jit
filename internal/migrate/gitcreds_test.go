// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package migrate

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/profile"
)

func TestParseGitCredentialInput(t *testing.T) {
	// Split attributes, terminated by a blank line; an unknown key and
	// anything after the blank line are ignored.
	in := "protocol=https\nhost=github.com\npath=octocat/repo.git\nusername=octocat\npassword=ghp_fixture\ncapability[]=authtype\n\nprotocol=leftover\n"
	c, err := ParseGitCredentialInput(strings.NewReader(in))
	if err != nil {
		t.Fatalf("ParseGitCredentialInput: %v", err)
	}
	if c.Protocol != "https" || c.Host != "github.com" || c.Username != "octocat" || c.Password != "ghp_fixture" {
		t.Errorf("parsed = %+v, want the https github.com octocat pair", c)
	}
	if c.Path != "octocat/repo.git" {
		t.Errorf("Path = %q, want octocat/repo.git", c.Path)
	}

	// The compact url= form expands into the same components git derives.
	c, err = ParseGitCredentialInput(strings.NewReader("url=https://bob:s3cret@ghe.example.com/x.git\n\n"))
	if err != nil {
		t.Fatalf("ParseGitCredentialInput (url form): %v", err)
	}
	if c.Protocol != "https" || c.Host != "ghe.example.com" || c.Username != "bob" || c.Password != "s3cret" {
		t.Errorf("url-form parse = %+v", c)
	}
}

func TestGitProfileName(t *testing.T) {
	cases := map[string]string{
		"github.com":           "git-github.com",
		"ghe.example.com:8443": "git-ghe.example.com-8443",
		"":                     "",
		"///":                  "",
	}
	for host, want := range cases {
		if got := GitProfileName(host); got != want {
			t.Errorf("GitProfileName(%q) = %q, want %q", host, got, want)
		}
	}
}

func writeGitCredentialsFile(t *testing.T, home, content string) {
	t.Helper()
	writeFile(t, GitCredentialsPath(home), content)
}

func TestDiscoverGitCredentials(t *testing.T) {
	home := t.TempDir()
	// A normal https entry, a second host, a no-password entry (skipped), a
	// malformed line (skipped), and a duplicate host (deduped, first wins).
	writeGitCredentialsFile(t, home, strings.Join([]string{
		"https://octocat:ghp_fixture@github.com",
		"https://bob:s3cret@ghe.example.com",
		"https://nopassword@nopass.example.com",
		"not a url at all",
		"https://octocat:second@github.com",
		"",
	}, "\n"))
	// An XDG-located store adds one more host.
	xdg := GitCredentialsXDGPath(home)
	if err := os.MkdirAll(filepath.Dir(xdg), 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, xdg, "https://carol:tok@gitlab.example.com\n")

	creds, err := DiscoverGitCredentials(home)
	if err != nil {
		t.Fatalf("DiscoverGitCredentials: %v", err)
	}
	var hosts []string
	for _, c := range creds {
		hosts = append(hosts, c.Host)
	}
	want := []string{"ghe.example.com", "github.com", "gitlab.example.com"}
	if strings.Join(hosts, ",") != strings.Join(want, ",") {
		t.Errorf("hosts = %v, want %v (sorted, deduped, plaintext-only)", hosts, want)
	}
	// First entry wins for a duplicated host.
	for _, c := range creds {
		if c.Host == "github.com" && c.Password != "ghp_fixture" {
			t.Errorf("github.com password = %q, want the first entry's ghp_fixture", c.Password)
		}
	}
}

func TestDiscoverGitCredentialsMissingFiles(t *testing.T) {
	creds, err := DiscoverGitCredentials(t.TempDir())
	if err != nil {
		t.Fatalf("DiscoverGitCredentials with no store files: %v", err)
	}
	if len(creds) != 0 {
		t.Errorf("want no credentials from an empty home, got %v", creds)
	}
}

func TestStoreAndEraseGitCredential(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	v := newTestVault(t)

	err := StoreGitCredential(v, GitCredential{Protocol: "https", Host: "github.com", Username: "octocat", Password: "ghp_fixture"})
	if err != nil {
		t.Fatalf("StoreGitCredential: %v", err)
	}
	if got, err := v.Get("git-github.com/PASSWORD"); err != nil || string(got) != "ghp_fixture" {
		t.Errorf("PASSWORD after store = (%q, %v), want the stored token", got, err)
	}
	if got, err := v.Get("git-github.com/USERNAME"); err != nil || string(got) != "octocat" {
		t.Errorf("USERNAME after store = (%q, %v), want octocat", got, err)
	}
	if err := StoreGitCredential(v, GitCredential{Host: "x.example.com", Username: "alice"}); err == nil {
		t.Error("StoreGitCredential with an empty password must fail")
	}

	if err := EraseGitCredential(v, "github.com"); err != nil {
		t.Fatalf("EraseGitCredential: %v", err)
	}
	globalRoot, _ := profile.GlobalRoot()
	manifestPath, _ := profile.Path(globalRoot, "git-github.com")
	if _, err := os.Stat(manifestPath); !os.IsNotExist(err) {
		t.Errorf("profile manifest still present after erase, stat err = %v", err)
	}
	// Idempotent, like git erasing a credential it never stored.
	if err := EraseGitCredential(v, "github.com"); err != nil {
		t.Errorf("second EraseGitCredential: %v", err)
	}
	if err := EraseGitCredential(v, "never-stored.example.com"); err != nil {
		t.Errorf("EraseGitCredential for a never-stored host: %v", err)
	}
}

func TestApplyGitCredential(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	v := newTestVault(t)

	// A pre-existing plaintext `store` helper is exactly what jit displaces.
	writeFile(t, filepath.Join(home, ".gitconfig"), "[user]\n\tname = Octo Cat\n[credential]\n\thelper = store\n")
	writeGitCredentialsFile(t, home, strings.Join([]string{
		"https://octocat:ghp_fixture@github.com",
		"https://bob:s3cret@ghe.example.com",
		"",
	}, "\n"))

	backups := NewBackupTracker()
	mig, err := ApplyGitCredential(v, home, "github.com", backups)
	if err != nil {
		t.Fatalf("ApplyGitCredential: %v", err)
	}
	if !mig.ReplacedStoreHelper {
		t.Error("expected ReplacedStoreHelper=true when a store helper was configured")
	}

	// The credential is in the vault.
	if got, err := v.Get("git-github.com/PASSWORD"); err != nil || string(got) != "ghp_fixture" {
		t.Errorf("vaulted PASSWORD = (%q, %v), want ghp_fixture", got, err)
	}

	// credential.helper is now jit, and the store helper is gone.
	helpers, err := gitCredentialHelpers(gitGlobalConfigPath(home))
	if err != nil {
		t.Fatalf("gitCredentialHelpers: %v", err)
	}
	if strings.Join(helpers, ",") != "jit" {
		t.Errorf("credential.helper = %v, want just [jit] (store replaced)", helpers)
	}

	// The migrated host is gone from the store; the other host stays.
	rest, _ := os.ReadFile(GitCredentialsPath(home)) // #nosec G304 -- test path
	if strings.Contains(string(rest), "github.com") {
		t.Errorf("github.com still in the store after migration:\n%s", rest)
	}
	if !strings.Contains(string(rest), "ghe.example.com") {
		t.Errorf("ghe.example.com wrongly removed from the store:\n%s", rest)
	}

	// The helper executable was written.
	if _, err := os.Stat(mig.HelperPath); err != nil {
		t.Errorf("helper not written: %v", err)
	}

	// Migrating the second host is idempotent on the helper (no duplicate jit).
	if _, err := ApplyGitCredential(v, home, "ghe.example.com", backups); err != nil {
		t.Fatalf("ApplyGitCredential (second host): %v", err)
	}
	helpers, _ = gitCredentialHelpers(gitGlobalConfigPath(home))
	if strings.Join(helpers, ",") != "jit" {
		t.Errorf("after second host, credential.helper = %v, want a single [jit]", helpers)
	}
	rest, _ = os.ReadFile(GitCredentialsPath(home)) // #nosec G304 -- test path
	if strings.TrimSpace(string(rest)) != "" {
		t.Errorf("store not empty after migrating both hosts:\n%q", rest)
	}
}

func TestWriteGitHelper(t *testing.T) {
	home := t.TempDir()
	path, err := writeGitHelper(home)
	if err != nil {
		t.Fatalf("writeGitHelper: %v", err)
	}
	if path != GitHelperPath(home) {
		t.Errorf("helper path = %q, want %q", path, GitHelperPath(home))
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat helper: %v", err)
	}
	if info.Mode().Perm()&0o100 == 0 {
		t.Errorf("helper not executable, mode = %v", info.Mode())
	}
	data, err := os.ReadFile(path) // #nosec G304 -- test-controlled path
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "git-credential \"$@\"") {
		t.Errorf("helper script doesn't dispatch to `jit git-credential`:\n%s", data)
	}
}
