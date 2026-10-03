// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const kubeloginKubeconfig = `apiVersion: v1
kind: Config
users:
- name: oidc-dev
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      command: kubectl
      args: [oidc-login, get-token, --oidc-issuer-url=https://issuer.example.com, --oidc-client-id=kube]
- name: oidc-disk
  user:
    exec:
      command: /opt/homebrew/bin/kubelogin
      args: [get-token, --oidc-issuer-url=https://issuer.example.com, --token-cache-storage=disk]
- name: oidc-keyring
  user:
    exec:
      command: kubectl-oidc_login
      args: [get-token, --token-cache-storage, keyring]
- name: aks
  user:
    exec:
      command: kubelogin
      args: [get-token, --login, azurecli, --server-id, 6dae42f8-4368-4678-94ff-3960e28e3630]
- name: eks
  user:
    exec:
      command: aws
      args: [eks, get-token, --cluster-name, prod]
- name: plain
  user:
    token: abc
`

func kubeloginHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	for rel, body := range map[string]string{
		".kube/config": kubeloginKubeconfig,
		".kube/cache/oidc-login/" + strings.Repeat("ab", 32):           `{"id_token":"eyJ.a.b","refresh_token":"rt-one"}`,
		".kube/cache/oidc-login/" + strings.Repeat("ab", 32) + ".lock": "",
		".kube/cache/oidc-login/" + strings.Repeat("cd", 32):           `{"refresh_token":"rt-two"}`,
	} {
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

func TestDiscoverKubeloginUsers(t *testing.T) {
	home := kubeloginHome(t)
	got, err := DiscoverKubeloginUsers(home)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"oidc-dev", "oidc-disk"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("discovered %q, want %q (keyring, aws and token users are not kubelogin-on-disk)", got, want)
	}
}

func TestApplyKubeloginKeyring(t *testing.T) {
	home := kubeloginHome(t)
	v := newTestVault(t)
	users, _ := DiscoverKubeloginUsers(home)
	res, err := ApplyKubeloginKeyring(v, home, users, NewBackupTracker())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.CacheFiles) != 2 {
		t.Fatalf("removed %q, want the two token files", res.CacheFiles)
	}
	b, _ := os.ReadFile(KubeconfigPath(home))
	cfg := string(b)
	if strings.Count(cfg, kubeloginKeyringFlag) != 2 || strings.Contains(cfg, "--token-cache-storage=disk") {
		t.Fatalf("kubeconfig after the switch:\n%s", cfg)
	}
	for _, keep := range []string{"--oidc-issuer-url=https://issuer.example.com", "--oidc-client-id=kube", "token: abc", "--cluster-name"} {
		if !strings.Contains(cfg, keep) {
			t.Errorf("the switch lost %q:\n%s", keep, cfg)
		}
	}
	if again, _ := DiscoverKubeloginUsers(home); len(again) != 0 {
		t.Errorf("switched users found again: %q", again)
	}
	entries, _ := os.ReadDir(KubeloginCacheDir(home))
	if len(entries) != 1 || !strings.HasSuffix(entries[0].Name(), ".lock") {
		t.Fatalf("cache dir after the switch: %v, want only the lock file", entries)
	}
	recs, _ := LoadBackupRecords(v.Root)
	linked := 0
	for _, r := range recs {
		if IsKubeloginCacheFile(home, r.OriginalPath) && containsPath(r.RestoreWith, KubeconfigPath(home)) {
			linked++
		}
	}
	if linked != 2 {
		t.Fatalf("%d cache backups linked to the kubeconfig, want 2", linked)
	}
	for _, r := range LatestBackups(recs) {
		if err := RestoreFromBackup(v, r); err != nil {
			t.Fatal(err)
		}
	}
	if b, _ := os.ReadFile(KubeconfigPath(home)); string(b) != kubeloginKubeconfig {
		t.Fatal("undo did not restore the kubeconfig byte for byte")
	}
	if got, _ := kubeloginCacheFiles(home); len(got) != 2 {
		t.Fatalf("undo restored %q, want both logins", got)
	}
}

func TestWithKeyringStorage(t *testing.T) {
	in := []interface{}{"get-token", "--token-cache-storage", "disk", "--x=y"}
	got := withKeyringStorage(in)
	want := []interface{}{"get-token", "--x=y", kubeloginKeyringFlag}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestApplyKubeloginKeyringRefusesANonKubeloginUser(t *testing.T) {
	home := kubeloginHome(t)
	if _, err := ApplyKubeloginKeyring(newTestVault(t), home, []string{"eks"}, nil); err == nil {
		t.Fatal("switched a user that does not run kubelogin")
	}
	if b, _ := os.ReadFile(KubeconfigPath(home)); string(b) != kubeloginKubeconfig {
		t.Fatal("a refused switch changed the kubeconfig")
	}
}

// A kubeconfig kept as a link into a dotfiles repo stays a link.
func TestApplyKubeloginKeyringWritesThroughALink(t *testing.T) {
	home := kubeloginHome(t)
	v := newTestVault(t)
	repo := filepath.Join(t.TempDir(), "kubeconfig")
	data, _ := os.ReadFile(KubeconfigPath(home)) // #nosec G304 -- test path
	if err := os.WriteFile(repo, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(KubeconfigPath(home)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(repo, KubeconfigPath(home)); err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyKubeloginKeyring(v, home, []string{"oidc-dev"}, nil); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Lstat(KubeconfigPath(home)); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the link was replaced: %v %v", info.Mode(), err)
	}
	if b, _ := os.ReadFile(repo); !strings.Contains(string(b), kubeloginKeyringFlag) { // #nosec G304 -- test path
		t.Fatalf("the repo file was not rewritten:\n%s", b)
	}
}
