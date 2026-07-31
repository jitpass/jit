// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/profile"
)

func writeKubeconfigFixture(t *testing.T, home, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(home, ".kube"), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	writeFile(t, KubeconfigPath(home), content)
}

const kubeconfigTokenFixture = `
apiVersion: v1
kind: Config
clusters:
- name: mycluster
  cluster:
    server: https://example.com
current-context: myctx
contexts:
- name: myctx
  context:
    cluster: mycluster
    user: myuser
users:
- name: myuser
  user:
    token: sk_test_token
- name: clean
  user:
    username: someone
`

const kubeconfigCertFixture = `
apiVersion: v1
kind: Config
users:
- name: certuser
  user:
    client-certificate-data: Y2VydA==
    client-key-data: a2V5
`

func TestDiscoverKubeconfigUsersFindsTokenAndCertUsers(t *testing.T) {
	home := t.TempDir()
	writeKubeconfigFixture(t, home, kubeconfigTokenFixture)

	found, err := DiscoverKubeconfigUsers(home)
	if err != nil {
		t.Fatalf("DiscoverKubeconfigUsers: %v", err)
	}
	want := []string{"myuser"}
	if len(found) != len(want) || found[0] != want[0] {
		t.Errorf("found = %v, want %v (clean user has no migratable auth)", found, want)
	}
}

func TestDiscoverKubeconfigUsersSkipsIncompleteCertPair(t *testing.T) {
	home := t.TempDir()
	writeKubeconfigFixture(t, home, `
users:
- name: halfuser
  user:
    client-key-data: a2V5
`)
	found, err := DiscoverKubeconfigUsers(home)
	if err != nil {
		t.Fatalf("DiscoverKubeconfigUsers: %v", err)
	}
	if len(found) != 0 {
		t.Errorf("found = %v, want empty (only half the cert/key pair present)", found)
	}
}

func TestDiscoverKubeconfigUsersMissingFile(t *testing.T) {
	home := t.TempDir()
	found, err := DiscoverKubeconfigUsers(home)
	if err != nil {
		t.Fatalf("DiscoverKubeconfigUsers with no ~/.kube/config: %v", err)
	}
	if len(found) != 0 {
		t.Errorf("found = %v, want empty", found)
	}
}

func TestApplyKubeconfigUserTokenMovesSecretAndRewritesExecBlock(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeKubeconfigFixture(t, home, kubeconfigTokenFixture)

	v := newTestVault(t)
	result, err := ApplyKubeconfigUser(v, home, "myuser")
	if err != nil {
		t.Fatalf("ApplyKubeconfigUser: %v", err)
	}
	if result.AuthType != "token" {
		t.Errorf("AuthType = %q, want token", result.AuthType)
	}
	if result.VaultProfileName != "k8s-myuser" {
		t.Errorf("VaultProfileName = %q, want k8s-myuser", result.VaultProfileName)
	}

	got, err := v.Get("k8s-myuser/TOKEN")
	if err != nil || string(got) != "sk_test_token" {
		t.Errorf("TOKEN = (%q, %v), want (sk_test_token, nil)", got, err)
	}

	raw, err := os.ReadFile(KubeconfigPath(home)) // #nosec G304 -- test-controlled path
	if err != nil {
		t.Fatalf("reading rewritten kubeconfig: %v", err)
	}
	content := string(raw)
	if strings.Contains(content, "sk_test_token") {
		t.Fatal("rewritten kubeconfig must not contain the raw token")
	}
	if !strings.Contains(content, "client.authentication.k8s.io/v1") {
		t.Errorf("rewritten kubeconfig missing the exec apiVersion, got:\n%s", content)
	}
	if !strings.Contains(content, "k8s-exec-credential") || !strings.Contains(content, "k8s-myuser") {
		t.Errorf("rewritten kubeconfig missing the k8s-exec-credential invocation, got:\n%s", content)
	}
	if !strings.Contains(content, "interactiveMode: Never") {
		t.Errorf("rewritten kubeconfig missing interactiveMode: Never, got:\n%s", content)
	}
	// Untouched user and cluster/context data must survive the remarshal.
	if !strings.Contains(content, "username: someone") {
		t.Errorf("rewritten kubeconfig lost the unrelated 'clean' user, got:\n%s", content)
	}
	if !strings.Contains(content, "server: https://example.com") {
		t.Errorf("rewritten kubeconfig lost cluster data, got:\n%s", content)
	}

	p, err := profile.Load(t.TempDir(), result.VaultProfileName)
	if err != nil {
		t.Fatalf("loading migrated profile via the global fallback: %v", err)
	}
	if p["TOKEN"] != "k8s-myuser/TOKEN" {
		t.Errorf("profile entry = %q, want k8s-myuser/TOKEN", p["TOKEN"])
	}
}

func TestApplyKubeconfigUserClientCertMovesBothFields(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeKubeconfigFixture(t, home, kubeconfigCertFixture)

	v := newTestVault(t)
	result, err := ApplyKubeconfigUser(v, home, "certuser")
	if err != nil {
		t.Fatalf("ApplyKubeconfigUser: %v", err)
	}
	if result.AuthType != "client-cert" {
		t.Errorf("AuthType = %q, want client-cert", result.AuthType)
	}
	wantVars := []string{"CLIENT_CERTIFICATE_DATA", "CLIENT_KEY_DATA"}
	if len(result.Variables) != len(wantVars) {
		t.Fatalf("Variables = %v, want %v", result.Variables, wantVars)
	}

	cert, err := v.Get("k8s-certuser/CLIENT_CERTIFICATE_DATA")
	if err != nil || string(cert) != "Y2VydA==" {
		t.Errorf("CLIENT_CERTIFICATE_DATA = (%q, %v), want (Y2VydA==, nil)", cert, err)
	}
	key, err := v.Get("k8s-certuser/CLIENT_KEY_DATA")
	if err != nil || string(key) != "a2V5" {
		t.Errorf("CLIENT_KEY_DATA = (%q, %v), want (a2V5, nil)", key, err)
	}
}

func TestApplyKubeconfigUserWritesBackup(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeKubeconfigFixture(t, home, kubeconfigTokenFixture)

	v := newTestVault(t)
	result, err := ApplyKubeconfigUser(v, home, "myuser")
	if err != nil {
		t.Fatalf("ApplyKubeconfigUser: %v", err)
	}
	backup, err := v.Get(result.Backup)
	if err != nil {
		t.Fatalf("reading backup from vault: %v", err)
	}
	if !strings.Contains(string(backup), "sk_test_token") {
		t.Error("backup should contain the original plaintext token")
	}
}

func TestApplyKubeconfigUserMissingUserErrors(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeKubeconfigFixture(t, home, kubeconfigTokenFixture)

	v := newTestVault(t)
	if _, err := ApplyKubeconfigUser(v, home, "nonexistent"); err == nil {
		t.Fatal("expected an error migrating a user that doesn't exist")
	}
}

func TestApplyKubeconfigUserCleanUserErrors(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeKubeconfigFixture(t, home, kubeconfigTokenFixture)

	v := newTestVault(t)
	if _, err := ApplyKubeconfigUser(v, home, "clean"); err == nil {
		t.Fatal("expected an error migrating a user with no migratable credentials")
	}
}

// A user entry with BOTH a token and a client cert/key pair must have all
// three vaulted — the rewrite deletes all three regardless.
//
// The early return on token meant the cert and key were removed from
// ~/.kube/config having never been stored anywhere: gone from the live file,
// absent from the vault, unmentioned in the plan, and recoverable only by
// digging the whole-file backup out by hand.
func TestKubeconfigUserSecretsKeepsEveryCredentialPresent(t *testing.T) {
	userMap := map[string]interface{}{
		"token":                   "sha256~fixture-token",
		"client-certificate-data": "Y2VydA==",
		"client-key-data":         "a2V5",
	}
	authType, secrets := kubeconfigUserSecrets(userMap)

	for _, key := range []string{"TOKEN", "CLIENT_CERTIFICATE_DATA", "CLIENT_KEY_DATA"} {
		if secrets[key] == "" {
			t.Errorf("%s was not vaulted, but the rewrite deletes its kubeconfig field: it would be destroyed", key)
		}
	}
	if authType != "token+client-cert" {
		t.Errorf("AuthType = %q, want token+client-cert so the plan names what it took", authType)
	}
}

// The single-kind cases must be unchanged.
func TestKubeconfigUserSecretsSingleKinds(t *testing.T) {
	authType, secrets := kubeconfigUserSecrets(map[string]interface{}{"token": "t"})
	if authType != "token" || secrets["TOKEN"] != "t" || len(secrets) != 1 {
		t.Errorf("token-only = (%q, %v), want token with just TOKEN", authType, secrets)
	}

	authType, secrets = kubeconfigUserSecrets(map[string]interface{}{
		"client-certificate-data": "Y2VydA==",
		"client-key-data":         "a2V5",
	})
	if authType != "client-cert" || secrets["CLIENT_CERTIFICATE_DATA"] != "Y2VydA==" || secrets["CLIENT_KEY_DATA"] != "a2V5" {
		t.Errorf("cert-only = (%q, %v), want client-cert with the pair", authType, secrets)
	}
}
