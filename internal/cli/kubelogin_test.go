// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/migrate"
)

// Naming the cache file the scan reported, or ~/.kube/config, plans the
// switch to the keychain; --only scopes it with the kube category; a real
// run rewrites the exec args and clears the plaintext cache.
func TestMigrateSwitchesKubeloginToTheKeychain(t *testing.T) {
	home := withFixtureHome(t)
	withTestKeystore(t)
	cfg := migrate.KubeconfigPath(home)
	cache := filepath.Join(migrate.KubeloginCacheDir(home), strings.Repeat("ab", 32))
	for p, body := range map[string]string{
		cfg:   "apiVersion: v1\nusers:\n- name: dev\n  user:\n    exec:\n      command: kubectl\n      args: [oidc-login, get-token, --oidc-issuer-url=https://issuer.example.com]\n",
		cache: `{"refresh_token":"rt-1"}`,
	} {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	out, err := execMigrate(t, "--dry-run", cache)
	if err != nil {
		t.Fatalf("dry run: %v\n%s", err, out)
	}
	if !strings.Contains(dryRunPlanOnly(out), "kubelogin user") {
		t.Fatalf("the plan for the scan's cache file lacks the switch:\n%s", out)
	}
	out, err = execMigrate(t, "--dry-run", "--only", "aws", cfg)
	if err != nil {
		t.Fatalf("dry run --only aws: %v\n%s", err, out)
	}
	if strings.Contains(dryRunPlanOnly(out), "kubelogin user") {
		t.Fatalf("--only aws still planned the kubelogin switch:\n%s", out)
	}

	out, err = execMigrate(t, "--yes", cfg)
	if err != nil {
		t.Fatalf("migrate: %v\n%s", err, out)
	}
	b, _ := os.ReadFile(cfg) // #nosec G304 -- test path
	if !strings.Contains(string(b), "--token-cache-storage=keyring") {
		t.Fatalf("kubeconfig after migrate:\n%s", b)
	}
	if _, err := os.Stat(cache); !os.IsNotExist(err) {
		t.Fatal("the plaintext cache is still there")
	}
}
