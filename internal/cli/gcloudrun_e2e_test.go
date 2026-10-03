// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/migrate"
	"github.com/jitpass/jit/internal/sealstore"
)

// TestGcloudRunE2E drives the REAL Google Cloud SDK through gcloud-run:
// seal a login gcloud itself wrote, run gcloud commands on the unsealed
// store, capture a new login, and check nothing is left in plaintext. No
// Google account: a local token endpoint answers every refresh, wired in
// through gcloud's own auth/token_host property (the spike's method,
// spike/gcloud-sealed-config). The vault uses the test key store.
//
// Opt-in, since it needs the SDK installed:
//
//	JIT_GCLOUD_E2E=1 go test -run TestGcloudRunE2E -v ./internal/cli/
func TestGcloudRunE2E(t *testing.T) {
	if os.Getenv("JIT_GCLOUD_E2E") == "" {
		t.Skip("set JIT_GCLOUD_E2E=1 to run against the installed gcloud")
	}
	gcloud, err := exec.LookPath("gcloud")
	if err != nil {
		t.Skip("gcloud not installed")
	}
	sdkBin := filepath.Dir(mustEval(t, gcloud))

	// The token endpoint: records the refresh token each request presents.
	var mu sync.Mutex
	var presented []string
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		mu.Lock()
		n++
		presented = append(presented, r.Form.Get("refresh_token"))
		body, _ := json.Marshal(map[string]any{
			"access_token": fmt.Sprintf("ya29.E2E-%d", n), "expires_in": 3600, "token_type": "Bearer",
		})
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	seen := func(token string) bool {
		mu.Lock()
		defer mu.Unlock()
		for _, p := range presented {
			if p == token {
				return true
			}
		}
		return false
	}

	home := withFixtureHome(t)
	withTestKeystore(t)
	t.Setenv("CLOUDSDK_CONFIG", "")
	t.Setenv("CLOUDSDK_CORE_DISABLE_PROMPTS", "1")
	t.Setenv("CLOUDSDK_COMPONENT_MANAGER_DISABLE_UPDATE_CHECK", "1")
	dir := migrate.GcloudConfigDir(home)

	// A login written by gcloud itself, in the default config dir.
	direct := func(args ...string) {
		t.Helper()
		c := exec.Command(gcloud, args...) // #nosec G204 -- the installed gcloud, test args
		c.Env = append(os.Environ(), "CLOUDSDK_CONFIG="+dir)
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("gcloud %v: %v\n%s", args, err, out)
		}
	}
	direct("config", "set", "auth/token_host", srv.URL+"/token")
	direct("config", "set", "project", "e2e-proj")
	direct("auth", "activate-refresh-token", "e2e@example.com", "1//E2E-FIRST")

	v, err := openVault()
	if err != nil {
		t.Fatal(err)
	}
	res, err := migrate.GcloudStore.Seal(v, home)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Files) != 3 {
		t.Fatalf("sealed %q, want credentials.db and the two legacy files", res.Files)
	}
	assertNoPlaintext(t, dir)

	run := func(tool string, args ...string) (int, string) {
		t.Helper()
		var errOut bytes.Buffer
		cmd := &cobra.Command{}
		cmd.SetErr(&errOut)
		code, err := runStoreRun(cmd, migrate.GcloudStore, tool, args)
		if err != nil {
			t.Fatalf("%s %v: %v\n%s", filepath.Base(tool), args, err, errOut.String())
		}
		return code, errOut.String()
	}

	// 1. Real gcloud reads the unsealed login: it refreshes with the
	//    sealed refresh token.
	if code, _ := run(gcloud, "auth", "print-access-token"); code != 0 {
		t.Fatalf("print-access-token exited %d", code)
	}
	if !seen("1//E2E-FIRST") {
		t.Fatalf("the endpoint never saw the sealed refresh token; presented %q", presented)
	}
	assertNoPlaintext(t, dir)

	// 2. A settings write lands in the real dir; the store is not resealed.
	before, _ := v.Get(migrate.GcloudStorePath)
	if code, stderr := run(gcloud, "config", "set", "compute/region", "us-east1"); code != 0 || strings.Contains(stderr, "sealed") {
		t.Fatalf("config set: %d, %q", code, stderr)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "configurations", "config_default")); !strings.Contains(string(b), "us-east1") {
		t.Fatalf("the region did not reach the settings dir:\n%s", b)
	}
	if after, _ := v.Get(migrate.GcloudStorePath); !bytes.Equal(before, after) {
		t.Fatal("a settings change resealed the store")
	}

	// 3. A new login through the wrap is captured into the vault.
	_, stderr := run(gcloud, "auth", "activate-refresh-token", "e2e2@example.com", "1//E2E-SECOND")
	if !strings.Contains(stderr, "sealed gcloud's login") {
		t.Fatalf("activate did not reseal: %q", stderr)
	}
	blob, _ := v.Get(migrate.GcloudStorePath)
	if !bytes.Contains(blob, []byte("1//E2E-SECOND")) || !bytes.Contains(blob, []byte("1//E2E-FIRST")) {
		t.Fatal("the vault does not hold both accounts after the second login")
	}
	assertNoPlaintext(t, dir)

	// 4. The GKE auth plugin runs gcloud from PATH; inside the run that
	//    gcloud sees the outer run's store (the nested-run path).
	if plugin := filepath.Join(sdkBin, "gke-gcloud-auth-plugin"); fileExists(plugin) {
		t.Setenv("PATH", sdkBin+string(os.PathListSeparator)+os.Getenv("PATH"))
		if code, _ := run(plugin); code != 0 {
			t.Fatalf("gke-gcloud-auth-plugin exited %d", code)
		}
	}

	// 5. The docker helper, which loads gcloud's library in-process.
	if helper := filepath.Join(sdkBin, "docker-credential-gcloud"); fileExists(helper) {
		withStdin(t, "https://gcr.io\n", func() {
			if code, _ := run(helper, "get"); code != 0 {
				t.Fatalf("docker-credential-gcloud exited %d", code)
			}
		})
	}

	// 6. Concurrent runs share nothing they can break.
	var wg sync.WaitGroup
	codes := make([]int, 6)
	for i := range codes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			var errOut bytes.Buffer
			cmd := &cobra.Command{}
			cmd.SetErr(&errOut)
			codes[i], _ = runStoreRun(cmd, migrate.GcloudStore, gcloud, []string{"auth", "print-access-token"})
		}(i)
	}
	wg.Wait()
	for i, c := range codes {
		if c != 0 {
			t.Errorf("concurrent run %d exited %d", i, c)
		}
	}

	assertNoPlaintext(t, dir)
	root, _ := vaultRootDir()
	if entries, _ := os.ReadDir(storeRunBase(root, migrate.GcloudStore)); len(entries) != 0 {
		t.Fatalf("run dirs left behind: %v", entries)
	}
}

func assertNoPlaintext(t *testing.T, dir string) {
	t.Helper()
	if left, _ := sealstore.Gcloud.Plaintext(dir); len(left) != 0 {
		t.Fatalf("plaintext in %s: %q", dir, left)
	}
}

func mustEval(t *testing.T, p string) string {
	t.Helper()
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// withStdin runs f with os.Stdin reading body: the forked tool inherits it.
func withStdin(t *testing.T, body string, f func()) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.WriteString(body)
	_ = w.Close()
	orig := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = orig; _ = r.Close() }()
	f()
}
