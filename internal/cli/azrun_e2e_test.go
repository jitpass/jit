// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/migrate"
	"github.com/jitpass/jit/internal/sealstore"
)

// fakeEntra answers what the Azure CLI needs from Entra ID and ARM:
// spike/azure-cli-store's fake_entra.py ported. Every refresh rotates the
// refresh token. slowRefresh holds refresh-grant answers back, so a test
// can make one run reseal after another.
type fakeEntra struct {
	base        string
	slowRefresh time.Duration
	mu          sync.Mutex
	n           int
	rts         []string // refresh tokens presented
}

const (
	entraTenant = "11111111-2222-3333-4444-555555555555"
	entraSub    = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	entraOID    = "99999999-8888-7777-6666-555555555555"
)

func b64JSON(v any) string {
	b, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (f *fakeEntra) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	reply := func(v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	p := r.URL.Path
	tenant := strings.Split(strings.TrimPrefix(p, "/"), "/")[0]
	switch {
	case strings.HasSuffix(p, "/metadata/endpoints"):
		reply(map[string]any{"name": "FakeCloud", "resourceManager": f.base + "/arm/", "portal": f.base + "/portal/",
			"authentication": map[string]any{"loginEndpoint": f.base, "audiences": []string{f.base + "/arm/"}, "tenant": "common"},
			"graphAudience":  f.base + "/graph/", "suffixes": map[string]any{}})
	case strings.HasSuffix(p, "/v2.0/.well-known/openid-configuration"):
		reply(map[string]any{"issuer": f.base + "/" + tenant + "/v2.0", "authorization_endpoint": f.base + "/" + tenant + "/oauth2/v2.0/authorize",
			"token_endpoint": f.base + "/" + tenant + "/oauth2/v2.0/token", "device_authorization_endpoint": f.base + "/" + tenant + "/oauth2/v2.0/devicecode"})
	case strings.HasPrefix(p, "/arm/tenants"):
		reply(map[string]any{"value": []any{map[string]string{"id": "/tenants/" + entraTenant, "tenantId": entraTenant, "displayName": "Fake"}}})
	case strings.HasPrefix(p, "/arm/subscriptions"):
		reply(map[string]any{"value": []any{map[string]any{"id": "/subscriptions/" + entraSub, "subscriptionId": entraSub, "tenantId": entraTenant,
			"displayName": "Fake Sub", "state": "Enabled", "managedByTenants": []any{}}}})
	case strings.HasSuffix(p, "/oauth2/v2.0/devicecode"):
		reply(map[string]any{"device_code": "dc", "user_code": "ABCD", "verification_uri": "https://microsoft.com/devicelogin",
			"expires_in": 900, "interval": 1, "message": "To sign in, enter the code ABCD"})
	case strings.HasSuffix(p, "/oauth2/v2.0/token"):
		_ = r.ParseForm()
		grant := r.Form.Get("grant_type")
		if grant == "refresh_token" && f.slowRefresh > 0 {
			time.Sleep(f.slowRefresh)
		}
		f.mu.Lock()
		f.n++
		n := f.n
		if rt := r.Form.Get("refresh_token"); rt != "" {
			f.rts = append(f.rts, rt)
		}
		f.mu.Unlock()
		out := map[string]any{"token_type": "Bearer", "expires_in": 3600, "ext_expires_in": 3600, "scope": r.Form.Get("scope"),
			"access_token": fmt.Sprintf("at-%d", n)}
		if grant != "client_credentials" {
			if tenant == "organizations" || tenant == "common" {
				tenant = entraTenant
			}
			now := time.Now().Unix()
			out["refresh_token"] = fmt.Sprintf("rt-%d", n)
			out["id_token"] = "e30." + b64JSON(map[string]any{"aud": r.Form.Get("client_id"), "iss": f.base + "/" + tenant + "/v2.0",
				"iat": now, "nbf": now, "exp": now + 3600, "oid": entraOID, "sub": "sub-1", "tid": tenant,
				"preferred_username": "dev@example.com", "name": "Dev"}) + ".sig"
			out["client_info"] = b64JSON(map[string]string{"uid": entraOID, "utid": tenant})
		}
		reply(out)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (f *fakeEntra) presented(rt string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, p := range f.rts {
		if p == rt {
			return true
		}
	}
	return false
}

// TestAzRunE2E drives the REAL Azure CLI through az-run: a device-code
// login az itself wrote, sealed; a fetch on the unsealed store; a refresh
// that rotates the token and is sealed back; a service principal login and
// a refresh run side by side, both kept by the reseal's merge; sign-out.
// Entra ID and ARM are faked in-process over TLS (MSAL refuses http),
// wired in as a custom cloud with instance discovery off
// (spike/azure-cli-store). The vault uses the test key store.
//
//	JIT_AZURE_E2E=1 go test -run TestAzRunE2E -v ./internal/cli/
func TestAzRunE2E(t *testing.T) {
	if os.Getenv("JIT_AZURE_E2E") == "" {
		t.Skip("set JIT_AZURE_E2E=1 to run against the installed Azure CLI")
	}
	az, err := exec.LookPath("az")
	if err != nil {
		t.Skip("az not installed")
	}
	entra := &fakeEntra{}
	srv := httptest.NewTLSServer(entra)
	defer srv.Close()
	entra.base = srv.URL
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("REQUESTS_CA_BUNDLE", caFile)
	t.Setenv("AZURE_CORE_COLLECT_TELEMETRY", "false")
	t.Setenv("AZURE_CONFIG_DIR", "")

	home := withFixtureHome(t)
	withTestKeystore(t)
	root, _ := vaultRootDir()
	dir := migrate.AzureConfigDir(home)
	direct := func(args ...string) {
		t.Helper()
		c := exec.Command(az, args...) // #nosec G204 -- the installed Azure CLI, test args
		c.Env = append(os.Environ(), "AZURE_CONFIG_DIR="+dir)
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("az %v: %v\n%s", args, err, out)
		}
	}
	direct("config", "set", "core.instance_discovery=false", "core.only_show_errors=true")
	direct("cloud", "register", "-n", "FakeCloud", "--endpoint-resource-manager", srv.URL+"/arm/")
	direct("cloud", "set", "-n", "FakeCloud")
	direct("login", "--use-device-code", "-o", "none")

	v, err := openVault()
	if err != nil {
		t.Fatal(err)
	}
	res, err := migrate.AzureStore.Seal(v, home)
	if err != nil || len(res.Files) != 1 {
		t.Fatalf("sealed %v, %v", res.Files, err)
	}
	noPlaintext := func() {
		t.Helper()
		for _, name := range sealstore.Azure.Secrets {
			if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
				t.Fatalf("%s is in plaintext in %s", name, dir)
			}
		}
	}
	noPlaintext()

	run := func(args ...string) string {
		t.Helper()
		var errOut bytes.Buffer
		cmd := &cobra.Command{}
		cmd.SetErr(&errOut)
		code, err := runStoreRun(cmd, migrate.AzureStore, az, args)
		if err != nil || code != 0 {
			t.Fatalf("az %v: exit %d, %v\n%s", args, code, err, errOut.String())
		}
		return errOut.String()
	}
	sealedRTs := func() map[string]string {
		t.Helper()
		blob, _, err := migrate.AzureStore.ReadSealed(v)
		if err != nil {
			t.Fatal(err)
		}
		files, _ := sealstore.Files(blob)
		var cache struct {
			RefreshToken map[string]struct{ Secret string } `json:"RefreshToken"`
		}
		_ = json.Unmarshal(files["msal_token_cache.json"], &cache)
		out := map[string]string{}
		for k, e := range cache.RefreshToken {
			out[k] = e.Secret
		}
		return out
	}
	expire := func() {
		t.Helper()
		blob, dek, err := migrate.AzureStore.ReadSealed(v)
		if err != nil {
			t.Fatal(err)
		}
		files, _ := sealstore.Files(blob)
		var cache map[string]map[string]map[string]any
		if err := json.Unmarshal(files["msal_token_cache.json"], &cache); err != nil {
			t.Fatal(err)
		}
		for _, e := range cache["AccessToken"] {
			e["expires_on"], e["extended_expires_on"] = "1000", "1000"
		}
		files["msal_token_cache.json"], _ = json.Marshal(cache)
		expired, _ := sealstore.PackFiles(files)
		if _, err := migrate.AzureStore.Reseal(v, home, "", blob, dek, expired); err != nil {
			t.Fatal(err)
		}
	}
	oneRT := func() string {
		t.Helper()
		rts := sealedRTs()
		if len(rts) != 1 {
			t.Fatalf("sealed refresh tokens %v, want one", rts)
		}
		for _, rt := range rts {
			return rt
		}
		return ""
	}

	// 1. A fetch with a valid access token: served from the unsealed
	//    store, nothing to reseal.
	_, dek0, _ := migrate.AzureStore.ReadSealed(v)
	run("account", "get-access-token", "-o", "none")
	if _, dek1, _ := migrate.AzureStore.ReadSealed(v); !bytes.Equal(dek0, dek1) {
		t.Fatal("a fetch from cache resealed the store")
	}
	noPlaintext()

	// 2. Expired: the refresh presents the sealed token, and the rotated
	//    one is sealed in its place, silently.
	first := oneRT()
	expire()
	if stderr := run("account", "get-access-token", "-o", "none"); strings.Contains(stderr, "sealed") {
		t.Fatalf("a routine refresh announced itself: %q", stderr)
	}
	if !entra.presented(first) {
		t.Fatalf("the refresh never presented the sealed token %s", first)
	}
	second := oneRT()
	if second == first {
		t.Fatal("the rotated refresh token was not sealed")
	}
	noPlaintext()

	// 3. Side by side: a refresh held back at the token endpoint, and a
	//    service principal login that seals first. The refresh's reseal
	//    was overtaken, so it merges: both survive.
	expire()
	entra.slowRefresh = 3 * time.Second
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		run("account", "get-access-token", "-o", "none")
	}()
	time.Sleep(time.Second) // the refresh run has read the store
	run("login", "--service-principal", "-u", "app-123", "-p", "SpSecret-e2e", "--tenant", entraTenant, "--allow-no-subscriptions", "-o", "none")
	wg.Wait()
	entra.slowRefresh = 0
	blob, _, _ := migrate.AzureStore.ReadSealed(v)
	files, _ := sealstore.Files(blob)
	if !bytes.Contains(files["service_principal_entries.json"], []byte("SpSecret-e2e")) {
		t.Fatalf("the service principal login was lost to the refresh's reseal: %v", keysOf(files))
	}
	if rt := sealedRTs(); len(rt) == 0 || containsValue(rt, second) {
		t.Fatalf("the refresh's rotated token was lost: %v (before %s)", rt, second)
	}
	noPlaintext()

	// 4. Sign-out: the store empties, and the run says so.
	if stderr := run("account", "clear"); !strings.Contains(stderr, "signed out") {
		t.Fatalf("sign-out said %q", stderr)
	}
	blob, _, _ = migrate.AzureStore.ReadSealed(v)
	if !sealstore.Empty(blob) {
		files, _ := sealstore.Files(blob)
		t.Fatalf("signed out, yet the vault holds %v", keysOf(files))
	}
	noPlaintext()
	if entries, _ := os.ReadDir(storeRunBase(root, migrate.AzureStore)); len(entries) > 0 {
		t.Fatalf("run dirs left behind: %d entries", len(entries))
	}
}

func keysOf(m map[string][]byte) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func containsValue(m map[string]string, v string) bool {
	for _, x := range m {
		if x == v {
			return true
		}
	}
	return false
}
