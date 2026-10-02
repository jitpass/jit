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
	"time"

	"github.com/jitpass/jit/internal/migrate"
	"github.com/jitpass/jit/internal/vault"
)

// fakeIdentityCenter answers the SSO OIDC and SSO portal calls the AWS CLI
// makes, the spike's fake_sso_server.py ported (spike/aws-sso-process).
// Every refresh rotates the refresh token, as Identity Center does.
type fakeIdentityCenter struct {
	mu  sync.Mutex
	n   int
	ops []string // op, op(grant) for CreateToken
	rts []string // refresh tokens presented to a refresh
}

func (f *fakeIdentityCenter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
	reply := func(v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	switch r.URL.Path {
	case "/client/register":
		f.ops = append(f.ops, "RegisterClient")
		reply(map[string]any{"clientId": "cid", "clientSecret": "csecret", "clientIdIssuedAt": time.Now().Unix(), "clientSecretExpiresAt": time.Now().Add(90 * 24 * time.Hour).Unix()})
	case "/device_authorization":
		f.ops = append(f.ops, "StartDeviceAuthorization")
		reply(map[string]any{"deviceCode": "dc", "userCode": "ABCD", "verificationUri": "https://device.example/", "verificationUriComplete": "https://device.example/?c=ABCD", "expiresIn": 600, "interval": 1})
	case "/token":
		grant, _ := body["grantType"].(string)
		f.ops = append(f.ops, "CreateToken("+grant[strings.LastIndex(grant, ":")+1:]+")")
		if rt, _ := body["refreshToken"].(string); rt != "" {
			f.rts = append(f.rts, rt)
		}
		reply(map[string]any{"accessToken": fmt.Sprintf("access-%d", f.n), "expiresIn": 3600, "tokenType": "Bearer", "refreshToken": fmt.Sprintf("1//refresh-%d", f.n)})
	case "/federation/credentials":
		f.ops = append(f.ops, "GetRoleCredentials")
		reply(map[string]any{"roleCredentials": map[string]any{"accessKeyId": fmt.Sprintf("ASIAE2E%09d", f.n), "secretAccessKey": "s", "sessionToken": "t", "expiration": time.Now().Add(time.Hour).UnixMilli()}})
	case "/logout":
		f.ops = append(f.ops, "Logout")
		w.WriteHeader(http.StatusOK)
	default:
		f.ops = append(f.ops, "unknown "+r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}
}

func (f *fakeIdentityCenter) take() (ops, rts []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	ops, rts = f.ops, f.rts
	f.ops, f.rts = nil, nil
	return ops, rts
}

// TestAWSSSOE2E drives the REAL AWS CLI through jit aws-sso's core: a
// native login, sealing, fetches through the sealed login, a refresh that
// rotates the token, concurrent refreshes, a login captured on the next
// fetch, and sign-out. Identity Center is faked in-process, wired in with
// the CLI's own AWS_ENDPOINT_URL_SSO[_OIDC]; the vault uses the test key
// store. The outer hop (the AWS CLI running credential_process) is the
// spike's E2/E7/E11, proven there with the same CLI.
//
//	JIT_AWS_SSO_E2E=1 go test -run TestAWSSSOE2E -v ./internal/cli/
func TestAWSSSOE2E(t *testing.T) {
	if os.Getenv("JIT_AWS_SSO_E2E") == "" {
		t.Skip("set JIT_AWS_SSO_E2E=1 to run against the installed AWS CLI")
	}
	awsBin, err := exec.LookPath("aws")
	if err != nil {
		t.Skip("aws not installed")
	}
	idc := &fakeIdentityCenter{}
	srv := httptest.NewServer(idc)
	defer srv.Close()
	t.Setenv("AWS_ENDPOINT_URL_SSO", srv.URL)
	t.Setenv("AWS_ENDPOINT_URL_SSO_OIDC", srv.URL)
	t.Setenv("AWS_PAGER", "")

	home := withFixtureHome(t)
	withTestKeystore(t)
	t.Cleanup(migrate.SetJitExecutableForTesting("/usr/local/bin/jit"))
	root, _ := vaultRootDir()
	v, err := openVault()
	if err != nil {
		t.Fatal(err)
	}
	cfg := migrate.AWSConfigPath(home)
	if err := os.MkdirAll(filepath.Dir(cfg), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg, []byte("[profile dev]\nsso_session = corp\nsso_account_id = 111122223333\nsso_role_name = Developer\nregion = us-east-1\n\n[sso-session corp]\nsso_start_url = https://corp.awsapps.com/start\nsso_region = us-east-1\nsso_registration_scopes = sso:account:access\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	login := func(args ...string) {
		t.Helper()
		c := exec.Command(awsBin, append([]string{"sso", "login", "--use-device-code", "--no-browser"}, args...)...) // #nosec G204 -- the installed AWS CLI, test args
		c.Env = append(os.Environ(), "HOME="+home)
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("aws sso login: %v\n%s", err, out)
		}
	}
	fetch := func() string {
		t.Helper()
		var errOut bytes.Buffer
		out, err := awsSSOWithLogin(&errOut, v, home, root, awsBin, "dev", []string{"configure", "export-credentials", "--profile", "dev", "--format", "process"})
		if err != nil {
			t.Fatalf("fetch: %v\n%s", err, errOut.String())
		}
		var doc struct{ AccessKeyId string }
		if err := json.Unmarshal(out, &doc); err != nil || doc.AccessKeyId == "" {
			t.Fatalf("fetch printed %q", out)
		}
		return doc.AccessKeyId
	}
	plaintext := func() []string {
		var left []string
		for _, d := range []string{migrate.AWSSSOCacheDir(home), filepath.Join(home, ".aws", "cli", "cache")} {
			entries, _ := os.ReadDir(d)
			for _, e := range entries {
				if strings.HasSuffix(e.Name(), ".json") {
					left = append(left, filepath.Join(d, e.Name()))
				}
			}
		}
		return left
	}

	// 1. A native login, then sealing.
	login("--sso-session", "corp")
	if _, err := migrate.ApplyAWSSSO(v, home, []string{"dev"}, nil); err != nil {
		t.Fatal(err)
	}
	if left := plaintext(); len(left) != 0 {
		t.Fatalf("plaintext after sealing: %q", left)
	}
	idc.take()

	// 2. A fetch through the sealed login: role credentials, no refresh.
	fetch()
	if ops, _ := idc.take(); strings.Join(ops, " ") != "GetRoleCredentials" {
		t.Fatalf("fetch ops %q", ops)
	}
	if left := plaintext(); len(left) != 0 {
		t.Fatalf("plaintext after a fetch: %q", left)
	}

	// 3. An expired access token: AWS's own refresh, rotation sealed back.
	expireSealedAWSLogin(t, v, home)
	before := sealedRefreshToken(t, v)
	fetch()
	ops, rts := idc.take()
	if len(rts) != 1 || rts[0] != before || !strings.Contains(strings.Join(ops, " "), "CreateToken(refresh_token)") {
		t.Fatalf("refresh: ops %q presented %q, want the sealed %q", ops, rts, before)
	}
	if after := sealedRefreshToken(t, v); after == before {
		t.Fatal("the rotated refresh token was not sealed back")
	}

	// 4. Concurrent fetches with an expired token: one refresh.
	expireSealedAWSLogin(t, v, home)
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() { defer wg.Done(); fetch() }()
	}
	wg.Wait()
	if _, rts := idc.take(); len(rts) != 1 {
		t.Fatalf("4 concurrent fetches refreshed %d times, want 1", len(rts))
	}

	// 5. `aws sso login --profile dev` on the rewritten profile works, and
	//    the next fetch captures it.
	login("--profile", "dev")
	if len(plaintext()) == 0 {
		t.Fatal("the native login wrote nothing to capture")
	}
	idc.take()
	fetch()
	if left := plaintext(); len(left) != 0 {
		t.Fatalf("the native login was not captured: %q", left)
	}

	// 6. Sign-out: server-side Logout, no login left in the vault.
	var errOut bytes.Buffer
	if _, err := awsSSOWithLogin(&errOut, v, home, root, awsBin, "", []string{"sso", "logout"}); err != nil {
		t.Fatalf("logout: %v\n%s", err, errOut.String())
	}
	if ops, _ := idc.take(); !strings.Contains(strings.Join(ops, " "), "Logout") {
		t.Fatalf("logout ops %q", ops)
	}
	if _, err := awsSSOWithLogin(&errOut, v, home, root, awsBin, "dev", []string{"configure", "export-credentials", "--profile", "dev", "--format", "process"}); err == nil || !strings.Contains(err.Error(), "aws sso login --profile dev") {
		t.Fatalf("fetch after logout: %v", err)
	}
	if entries, _ := os.ReadDir(awsSSORunBase(root)); len(entries) != 0 {
		t.Fatalf("run dirs left: %v", entries)
	}
}

// sealedLoginDoc unpacks the sealed cache and returns the token file's
// document and path inside stage.
func sealedLoginDoc(t *testing.T, v *vault.Vault) (map[string]any, string, string) {
	t.Helper()
	blob, err := v.Get(migrate.AWSSSOStorePath)
	if err != nil {
		t.Fatal(err)
	}
	stage := t.TempDir()
	if err := migrate.AWSSSOLayout.Unpack(blob, stage); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(filepath.Join(stage, "cache"))
	for _, e := range entries {
		p := filepath.Join(stage, "cache", e.Name())
		b, _ := os.ReadFile(p) // #nosec G304 -- test stage
		var doc map[string]any
		if json.Unmarshal(b, &doc) == nil && doc["accessToken"] != nil {
			return doc, p, stage
		}
	}
	t.Fatal("no token in the sealed login")
	return nil, "", ""
}

func sealedRefreshToken(t *testing.T, v *vault.Vault) string {
	t.Helper()
	doc, _, _ := sealedLoginDoc(t, v)
	s, _ := doc["refreshToken"].(string)
	return s
}

// expireSealedAWSLogin rewrites the sealed token's expiry into the past, so
// the next fetch must refresh.
func expireSealedAWSLogin(t *testing.T, v *vault.Vault, home string) {
	t.Helper()
	doc, p, stage := sealedLoginDoc(t, v)
	doc["expiresAt"] = "2000-01-01T00:00:00Z"
	b, _ := json.Marshal(doc)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	blob, err := migrate.AWSSSOLayout.Pack(stage)
	if err != nil {
		t.Fatal(err)
	}
	if err := migrate.StoreAWSSSOCache(v, home, blob); err != nil {
		t.Fatal(err)
	}
}
