// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/jitpass/jit/internal/migrate"
	"github.com/jitpass/jit/internal/vault"
)

// fakeSignIn answers the AWS Sign-In CreateOAuth2Token call (POST /v1/token,
// rest-json, the body IS the TokenInput) that `aws login` and botocore's
// refresh make: spike/aws-login-process's fake_signin.py ported. Each call
// rotates the refresh token, as AWS does.
type fakeSignIn struct {
	session string // the session ARN the ID token names
	mu      sync.Mutex
	n       int
	grants  []string
	rts     []string // refresh tokens presented
	dpop    int      // calls that carried a DPoP proof
}

func (f *fakeSignIn) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
	var in map[string]any
	_ = json.NewDecoder(r.Body).Decode(&in)
	grant, _ := in["grantType"].(string)
	f.grants = append(f.grants, grant)
	if rt, _ := in["refreshToken"].(string); rt != "" {
		f.rts = append(f.rts, rt)
	}
	if r.Header.Get("DPoP") != "" {
		f.dpop++
	}
	claims, _ := json.Marshal(map[string]string{"sub": f.session})
	idToken := "e30." + base64.RawURLEncoding.EncodeToString(claims) + ".sig"
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"accessToken":  map[string]string{"accessKeyId": fmt.Sprintf("ASIALOGIN%08d", f.n), "secretAccessKey": "s", "sessionToken": "t"},
		"refreshToken": fmt.Sprintf("login-rt-%d", f.n),
		"idToken":      idToken,
		"tokenType":    "aws_sigv4",
		"expiresIn":    900,
	})
}

func (f *fakeSignIn) take() (grants, rts []string, dpop int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	grants, rts, dpop = f.grants, f.rts, f.dpop
	f.grants, f.rts, f.dpop = nil, nil, 0
	return grants, rts, dpop
}

// remoteSignIn plays the person at the other device for `aws login
// --remote`: it reads the authorization URL the CLI prints, and pastes back
// the code the browser would show, base64("state=…&code=…").
func remoteSignIn(t *testing.T) (stdin io.Reader, stdout io.Writer, done func() string) {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	var seen bytes.Buffer
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		state := regexp.MustCompile(`[?&]state=([^&\s]+)`)
		sc := bufio.NewScanner(outR)
		for sc.Scan() {
			seen.WriteString(sc.Text() + "\n")
			if m := state.FindStringSubmatch(sc.Text()); m != nil {
				code := base64.StdEncoding.EncodeToString([]byte("state=" + m[1] + "&code=authcode"))
				_, _ = io.WriteString(inW, code+"\n")
				// The one answer the CLI reads. Closing now matters: exec
				// waits for a non-file stdin to reach EOF before Run returns.
				_ = inW.Close()
			}
		}
		_ = inW.Close()
	}()
	return inR, outW, func() string { _ = outW.Close(); <-finished; return seen.String() }
}

// TestAWSLoginE2E drives the REAL AWS CLI's `aws login` through sealing: a
// native sign-in (the cross-device flow, its code pasted back), the profile
// sealed, a fetch, a refresh that rotates the token with the sealed DPoP
// key, a sign-in through `jit aws-sso login` that never touches ~/.aws, and
// sign-out. Sign-In is faked in-process, wired in with the CLI's own
// AWS_ENDPOINT_URL_SIGNIN.
//
//	JIT_AWS_SSO_E2E=1 go test -run TestAWSLoginE2E -v ./internal/cli/
func TestAWSLoginE2E(t *testing.T) {
	if os.Getenv("JIT_AWS_SSO_E2E") == "" {
		t.Skip("set JIT_AWS_SSO_E2E=1 to run against the installed AWS CLI")
	}
	awsBin, err := exec.LookPath("aws")
	if err != nil {
		t.Skip("aws not installed")
	}
	const session = "arn:aws:iam::111122223333:user/dev"
	signin := &fakeSignIn{session: session}
	srv := httptest.NewServer(signin)
	defer srv.Close()
	t.Setenv("AWS_ENDPOINT_URL_SIGNIN", srv.URL)
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
	// The profile exists before the sign-in, as a returning user's does
	// (a new one would also get the CLI's first-run hint).
	if err := os.WriteFile(cfg, []byte("[profile dev]\nregion = us-east-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// 1. A native sign-in, the way the user did it before jit.
	stdin, stdout, done := remoteSignIn(t)
	c := exec.Command(awsBin, "login", "--profile", "dev", "--remote") // #nosec G204 -- the installed AWS CLI, test args
	c.Env = append(os.Environ(), "HOME="+home)
	c.Stdin, c.Stdout, c.Stderr = stdin, stdout, stdout
	err = c.Run()
	if out := done(); err != nil {
		t.Fatalf("aws login: %v\n%s", err, out)
	}
	if grants, _, _ := signin.take(); len(grants) != 1 || grants[0] != "authorization_code" {
		t.Fatalf("native sign-in made %v", grants)
	}
	cacheFile := migrate.AWSLoginCacheFile(home, session)
	if _, err := os.Stat(cacheFile); err != nil {
		t.Fatalf("the native sign-in left no session at %s: %v", cacheFile, err)
	}

	// 2. Sealed.
	profiles, err := migrate.DiscoverAWSSSOProfiles(home)
	if err != nil || len(profiles) != 1 || profiles[0] != "dev" {
		t.Fatalf("discovered %v, %v", profiles, err)
	}
	if _, err := migrate.ApplyAWSSSO(v, home, profiles, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(cacheFile); !os.IsNotExist(err) {
		t.Fatal("the session is still on disk after sealing")
	}
	b, _ := os.ReadFile(cfg) // #nosec G304 -- test path
	if strings.Contains(string(b), "login_session") || !strings.Contains(string(b), "jit aws-sso login --profile dev") {
		t.Fatalf("rewritten config:\n%s", b)
	}

	fetch := func() string {
		t.Helper()
		var errOut bytes.Buffer
		out, err := awsSSOWithLogin(&errOut, v, home, root, awsBin, awsSSOInvocation{profile: "dev", args: []string{"configure", "export-credentials", "--profile", "dev", "--format", "process"}})
		if err != nil {
			t.Fatalf("fetch: %v\n%s", err, errOut.String())
		}
		var doc struct{ AccessKeyId string }
		if err := json.Unmarshal(out, &doc); err != nil {
			t.Fatalf("fetch output %q: %v", out, err)
		}
		return doc.AccessKeyId
	}

	// 3. A fetch while the session's credentials are fresh: no call.
	if id := fetch(); id != "ASIALOGIN00000001" {
		t.Fatalf("first fetch served %s", id)
	}
	if grants, _, _ := signin.take(); len(grants) != 0 {
		t.Fatalf("a fresh session called Sign-In: %v", grants)
	}

	// 4. Expired: the refresh presents the sealed token, signed with the
	// sealed DPoP key, and the rotated one is sealed in its place.
	expireSealedLoginSession(t, v, home)
	if id := fetch(); id != "ASIALOGIN00000002" {
		t.Fatalf("refresh served %s", id)
	}
	grants, rts, dpop := signin.take()
	if len(grants) != 1 || grants[0] != "refresh_token" || len(rts) != 1 || rts[0] != "login-rt-1" || dpop != 1 {
		t.Fatalf("refresh: grants %v rts %v dpop %d", grants, rts, dpop)
	}
	if rt := sealedLoginField(t, v, "refreshToken"); rt != "login-rt-2" {
		t.Fatalf("sealed refresh token after rotation: %q", rt)
	}

	// 5. Plain `aws login` refuses the sealed profile; `jit aws-sso login`
	// signs it in straight into the vault.
	c = exec.Command(awsBin, "login", "--profile", "dev", "--remote") // #nosec G204 -- as above
	c.Env = append(os.Environ(), "HOME="+home)
	if out, err := c.CombinedOutput(); err == nil || !strings.Contains(string(out), "Credential Process") {
		t.Fatalf("aws login on the sealed profile: %v\n%s", err, out)
	}
	args, err := migrate.AWSSealedLoginArgs(root, home, "dev", true)
	if err != nil {
		t.Fatal(err)
	}
	stdin, stdout, done = remoteSignIn(t)
	var errOut bytes.Buffer
	_, err = awsSSOWithLogin(&errOut, v, home, root, awsBin, awsSSOInvocation{profile: "dev", args: args, stdin: stdin, stdout: stdout})
	if out := done(); err != nil {
		t.Fatalf("jit aws-sso login: %v\n%s%s", err, out, errOut.String())
	}
	if grants, _, _ := signin.take(); len(grants) != 1 || grants[0] != "authorization_code" {
		t.Fatalf("jit aws-sso login made %v", grants)
	}
	if rt := sealedLoginField(t, v, "refreshToken"); rt != "login-rt-3" {
		t.Fatalf("sealed refresh token after jit aws-sso login: %q", rt)
	}
	if entries, _ := os.ReadDir(migrate.AWSLoginCacheDir(home)); len(entries) != 0 {
		t.Fatalf("jit aws-sso login left %d files in ~/.aws/login/cache", len(entries))
	}

	// 6. Signed out: nothing sealed answers, and the error says what to run.
	if _, err := awsSSOWithLogin(&errOut, v, home, root, awsBin, awsSSOInvocation{signOut: true}); err != nil {
		t.Fatalf("sign-out: %v\n%s", err, errOut.String())
	}
	if in, known := migrate.AWSSSOSignedIn(root); in || !known {
		t.Fatalf("after sign-out: signedIn %v known %v", in, known)
	}
	_, err = awsSSOWithLogin(&errOut, v, home, root, awsBin, awsSSOInvocation{profile: "dev", args: []string{"configure", "export-credentials", "--profile", "dev", "--format", "process"}})
	if err == nil || !strings.Contains(err.Error(), "jit aws-sso login --profile dev") {
		t.Fatalf("fetch after sign-out: %v", err)
	}
}

// sealedLoginSession unpacks the sealed store and returns the one `aws
// login` session in it, with its path in the stage dir.
func sealedLoginSession(t *testing.T, v interface{ Get(string) ([]byte, error) }) (map[string]any, string, string) {
	t.Helper()
	blob, err := v.Get(migrate.AWSSSOStorePath)
	if err != nil {
		t.Fatal(err)
	}
	stage := t.TempDir()
	if err := migrate.AWSSSOLayout.Unpack(blob, stage); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(filepath.Join(stage, "login", "cache"))
	if len(entries) != 1 {
		t.Fatalf("%d sessions sealed, want 1", len(entries))
	}
	p := filepath.Join(stage, "login", "cache", entries[0].Name())
	b, _ := os.ReadFile(p) // #nosec G304 -- test stage
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	return doc, p, stage
}

func sealedLoginField(t *testing.T, v interface{ Get(string) ([]byte, error) }, key string) string {
	t.Helper()
	doc, _, _ := sealedLoginSession(t, v)
	s, _ := doc[key].(string)
	return s
}

// expireSealedLoginSession moves the sealed session's credentials into the
// past, so the next fetch must refresh.
func expireSealedLoginSession(t *testing.T, v *vault.Vault, home string) {
	t.Helper()
	doc, p, stage := sealedLoginSession(t, v)
	access, _ := doc["accessToken"].(map[string]any)
	access["expiresAt"] = "2000-01-01T00:00:00Z"
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
