// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jitpass/jit/internal/agent"
	"github.com/jitpass/jit/internal/migrate"
	"github.com/jitpass/jit/internal/sealstore"
	"github.com/jitpass/jit/internal/vault"
)

// fakeAWS stands in for the AWS CLI the way the spike measured it: it
// reads the token cache under $HOME, can rotate the token the way a
// refresh does, fails like the real CLI with no login, and records the
// environment it was given to $OUT. With SLEEP it records its run interval
// to $SPANS, for the lock test.
const fakeAWS = `#!/bin/sh
{ echo "HOME=$HOME"; echo "CFG=$AWS_CONFIG_FILE"; echo "CREDS=$AWS_SHARED_CREDENTIALS_FILE"; echo "CHAIN=${_AWS_CLI_PROFILE_CHAIN-unset}"; echo "PROFILE=${AWS_PROFILE-unset}"; echo "ARGS=$*"; } > "$OUT"
cache="$HOME/.aws/sso/cache"
if [ -n "$SLEEP" ]; then s=$(python3 -c 'import time;print(time.time())'); sleep "$SLEEP"; e=$(python3 -c 'import time;print(time.time())'); echo "$s $e" >> "$SPANS"; fi
case "$1 $2" in
  "configure export-credentials")
    if ! ls "$cache"/tok*.json >/dev/null 2>&1; then
      echo "aws: [ERROR]: Error loading SSO Token: Token for corp does not exist" >&2; exit 253
    fi
    if [ "$ROTATE" = 1 ]; then printf '{"accessToken":"a2","refreshToken":"1//ROTATED"}' > "$cache/tok.json"; fi
    echo '{"Version":1,"AccessKeyId":"ASIAFAKE","SecretAccessKey":"s","SessionToken":"t","Expiration":"2099-01-01T00:00:00+00:00"}' ;;
  "sso logout") rm -f "$cache"/tok*.json ;;
esac
`

type awsSSOFixture struct {
	home, root, aws, out string
	v                    *vault.Vault
}

func newAWSSSOFixture(t *testing.T) awsSSOFixture {
	t.Helper()
	home := withFixtureHome(t)
	withTestKeystore(t)
	root, err := vaultRootDir()
	if err != nil {
		t.Fatal(err)
	}
	v, err := openVault()
	if err != nil {
		t.Fatal(err)
	}
	f := awsSSOFixture{home: home, root: root, v: v,
		aws: filepath.Join(t.TempDir(), "aws"), out: filepath.Join(t.TempDir(), "env")}
	if err := os.WriteFile(f.aws, []byte(fakeAWS), 0o755); err != nil { // #nosec G306 -- a test stub must be executable
		t.Fatal(err)
	}
	t.Setenv("OUT", f.out)
	return f
}

// seal puts a login with refresh token rt in the vault, as migrate would.
func (f awsSSOFixture) seal(t *testing.T, rt string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "sso", "cache"), 0o700); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"tok.json": `{"accessToken":"a","refreshToken":"` + rt + `"}`, "reg.json": `{"clientId":"c"}`} {
		if err := os.WriteFile(filepath.Join(dir, "sso", "cache", name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	blob, err := migrate.AWSSSOLayout.Pack(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := migrate.StoreAWSSSOCache(f.v, f.home, blob); err != nil {
		t.Fatal(err)
	}
}

func (f awsSSOFixture) fetch(t *testing.T) ([]byte, string, error) {
	t.Helper()
	var errOut bytes.Buffer
	out, err := awsSSOWithLogin(&errOut, f.v, f.home, f.root, f.aws, awsSSOInvocation{profile: "dev", args: []string{"configure", "export-credentials", "--profile", "dev", "--format", "process"}})
	return out, errOut.String(), err
}

func (f awsSSOFixture) sealedBlob(t *testing.T) string {
	t.Helper()
	b, err := f.v.Get(migrate.AWSSSOStorePath)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestAWSSSOFetchesThroughTheSealedLogin(t *testing.T) {
	f := newAWSSSOFixture(t)
	f.seal(t, "1//SEALED")
	t.Setenv("_AWS_CLI_PROFILE_CHAIN", "dev")
	t.Setenv("AWS_PROFILE", "dev")

	out, _, err := f.fetch(t)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"AccessKeyId":"ASIAFAKE"`) {
		t.Fatalf("output %q", out)
	}
	env, _ := os.ReadFile(f.out)
	for _, want := range []string{
		"HOME=" + awsSSORunBase(f.root) + "/",
		"CFG=" + migrate.AWSSSOSealedConfigPath(f.root),
		"CREDS=/dev/null",
		"CHAIN=unset", // the loop guard would refuse dev inside an outer export of dev
		"PROFILE=unset",
		"ARGS=configure export-credentials --profile dev --format process",
	} {
		if !strings.Contains(string(env), want) {
			t.Errorf("inner env lacks %q:\n%s", want, env)
		}
	}
	if entries, _ := os.ReadDir(awsSSORunBase(f.root)); len(entries) != 0 {
		t.Errorf("run dirs left: %v", entries)
	}
	if _, err := os.Stat(migrate.AWSSSOCacheDir(f.home)); !os.IsNotExist(err) {
		t.Error("a fetch wrote the token cache into the real home")
	}
	if !strings.Contains(f.sealedBlob(t), "1//SEALED") {
		t.Error("an unrotated fetch changed the sealed login")
	}
}

// D4: the refresh rotates the token; the vault must take it back or the
// next run presents one Identity Center has already rotated away.
func TestAWSSSOResealsTheRotatedToken(t *testing.T) {
	f := newAWSSSOFixture(t)
	f.seal(t, "1//OLD")
	t.Setenv("ROTATE", "1")
	if _, _, err := f.fetch(t); err != nil {
		t.Fatal(err)
	}
	blob := f.sealedBlob(t)
	if !strings.Contains(blob, "1//ROTATED") || strings.Contains(blob, "1//OLD") {
		t.Fatal("the rotated refresh token was not sealed back")
	}
	if !strings.Contains(blob, `"clientId":"c"`) {
		t.Fatal("the reseal dropped the client registration")
	}
}

// D5: a login `aws sso login` just wrote to the real cache is moved into
// the vault on the next fetch, and used by it.
func TestAWSSSOCapturesANativeLogin(t *testing.T) {
	f := newAWSSSOFixture(t)
	f.seal(t, "1//OLD")
	cache := migrate.AWSSSOCacheDir(f.home)
	if err := os.MkdirAll(cache, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cache, "tok.json"), []byte(`{"accessToken":"n","refreshToken":"1//FRESH"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.fetch(t); err != nil {
		t.Fatal(err)
	}
	if entries, _ := os.ReadDir(cache); len(entries) != 0 {
		t.Fatalf("the native login was left in plaintext: %v", entries)
	}
	if !strings.Contains(f.sealedBlob(t), "1//FRESH") {
		t.Fatal("the native login was not captured")
	}
}

func TestAWSSSONoLoginSaysWhatToRun(t *testing.T) {
	f := newAWSSSOFixture(t)
	_, _, err := f.fetch(t)
	if err == nil || !strings.Contains(err.Error(), "jit aws-sso login --profile dev") {
		t.Fatalf("error %v, want the login command", err)
	}
}

func TestAWSSSOLogout(t *testing.T) {
	f := newAWSSSOFixture(t)
	f.seal(t, "1//LIVE")
	var errOut bytes.Buffer
	if _, err := awsSSOWithLogin(&errOut, f.v, f.home, f.root, f.aws, awsSSOInvocation{signOut: true}); err != nil {
		t.Fatal(err)
	}
	blob := f.sealedBlob(t)
	if strings.Contains(blob, "1//LIVE") || !strings.Contains(blob, `"clientId":"c"`) {
		t.Fatal("logout did not leave the vault without the login (and with the registration)")
	}
	if _, _, err := f.fetch(t); err == nil {
		t.Fatal("a fetch after logout found a login")
	}
}

// D4: concurrent fetches run one at a time, so only one can refresh.
func TestAWSSSORunsOneAtATime(t *testing.T) {
	f := newAWSSSOFixture(t)
	f.seal(t, "1//X")
	spans := filepath.Join(t.TempDir(), "spans")
	t.Setenv("SPANS", spans)
	t.Setenv("SLEEP", "0.3")
	var wg sync.WaitGroup
	for range 3 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := f.fetch(t); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	b, _ := os.ReadFile(spans)
	type span struct{ s, e float64 }
	var got []span
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		parts := strings.Fields(line)
		if len(parts) != 2 {
			continue
		}
		s, _ := strconv.ParseFloat(parts[0], 64)
		e, _ := strconv.ParseFloat(parts[1], 64)
		got = append(got, span{s, e})
	}
	if len(got) != 3 {
		t.Fatalf("spans %q", b)
	}
	for i := range got {
		for j := range got {
			if i != j && got[i].s < got[j].e && got[j].s < got[i].e {
				t.Fatalf("runs %d and %d overlapped: %v %v", i, j, got[i], got[j])
			}
		}
	}
}

func TestAWSSSOEnv(t *testing.T) {
	got := awsSSOEnv([]string{"PATH=/bin", "HOME=/Users/u", "AWS_PROFILE=x", "_AWS_CLI_PROFILE_CHAIN=dev", "AWS_ACCESS_KEY_ID=k", "AWS_LOGIN_CACHE_DIRECTORY=/Users/u/.aws/login/cache", "AWS_REGION=eu-west-1"}, "/run", "/sealed")
	want := "PATH=/bin|AWS_REGION=eu-west-1|HOME=/run|AWS_CONFIG_FILE=/sealed|AWS_SHARED_CREDENTIALS_FILE=/dev/null"
	if strings.Join(got, "|") != want {
		t.Fatalf("env %q", got)
	}
}

// A sealed AWS SSO login is in use while ~/.aws/config fetches through it:
// `jit vault orphans` must never offer to prune it, and status counts it as
// managed elsewhere. Once no profile uses it, it is an orphan again.
func TestVaultOrphansSparesTheSealedAWSSSOLogin(t *testing.T) {
	home := withFixtureHome(t)
	cwd := withFixtureCwd(t)
	stubUserPresence(t)
	t.Cleanup(func() { vaultOrphansPrune = false; vaultOrphansYes = false })
	writeFixtureProfile(t, cwd, "myapp", "API_KEY: kept/API_KEY\n")
	root := seedFixtureVault(t, "kept/API_KEY")
	v := &vault.Vault{Root: root, KeyWrapper: newFakeKeyWrapper(), RecipientID: "test-device"}
	if err := v.Set(migrate.AWSSSOStorePath, []byte("sealed")); err != nil {
		t.Fatal(err)
	}
	orphans := func() string {
		t.Helper()
		var buf bytes.Buffer
		rootCmd.SetOut(&buf)
		rootCmd.SetErr(&buf)
		rootCmd.SetArgs([]string{"vault", "orphans"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("jit vault orphans: %v", err)
		}
		return buf.String()
	}
	cfg := migrate.AWSConfigPath(home)
	if err := os.MkdirAll(filepath.Dir(cfg), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg, []byte("[profile dev]\nsso_session = corp\ncredential_process = /usr/local/bin/jit aws-sso --profile dev\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out := orphans(); strings.Contains(out, "aws-sso") {
		t.Fatalf("the sealed AWS SSO login was listed as an orphan:\n%s", out)
	}
	rec, err := reconcileSecrets(root, cwd, v)
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range rec.Groups {
		if g.Name == "aws-sso" && g.State != stateManagedElsewhere {
			t.Fatalf("status classes the sealed SSO login %v", g.State)
		}
	}
	if err := os.WriteFile(cfg, []byte("[profile dev]\nregion = us-east-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out := orphans(); !strings.Contains(out, "aws-sso") {
		t.Fatalf("with no profile using it, the login is an orphan:\n%s", out)
	}
}

// A killed `jit aws-sso` leaves its folder, the login unsealed in it:
// doctor names it with the command that removes it, wrap or no wrap.
func TestDoctorReportsAnInterruptedAWSSSORun(t *testing.T) {
	home := withFixtureHome(t)
	root, err := vaultRootDir()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sealstore.NewRunDir(awsSSORunBase(root), 999999, 1); err != nil {
		t.Fatal(err)
	}
	got := storeWrapFindings(home, root)
	if len(got) != 1 || got[0].Kind != kindWrapStore || !strings.HasPrefix(got[0].Detail, "aws-sso: ") {
		t.Fatalf("findings %+v", got)
	}
	if fixes := fixesFor(got[0].Kind, got[0].Action); len(fixes) != 1 || fixes[0].Command != "jit service restart" {
		t.Fatalf("fixes %+v", fixes)
	}
}

func writeAWSSSOHome(t *testing.T, home string) {
	t.Helper()
	for rel, body := range map[string]string{
		".aws/config":             "[profile dev]\nsso_session = corp\nsso_account_id = 111122223333\nsso_role_name = Developer\n\n[sso-session corp]\nsso_start_url = https://corp.awsapps.com/start\nsso_region = us-east-1\n",
		".aws/sso/cache/tok.json": `{"accessToken":"a","refreshToken":"1//LOGIN"}`,
	} {
		p := filepath.Join(home, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// `jit migrate ~/.aws/config` plans and seals the SSO profiles; naming the
// token file the scan reported does the same; --only scopes them with the
// rest of the aws category.
func TestMigrateSealsAWSSSOProfiles(t *testing.T) {
	home := withFixtureHome(t)
	withTestKeystore(t)
	t.Cleanup(migrate.SetJitExecutableForTesting("/usr/local/bin/jit"))
	writeAWSSSOHome(t, home)
	cfg := migrate.AWSConfigPath(home)

	out, err := execMigrate(t, "--dry-run", filepath.Join(migrate.AWSSSOCacheDir(home), "tok.json"))
	if err != nil {
		t.Fatalf("dry run: %v\n%s", err, out)
	}
	if !strings.Contains(out, "AWS sign-in profile") || !strings.Contains(dryRunPlanOnly(out), "dev") {
		t.Fatalf("the plan for the scan's token file lacks the SSO profile:\n%s", out)
	}
	out, err = execMigrate(t, "--dry-run", "--only", "env", cfg)
	if err != nil {
		t.Fatalf("dry run --only env: %v\n%s", err, out)
	}
	if strings.Contains(dryRunPlanOnly(out), "AWS sign-in profile") {
		t.Fatalf("--only env still planned the SSO profiles:\n%s", out)
	}

	out, err = execMigrate(t, "--yes", cfg)
	if err != nil {
		t.Fatalf("migrate: %v\n%s", err, out)
	}
	b, _ := os.ReadFile(cfg) // #nosec G304 -- test path
	if !strings.Contains(string(b), "credential_process = /usr/local/bin/jit aws-sso --profile dev") || strings.Contains(string(b), "sso_role_name") {
		t.Fatalf("config after migrate:\n%s", b)
	}
	if entries, _ := os.ReadDir(migrate.AWSSSOCacheDir(home)); len(entries) != 0 {
		t.Fatalf("the token cache is still on disk: %v", entries)
	}
	v, _ := openVault()
	blob, err := v.Get(migrate.AWSSSOStorePath)
	if err != nil || !strings.Contains(string(blob), "1//LOGIN") {
		t.Fatalf("vault: %q, %v", blob, err)
	}

	// The app's view, prompt-free: the aws row says which profiles fetch
	// through jit and that a login is sealed (to offer Sign Out), and the
	// sealed login's user names its store rather than only a file.
	listed, err := execWrap(t, "list", "--format", "json", "--all")
	if err != nil {
		t.Fatal(err)
	}
	var res wrapListResult
	if err := json.Unmarshal([]byte(listed), &res); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range res.Tools {
		if r.Tool == "aws" {
			found = true
			if len(r.SSOProfiles) != 1 || r.SSOProfiles[0] != "dev" || r.SSOSignedIn == nil || !*r.SSOSignedIn {
				t.Errorf("aws row SSO fields: profiles %q signed in %v", r.SSOProfiles, r.SSOSignedIn)
			}
		}
	}
	if !found {
		t.Fatal("no aws row in wrap list --all")
	}
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	vaultListFormat, vaultListUsers = "json", true
	t.Cleanup(func() { vaultListFormat, vaultListUsers = "text", false })
	rootCmd.SetArgs([]string{"vault", "list", "--format", "json", "--users"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"store": "aws-sso"`) {
		t.Errorf("vault list --users does not name the store:\n%s", buf.String())
	}
}

// fakeCredCache stands in for the service's AWS cache.
type fakeCredCache struct {
	mu      sync.Mutex
	data    map[string][]byte
	getErr  error
	gets    int
	puts    map[string]time.Time
	cleared int
}

func (f *fakeCredCache) AWSCacheGet(p string) ([]byte, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gets++
	if f.getErr != nil {
		return nil, false, f.getErr
	}
	d, ok := f.data[p]
	return d, ok, nil
}

func (f *fakeCredCache) AWSCachePut(p string, d []byte, exp time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.puts == nil {
		f.puts = map[string]time.Time{}
	}
	f.puts[p] = exp
	return nil
}

func (f *fakeCredCache) AWSCacheClear() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cleared++
	return nil
}

func withFakeCredCache(t *testing.T, f *fakeCredCache) {
	t.Helper()
	orig := awsSSOCache
	awsSSOCache = func() awsCredCache { return f }
	t.Cleanup(func() { awsSSOCache = orig })
}

func execAWSSSO(t *testing.T, f awsSSOFixture, args ...string) (string, error) {
	t.Helper()
	orig := awsSSOBinary
	awsSSOBinary = func(string) string { return f.aws }
	t.Cleanup(func() { awsSSOBinary = orig })
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs(append([]string{"aws-sso"}, args...))
	err := rootCmd.Execute()
	return buf.String(), err
}

// A cache hit answers without the AWS CLI and without unsealing anything.
func TestAWSSSOServesFromTheServiceCache(t *testing.T) {
	f := newAWSSSOFixture(t)
	f.seal(t, "1//SEALED")
	cache := &fakeCredCache{data: map[string][]byte{"dev": []byte(`{"AccessKeyId":"ASIACACHED"}`)}}
	withFakeCredCache(t, cache)
	out, err := execAWSSSO(t, f, "--profile", "dev")
	if err != nil || !strings.Contains(out, "ASIACACHED") {
		t.Fatalf("out %q err %v", out, err)
	}
	if _, err := os.Stat(f.out); !os.IsNotExist(err) {
		t.Fatal("a cache hit still ran the AWS CLI")
	}
}

// A miss fetches, then offers the result with the expiry AWS gave it.
func TestAWSSSOFillsTheServiceCache(t *testing.T) {
	f := newAWSSSOFixture(t)
	f.seal(t, "1//SEALED")
	cache := &fakeCredCache{}
	withFakeCredCache(t, cache)
	out, err := execAWSSSO(t, f, "--profile", "dev")
	if err != nil || !strings.Contains(out, "ASIAFAKE") {
		t.Fatalf("out %q err %v", out, err)
	}
	if exp, ok := cache.puts["dev"]; !ok || exp.Year() != 2099 {
		t.Fatalf("puts %v", cache.puts)
	}
}

// While `aws sso login` has a login waiting in plaintext, the cache must
// not answer: only a real fetch seals that login. And capturing it clears
// what was cached from the previous one.
func TestAWSSSOWaitingLoginBypassesTheCache(t *testing.T) {
	f := newAWSSSOFixture(t)
	f.seal(t, "1//OLD")
	cache := &fakeCredCache{data: map[string][]byte{"dev": []byte(`{"AccessKeyId":"ASIASTALE"}`)}}
	withFakeCredCache(t, cache)
	dir := migrate.AWSSSOCacheDir(f.home)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tok.json"), []byte(`{"accessToken":"n","refreshToken":"1//NEW"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := execAWSSSO(t, f, "--profile", "dev")
	if err != nil || strings.Contains(out, "ASIASTALE") {
		t.Fatalf("out %q err %v", out, err)
	}
	if cache.gets != 0 || cache.cleared != 1 {
		t.Fatalf("gets %d cleared %d; want the cache skipped and cleared by the capture", cache.gets, cache.cleared)
	}
}

// A consent refusal at the cache is the user's answer: no second prompt
// from a fallback unseal.
func TestAWSSSOCacheRefusalIsFinal(t *testing.T) {
	f := newAWSSSOFixture(t)
	f.seal(t, "1//SEALED")
	withFakeCredCache(t, &fakeCredCache{getErr: errors.New("consent: access to your aws credential was not granted")})
	if _, err := execAWSSSO(t, f, "--profile", "dev"); err == nil || !strings.Contains(err.Error(), "not granted") {
		t.Fatalf("err %v", err)
	}
	if _, err := os.Stat(f.out); !os.IsNotExist(err) {
		t.Fatal("a refused cache read fell through to a fetch")
	}
}

// The real service, end to end: `jit aws-sso`'s unseal is the consented
// aws read the service records, so its offer after the fetch is accepted,
// and the next fetch is served from memory without the AWS CLI.
func TestAWSSSOCacheWithTheRealService(t *testing.T) {
	f := newAWSSSOFixture(t)
	socket := filepath.Join(shortTempDir(t), "a.sock")
	server := agent.NewServer(socket, func() agent.MEKFetcher { return &fakeMEKFetcher{key: bytes.Repeat([]byte{0x24}, 32)} }, time.Minute)
	if err := server.Listen(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = server.Serve(ctx); close(done) }()
	t.Cleanup(func() { cancel(); _ = server.Close(); <-done })

	client := agent.NewClient(socket)
	v := &vault.Vault{Root: f.root, KeyWrapper: client, RecipientID: "test-device"}
	f.v = v
	f.seal(t, "1//SEALED")
	orig := awsSSOCache
	awsSSOCache = func() awsCredCache { return client }
	t.Cleanup(func() { awsSSOCache = orig })

	if _, _, err := f.fetch(t); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(f.out); err != nil {
		t.Fatal(err)
	}
	out, ok, err := awsSSOCachedCredentials("dev")
	if err != nil || !ok || !strings.Contains(string(out), "ASIAFAKE") {
		t.Fatalf("cache after a fetch: %q, %v, %v", out, ok, err)
	}
	if _, err := os.Stat(f.out); !os.IsNotExist(err) {
		t.Fatal("the cached answer ran the AWS CLI")
	}
	if err := client.Lock(); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := awsSSOCachedCredentials("dev"); ok {
		t.Fatal("the cache answered after the vault locked")
	}
}

// shortTempDir is a temp dir short enough for a Unix socket path (macOS
// caps those near 104 bytes; t.TempDir under /var/folders is too long).
func shortTempDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("/tmp", "jit")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return d
}
