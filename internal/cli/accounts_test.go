// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/vault"
	"github.com/jitpass/jit/internal/wrap"
)

// accountFixture is a wrapped tool: its catalog entry, a vault holding the
// wrap's token, and a fake real tool that logs each call with whatever
// token it was given. For a login it writes a fresh token where the
// catalog says the tool keeps it.
type accountFixture struct {
	w      *accountWrap
	v      *vault.Vault
	log    string
	opened int
}

func newAccountFixture(t *testing.T, tool, loginWrites string) *accountFixture {
	t.Helper()
	entry, ok := wrap.Lookup(tool)
	if !ok {
		t.Fatalf("%s isn't cataloged", tool)
	}
	home := t.TempDir()
	bin := t.TempDir()
	log := filepath.Join(bin, "calls.log")
	tokenVar := entry.PrimaryVar()
	script := "#!/bin/sh\n" +
		"echo \"$* " + tokenVar + "=[${" + tokenVar + "}]\" >> " + log + "\n"
	if loginWrites != "" {
		src := wrap.ExpandHome(home, entry.Sources[0].Path)
		if err := os.MkdirAll(filepath.Dir(src), 0o700); err != nil {
			t.Fatal(err)
		}
		script += "case \"$*\" in *login*) printf '%s' '" + loginWrites + "' > '" + src + "';; esac\n"
	}
	realTool := filepath.Join(bin, tool)
	if err := os.WriteFile(realTool, []byte(script), 0o700); err != nil { // #nosec G306 -- test fixture must be executable
		t.Fatal(err)
	}
	v := &vault.Vault{Root: t.TempDir(), KeyWrapper: newFakeKeyWrapper(), RecipientID: "test-device"}
	path := entry.VaultPath(tokenVar)
	if err := v.Set(path, []byte("vaulted-token")); err != nil {
		t.Fatal(err)
	}
	// The injected variable is set here the way the user's shell might
	// have it; the real tool must never see it on an account command.
	t.Setenv(tokenVar, "vaulted-token")
	return &accountFixture{
		w:   &accountWrap{home: home, entry: entry, realTool: realTool, vaultPath: path, tokenVars: entry.TokenVars()},
		v:   v,
		log: log,
	}
}

func (f *accountFixture) run(t *testing.T, args string) (string, int) {
	t.Helper()
	m, ok := f.w.entry.MatchAccount(f.w.home, strings.Fields(args))
	if !ok {
		t.Fatalf("%s %s matched no account rule", f.w.entry.Tool, args)
	}
	var out bytes.Buffer
	open := func() (*vault.Vault, error) { f.opened++; return f.v, nil }
	ro := func() (*vault.Vault, error) { return &vault.Vault{Root: f.v.Root, RecipientID: "test-device"}, nil }
	code := f.w.answer(&out, m, strings.Fields(args), open, ro)
	// Messages wrap at the terminal width; compare the words.
	return strings.Join(strings.Fields(out.String()), " "), code
}

func (f *accountFixture) calls(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(f.log)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return string(data)
}

// vercel logout with the token injected revokes that token on Vercel's
// side. Run by jit it never sees the token, so it can't.
func TestAccountLogoutNeverSeesTheToken(t *testing.T) {
	f := newAccountFixture(t, "vercel", "")
	out, code := f.run(t, "logout")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	calls := f.calls(t)
	if !strings.Contains(calls, "logout VERCEL_TOKEN=[]") {
		t.Fatalf("logout ran with a token:\n%s", calls)
	}
	if !strings.Contains(out, "still uses the token in the vault") || !strings.Contains(out, "jit vault rm wrap-vercel/VERCEL_TOKEN") {
		t.Fatalf("output = %q", out)
	}
	if got, err := f.v.Get("wrap-vercel/VERCEL_TOKEN"); err != nil || string(got) != "vaulted-token" {
		t.Fatalf("vault token = %q, %v; a logout must leave it", got, err)
	}
}

func TestAccountSwitchIsRefusedAndNeverRuns(t *testing.T) {
	f := newAccountFixture(t, "vercel", "")
	out, code := f.run(t, "switch my-team")
	if code == 0 {
		t.Fatal("a refused switch must fail")
	}
	if calls := f.calls(t); calls != "" {
		t.Fatalf("the tool ran:\n%s", calls)
	}
	for _, want := range []string{"can't change the account", "--scope <team>", "jit vault set wrap-vercel/VERCEL_TOKEN"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

// A login runs with no token, then its fresh token moves into the vault
// and out of the plaintext file the tool wrote it to.
func TestAccountLoginRevaults(t *testing.T) {
	f := newAccountFixture(t, "flyctl", "access_token: fresh-token\n")
	out, code := f.run(t, "auth login")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	if calls := f.calls(t); !strings.Contains(calls, "auth login FLY_API_TOKEN=[]") {
		t.Fatalf("login ran with a token:\n%s", calls)
	}
	got, err := f.v.Get("wrap-flyctl/FLY_API_TOKEN")
	if err != nil || string(got) != "fresh-token" {
		t.Fatalf("vault token = %q, %v; want fresh-token", got, err)
	}
	src, err := os.ReadFile(wrap.ExpandHome(f.w.home, "~/.fly/config.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(src), "fresh-token") {
		t.Fatalf("plaintext left behind:\n%s", src)
	}
	if !strings.Contains(out, "moved the new token into the vault") {
		t.Fatalf("output = %q", out)
	}
}

// A login that leaves nothing jit can find keeps the vault's token, and
// says so rather than claiming a move.
func TestAccountLoginWithNothingToMove(t *testing.T) {
	f := newAccountFixture(t, "cursor-agent", "")
	out, code := f.run(t, "login")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if f.opened != 0 {
		t.Fatal("vault unlocked with nothing to store")
	}
	if !strings.Contains(out, "saved no token jit can pick up") {
		t.Fatalf("output = %q", out)
	}
}

// A failed login changes nothing.
func TestAccountLoginFailureKeepsVault(t *testing.T) {
	f := newAccountFixture(t, "flyctl", "access_token: fresh-token\n")
	if err := os.WriteFile(f.w.realTool, []byte("#!/bin/sh\nexit 3\n"), 0o700); err != nil { // #nosec G306 -- test fixture
		t.Fatal(err)
	}
	if _, code := f.run(t, "auth login"); code != 3 {
		t.Fatalf("exit %d, want the tool's 3", code)
	}
	if f.opened != 0 {
		t.Fatal("vault opened after a failed login")
	}
}

// -p naming another profile runs on that profile's own saved login: the
// wrapped (default profile's) key must not go to another account.
func TestAccountProfileRunsUnwrapped(t *testing.T) {
	f := newAccountFixture(t, "stripe", "")
	var gotArgs []string
	var gotEnv []string
	f.w.execFn = func(args []string) error { gotArgs, gotEnv = args, f.w.env(); return nil }
	out, _ := f.run(t, "-p other customers list")
	if strings.Join(gotArgs, " ") != "-p other customers list" {
		t.Fatalf("exec args = %v", gotArgs)
	}
	for _, kv := range gotEnv {
		if strings.HasPrefix(kv, "STRIPE_API_KEY=") {
			t.Fatalf("the wrapped key went to profile other: %s", kv)
		}
	}
	if !strings.Contains(out, "`-p other`") && !strings.Contains(out, "-p other") {
		t.Fatalf("output = %q", out)
	}
}

// `pulumi login` run without the token must still ask pulumi to encrypt
// the credentials file it writes.
func TestAccountUnwrappedRunKeepsShimEnv(t *testing.T) {
	f := newAccountFixture(t, "pulumi", "")
	t.Setenv("PULUMI_CREDENTIAL_STORE", "")
	if err := os.Unsetenv("PULUMI_CREDENTIAL_STORE"); err != nil {
		t.Fatal(err)
	}
	env := strings.Join(f.w.env(), "\n")
	if !strings.Contains(env, "PULUMI_CREDENTIAL_STORE=auto") {
		t.Fatal("PULUMI_CREDENTIAL_STORE not set for the unwrapped run")
	}
	if strings.Contains(env, "PULUMI_ACCESS_TOKEN=") {
		t.Fatal("the token went along")
	}
}

// gh keeps a secret per account and the profile names only the one in
// use; undo must name them all, not strand the rest unmentioned.
func TestWrapSecretsKeptListsEveryAccount(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	root, err := vaultRootDir()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"wrap-gh/GH_TOKEN", "wrap-gh/accounts/amy", "wrap-gh/accounts/zed", "wrap-ghx/OTHER", "aws/key"} {
		file := filepath.Join(root, "vault", p+".enc")
		if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got := wrapSecretsKept("gh", []string{"wrap-gh/accounts/zed"})
	want := "wrap-gh/GH_TOKEN,wrap-gh/accounts/amy,wrap-gh/accounts/zed"
	if strings.Join(got, ",") != want {
		t.Fatalf("kept = %v, want %s", got, want)
	}
}

// vercel's login is OAuth with a token it refreshes itself: it runs with
// no token, and nothing short-lived is frozen into the vault.
func TestAccountOAuthLoginKeepsTheVault(t *testing.T) {
	f := newAccountFixture(t, "vercel", "")
	src := wrap.ExpandHome(f.w.home, f.w.entry.Sources[0].Path)
	if err := os.MkdirAll(filepath.Dir(src), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src, []byte(`{"token":"short-lived"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	out, code := f.run(t, "login")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if calls := f.calls(t); !strings.Contains(calls, "login VERCEL_TOKEN=[]") {
		t.Fatalf("login ran with a token:\n%s", calls)
	}
	if f.opened != 0 {
		t.Fatal("vault opened for an OAuth login")
	}
	if got, _ := f.v.Get("wrap-vercel/VERCEL_TOKEN"); string(got) != "vaulted-token" {
		t.Fatalf("vault token = %q, want the durable one kept", got)
	}
	if !strings.Contains(out, "logins can expire") && strings.Contains(out, "jit vault set wrap-vercel/VERCEL_TOKEN") {
		t.Fatalf("output = %q", out)
	}
}
