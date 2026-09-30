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

	"github.com/jitpass/jit/internal/profile"
	"github.com/jitpass/jit/internal/vault"
	"github.com/jitpass/jit/internal/wrap"
)

// ghAuthFixture is a wrapped gh: a wrap-gh profile, a vault, gh's hosts.yml
// and a fake real gh that logs each call along with any token it was given.
type ghAuthFixture struct {
	w      *ghWrap
	v      *vault.Vault
	log    string
	opened int
}

func newGhAuthFixture(t *testing.T, tokenPath string, keyring []string, active string) *ghAuthFixture {
	t.Helper()
	home := t.TempDir()
	cfg := t.TempDir()
	t.Setenv("GH_CONFIG_DIR", cfg)
	hosts := "github.com:\n    users:\n"
	for _, login := range keyring {
		hosts += "        " + login + ":\n"
	}
	hosts += "    user: " + active + "\n"
	if err := os.WriteFile(filepath.Join(cfg, "hosts.yml"), []byte(hosts), 0o600); err != nil {
		t.Fatal(err)
	}

	bin := t.TempDir()
	log := filepath.Join(bin, "calls.log")
	// `auth token --hostname H --user X` prints tok-X, like the real one.
	script := "#!/bin/sh\n" +
		"echo \"$* GH_TOKEN=${GH_TOKEN} GITHUB_TOKEN=${GITHUB_TOKEN}\" >> " + log + "\n" +
		"if [ \"$1 $2\" = \"auth token\" ]; then echo \"tok-$6\"; fi\n"
	realGh := filepath.Join(bin, "gh")
	if err := os.WriteFile(realGh, []byte(script), 0o700); err != nil { // #nosec G306 -- test fixture must be executable
		t.Fatal(err)
	}

	path := filepath.Join(home, "wrap-gh.yaml")
	data, err := profile.MarshalOrdered(profile.Profile{"GH_TOKEN": tokenPath}, []string{"GH_TOKEN"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	p, order, err := profile.LoadFileOrdered(path)
	if err != nil {
		t.Fatal(err)
	}
	v := &vault.Vault{Root: t.TempDir(), KeyWrapper: newFakeKeyWrapper(), RecipientID: "test-device"}
	return &ghAuthFixture{
		w:   &ghWrap{home: home, realGh: realGh, profilePath: path, profile: p, order: order, tokenVar: "GH_TOKEN"},
		v:   v,
		log: log,
	}
}

func (f *ghAuthFixture) switchTo(t *testing.T, login string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	ro := func() (*vault.Vault, error) { return &vault.Vault{Root: f.v.Root, RecipientID: "test-device"}, nil }
	open := func() (*vault.Vault, error) { f.opened++; return f.v, nil }
	err := ghSwitch(&out, f.w, login, ro, open)
	return out.String(), err
}

func (f *ghAuthFixture) profileToken(t *testing.T) string {
	t.Helper()
	p, err := profile.LoadFile(f.w.profilePath)
	if err != nil {
		t.Fatal(err)
	}
	return p["GH_TOKEN"]
}

func (f *ghAuthFixture) calls(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(f.log)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return string(data)
}

// The reported bug: the wrap uses one account, gh's keyring holds two, and
// `gh auth switch --user` has to actually move what gh calls use.
func TestGhSwitchCopiesKeyringAccountIntoVault(t *testing.T) {
	// A token in the user's own environment is what makes gh refuse; the
	// real gh must never see one from here.
	t.Setenv("GH_TOKEN", "from-the-shell")
	t.Setenv("GITHUB_TOKEN", "from-the-shell")
	f := newGhAuthFixture(t, "wrap-gh/GH_TOKEN", []string{"amy", "zed"}, "zed")

	out, err := f.switchTo(t, "amy")
	if err != nil {
		t.Fatalf("switch: %v", err)
	}
	if got := f.profileToken(t); got != "wrap-gh/accounts/amy" {
		t.Fatalf("profile GH_TOKEN = %q, want wrap-gh/accounts/amy", got)
	}
	got, err := f.v.Get("wrap-gh/accounts/amy")
	if err != nil || string(got) != "tok-amy" {
		t.Fatalf("vault copy = %q, %v; want tok-amy", got, err)
	}
	calls := f.calls(t)
	if strings.Contains(calls, "from-the-shell") {
		t.Fatalf("real gh was given a token:\n%s", calls)
	}
	if !strings.Contains(calls, "auth switch --hostname github.com --user amy") {
		t.Fatalf("gh's own active account not kept in step:\n%s", calls)
	}
	if !strings.Contains(out, "gh now uses amy") || !strings.Contains(out, "Copied amy's token") {
		t.Fatalf("output = %q", out)
	}
}

// Between accounts the vault already holds, a switch is a profile edit:
// no vault unlock, so no Touch ID for choosing an account.
func TestGhSwitchBetweenVaultedAccountsOpensNothing(t *testing.T) {
	f := newGhAuthFixture(t, "wrap-gh/accounts/zed", nil, "")
	for _, login := range []string{"amy", "zed"} {
		if err := f.v.Set(wrap.GhAccountVaultPath(login), []byte("tok-"+login)); err != nil {
			t.Fatal(err)
		}
	}

	// No --user and one other account: that one, the way gh toggles.
	if _, err := f.switchTo(t, ""); err != nil {
		t.Fatalf("switch: %v", err)
	}
	if got := f.profileToken(t); got != "wrap-gh/accounts/amy" {
		t.Fatalf("profile GH_TOKEN = %q, want wrap-gh/accounts/amy", got)
	}
	if f.opened != 0 {
		t.Fatalf("vault unlocked %d times for a switch between vaulted accounts", f.opened)
	}
	if calls := f.calls(t); calls != "" {
		t.Fatalf("real gh ran for accounts it isn't signed in to:\n%s", calls)
	}

	out, err := f.switchTo(t, "amy")
	if err != nil || !strings.Contains(out, "already uses amy") {
		t.Fatalf("same account = %q, %v", out, err)
	}
}

func TestGhSwitchUnknownAccountChangesNothing(t *testing.T) {
	f := newGhAuthFixture(t, "wrap-gh/GH_TOKEN", []string{"zed"}, "zed")
	_, err := f.switchTo(t, "amy")
	if err == nil || !strings.Contains(err.Error(), "gh auth login") {
		t.Fatalf("err = %v, want the login remedy", err)
	}
	if got := f.profileToken(t); got != "wrap-gh/GH_TOKEN" {
		t.Fatalf("profile moved to %q on a failed switch", got)
	}
	if f.opened != 0 {
		t.Fatal("vault unlocked for an account there is no token for")
	}
}

func TestGhSwitchRefusesNonUsername(t *testing.T) {
	f := newGhAuthFixture(t, "wrap-gh/GH_TOKEN", []string{"zed"}, "zed")
	if _, err := f.switchTo(t, "../GH_TOKEN"); err == nil {
		t.Fatal("a path-shaped --user must be refused")
	}
	if got := f.profileToken(t); got != "wrap-gh/GH_TOKEN" {
		t.Fatalf("profile moved to %q", got)
	}
}
