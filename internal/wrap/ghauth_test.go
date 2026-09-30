// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package wrap

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestParseGhAuth(t *testing.T) {
	cases := []struct {
		args []string
		want GhAuthCommand
		ok   bool
	}{
		{[]string{"auth", "switch"}, GhAuthCommand{Sub: "switch"}, true},
		{[]string{"auth", "switch", "--user", "octo"}, GhAuthCommand{Sub: "switch", User: "octo"}, true},
		{[]string{"auth", "switch", "-u", "octo", "-h", "github.com"}, GhAuthCommand{Sub: "switch", User: "octo", Host: "github.com"}, true},
		{[]string{"auth", "switch", "--user=octo", "--hostname=ghe.example.com"}, GhAuthCommand{Sub: "switch", User: "octo", Host: "ghe.example.com"}, true},
		{[]string{"auth", "login", "--with-token"}, GhAuthCommand{Sub: "login"}, true},
		{[]string{"auth", "logout", "-u", "octo"}, GhAuthCommand{Sub: "logout", User: "octo"}, true},
		{[]string{"auth", "refresh", "-s", "read:packages"}, GhAuthCommand{Sub: "refresh"}, true},
		{[]string{"auth", "switch", "--user"}, GhAuthCommand{Sub: "switch"}, true}, // gh reports the missing value
		// Not account commands: the normal wrapped path.
		{[]string{"auth", "status"}, GhAuthCommand{}, false},
		{[]string{"auth", "token"}, GhAuthCommand{}, false},
		{[]string{"auth", "switch", "--help"}, GhAuthCommand{}, false},
		{[]string{"pr", "list"}, GhAuthCommand{}, false},
		{[]string{"auth"}, GhAuthCommand{}, false},
		{nil, GhAuthCommand{}, false},
	}
	for _, c := range cases {
		got, ok := ParseGhAuth(c.args)
		if ok != c.ok || got != c.want {
			t.Errorf("ParseGhAuth(%q) = %+v, %v; want %+v, %v", c.args, got, ok, c.want, c.ok)
		}
	}
	if (GhAuthCommand{Host: "github.com"}).OtherHost() || (GhAuthCommand{}).OtherHost() {
		t.Error("github.com, or no host, must not count as another host")
	}
	if !(GhAuthCommand{Host: "ghe.example.com"}).OtherHost() {
		t.Error("an enterprise host is another host")
	}
}

func TestGhAccountVaultPath(t *testing.T) {
	if got := GhAccountFromVaultPath(GhAccountVaultPath("octo-cat")); got != "octo-cat" {
		t.Fatalf("round trip = %q", got)
	}
	for _, p := range []string{"wrap-gh/GH_TOKEN", "wrap-gh/accounts/", "wrap-gh/accounts/a/b", "wrap-gh/accounts/-bad", "other/accounts/octo"} {
		if got := GhAccountFromVaultPath(p); got != "" {
			t.Errorf("GhAccountFromVaultPath(%q) = %q, want none", p, got)
		}
	}
	got := GhAccountsInVault([]string{"wrap-gh/GH_TOKEN", "wrap-gh/accounts/zed", "aws/key", "wrap-gh/accounts/amy"})
	if !slices.Equal(got, []string{"amy", "zed"}) {
		t.Fatalf("GhAccountsInVault = %v", got)
	}
}

func TestValidGhLogin(t *testing.T) {
	for _, ok := range []string{"a", "octo", "octo-cat", "a1-b2", strings.Repeat("a", 39)} {
		if !ValidGhLogin(ok) {
			t.Errorf("%q should be valid", ok)
		}
	}
	for _, bad := range []string{"", "-octo", "octo-", "oc--to", "oc/to", "../x", "oc to", strings.Repeat("a", 40)} {
		if ValidGhLogin(bad) {
			t.Errorf("%q should be refused", bad)
		}
	}
}

func TestGhKeyringAccounts(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GH_CONFIG_DIR", dir)
	home := t.TempDir()

	logins, active, err := GhKeyringAccounts(home)
	if err != nil || logins != nil || active != "" {
		t.Fatalf("no hosts.yml = %v %q %v, want nothing", logins, active, err)
	}

	write := func(body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, "hosts.yml"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("github.com:\n    git_protocol: https\n    users:\n        zed:\n        amy:\n    user: zed\n" +
		"ghe.example.com:\n    users:\n        other:\n    user: other\n")
	logins, active, err = GhKeyringAccounts(home)
	if err != nil || !slices.Equal(logins, []string{"amy", "zed"}) || active != "zed" {
		t.Fatalf("multi-account = %v %q %v", logins, active, err)
	}

	// gh before 2.40: one account, no users map, token in the file.
	write("github.com:\n    oauth_token: not-returned\n    user: solo\n")
	logins, active, err = GhKeyringAccounts(home)
	if err != nil || !slices.Equal(logins, []string{"solo"}) || active != "solo" {
		t.Fatalf("single-account = %v %q %v", logins, active, err)
	}
}

func TestPickGhSwitchTarget(t *testing.T) {
	if got, err := PickGhSwitchTarget([]string{"amy", "zed"}, "zed"); err != nil || got != "amy" {
		t.Fatalf("two accounts = %q %v, want amy", got, err)
	}
	// The wrap's account unknown (wrap-gh/GH_TOKEN): gh's toggle can't be
	// guessed, so it asks rather than maybe switching to the same account.
	if _, err := PickGhSwitchTarget([]string{"amy", "zed"}, ""); err == nil || !strings.Contains(err.Error(), "amy, zed") {
		t.Fatalf("unknown current = %v, want a list to pick from", err)
	}
	if _, err := PickGhSwitchTarget([]string{"amy", "bob", "zed"}, "zed"); err == nil {
		t.Fatal("three accounts must ask")
	}
	if _, err := PickGhSwitchTarget(nil, ""); err == nil || !strings.Contains(err.Error(), "gh auth login") {
		t.Fatalf("no accounts = %v", err)
	}
}
