// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package wrap

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMatchAccount(t *testing.T) {
	cases := []struct {
		tool    string
		args    string
		action  AccountAction // "" = no match, the normal wrapped path
		profile string
	}{
		{"vercel", "logout", AccountLogout, ""},
		{"vercel", "login", AccountLoginExpiring, ""},
		{"railway", "login", AccountLoginExpiring, ""},
		{"opencode", "providers login", AccountLogin, ""},
		{"databricks", "auth switch", AccountSwitch, ""},
		{"circleci", "auth logout", AccountLogout, ""},
		{"snow", "--environment prod sql", AccountProfile, "prod"},
		{"wrangler", "--profile work deploy", AccountProfile, "work"},
		{"hf", "login", "", ""}, // hf never had top-level login
		{"snyk", "logout", "", ""},
		{"vercel", "switch", AccountSwitch, ""},
		{"vercel", "switch my-team", AccountSwitch, ""},
		{"vercel", "deploy --prod", "", ""},
		{"vercel", "logout --help", "", ""},
		{"vercel", "__complete logout", "", ""}, // a TAB press, handled before the rules
		{"wrangler", "auth activate work", AccountSwitch, ""},
		{"wrangler", "deploy", "", ""},
		{"hf", "auth login", AccountLoginExpiring, ""},
		{"vault", "login -method=oidc", AccountLoginExpiring, ""},
		{"hf", "auth switch", AccountSwitch, ""},
		{"hf", "auth whoami", "", ""},
		{"hcloud", "context use work", AccountSwitch, ""},
		{"hcloud", "--context work server list", AccountProfile, "work"}, // no cli.toml: every context is another
		{"hcloud", "server list", "", ""},
		// A switch never runs, profile flag or not.
		{"doctl", "--context work auth switch", AccountSwitch, ""},
		{"doctl", "auth init", AccountLogin, ""},
		// A login for another profile is that profile's, not the wrap's.
		{"doctl", "auth init --context work", AccountProfile, "work"},
		{"doctl", "--context=default compute droplet list", "", ""},
		{"stripe", "-p other customers list", AccountProfile, "other"},
		{"stripe", "--project-name=other login", AccountProfile, "other"},
		{"stripe", "-p default customers list", "", ""},
		{"stripe", "login", AccountLogin, ""},
		{"databricks", "-p DEFAULT clusters list", "", ""},
		{"databricks", "--profile prod clusters list", AccountProfile, "prod"},
		{"snow", "-c prod sql -q x", AccountProfile, "prod"},
		{"snow", "connection set-default prod", AccountSwitch, ""},
		// Flags that name files or servers, not accounts, are no rule.
		{"jira", "-c ~/other.yml issue list", "", ""},
		{"ngrok", "http 80 --config a.yml,b.yml", "", ""},
		{"vault", "-address=https://other:8200 kv get x", "", ""},
		{"codex", "login --with-api-key", "", ""},
		// -h is help for these tools, never an account change.
		{"vercel", "login -h", "", ""},
		{"doctl", "auth switch -h", "", ""},
		// Words after "--" are the tool's arguments to something else.
		{"vercel", "env run -- logout", "", ""},
		// Tools with no rules, and non-shim kinds, never match.
		{"openai", "login", "", ""},
		{"gcloud", "auth login", "", ""},
		{"aws", "sso login", "", ""},
	}
	for _, c := range cases {
		e, ok := Lookup(c.tool)
		if !ok {
			t.Fatalf("%s isn't cataloged", c.tool)
		}
		m, ok := e.MatchAccount(t.TempDir(), strings.Fields(c.args))
		if c.action == "" {
			if ok {
				t.Errorf("%s %s matched %+v, want the normal wrapped path", c.tool, c.args, m)
			}
			continue
		}
		if !ok || m.Rule.Action != c.action || m.Profile != c.profile {
			t.Errorf("%s %s = %+v (%v), want %s %q", c.tool, c.args, m, ok, c.action, c.profile)
		}
	}
}

// Every rule belongs to a shim tool and names a command; a switch is the
// only refusal, so each one says which words it refuses.
func TestCatalogAccountsWellFormed(t *testing.T) {
	for tool, spec := range catalogAccounts {
		e, _ := Lookup(tool)
		if e.Kind != KindShim {
			t.Errorf("%s: account rules on a %s tool", tool, e.Kind)
		}
		if tool == "gh" {
			t.Error("gh's accounts are ghauth.go's; a rule here would never run")
		}
		seen := map[string]bool{}
		for _, r := range spec.rules {
			key := strings.Join(r.Command, " ")
			if key == "" || seen[key] {
				t.Errorf("%s: empty or duplicate rule %q", tool, key)
			}
			seen[key] = true
			switch r.Action {
			case AccountLogin, AccountLoginExpiring, AccountLogout, AccountSwitch:
			default:
				t.Errorf("%s %s: action %q isn't a rule action", tool, key, r.Action)
			}
		}
		for _, f := range spec.profileFlags {
			if !strings.HasPrefix(f, "-") {
				t.Errorf("%s: profile flag %q isn't a flag", tool, f)
			}
		}
	}
}

// hcloud and snow vaulted the FIRST profile in their config; naming that
// one is the wrap's own call, naming another runs on its own login.
func TestMatchAccountDefaultFromConfig(t *testing.T) {
	home := t.TempDir()
	write := func(rel, body string) {
		t.Helper()
		p := ExpandHome(home, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("~/.config/hcloud/cli.toml", "active_context = \"personal\"\n\n[preferences]\n  debug = false\n\n"+
		"[[contexts]]\n  name = \"work\"\n  token = \"\"\n\n[[contexts]]\n  name = \"personal\"\n  token = \"t2\"\n")
	write("~/.snowflake/config.toml", "default_connection_name = \"b\"\n\n[connections.\"prod\"]\npassword = \"\"\n\n[connections.dev]\npassword = \"p\"\n")

	cases := []struct {
		tool, args string
		other      bool
	}{
		{"hcloud", "--context work server list", false},
		{"hcloud", "--context personal server list", true},
		{"snow", "-c prod sql -q x", false},
		{"snow", "--connection=dev sql -q x", true},
	}
	for _, c := range cases {
		e, _ := Lookup(c.tool)
		m, ok := e.MatchAccount(home, strings.Fields(c.args))
		if c.other != (ok && m.Rule.Action == AccountProfile) {
			t.Errorf("%s %s = %+v, %v; want other=%v", c.tool, c.args, m, ok, c.other)
		}
	}
}
