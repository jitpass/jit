// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package wrap

import (
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
		{"vercel", "login", AccountLogin, ""},
		{"vercel", "switch", AccountSwitch, ""},
		{"vercel", "switch my-team", AccountSwitch, ""},
		{"vercel", "deploy --prod", "", ""},
		{"vercel", "logout --help", "", ""},
		{"vercel", "__complete logout", "", ""}, // a TAB press, handled before the rules
		{"wrangler", "auth activate work", AccountSwitch, ""},
		{"wrangler", "deploy", "", ""},
		{"hf", "auth login", AccountLogin, ""},
		{"hf", "login", AccountLogin, ""},
		{"hf", "auth switch", AccountSwitch, ""},
		{"hf", "auth whoami", "", ""},
		{"hcloud", "context use work", AccountSwitch, ""},
		{"hcloud", "--context work server list", AccountProfile, "work"},
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
		{"jira", "issue list", "", ""},
		{"jira", "-c ~/other.yml issue list", AccountProfile, "~/other.yml"},
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
		m, ok := e.MatchAccount(strings.Fields(c.args))
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
			case AccountLogin, AccountLogout, AccountSwitch:
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
