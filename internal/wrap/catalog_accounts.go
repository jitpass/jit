// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package wrap

// The account commands of each shim tool (accounts.go says what the
// actions do). Kept beside the catalog rather than inside each entry so the
// whole table reads at once. Every rule was checked against the tool's own
// source or docs as of 2026-09-30: a command listed here is one that, with
// the token injected, refuses, does nothing, reports the wrong account,
// revokes the injected token, or writes it back to disk. gh is not here:
// its accounts get a vault secret each (ghauth.go). Tools whose account
// commands live only inside an interactive session (claude's /login,
// copilot's /login) can't be reached from the command line and aren't
// listed.

type accountSpec struct {
	rules          []AccountRule
	profileFlags   []string
	defaultProfile string
}

func login(words ...string) AccountRule  { return AccountRule{Command: words, Action: AccountLogin} }
func logout(words ...string) AccountRule { return AccountRule{Command: words, Action: AccountLogout} }
func switchTo(hint string, words ...string) AccountRule {
	return AccountRule{Command: words, Action: AccountSwitch, Hint: hint}
}

var catalogAccounts = map[string]accountSpec{
	// glab: login warns GITLAB_TOKEN "takes precedence" and carries on;
	// the stored login is never used.
	"glab": {rules: []AccountRule{login("auth", "login"), logout("auth", "logout")}},
	// ngrok: add-authtoken writes the token to ngrok.yml in plaintext;
	// NGROK_AUTHTOKEN overrides whatever --config names.
	"ngrok": {rules: []AccountRule{login("config", "add-authtoken")}, profileFlags: []string{"--config"}},
	// doctl: the env var feeds only the default context; auth init/switch/
	// remove save viper's whole settings map, env token included.
	"doctl": {
		rules: []AccountRule{
			login("auth", "init"), logout("auth", "remove"),
			switchTo("", "auth", "switch"),
		},
		profileFlags: []string{"--context"}, defaultProfile: "default",
	},
	// stripe: STRIPE_API_KEY outranks --project-name and --api-key.
	"stripe": {
		rules:        []AccountRule{login("login"), logout("logout")},
		profileFlags: []string{"-p", "--project-name"}, defaultProfile: "default",
	},
	// hcloud: "HCLOUD_TOKEN is set. The active context will have no
	// effect"; context create offers to save the env token into cli.toml.
	"hcloud": {
		rules: []AccountRule{
			login("context", "create"), logout("context", "delete"),
			switchTo("", "context", "use"),
		},
		profileFlags: []string{"--context"},
	},
	// flyctl: login and logout both finish by saying FLY_API_TOKEN is
	// still what flyctl will use.
	"flyctl": {rules: []AccountRule{login("auth", "login"), logout("auth", "logout")}},
	// vercel: the env token becomes --token, so switch refuses ("doesn't
	// work with --token") and logout revokes the injected token itself.
	"vercel": {rules: []AccountRule{
		login("login"), logout("logout"),
		switchTo("`--scope <team>` picks the team on each command", "switch"),
	}},
	// railway: login sees the env token and returns without logging in.
	"railway": {rules: []AccountRule{login("login"), logout("logout")}},
	// databricks: the env PAT is layered over whichever profile -p names.
	"databricks": {
		rules:        []AccountRule{login("auth", "login")},
		profileFlags: []string{"-p", "--profile"}, defaultProfile: "DEFAULT",
	},
	// hf: logout deletes the stored token then fails "you are still logged
	// in"; switch warns HF_TOKEN "will override" the account switched to.
	"hf": {rules: []AccountRule{
		login("auth", "login"), logout("auth", "logout"), switchTo("", "auth", "switch"),
		login("login"), logout("logout"), // the pre-`hf auth` spellings
	}},
	// supabase: the env token outranks the stored one; login and logout
	// succeed silently and change nothing.
	"supabase": {rules: []AccountRule{login("login"), logout("logout")}},
	// wrangler: login and logout refuse while CLOUDFLARE_API_TOKEN is set,
	// and so does every auth profile command.
	"wrangler": {rules: []AccountRule{
		login("login"), logout("logout"),
		switchTo("", "auth", "activate"), switchTo("", "auth", "deactivate"),
		switchTo("", "auth", "create"), switchTo("", "auth", "delete"),
	}},
	// codex: login writes auth.json, which the wrap scrubbed.
	"codex": {rules: []AccountRule{login("login"), logout("logout")}},
	// opencode: auth login puts a key back in auth.json, where it outranks
	// the env var.
	"opencode": {rules: []AccountRule{login("auth", "login"), logout("auth", "logout")}},
	// cursor-agent, kiro-cli: the env key outranks the browser session.
	"cursor-agent": {rules: []AccountRule{login("login"), logout("logout")}},
	"kiro-cli":     {rules: []AccountRule{login("login"), logout("logout")}},
	// sentry-cli: login writes ~/.sentryclirc, which the env token then
	// silently overrides.
	"sentry-cli": {rules: []AccountRule{login("login")}},
	// snyk: auth stores the token in its config store.
	"snyk": {rules: []AccountRule{login("auth"), logout("logout")}},
	// vault: login warns VAULT_TOKEN "will take precedence"; -address
	// names another cluster, which must not be sent this one's token.
	"vault": {rules: []AccountRule{login("login")}, profileFlags: []string{"-address", "--address"}},
	// pulumi: logging in with PULUMI_ACCESS_TOKEN set saves it into
	// ~/.pulumi/credentials.json.
	"pulumi": {rules: []AccountRule{login("login"), logout("logout")}},
	// snow: plain SNOWFLAKE_* variables apply to every connection, so -c
	// would send one connection's password as another user.
	"snow": {
		rules:        []AccountRule{switchTo("`-c <name>` picks a connection on each command", "connection", "set-default")},
		profileFlags: []string{"-c", "--connection"},
	},
	// jira: the env token outranks each server's stored one.
	"jira": {profileFlags: []string{"-c", "--config"}},
}

func init() {
	for tool, spec := range catalogAccounts {
		e, ok := catalog[tool]
		if !ok {
			panic("catalogAccounts names " + tool + ", which isn't in the catalog")
		}
		e.Accounts, e.ProfileFlags, e.DefaultProfile = spec.rules, spec.profileFlags, spec.defaultProfile
		catalog[tool] = e
	}
}
