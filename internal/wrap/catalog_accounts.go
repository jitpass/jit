// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package wrap

import "regexp"

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
	rules              []AccountRule
	profileFlags       []string
	defaultProfile     string
	defaultProfileFrom *ProfileNameSource
}

// The first `name = "…"` line in hcloud's cli.toml belongs to the first
// [[contexts]] entry (active_context sits above the tables and is not a
// `name` key) — the context whose token `jit wrap hcloud` vaulted.
var hcloudFirstContext = &ProfileNameSource{
	Path:    "~/.config/hcloud/cli.toml",
	pattern: regexp.MustCompile(`^\s*name\s*=\s*"([^"]+)"`),
}

// snow's first [connections.<name>] header: the connection whose password
// `jit wrap snow` vaulted.
var snowFirstConnection = &ProfileNameSource{
	Path:    "~/.snowflake/config.toml",
	pattern: regexp.MustCompile(`^\s*\[connections\."?([^"\]]+)"?\]`),
}

func login(words ...string) AccountRule  { return AccountRule{Command: words, Action: AccountLogin} }
func logout(words ...string) AccountRule { return AccountRule{Command: words, Action: AccountLogout} }
func expiringLogin(hint string, words ...string) AccountRule {
	return AccountRule{Command: words, Action: AccountLoginExpiring, Hint: hint}
}
func switchTo(hint string, words ...string) AccountRule {
	return AccountRule{Command: words, Action: AccountSwitch, Hint: hint}
}

var catalogAccounts = map[string]accountSpec{
	// glab: login warns GITLAB_TOKEN "takes precedence" and carries on;
	// the stored login is never used.
	"glab": {rules: []AccountRule{login("auth", "login"), logout("auth", "logout")}},
	// ngrok: add-authtoken writes the token to ngrok.yml in plaintext.
	// (--config names config FILES, several at once, not accounts.)
	"ngrok": {rules: []AccountRule{login("config", "add-authtoken")}},
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
		profileFlags: []string{"--context"}, defaultProfileFrom: hcloudFirstContext,
	},
	// flyctl: login and logout both finish by saying FLY_API_TOKEN is
	// still what flyctl will use.
	"flyctl": {rules: []AccountRule{login("auth", "login"), logout("auth", "logout")}},
	// vercel: the env token becomes --token, so switch refuses ("doesn't
	// work with --token") and logout revokes the injected token itself.
	// login is the OAuth device flow now: a short-lived token plus a
	// refresh token the CLI renews, which it skips under VERCEL_TOKEN.
	"vercel": {rules: []AccountRule{
		expiringLogin("", "login"), logout("logout"),
		switchTo("`--scope <team>` picks the team on each command", "switch"),
	}},
	// railway: login sees the env token and returns without logging in;
	// run without it, it saves only an OAuth user.accessToken it refreshes.
	"railway": {rules: []AccountRule{expiringLogin("", "login"), logout("logout")}},
	// databricks: with -p, the env PAT fills in a profile that has no auth
	// of its own, or clashes with the auth it has. auth switch writes the
	// default profile later wrapped calls would then send the PAT to.
	"databricks": {
		rules: []AccountRule{
			login("auth", "login"), logout("auth", "logout"),
			switchTo("`-p <profile>` picks a profile on each command", "auth", "switch"),
		},
		profileFlags: []string{"-p", "--profile"}, defaultProfile: "DEFAULT",
	},
	// hf: logout deletes the stored token then fails "you are still logged
	// in"; switch warns HF_TOKEN "will override" the account switched to.
	// Its browser login issues a short-lived token; a pasted one is durable.
	"hf": {rules: []AccountRule{
		expiringLogin("Logged in with a pasted access token? `jit wrap hf` moves it into the vault.", "auth", "login"),
		logout("auth", "logout"), switchTo("", "auth", "switch"),
	}},
	// supabase: login takes --token, then SUPABASE_ACCESS_TOKEN, then
	// stdin, so with the env token set it saves the injected token to
	// disk; the env token outranks the stored one for logout too.
	"supabase": {rules: []AccountRule{login("login"), logout("logout")}},
	// wrangler: login and logout refuse while CLOUDFLARE_API_TOKEN is set,
	// and so does every auth profile command; --profile is silently
	// ignored under it. Its login is OAuth (see the catalog entry).
	"wrangler": {
		rules: []AccountRule{
			expiringLogin("", "login"), logout("logout"),
			switchTo("", "auth", "activate"), switchTo("", "auth", "deactivate"),
			switchTo("", "auth", "create"), switchTo("", "auth", "delete"),
		},
		profileFlags: []string{"--profile"},
	},
	// codex has no rules on purpose: its interactive TUI reads only
	// auth.json (CODEX_API_KEY reaches `codex exec` alone), so a login
	// re-vaulted out of auth.json would log interactive codex out again.
	// opencode: providers login (alias auth) puts a key back in
	// auth.json, where it outranks the env var.
	"opencode": {rules: []AccountRule{
		login("providers", "login"), logout("providers", "logout"),
		login("auth", "login"), logout("auth", "logout"),
	}},
	// cursor-agent, kiro-cli: the env key outranks the browser session.
	"cursor-agent": {rules: []AccountRule{login("login"), logout("logout")}},
	"kiro-cli":     {rules: []AccountRule{login("login"), logout("logout")}},
	// sentry-cli: login writes ~/.sentryclirc, which the env token then
	// silently overrides.
	"sentry-cli": {rules: []AccountRule{login("login")}},
	// snyk: auth stores the token in its config store. (There is no
	// logout command; `snyk config unset api` is its nearest.)
	"snyk": {rules: []AccountRule{login("auth")}},
	// vault: login warns VAULT_TOKEN "will take precedence". The tokens
	// it stores carry a lease, often a short one.
	"vault": {rules: []AccountRule{
		expiringLogin("Logged in with a long-lived token? `jit wrap vault` moves it into the vault.", "login"),
	}},
	// pulumi: logging in with PULUMI_ACCESS_TOKEN set saves it into
	// ~/.pulumi/credentials.json.
	"pulumi": {rules: []AccountRule{login("login"), logout("logout")}},
	// snow: plain SNOWFLAKE_* variables apply to every connection, so -c
	// would send one connection's password as another user.
	"snow": {
		rules:        []AccountRule{switchTo("`-c <name>` picks a connection on each command", "connection", "set-default")},
		profileFlags: []string{"-c", "--connection", "--environment"}, defaultProfileFrom: snowFirstConnection,
	},
	// circleci v1: auth logout's own help says CIRCLE_TOKEN keeps the CLI
	// authenticated; login stores to the keyring or config.yml.
	"circleci": {rules: []AccountRule{login("auth", "login"), logout("auth", "logout")}},
}

func init() {
	for tool, spec := range catalogAccounts {
		e, ok := catalog[tool]
		if !ok {
			panic("catalogAccounts names " + tool + ", which isn't in the catalog")
		}
		e.Accounts, e.ProfileFlags, e.DefaultProfile = spec.rules, spec.profileFlags, spec.defaultProfile
		e.DefaultProfileFrom = spec.defaultProfileFrom
		catalog[tool] = e
	}
}
