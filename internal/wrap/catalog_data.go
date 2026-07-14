// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package wrap

// The catalog entries. Pure data, zero branching (docs/WRAP-PLAN.md §4):
// adding a tool means one block here plus a testdata/<tool>/ fixture, and
// nothing else. Paths and selectors are asserted against those fixtures in
// catalog_test.go / extract tests — a fixture is a sanitized copy of the
// real file the tool writes.
//
// Kind selection follows the plan's three-question checklist: a tool with
// its own pluggable credential mechanism is KindNative (the mechanism
// reaches SDKs a shim can't); a tool that reads an env var is KindShim; a
// tool with neither isn't in the catalog.
var catalog = map[string]CatalogEntry{
	"gh": {
		Tool:    "gh",
		Kind:    KindShim,
		Doc:     "GitHub CLI OAuth token",
		EnvVars: map[string]string{"GH_TOKEN": "GH_TOKEN"},
		Order:   []string{"GH_TOKEN"},
		Sources: []TokenSource{
			{Path: "~/.config/gh/hosts.yml", Format: "yaml", Selector: "github.com/oauth_token"},
		},
		TokenCommand: []string{"gh", "auth", "token"}, // modern gh stores in the keyring; this is its documented export
		VerifyHint:   "gh auth status",
	},
	"glab": {
		Tool:    "glab",
		Kind:    KindShim,
		Doc:     "GitLab CLI personal access token",
		EnvVars: map[string]string{"GITLAB_TOKEN": "GITLAB_TOKEN"},
		Order:   []string{"GITLAB_TOKEN"},
		Sources: []TokenSource{
			{Path: "~/.config/glab-cli/config.yml", Format: "yaml", Selector: "hosts/gitlab.com/token"},
		},
		VerifyHint: "glab auth status",
	},
	"ngrok": {
		Tool:    "ngrok",
		Kind:    KindShim,
		Doc:     "ngrok agent authtoken",
		EnvVars: map[string]string{"NGROK_AUTHTOKEN": "NGROK_AUTHTOKEN"},
		Order:   []string{"NGROK_AUTHTOKEN"},
		Sources: []TokenSource{
			// agent config v3 nests under agent:; v2 is top-level.
			{Path: "~/Library/Application Support/ngrok/ngrok.yml", Format: "yaml", Selector: "agent/authtoken"},
			{Path: "~/Library/Application Support/ngrok/ngrok.yml", Format: "yaml", Selector: "authtoken"},
			{Path: "~/.config/ngrok/ngrok.yml", Format: "yaml", Selector: "agent/authtoken"},
			{Path: "~/.config/ngrok/ngrok.yml", Format: "yaml", Selector: "authtoken"},
		},
		VerifyHint: "ngrok config check",
	},
	"doctl": {
		Tool:    "doctl",
		Kind:    KindShim,
		Doc:     "DigitalOcean API token",
		EnvVars: map[string]string{"DIGITALOCEAN_ACCESS_TOKEN": "DIGITALOCEAN_ACCESS_TOKEN"},
		Order:   []string{"DIGITALOCEAN_ACCESS_TOKEN"},
		Sources: []TokenSource{
			{Path: "~/Library/Application Support/doctl/config.yaml", Format: "yaml", Selector: "access-token"},
			{Path: "~/.config/doctl/config.yaml", Format: "yaml", Selector: "access-token"},
		},
		VerifyHint: "doctl account get",
	},
	"stripe": {
		Tool:    "stripe",
		Kind:    KindShim,
		Doc:     "Stripe CLI API key",
		EnvVars: map[string]string{"STRIPE_API_KEY": "STRIPE_API_KEY"},
		Order:   []string{"STRIPE_API_KEY"},
		Sources: []TokenSource{
			{Path: "~/.config/stripe/config.toml", Format: "toml", Selector: "default/live_mode_api_key"},
			{Path: "~/.config/stripe/config.toml", Format: "toml", Selector: "default/test_mode_api_key"},
		},
		VerifyHint: "stripe config --list",
	},
	"openai": {
		Tool:    "openai",
		Kind:    KindShim,
		Doc:     "OpenAI API key",
		EnvVars: map[string]string{"OPENAI_API_KEY": "OPENAI_API_KEY"},
		Order:   []string{"OPENAI_API_KEY"},
		// No Sources and no TokenCommand: the key lives wherever the user
		// pasted it (usually a shell export — migrate's territory). Wrap
		// still works: `jit vault set wrap-openai/OPENAI_API_KEY` first.
	},

	"aws": {
		Tool:           "aws",
		Kind:           KindNative,
		Doc:            "AWS access keys — served via credential_process, which SDKs consult too",
		NativeCategory: "aws",
	},
	"terraform": {
		Tool:           "terraform",
		Kind:           KindNative,
		Doc:            "Terraform Cloud API token — served via credentials_helper; terraform login/logout keep working",
		NativeCategory: "terraform",
	},
}
