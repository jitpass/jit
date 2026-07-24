// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package wrap

// The catalog entries. Pure data, zero branching (docs/internal/WRAP-PLAN.md §4):
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
		EnvVars: map[string]string{"NGROK_AUTHTOKEN": "NGROK_AUTHTOKEN"}, // #nosec G101 -- env var name, not a credential
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
	"hcloud": {
		Tool:    "hcloud",
		Kind:    KindShim,
		Doc:     "Hetzner Cloud API token",
		EnvVars: map[string]string{"HCLOUD_TOKEN": "HCLOUD_TOKEN"},
		Order:   []string{"HCLOUD_TOKEN"},
		Sources: []TokenSource{
			// [[contexts]] name/token pairs; the line extractor matches the
			// first context's token — the active one for single-context
			// setups, which is the common case worth auto-migrating.
			{Path: "~/.config/hcloud/cli.toml", Format: "toml", Selector: "contexts/token"},
		},
		VerifyHint: "hcloud server list",
	},
	"flyctl": {
		Tool:    "flyctl",
		Kind:    KindShim,
		Doc:     "Fly.io access token",
		EnvVars: map[string]string{"FLY_API_TOKEN": "FLY_API_TOKEN"}, // #nosec G101 -- env var name, not a credential
		Order:   []string{"FLY_API_TOKEN"},
		Sources: []TokenSource{
			{Path: "~/.fly/config.yml", Format: "yaml", Selector: "access_token"},
		},
		VerifyHint: "flyctl auth whoami",
	},
	"vercel": {
		Tool:    "vercel",
		Kind:    KindShim,
		Doc:     "Vercel CLI token",
		EnvVars: map[string]string{"VERCEL_TOKEN": "VERCEL_TOKEN"}, // #nosec G101 -- env var name, not a credential
		Order:   []string{"VERCEL_TOKEN"},
		Sources: []TokenSource{
			{Path: "~/Library/Application Support/com.vercel.cli/auth.json", Format: "json", Selector: "token"},
		},
		VerifyHint: "vercel whoami",
	},
	"railway": {
		Tool:    "railway",
		Kind:    KindShim,
		Doc:     "Railway CLI token",
		EnvVars: map[string]string{"RAILWAY_TOKEN": "RAILWAY_TOKEN"},
		Order:   []string{"RAILWAY_TOKEN"},
		Sources: []TokenSource{
			{Path: "~/.railway/config.json", Format: "json", Selector: "user/token"},
		},
		VerifyHint: "railway whoami",
	},
	"databricks": {
		Tool:    "databricks",
		Kind:    KindShim,
		Doc:     "Databricks personal access token",
		EnvVars: map[string]string{"DATABRICKS_TOKEN": "DATABRICKS_TOKEN"},
		Order:   []string{"DATABRICKS_TOKEN"},
		Sources: []TokenSource{
			// .databrickscfg is INI; the toml extractor's line shape covers it.
			{Path: "~/.databrickscfg", Format: "toml", Selector: "DEFAULT/token"},
		},
		VerifyHint: "databricks current-user me",
	},
	"hf": {
		Tool:    "hf",
		Kind:    KindShim,
		Doc:     "Hugging Face Hub access token",
		EnvVars: map[string]string{"HF_TOKEN": "HF_TOKEN"},
		Order:   []string{"HF_TOKEN"},
		Sources: []TokenSource{
			// `hf auth login` writes the active token as the file's entire
			// contents — no keys, no structure. HF_TOKEN (which the shim
			// injects) is documented to take priority over this file. The
			// path is the documented default; with HF_HOME/XDG_CACHE_HOME
			// set it moves, and the wrap flow falls back to `jit vault set`.
			{Path: "~/.cache/huggingface/token", Format: "raw"},
		},
		VerifyHint: "hf auth whoami",
	},
	"supabase": {
		Tool:    "supabase",
		Kind:    KindShim,
		Doc:     "Supabase personal access token",
		EnvVars: map[string]string{"SUPABASE_ACCESS_TOKEN": "SUPABASE_ACCESS_TOKEN"}, // #nosec G101 -- env var name, not a credential
		Order:   []string{"SUPABASE_ACCESS_TOKEN"},
		Sources: []TokenSource{
			// `supabase login` prefers the OS keyring (already encrypted at
			// rest) and writes this plain file only as its fallback — the
			// case worth migrating. The env var is the CLI's highest-priority
			// token source, so the shim's injection always wins.
			{Path: "~/.supabase/access-token", Format: "raw"},
		},
		VerifyHint: "supabase projects list",
	},
	"wrangler": {
		Tool:    "wrangler",
		Kind:    KindShim,
		Doc:     "Cloudflare API token for the Workers CLI",
		EnvVars: map[string]string{"CLOUDFLARE_API_TOKEN": "CLOUDFLARE_API_TOKEN"}, // #nosec G101 -- env var name, not a credential
		Order:   []string{"CLOUDFLARE_API_TOKEN"},
		// No Sources. `wrangler login` writes a short-lived OAuth access
		// token (refresh-only) to ~/.config/.wrangler/config/default.toml,
		// and newer wrangler encrypts even that into default.enc with the key
		// in the OS keychain, so there's usually no durable plaintext to
		// migrate. CLOUDFLARE_API_TOKEN, which the shim injects and which
		// wrangler treats as its highest-priority credential, expects a
		// durable API token from the Cloudflare dashboard. Wrap is for those
		// setups: `jit vault set wrap-wrangler/CLOUDFLARE_API_TOKEN` first.
		// Auto-migrating the OAuth token would yield a wrap that breaks the
		// moment it expires.
		VerifyHint: "wrangler whoami",
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
	"claude": {
		Tool:    "claude",
		Kind:    KindShim,
		Doc:     "Anthropic API key for Claude Code",
		EnvVars: map[string]string{"ANTHROPIC_API_KEY": "ANTHROPIC_API_KEY"},
		Order:   []string{"ANTHROPIC_API_KEY"},
		// No Sources and no TokenCommand: on macOS Claude Code keeps its
		// subscription OAuth in the Keychain (already encrypted at rest,
		// nothing to migrate), and an API key lives wherever the user
		// exported it (shell config — migrate's territory). Wrap is for
		// API-key setups: `jit vault set wrap-claude/ANTHROPIC_API_KEY`
		// first. ANTHROPIC_API_KEY switches Claude Code to API billing,
		// which is exactly what an API-key user wants and a subscription
		// user doesn't — docs/wrap/claude.md carries that caveat.
	},
	"gemini": {
		Tool:    "gemini",
		Kind:    KindShim,
		Doc:     "Gemini API key",
		EnvVars: map[string]string{"GEMINI_API_KEY": "GEMINI_API_KEY"},
		Order:   []string{"GEMINI_API_KEY"},
		Sources: []TokenSource{
			// Gemini CLI's documented .env loading: ~/.gemini/.env is its
			// dedicated file, plain ~/.env the documented fallback. dotenv
			// KEY=value lines are the toml extractor's sectionless line
			// shape. If jit migrate already turned either path into a
			// live mount, ExtractToken's FIFO guard refuses to read it
			// (rather than "discovering" today's decoy cycle as the token)
			// — see that function's doc comment.
			{Path: "~/.gemini/.env", Format: "toml", Selector: "GEMINI_API_KEY"},
			{Path: "~/.env", Format: "toml", Selector: "GEMINI_API_KEY"},
		},
		VerifyHint: `gemini -p "hello"`,
	},
	"codex": {
		Tool:    "codex",
		Kind:    KindShim,
		Doc:     "OpenAI API key for Codex CLI",
		EnvVars: map[string]string{"CODEX_API_KEY": "CODEX_API_KEY"},
		Order:   []string{"CODEX_API_KEY"},
		Sources: []TokenSource{
			// ~/.codex/auth.json's OPENAI_API_KEY field is set only by an
			// API-key login (`codex login --with-api-key`) — a ChatGPT
			// OAuth login leaves it null, which extractJSON reads as
			// not-found, so the OAuth tokens in the same file are never
			// what gets vaulted or scrubbed. The shim injects
			// CODEX_API_KEY (Codex's documented non-interactive auth var),
			// deliberately NOT OPENAI_API_KEY: codex spawns the user's
			// commands as children, and OPENAI_API_KEY in that inherited
			// environment would hand the key to every one of them.
			{Path: "~/.codex/auth.json", Format: "json", Selector: "OPENAI_API_KEY"},
		},
		VerifyHint: `codex exec "say hi"`,
	},
	"sentry-cli": {
		Tool:    "sentry-cli",
		Kind:    KindShim,
		Doc:     "Sentry CLI auth token",
		EnvVars: map[string]string{"SENTRY_AUTH_TOKEN": "SENTRY_AUTH_TOKEN"}, // #nosec G101 -- env var name, not a credential
		Order:   []string{"SENTRY_AUTH_TOKEN"},
		Sources: []TokenSource{
			// .sentryclirc is INI; `sentry-cli login` writes the token under
			// [auth]. The toml extractor's line shape covers it (same as
			// .databrickscfg). SENTRY_AUTH_TOKEN, which the shim injects, is the
			// CLI's documented highest-priority credential.
			{Path: "~/.sentryclirc", Format: "toml", Selector: "auth/token"},
		},
		VerifyHint: "sentry-cli info",
	},
	"snyk": {
		Tool:    "snyk",
		Kind:    KindShim,
		Doc:     "Snyk CLI API token",
		EnvVars: map[string]string{"SNYK_TOKEN": "SNYK_TOKEN"}, // #nosec G101 -- env var name, not a credential
		Order:   []string{"SNYK_TOKEN"},
		Sources: []TokenSource{
			// `snyk auth` writes the token via the `configstore` library as the
			// JSON field "api" (not "token"). SNYK_TOKEN, which the shim injects,
			// is the CLI's documented env credential and takes priority.
			{Path: "~/.config/configstore/snyk.json", Format: "json", Selector: "api"},
		},
		VerifyHint: "snyk config get api",
	},
	"circleci": {
		Tool:    "circleci",
		Kind:    KindShim,
		Doc:     "CircleCI CLI personal API token",
		EnvVars: map[string]string{"CIRCLECI_CLI_TOKEN": "CIRCLECI_CLI_TOKEN"}, // #nosec G101 -- env var name, not a credential
		Order:   []string{"CIRCLECI_CLI_TOKEN"},
		Sources: []TokenSource{
			// `circleci setup` writes the token top-level in cli.yml.
			{Path: "~/.circleci/cli.yml", Format: "yaml", Selector: "token"},
		},
		VerifyHint: "circleci diagnostic",
	},
	"vault": {
		Tool:    "vault",
		Kind:    KindShim,
		Doc:     "HashiCorp Vault token",
		EnvVars: map[string]string{"VAULT_TOKEN": "VAULT_TOKEN"}, // #nosec G101 -- env var name, not a credential
		Order:   []string{"VAULT_TOKEN"},
		Sources: []TokenSource{
			// `vault login` writes the current token as the whole file contents
			// of ~/.vault-token (no keys, no structure). VAULT_TOKEN, which the
			// shim injects, is Vault's documented highest-priority credential and
			// overrides the file. Note: these tokens carry a TTL — wrap a
			// long-lived token; a short-lived one breaks when it expires (see the
			// docs page), the same caveat wrangler's OAuth token has.
			{Path: "~/.vault-token", Format: "raw"},
		},
		VerifyHint: "vault token lookup",
	},
	"pulumi": {
		Tool:    "pulumi",
		Kind:    KindShim,
		Doc:     "Pulumi access token",
		EnvVars: map[string]string{"PULUMI_ACCESS_TOKEN": "PULUMI_ACCESS_TOKEN"}, // #nosec G101 -- env var name, not a credential
		Order:   []string{"PULUMI_ACCESS_TOKEN"},
		// No Sources. `pulumi login` writes the token into
		// ~/.pulumi/credentials.json under an `accessTokens` map keyed by the
		// backend URL (https://api.pulumi.com), which the catalog's flat
		// selector can't address. PULUMI_ACCESS_TOKEN, which the shim injects and
		// which pulumi treats as its highest-priority credential, expects a
		// durable token from app.pulumi.com/account/tokens. Wrap is for those:
		// `jit vault set wrap-pulumi/PULUMI_ACCESS_TOKEN` first.
		VerifyHint: "pulumi whoami",
	},

	"aws": {
		Tool:           "aws",
		Kind:           KindNative,
		Doc:            "AWS access keys, served via credential_process, which SDKs consult too",
		NativeCategory: "aws",
	},
	"terraform": {
		Tool:           "terraform",
		Kind:           KindNative,
		Doc:            "Terraform Cloud API token, served via credentials_helper; terraform login/logout keep working",
		NativeCategory: "terraform",
	},
	"docker": {
		Tool:           "docker",
		Kind:           KindNative,
		Doc:            "Docker registry logins, served via a credential helper; docker login/logout keep working",
		NativeCategory: "docker",
	},
	"git": {
		Tool:           "git",
		Kind:           KindNative,
		Doc:            "git HTTPS credentials, served via a credential helper; git push/fetch over HTTPS keeps working",
		NativeCategory: "git",
	},
}
