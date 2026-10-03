// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package wrap

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCatalogEntriesAreWellFormed is the review gate catalog_data.go PRs go
// through: every entry must satisfy the structural rules the wrap flow and
// audit signal rely on, so a bad data block fails here, not in production.
func TestCatalogEntriesAreWellFormed(t *testing.T) {
	tools := CatalogTools()
	if len(tools) == 0 {
		t.Fatal("catalog is empty")
	}
	for _, tool := range tools {
		e, ok := Lookup(tool)
		if !ok || e.Tool != tool {
			t.Errorf("%s: map key and Tool field disagree (%q)", tool, e.Tool)
		}
		if err := ValidateToolName(tool); err != nil {
			t.Errorf("%s: %v", tool, err)
		}
		if e.Doc == "" {
			t.Errorf("%s: missing Doc", tool)
		}
		switch e.Kind {
		case KindShim:
			if len(e.EnvVars) == 0 || len(e.Order) != len(e.EnvVars) || e.PrimaryVar() == "" {
				t.Errorf("%s: shim entry needs EnvVars and a matching Order", tool)
			}
			for _, name := range e.Order {
				if _, ok := e.EnvVars[name]; !ok {
					t.Errorf("%s: Order names %s but EnvVars doesn't map it", tool, name)
				}
			}
			for _, src := range e.Sources {
				if _, ok := extractors[src.Format]; !ok {
					t.Errorf("%s: source %s uses unregistered format %q", tool, src.Path, src.Format)
				}
				if src.Path == "" {
					t.Errorf("%s: source with empty path", tool)
				}
				// A raw source takes the whole file; its selector must stay
				// empty so the data can't imply structure that isn't there.
				if src.Format == "raw" {
					if src.Selector != "" {
						t.Errorf("%s: raw source %s must leave Selector empty", tool, src.Path)
					}
				} else if src.Selector == "" {
					t.Errorf("%s: source %s has an empty selector", tool, src.Path)
				}
			}
			if e.NativeCategory != "" {
				t.Errorf("%s: shim entry must not set NativeCategory", tool)
			}
		case KindNative:
			if e.NativeCategory == "" {
				t.Errorf("%s: native entry needs NativeCategory", tool)
			}
			if len(e.EnvVars) != 0 || len(e.Sources) != 0 {
				t.Errorf("%s: native entry must not carry shim fields", tool)
			}
		case KindCapture:
			// A capture entry's dispatch is its tool name (the shim execs
			// `jit <tool>-capture`); it injects nothing and discovers
			// nothing, so every shim/native field must stay empty.
			if len(e.EnvVars) != 0 || len(e.Sources) != 0 || len(e.TokenCommand) != 0 {
				t.Errorf("%s: capture entry must not carry shim fields", tool)
			}
			if e.NativeCategory != "" {
				t.Errorf("%s: capture entry must not set NativeCategory", tool)
			}
		case KindRunGrant:
			// A run-grant entry carries no token and names no mount — the
			// shim just re-execs through `jit run --grant-only`, so every
			// shim/native field must stay empty.
			if len(e.EnvVars) != 0 || len(e.Sources) != 0 || len(e.TokenCommand) != 0 {
				t.Errorf("%s: run-grant entry must not carry shim fields", tool)
			}
			if e.NativeCategory != "" {
				t.Errorf("%s: run-grant entry must not set NativeCategory", tool)
			}
		case KindGrant:
			// A grant entry names the global mount `jit run --with` takes
			// and nothing else: no token, no discovery, no category.
			if e.Grant == "" {
				t.Errorf("%s: grant entry needs Grant (the mount name)", tool)
			}
			if len(e.EnvVars) != 0 || len(e.Sources) != 0 || len(e.TokenCommand) != 0 || e.NativeCategory != "" {
				t.Errorf("%s: grant entry must not carry shim or native fields", tool)
			}
		case KindStore:
			// A store entry names the sealed store its family shares and
			// nothing else; the family's namesake must exist, since the
			// shim's plumbing command (`jit <Store>-run`) is named for it.
			if e.Store == "" {
				t.Errorf("%s: store entry needs Store", tool)
			}
			if len(e.EnvVars) != 0 || len(e.Sources) != 0 || len(e.TokenCommand) != 0 || e.NativeCategory != "" || e.Grant != "" {
				t.Errorf("%s: store entry must not carry shim, native or grant fields", tool)
			}
			if fam := StoreFamily(e.Store); len(fam) == 0 || fam[0] != e.Store {
				t.Errorf("%s: store %q has no namesake catalog entry (family %q)", tool, e.Store, fam)
			}
		default:
			t.Errorf("%s: unknown kind %q", tool, e.Kind)
		}
	}
}

func TestVaultPathAndExpandHome(t *testing.T) {
	gh, _ := Lookup("gh")
	if got := gh.VaultPath("GH_TOKEN"); got != "wrap-gh/GH_TOKEN" {
		t.Errorf("VaultPath = %q, want wrap-gh/GH_TOKEN", got)
	}
	if got := ExpandHome("/Users/alex", "~/.config/gh/hosts.yml"); got != "/Users/alex/.config/gh/hosts.yml" {
		t.Errorf("ExpandHome = %q", got)
	}
	if got := ExpandHome("/Users/alex", "/etc/thing"); got != "/etc/thing" {
		t.Errorf("ExpandHome mangled an absolute path: %q", got)
	}
}

// fixtureHomeFor installs a testdata fixture at the catalog path a tool's
// source expects, under a temp home — so the data (paths, selectors) and
// the extractors are tested together, exactly the combination audit and
// the wrap flow will run.
func fixtureHomeFor(t *testing.T, src TokenSource, fixture string) string {
	t.Helper()
	home := t.TempDir()
	data, err := os.ReadFile(filepath.Join("testdata", fixture))
	if err != nil {
		t.Fatalf("fixture %s: %v", fixture, err)
	}
	dest := ExpandHome(home, src.Path)
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dest, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return home
}

// TestCatalogSelectorsAgainstFixtures proves every file-backed catalog
// entry extracts a value from a sanitized copy of the real file format.
func TestCatalogSelectorsAgainstFixtures(t *testing.T) {
	cases := []struct {
		tool      string
		sourceIdx int
		fixture   string
		want      string
	}{
		{"gh", 0, "gh/hosts.yml", "gho_FIXTUREtoken1234567890abcdefFIXTURE"},
		{"glab", 0, "glab/config.yml", "glpat-FIXTUREtoken123456789"},
		{"ngrok", 0, "ngrok/ngrok-v3.yml", "2FIXTUREngrokTokenAbCdEf_1234567890abcd"},
		{"ngrok", 1, "ngrok/ngrok-v2.yml", "2FIXTUREngrokTokenAbCdEf_1234567890abcd"},
		{"doctl", 0, "doctl/config.yaml", "dop_v1_FIXTURE0123456789abcdef0123456789abcdef"},
		{"stripe", 0, "stripe/config.toml", "sk_live_FIXTURE0123456789abcdef"},
		{"stripe", 1, "stripe/config.toml", "sk_test_FIXTURE0123456789abcdef"},
		{"hcloud", 0, "hcloud/cli.toml", "FIXTUREhcloudToken0123456789abcdefFIXTURE0123456789abcdef"},
		{"flyctl", 0, "flyctl/config.yml", "FlyV1_FIXTUREflytoken0123456789abcdef"},
		{"vercel", 0, "vercel/auth.json", "FIXTUREvercelToken0123456789abcdef"},
		{"railway", 0, "railway/config.json", "FIXTURErailwayToken0123456789abcdef"},
		{"databricks", 0, "databricks/databrickscfg", "dapiFIXTURE0123456789abcdef"},
		{"hf", 0, "hf/token", "hf_FIXTUREtoken0123456789abcdefFIXTURE"},
		{"supabase", 0, "supabase/access-token", "sbp_FIXTURE0123456789abcdef0123456789abcdef"},
		{"gemini", 0, "gemini/env", "FIXTUREgeminiToken0123456789abcdefFIXTURE"},
		{"gemini", 1, "gemini/home-dotenv", "FIXTUREgeminiHomeFallback0123456789FIXTURE"},
		{"codex", 0, "codex/auth.json", "sk-FIXTUREcodexToken0123456789abcdefFIXTURE"},
		{"cline", 0, "cline/providers.json", "sk-ant-FIXTUREclineToken0123456789abcdefFIXTURE"},
		// The fixture carries an OAuth entry beside the API key, mirroring a
		// real multi-provider auth.json — the selector must reach only the
		// anthropic key and never an OAuth token.
		{"opencode", 0, "opencode/auth.json", "sk-ant-FIXTUREopencodeToken0123456789abcdefFIXTURE"},
		{"sentry-cli", 0, "sentry-cli/sentryclirc", "FIXTUREsentryToken0123456789abcdefFIXTURE"},
		{"snyk", 0, "snyk/snyk.json", "FIXTUREsnykToken0123-4567-89ab-cdef"},
		{"circleci", 0, "circleci/cli.yml", "FIXTUREcircleciToken0123456789abcdef"},
		{"vault", 0, "vault/vault-token", "hvs.FIXTUREvaultToken0123456789abcdef"},
		{"okta-cli-client", 0, "okta-cli-client/okta.yaml", "FIXTUREoktaToken0123456789abcdefFIXTURE"},
		// The first [connections.<name>] block wins, matching hcloud's
		// contexts/token semantics — "prod" here, not "staging".
		{"snow", 0, "snow/config.toml", "FIXTUREsnowflakePassword0123456789"},
	}
	for _, tc := range cases {
		entry, ok := Lookup(tc.tool)
		if !ok {
			t.Fatalf("%s not in catalog", tc.tool)
		}
		src := entry.Sources[tc.sourceIdx]
		home := fixtureHomeFor(t, src, tc.fixture)
		value, found, err := ExtractToken(home, src)
		if err != nil {
			t.Errorf("%s[%d]: %v", tc.tool, tc.sourceIdx, err)
			continue
		}
		if !found || value != tc.want {
			t.Errorf("%s[%d]: got (%q, %v), want (%q, true)", tc.tool, tc.sourceIdx, value, found, tc.want)
		}
	}
}

// TestVerifyHintsThatPrintASecretSayItSo guards JitPass's Verify, which
// runs a tool's VerifyHint and shows what it printed. A check whose
// output is a credential must carry VerifyPrintsSecret, and the set that
// does is pinned so adding one is a decision. Each verdict was read in
// the tool's source (2026-10-01): stripe config --list prints config.toml
// as it is; vault token lookup prints the token as id; snyk config get api
// prints the stored token.
func TestVerifyHintsThatPrintASecretSayItSo(t *testing.T) {
	// gcloud left this set on 2026-10-02: its wrap became a store-wrap,
	// checked with `gcloud auth list`, which prints account names only.
	prints := map[string]bool{"sops": true}
	// Commands that print the credential they check. A hint containing one
	// must be marked, whichever tool it belongs to.
	secretCommands := []string{
		"print-access-token", "print-identity-token", "auth token",
		"--decrypt", "token lookup", "config get api", "config --list",
		"--show-token",
	}
	for _, tool := range CatalogTools() {
		e, _ := Lookup(tool)
		if e.VerifyPrintsSecret && e.VerifyHint == "" {
			t.Errorf("%s: VerifyPrintsSecret without a VerifyHint", tool)
		}
		if e.VerifyPrintsSecret != prints[tool] {
			t.Errorf("%s: VerifyPrintsSecret = %v, want %v (hint %q)", tool, e.VerifyPrintsSecret, prints[tool], e.VerifyHint)
		}
		for _, c := range secretCommands {
			if strings.Contains(e.VerifyHint, c) && !e.VerifyPrintsSecret {
				t.Errorf("%s: hint %q contains %q, which prints a secret, but isn't marked", tool, e.VerifyHint, c)
			}
		}
	}
}

// TestVerifyHintsRunThroughTheWrap: a check the account rules answer
// (refused, run unwrapped, re-vaulted) would test something other than
// the wrapped key, so no hint may match one.
func TestVerifyHintsRunThroughTheWrap(t *testing.T) {
	home := t.TempDir()
	for _, tool := range CatalogTools() {
		e, _ := Lookup(tool)
		if e.Kind != KindShim || e.VerifyHint == "" {
			continue
		}
		args := strings.Fields(e.VerifyHint)[1:]
		if m, hit := e.MatchAccount(home, args); hit {
			t.Errorf("%s: hint %q matches account rule %+v", tool, e.VerifyHint, m.Rule)
		}
	}
}

func TestStoreFamily(t *testing.T) {
	got := StoreFamily("gcloud")
	want := []string{"gcloud", "bq", "docker-credential-gcloud", "git-credential-gcloud", "gsutil"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("StoreFamily(gcloud) = %q, want %q", got, want)
	}
	if got := StoreFamily("nothing"); len(got) != 0 {
		t.Fatalf("an unknown store has family %q", got)
	}
}

func TestStoreWrapShimArgv(t *testing.T) {
	got := shimArgv("bq", "/sdk/bin/bq", Entry{Store: "gcloud"}, []string{"ls", "--project_id=p"})
	want := []string{"jit", "gcloud-run", "--real", "/sdk/bin/bq", "--", "ls", "--project_id=p"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("shimArgv = %q, want %q", got, want)
	}
	if !(Entry{Store: "gcloud"}).IsProfileless() {
		t.Fatal("a store-wrap reported a profile")
	}
}

func TestReinstallCommand(t *testing.T) {
	cases := []struct {
		tool  string
		entry Entry
		want  string
	}{
		{"gh", Entry{Profile: "wrap-gh"}, "`jit wrap gh`"},
		{"bq", Entry{Store: "gcloud"}, "`jit wrap gcloud`"},
		{"clisso", Entry{Capture: "clisso"}, "`jit wrap clisso`"},
		{"mytool", Entry{Profile: "wrap-mytool"}, "`jit wrap add mytool ...`"},
		// A hand grant-wrap on another mount keeps its --grant flag only in
		// the user's memory: `jit wrap sops` would rebuild the catalog's own
		// sops grant, not this one.
		{"sops", Entry{With: "gcp"}, "`jit wrap add sops ...`"},
		{"sops", Entry{With: "sops"}, "`jit wrap sops`"},
	}
	for _, c := range cases {
		if got := reinstallCommand(c.tool, c.entry); got != c.want {
			t.Errorf("%s: %s, want %s", c.tool, got, c.want)
		}
	}
}
