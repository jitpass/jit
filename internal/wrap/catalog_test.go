// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package wrap

import (
	"os"
	"path/filepath"
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
