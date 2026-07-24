// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/inject"
	"github.com/jitpass/jit/internal/profile"
)

func TestParseTfvarsLines(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantMatches map[string]string // variable name -> unescaped value
		wantSkipped []string
	}{
		{
			name:        "simple secret string",
			input:       "db_password = \"hunter2\"\nregion = \"us-east-1\"\n",
			wantMatches: map[string]string{"db_password": "hunter2"},
		},
		{
			name:        "trailing comments",
			input:       "api_token = \"abc\" # prod token\nauth_secret = \"def\" // legacy\n",
			wantMatches: map[string]string{"api_token": "abc", "auth_secret": "def"},
		},
		{
			name:        "escapes unescaped like terraform would",
			input:       `api_key = "a\"b\\c\nd"` + "\n",
			wantMatches: map[string]string{"api_key": "a\"b\\c\nd"},
		},
		{
			name:        "heredoc secret is skipped and its body is never matched",
			input:       "cert_password = <<EOT\ninner_password = \"never me\"\nEOT\nother_token = \"real\"\n",
			wantMatches: map[string]string{"other_token": "real"},
			wantSkipped: []string{"cert_password"},
		},
		{
			name:        "assignment inside a map body is not top-level",
			input:       "tags = {\n  password = \"not-a-variable\"\n}\n",
			wantMatches: map[string]string{},
		},
		{
			name:        "secret-shaped list is skipped",
			input:       "api_keys = [\"a\", \"b\"]\n",
			wantMatches: map[string]string{},
			wantSkipped: []string{"api_keys"},
		},
		{
			name:        "secret-shaped non-string value is skipped",
			input:       "password_rotation_days = 30\n",
			wantMatches: map[string]string{},
			wantSkipped: []string{"password_rotation_days"},
		},
		{
			name:        "interpolation is skipped, never half-parsed",
			input:       "db_url = \"${var.scheme}://db\"\n",
			wantMatches: map[string]string{},
			wantSkipped: []string{"db_url"},
		},
		{
			name:        "hyphenated name cannot become an env var",
			input:       "db-password = \"x\"\n",
			wantMatches: map[string]string{},
			wantSkipped: []string{"db-password"},
		},
		{
			name:        "empty value is not a secret worth migrating",
			input:       "password = \"\"\n",
			wantMatches: map[string]string{},
		},
		{
			name:        "commented-out assignment is ignored",
			input:       "# password = \"x\"\n// token = \"y\"\n",
			wantMatches: map[string]string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, skipped := parseTfvarsLines(strings.Split(tt.input, "\n"))
			got := map[string]string{}
			for _, m := range matches {
				got[m.Name] = m.Value
			}
			if len(got) != len(tt.wantMatches) {
				t.Fatalf("matches = %v, want %v", got, tt.wantMatches)
			}
			for name, val := range tt.wantMatches {
				if got[name] != val {
					t.Errorf("match %q = %q, want %q", name, got[name], val)
				}
			}
			if len(skipped) != len(tt.wantSkipped) {
				t.Fatalf("skipped = %v, want %v", skipped, tt.wantSkipped)
			}
			for i := range tt.wantSkipped {
				if skipped[i] != tt.wantSkipped[i] {
					t.Errorf("skipped[%d] = %q, want %q", i, skipped[i], tt.wantSkipped[i])
				}
			}
		})
	}
}

func TestDiscoverTfvarsFiles(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "infra", "terraform.tfvars"), "region = \"us-east-1\"\ndb_password = \"hunter2\"\n")
	writeFile(t, filepath.Join(root, "infra", "prod.auto.tfvars"), "api_token = \"tok\"\n")
	// Secret-free file: nothing migratable, must not be discovered.
	writeFile(t, filepath.Join(root, "plain", "terraform.tfvars"), "region = \"eu-west-1\"\ninstance_type = \"t3.micro\"\n")
	// Noise dirs are skipped entirely.
	writeFile(t, filepath.Join(root, "node_modules", "x", "terraform.tfvars"), "password = \"nope\"\n")
	writeFile(t, filepath.Join(root, ".git", "terraform.tfvars"), "password = \"nope\"\n")
	// Wrong names never match.
	writeFile(t, filepath.Join(root, "infra", "variables.tf"), "variable \"db_password\" {}\n")
	writeFile(t, filepath.Join(root, "infra", "dev.tfvars"), "password = \"un-auto'd tfvars is CLI-only\"\n")
	// Secret-shaped but nothing migratable (heredoc only): reported in
	// complexOnly, never in found — `jit scan` flags this file, so a
	// migrate plan silent about it read as the funnel losing a finding.
	writeFile(t, filepath.Join(root, "certs", "terraform.tfvars"), "cert_password = <<EOT\npem\nEOT\n")

	found, complexOnly, err := DiscoverTfvarsFiles(root)
	if err != nil {
		t.Fatalf("DiscoverTfvarsFiles: %v", err)
	}
	want := []string{
		filepath.Join(root, "infra", "prod.auto.tfvars"),
		filepath.Join(root, "infra", "terraform.tfvars"),
	}
	if len(found) != len(want) {
		t.Fatalf("found = %v, want %v", found, want)
	}
	for i := range want {
		if found[i] != want[i] {
			t.Errorf("found[%d] = %q, want %q", i, found[i], want[i])
		}
	}
	wantComplex := []string{filepath.Join(root, "certs", "terraform.tfvars")}
	if len(complexOnly) != 1 || complexOnly[0] != wantComplex[0] {
		t.Errorf("complexOnly = %v, want %v", complexOnly, wantComplex)
	}
}

func TestApplyTfvarsDirMovesSecretsAndRedactsFiles(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "capstone")
	mainPath := filepath.Join(dir, "terraform.tfvars")
	autoPath := filepath.Join(dir, "prod.auto.tfvars")
	writeFile(t, mainPath, "region = \"us-east-1\"\ndb_password = \"from-main\"\ncert_password = <<EOT\npem\nEOT\n")
	// *.auto.tfvars outranks terraform.tfvars, so its db_password must win.
	writeFile(t, autoPath, "db_password = \"from-auto\"\napi_token = \"tok-123\"\n")

	v := newTestVault(t)
	result, err := ApplyTfvarsDir(v, dir, dir, []string{autoPath, mainPath})
	if err != nil {
		t.Fatalf("ApplyTfvarsDir: %v", err)
	}

	if result.ProfileName != "capstone-tfvars" {
		t.Errorf("ProfileName = %q, want %q", result.ProfileName, "capstone-tfvars")
	}
	wantVars := []string{"TF_VAR_api_token", "TF_VAR_db_password"}
	if len(result.Variables) != len(wantVars) || result.Variables[0] != wantVars[0] || result.Variables[1] != wantVars[1] {
		t.Errorf("Variables = %v, want %v", result.Variables, wantVars)
	}
	if len(result.SkippedComplex) != 1 || !strings.Contains(result.SkippedComplex[0], "cert_password") {
		t.Errorf("SkippedComplex = %v, want the heredoc cert_password reported", result.SkippedComplex)
	}

	// Terraform precedence: the auto.tfvars value is what lands in the vault.
	got, err := v.Get("capstone-tfvars/TF_VAR_db_password")
	if err != nil || string(got) != "from-auto" {
		t.Errorf("vault TF_VAR_db_password = (%q, %v), want (from-auto, nil)", got, err)
	}
	got, err = v.Get("capstone-tfvars/TF_VAR_api_token")
	if err != nil || string(got) != "tok-123" {
		t.Errorf("vault TF_VAR_api_token = (%q, %v), want (tok-123, nil)", got, err)
	}

	// The manifest maps the TF_VAR_ env names to those exact vault paths.
	entries, err := profile.LoadFile(result.ProfilePath)
	if err != nil {
		t.Fatalf("loading profile manifest: %v", err)
	}
	if entries["TF_VAR_db_password"] != "capstone-tfvars/TF_VAR_db_password" {
		t.Errorf("manifest TF_VAR_db_password = %q", entries["TF_VAR_db_password"])
	}

	mainContent := readFileString(t, mainPath)
	if strings.Contains(mainContent, "from-main") {
		t.Error("terraform.tfvars still contains the raw secret value")
	}
	if !strings.Contains(mainContent, "region = \"us-east-1\"") {
		t.Errorf("terraform.tfvars lost its non-secret line, got:\n%s", mainContent)
	}
	if !strings.Contains(mainContent, "cert_password = <<EOT") || !strings.Contains(mainContent, "pem") {
		t.Errorf("terraform.tfvars lost the skipped heredoc, got:\n%s", mainContent)
	}
	if !strings.Contains(mainContent, "jit run --profile capstone-tfvars -- terraform apply") {
		t.Errorf("terraform.tfvars missing the run-through-jit comment, got:\n%s", mainContent)
	}
	autoContent := readFileString(t, autoPath)
	if strings.Contains(autoContent, "from-auto") || strings.Contains(autoContent, "tok-123") {
		t.Errorf("prod.auto.tfvars still contains a raw secret value, got:\n%s", autoContent)
	}

	// Backups: encrypted vault copies of both originals, recoverable bytes.
	if len(result.Backups) != len(result.Files) {
		t.Fatalf("Backups = %v for Files = %v, want one per file", result.Backups, result.Files)
	}
	for i, f := range result.Files {
		orig := "region = \"us-east-1\"\ndb_password = \"from-main\"\ncert_password = <<EOT\npem\nEOT\n"
		if filepath.Base(f) == "prod.auto.tfvars" {
			orig = "db_password = \"from-auto\"\napi_token = \"tok-123\"\n"
		}
		backed, err := v.Get(result.Backups[i])
		if err != nil || string(backed) != orig {
			t.Errorf("backup of %s = (%q, %v), want the original bytes", f, backed, err)
		}
	}
	records, err := LoadBackupRecords(v.Root)
	if err != nil {
		t.Fatalf("LoadBackupRecords: %v", err)
	}
	if len(records) != 2 {
		t.Errorf("got %d backup records, want 2 (one per rewritten file)", len(records))
	}

	// Idempotency: nothing migratable is left, so discovery goes quiet.
	found, _, err := DiscoverTfvarsFiles(root)
	if err != nil {
		t.Fatalf("DiscoverTfvarsFiles after apply: %v", err)
	}
	if len(found) != 0 {
		t.Errorf("found = %v after apply, want none (already migrated)", found)
	}
}

func TestApplyTfvarsDirRerunReusesProfile(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "infra")
	path := filepath.Join(dir, "terraform.tfvars")
	writeFile(t, path, "db_password = \"one\"\n")

	v := newTestVault(t)
	first, err := ApplyTfvarsDir(v, dir, dir, []string{path})
	if err != nil {
		t.Fatalf("first ApplyTfvarsDir: %v", err)
	}

	// A later edit adds a new secret; the re-run must merge into the same
	// profile (claimNamespace's own-migration rule), not bump to "-2".
	appendToFile(t, path, "api_token = \"two\"\n")
	second, err := ApplyTfvarsDir(v, dir, dir, []string{path})
	if err != nil {
		t.Fatalf("second ApplyTfvarsDir: %v", err)
	}
	if second.ProfileName != first.ProfileName {
		t.Errorf("re-run claimed profile %q, want %q", second.ProfileName, first.ProfileName)
	}
	if second.NamespaceMovedFrom != "" {
		t.Errorf("NamespaceMovedFrom = %q, want empty on a re-run", second.NamespaceMovedFrom)
	}
	entries, err := profile.LoadFile(second.ProfilePath)
	if err != nil {
		t.Fatalf("loading profile manifest: %v", err)
	}
	if entries["TF_VAR_db_password"] == "" || entries["TF_VAR_api_token"] == "" {
		t.Errorf("manifest lost an entry across re-runs: %v", entries)
	}
	if got, err := v.Get("infra-tfvars/TF_VAR_db_password"); err != nil || string(got) != "one" {
		t.Errorf("first run's secret = (%q, %v), want (one, nil) after re-run", got, err)
	}
}

func TestApplyTfvarsDirNamespaceCollisionMoves(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "infra")
	path := filepath.Join(dir, "terraform.tfvars")
	writeFile(t, path, "db_password = \"mine\"\n")

	v := newTestVault(t)
	// Another project's migration already owns this vault path.
	if err := v.Set("infra-tfvars/TF_VAR_db_password", []byte("someone-else's")); err != nil {
		t.Fatalf("seeding conflicting secret: %v", err)
	}

	result, err := ApplyTfvarsDir(v, dir, dir, []string{path})
	if err != nil {
		t.Fatalf("ApplyTfvarsDir: %v", err)
	}
	if result.ProfileName != "infra-tfvars-2" {
		t.Errorf("ProfileName = %q, want %q (collision bump)", result.ProfileName, "infra-tfvars-2")
	}
	if result.NamespaceMovedFrom != "infra-tfvars" {
		t.Errorf("NamespaceMovedFrom = %q, want %q", result.NamespaceMovedFrom, "infra-tfvars")
	}
	if got, err := v.Get("infra-tfvars/TF_VAR_db_password"); err != nil || string(got) != "someone-else's" {
		t.Errorf("the other migration's secret = (%q, %v), must be untouched", got, err)
	}
}

// TestTfvarsProfileServesTFVarEnv closes the loop the migration promises:
// the profile ApplyTfvarsDir writes must resolve through the exact same
// inject path `jit run`/`jit export` use, yielding the TF_VAR_ variables
// terraform reads. This is the whole serving contract, verified without a
// real keychain-backed vault.
func TestTfvarsProfileServesTFVarEnv(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "svc")
	path := filepath.Join(dir, "terraform.tfvars")
	writeFile(t, path, "db_password = \"hunter2\"\nregion = \"eu-west-1\"\n")

	v := newTestVault(t)
	result, err := ApplyTfvarsDir(v, dir, dir, []string{path})
	if err != nil {
		t.Fatalf("ApplyTfvarsDir: %v", err)
	}

	p, err := profile.LoadFile(result.ProfilePath)
	if err != nil {
		t.Fatalf("loading profile: %v", err)
	}
	values, err := inject.Resolve(v, p)
	if err != nil {
		t.Fatalf("inject.Resolve: %v", err)
	}
	env := inject.MergeEnv([]string{"PATH=/usr/bin"}, values)
	found := false
	for _, kv := range env {
		if kv == "TF_VAR_db_password=hunter2" {
			found = true
		}
	}
	if !found {
		t.Errorf("merged env = %v, want it to carry TF_VAR_db_password=hunter2", env)
	}
}

func TestSortTfvarsByPrecedence(t *testing.T) {
	got := sortTfvarsByPrecedence([]string{
		"/x/b.auto.tfvars", "/x/terraform.tfvars", "/x/a.auto.tfvars",
	})
	want := []string{"/x/terraform.tfvars", "/x/a.auto.tfvars", "/x/b.auto.tfvars"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestDeriveTfvarsProfileName(t *testing.T) {
	if got := deriveTfvarsProfileName("/proj", "/proj/infra/prod"); got != "infra-prod-tfvars" {
		t.Errorf("nested dir = %q, want infra-prod-tfvars", got)
	}
	if got := deriveTfvarsProfileName("/proj", "/proj"); got != "proj-tfvars" {
		t.Errorf("root dir = %q, want proj-tfvars", got)
	}
}

func readFileString(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path) // #nosec G304 -- test-controlled path
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return string(data)
}

func appendToFile(t *testing.T, path, content string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600) // #nosec G304 -- test-controlled path
	if err != nil {
		t.Fatalf("opening %s: %v", path, err)
	}
	defer f.Close()
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("appending to %s: %v", path, err)
	}
}
