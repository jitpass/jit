// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/mount"
)

// streamlitFixture is the same shape audit's TestClassifyStreamlitSecrets
// pins as a real-world blind spot (2026-07-28): a vendor token under its own
// name, a secret-shaped top-level key, and a sectioned password among
// settings. The file audit's test flags is exactly the file this package
// must migrate — the D5 promise in fixture form.
const streamlitFixture = `# Streamlit secrets
OPENAI_API_KEY = "sk-proj-Ab3xKq9ZmPq2LrTvWn5cUd8eFg1hJk0uf4"
db_password = "Tr0ub4dor3xKq9ZmPq2Lr"

[connections.snowflake]
account = "ACME-PROD"
user = "analyst"
port = 443
password = "Xk92QmPl4TzWhuCmu2qcwnu9PnWfMKNA"
`

func TestDiscoverStreamlitSecretsFindsProjectAndGlobal(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "proj", streamlitDirName, streamlitFileName)
	writeFile(t, project, streamlitFixture)
	writeFile(t, StreamlitGlobalPath(home), streamlitFixture)
	// The two-part gate: a secrets.toml OUTSIDE .streamlit (a Rust config, a
	// Helm values file) and a different file INSIDE .streamlit are both not
	// Streamlit secrets — same rule as audit's classifyStreamlitSecrets.
	writeFile(t, filepath.Join(home, "proj", streamlitFileName), streamlitFixture)
	writeFile(t, filepath.Join(home, "proj", streamlitDirName, "config.toml"), `password = "Xk92QmPl4TzWhuCmu2qc"`)

	found, err := DiscoverStreamlitSecrets(home)
	if err != nil {
		t.Fatalf("DiscoverStreamlitSecrets: %v", err)
	}
	want := []string{StreamlitGlobalPath(home), project}
	if len(found) != 2 || found[0] != want[0] || found[1] != want[1] {
		t.Errorf("found = %v, want %v", found, want)
	}
}

func TestDiscoverStreamlitSecretsQuietCases(t *testing.T) {
	t.Run("no file", func(t *testing.T) {
		found, err := DiscoverStreamlitSecrets(t.TempDir())
		if err != nil || len(found) != 0 {
			t.Errorf("got (%v, %v), want (nil, nil)", found, err)
		}
	})

	t.Run("settings only", func(t *testing.T) {
		root := t.TempDir()
		writeFile(t, filepath.Join(root, streamlitDirName, streamlitFileName), "[connections.snowflake]\naccount = \"ACME-PROD\"\nport = 443\n")
		found, err := DiscoverStreamlitSecrets(root)
		if err != nil || len(found) != 0 {
			t.Errorf("got (%v, %v), want (nil, nil) — settings alone are nothing to move", found, err)
		}
	})
}

// TestFindSecretStreamlitLines pins which lines count and how they're named:
// the vendor token migrates on its value alone, the secret-shaped keys on
// their names, and the section folds into the variable name so two tables'
// identically named keys keep distinct vault paths (the collision audit's
// scanner doc explicitly leaves to a migrator).
func TestFindSecretStreamlitLines(t *testing.T) {
	matches := findSecretStreamlitLines(strings.Split(streamlitFixture, "\n"))
	if len(matches) != 3 {
		t.Fatalf("got %d matches, want 3: %+v", len(matches), matches)
	}
	byVar := map[string]string{}
	for _, m := range matches {
		byVar[m.VarName] = m.Value
	}
	if byVar["OPENAI_API_KEY"] != "sk-proj-Ab3xKq9ZmPq2LrTvWn5cUd8eFg1hJk0uf4" {
		t.Errorf("vendor-valued key missing or wrong: %v", byVar)
	}
	if byVar["DB_PASSWORD"] != "Tr0ub4dor3xKq9ZmPq2Lr" {
		t.Errorf("secret-shaped top-level key missing or wrong: %v", byVar)
	}
	if byVar["CONNECTIONS_SNOWFLAKE_PASSWORD"] != "Xk92QmPl4TzWhuCmu2qcwnu9PnWfMKNA" {
		t.Errorf("sectioned password must fold the table into its name: %v", byVar)
	}
}

// TestFindSecretStreamlitLinesSkipsUnrewritableShapes pins this side's
// stricter shape rule: only a single-line quoted string with no escapes is
// rewritable provably right. Everything else stays in place (and keeps its
// scan finding) rather than risking a corrupt template.
func TestFindSecretStreamlitLinesSkipsUnrewritableShapes(t *testing.T) {
	lines := strings.Split(`password = "has a \" escape Xk92QmPl4Tz"
api_key = "trailing comment Xk92QmPl4Tz" # prod
token = 12345
secret_key = """
password = "Xk92QmPl4TzWhuCmu2qcInsideMultiline"
"""
db_password = 'ok-single-quoted-Xk92QmPl4Tz'
`, "\n")

	matches := findSecretStreamlitLines(lines)
	if len(matches) != 1 {
		t.Fatalf("got %d matches, want only the clean single-quoted line: %+v", len(matches), matches)
	}
	m := matches[0]
	if m.VarName != "DB_PASSWORD" || m.Value != "ok-single-quoted-Xk92QmPl4Tz" || m.Quote != '\'' {
		t.Errorf("match = %+v, want DB_PASSWORD / the single-quoted value / quote '", m)
	}
}

// TestStreamlitVarNameCollisions mirrors pypirc's guard: distinct
// section/key pairs that sanitize to one name must be split apart, or the
// second silently overwrites the first in the vault and the mount serves
// table B's password for table A.
func TestStreamlitVarNameCollisions(t *testing.T) {
	lines := strings.Split(`[my-db]
password = "FirstDBPasswordQmPl4TzWhu"

[my_db]
password = "SecondDBPasswordu2qcwnu9P"
`, "\n")
	matches := findSecretStreamlitLines(lines)
	if len(matches) != 2 {
		t.Fatalf("got %d matches, want 2: %+v", len(matches), matches)
	}
	if matches[0].VarName == matches[1].VarName {
		t.Errorf("two tables must not collapse to one variable name, both got %q", matches[0].VarName)
	}
}

func TestApplyStreamlitSecretsMovesSecretsAndPreservesSettings(t *testing.T) {
	root := t.TempDir()
	project := filepath.Join(root, "acme-app")
	path := filepath.Join(project, streamlitDirName, streamlitFileName)
	writeFile(t, path, streamlitFixture)

	v := newTestVault(t)
	result, err := ApplyStreamlitSecrets(v, project, path, false)
	if err != nil {
		t.Fatalf("ApplyStreamlitSecrets: %v", err)
	}
	if result.ProfileName != "streamlit-acme-app" {
		t.Errorf("ProfileName = %q, want streamlit-acme-app", result.ProfileName)
	}
	if len(result.Variables) != 3 {
		t.Fatalf("Variables = %v, want 3", result.Variables)
	}

	got, err := v.Get(result.ProfileName + "/CONNECTIONS_SNOWFLAKE_PASSWORD")
	if err != nil || string(got) != "Xk92QmPl4TzWhuCmu2qcwnu9PnWfMKNA" {
		t.Errorf("vault secret = (%q, %v), want the snowflake password", got, err)
	}

	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat: %v", err)
	}
	if info.Mode()&os.ModeNamedPipe == 0 {
		t.Error("expected secrets.toml to be a FIFO after migration — st.secrets reads the file directly, so it must stay live")
	}

	tmpl, err := os.ReadFile(result.TemplatePath) // #nosec G304 -- test-controlled path
	if err != nil {
		t.Fatalf("reading template: %v", err)
	}
	content := string(tmpl)
	for _, secret := range []string{"sk-proj-", "Tr0ub4dor3xKq9ZmPq2Lr", "Xk92QmPl4TzWhuCmu2qcwnu9PnWfMKNA"} {
		if strings.Contains(content, secret) {
			t.Errorf("template must not contain the raw secret %q", secret)
		}
	}
	// Placeholders sit INSIDE the line's own quotes, so the served file is
	// valid TOML and byte-identical to the original.
	if !strings.Contains(content, `password = "${CONNECTIONS_SNOWFLAKE_PASSWORD}"`) {
		t.Errorf("template missing the quoted sectioned placeholder, got:\n%s", content)
	}
	for _, keep := range []string{"[connections.snowflake]", `account = "ACME-PROD"`, `user = "analyst"`, "port = 443", "# Streamlit secrets"} {
		if !strings.Contains(content, keep) {
			t.Errorf("template lost non-secret line %q, got:\n%s", keep, content)
		}
	}

	backup, err := v.Get(result.BackupPath)
	if err != nil {
		t.Fatalf("reading backup from vault: %v", err)
	}
	if !strings.Contains(string(backup), "Xk92QmPl4TzWhuCmu2qcwnu9PnWfMKNA") {
		t.Error("backup should contain the original plaintext content")
	}
}

func TestApplyStreamlitSecretsGlobalProfileName(t *testing.T) {
	home := t.TempDir()
	path := StreamlitGlobalPath(home)
	writeFile(t, path, `openai_key = "sk-proj-Ab3xKq9ZmPq2LrTvWn5cUd8eFg1hJk0uf4"`)

	v := newTestVault(t)
	result, err := ApplyStreamlitSecrets(v, home, path, true)
	if err != nil {
		t.Fatalf("ApplyStreamlitSecrets: %v", err)
	}
	if result.ProfileName != "streamlit" {
		t.Errorf("ProfileName = %q, want streamlit for the global file", result.ProfileName)
	}
}

// TestApplyStreamlitSecretsRoundTripsLosslessly is the guarantee that matters
// most for a mounted credential file: what the mount serves must be
// byte-identical to what was there before. If it isn't, `streamlit run` reads
// a secrets file that looks correct and isn't — the hardest failure mode to
// diagnose.
func TestApplyStreamlitSecretsRoundTripsLosslessly(t *testing.T) {
	const original = `# Streamlit secrets
OPENAI_API_KEY = "sk-proj-Ab3xKq9ZmPq2LrTvWn5cUd8eFg1hJk0uf4"

[connections.snowflake]
account = "ACME-PROD"
port = 443
password='Xk92QmPl4TzWhuCmu2qcwnu9PnWfMKNA'

[notes]
motd = """
password = "not-a-real-one-just-prose"
"""
`
	root := t.TempDir()
	project := filepath.Join(root, "app")
	path := filepath.Join(project, streamlitDirName, streamlitFileName)
	writeFile(t, path, original)

	v := newTestVault(t)
	result, err := ApplyStreamlitSecrets(v, project, path, false)
	if err != nil {
		t.Fatalf("ApplyStreamlitSecrets: %v", err)
	}

	tmpl, err := os.ReadFile(result.TemplatePath) // #nosec G304 -- test-controlled path
	if err != nil {
		t.Fatalf("reading template: %v", err)
	}
	// The assignment-shaped line inside the multi-line string must survive
	// verbatim in the template — rewriting it would corrupt the string.
	if !strings.Contains(string(tmpl), `password = "not-a-real-one-just-prose"`) {
		t.Errorf("template must leave multi-line string content untouched, got:\n%s", tmpl)
	}

	values := map[string]string{}
	for _, name := range result.Variables {
		got, err := v.Get(result.ProfileName + "/" + name)
		if err != nil {
			t.Fatalf("vault get %s: %v", name, err)
		}
		values[name] = string(got)
	}
	if rendered := string(mount.FormatTemplate(tmpl, values)); rendered != original {
		t.Errorf("round-trip is lossy.\nrendered: %q\noriginal: %q", rendered, original)
	}
}

// TestApplyStreamlitSecretsIsUndoable pins that a migration can be reversed:
// the FIFO is replaced by a regular file holding the original bytes.
func TestApplyStreamlitSecretsIsUndoable(t *testing.T) {
	root := t.TempDir()
	project := filepath.Join(root, "app")
	path := filepath.Join(project, streamlitDirName, streamlitFileName)
	writeFile(t, path, streamlitFixture)

	v := newTestVault(t)
	result, err := ApplyStreamlitSecrets(v, project, path, false)
	if err != nil {
		t.Fatalf("ApplyStreamlitSecrets: %v", err)
	}
	if info, err := os.Lstat(path); err != nil || info.Mode()&os.ModeNamedPipe == 0 {
		t.Fatalf("expected a FIFO after migrate, got %v (err=%v)", info, err)
	}

	if err := RestoreFromBackup(v, BackupRecord{OriginalPath: path, VaultPath: result.BackupPath}); err != nil {
		t.Fatalf("RestoreFromBackup: %v", err)
	}
	restored, err := os.ReadFile(path) // #nosec G304 -- test-controlled path
	if err != nil {
		t.Fatalf("reading restored file: %v", err)
	}
	if string(restored) != streamlitFixture {
		t.Errorf("restored bytes differ.\ngot:  %q\nwant: %q", restored, streamlitFixture)
	}
}

// TestApplyStreamlitSecretsRefusesLiteralPlaceholder ports ApplyNetrc's
// guard: mount.FormatTemplate is position-blind, so a file already
// containing the literal ${DB_PASSWORD} would get the real value substituted
// into that spot at serve time, and the served bytes would diverge from the
// original. Refusal is the only safe answer.
func TestApplyStreamlitSecretsRefusesLiteralPlaceholder(t *testing.T) {
	root := t.TempDir()
	project := filepath.Join(root, "app")
	path := filepath.Join(project, streamlitDirName, streamlitFileName)
	writeFile(t, path, `# db_password = ${DB_PASSWORD}
db_password = "Tr0ub4dor3xKq9ZmPq2Lr"
`)

	v := newTestVault(t)
	_, err := ApplyStreamlitSecrets(v, project, path, false)
	if err == nil {
		t.Fatal("ApplyStreamlitSecrets should refuse a file already containing its own placeholder")
	}
	if !strings.Contains(err.Error(), "${DB_PASSWORD}") {
		t.Errorf("error should name the offending placeholder, got %v", err)
	}
	if info, statErr := os.Lstat(path); statErr != nil || !info.Mode().IsRegular() {
		t.Errorf("refusal must leave the original file untouched, got %v (err=%v)", info, statErr)
	}
}
