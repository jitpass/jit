// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func parseFixtureEnv(t *testing.T, content string) (map[string]string, []int) {
	t.Helper()
	path := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}
	values, _, unparsed, err := parseEnvFile(path)
	if err != nil {
		t.Fatalf("parseEnvFile: %v", err)
	}
	return values, unparsed
}

// TestParseEnvFileExportPrefix: `export KEY=value` is real, common dotenv
// syntax (python-dotenv and godotenv both accept it; it lets the same file
// be `source`d by a shell). The old parser silently dropped these lines —
// the variable vanished from the vault, the profile, and the mount, on a
// command whose next step destroys the original file.
func TestParseEnvFileExportPrefix(t *testing.T) {
	values, unparsed := parseFixtureEnv(t, "export API_KEY=sk_live_123\nDB_URL=postgres://x\n")
	if len(unparsed) != 0 {
		t.Fatalf("unparsed = %v, want none", unparsed)
	}
	if values["API_KEY"] != "sk_live_123" {
		t.Errorf("API_KEY = %q, want the export-prefixed value, not a silently dropped line", values["API_KEY"])
	}
	if values["DB_URL"] != "postgres://x" {
		t.Errorf("DB_URL = %q, want unaffected plain line", values["DB_URL"])
	}
}

// TestParseEnvFileExportLikeKeyIsNotStripped: only `export ` followed by a
// key strips — a variable legitimately NAMED with an export prefix
// (exportFOO=1) must keep its own name.
func TestParseEnvFileExportLikeKeyIsNotStripped(t *testing.T) {
	values, unparsed := parseFixtureEnv(t, "exportFOO=1\n")
	if len(unparsed) != 0 {
		t.Fatalf("unparsed = %v, want none", unparsed)
	}
	if values["exportFOO"] != "1" {
		t.Errorf("exportFOO = %q, want its own literal name preserved", values["exportFOO"])
	}
}

// TestParseEnvFileMultilineQuoted: quoted values spanning several lines are
// real dotenv usage — PEM keys and certificates in .env files are the
// concrete case. The old parser stored the first line as a corrupt
// fragment (opening quote included) and silently discarded the rest.
func TestParseEnvFileMultilineQuoted(t *testing.T) {
	pem := "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg\n-----END PRIVATE KEY-----"
	values, unparsed := parseFixtureEnv(t, "SIGNING_KEY=\""+pem+"\"\nAFTER=1\n")
	if len(unparsed) != 0 {
		t.Fatalf("unparsed = %v, want none", unparsed)
	}
	if values["SIGNING_KEY"] != pem {
		t.Errorf("SIGNING_KEY = %q, want the full multiline value preserved", values["SIGNING_KEY"])
	}
	if values["AFTER"] != "1" {
		t.Errorf("AFTER = %q, the line following a multiline value must still parse", values["AFTER"])
	}
}

func TestParseEnvFileDoubleQuoteEscapes(t *testing.T) {
	values, unparsed := parseFixtureEnv(t, `KEY="a\"b\\c\nd"`+"\n")
	if len(unparsed) != 0 {
		t.Fatalf("unparsed = %v, want none", unparsed)
	}
	if want := "a\"b\\c\nd"; values["KEY"] != want {
		t.Errorf("KEY = %q, want %q (escapes expanded)", values["KEY"], want)
	}
}

func TestParseEnvFileSingleQuoteIsLiteral(t *testing.T) {
	values, unparsed := parseFixtureEnv(t, `KEY='a\nb'`+"\n")
	if len(unparsed) != 0 {
		t.Fatalf("unparsed = %v, want none", unparsed)
	}
	if want := `a\nb`; values["KEY"] != want {
		t.Errorf("KEY = %q, want %q (single quotes never expand escapes)", values["KEY"], want)
	}
}

func TestParseEnvFileBareValueKeptVerbatim(t *testing.T) {
	values, unparsed := parseFixtureEnv(t, "KEY=plain#notacomment\n")
	if len(unparsed) != 0 {
		t.Fatalf("unparsed = %v, want none", unparsed)
	}
	if values["KEY"] != "plain#notacomment" {
		t.Errorf("KEY = %q, want bare value kept verbatim, matching the old parser exactly", values["KEY"])
	}
}

func TestParseEnvFileReportsUnparsedLineNumbers(t *testing.T) {
	content := "GOOD=1\n" + // line 1
		"this line is not a KEY=value\n" + // line 2, unparsed
		"# comment\n" + // line 3
		"ALSO_GOOD=2\n" + // line 4
		"BROKEN=\"never closed\n" // line 5, unterminated quote
	values, unparsed := parseFixtureEnv(t, content)
	if values["GOOD"] != "1" || values["ALSO_GOOD"] != "2" {
		t.Errorf("values = %v, want the parseable lines still returned", values)
	}
	if len(unparsed) != 2 || unparsed[0] != 2 || unparsed[1] != 5 {
		t.Errorf("unparsed = %v, want [2 5], the exact 1-based lines a human needs to go fix", unparsed)
	}
}

// TestApplyEnvFileUnparsedLineAborts is the fail-loud half: ApplyEnvFile
// must refuse to migrate a file containing anything it couldn't parse —
// BEFORE touching the vault, the profile, or the file itself — rather
// than silently dropping the line and destroying the original.
func TestApplyEnvFileUnparsedLineAborts(t *testing.T) {
	v := newTestVault(t)
	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	original := "GOOD=1\nsource other.env\n"
	if err := os.WriteFile(envPath, []byte(original), 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}

	_, err := ApplyEnvFile(v, dir, envPath)
	if err == nil {
		t.Fatal("ApplyEnvFile succeeded on a file with an unparseable line, silent data loss on a destructive path")
	}
	if !strings.Contains(err.Error(), "line 2") {
		t.Errorf("error %q should name the offending line number", err)
	}
	if strings.Contains(err.Error(), "source other.env") {
		t.Errorf("error %q leaks the unparsed line's content, it may hold a real secret and this lands in scrollback", err)
	}

	data, readErr := os.ReadFile(envPath)
	if readErr != nil {
		t.Fatalf("re-reading fixture: %v", readErr)
	}
	if string(data) != original {
		t.Error("the .env file was modified despite the abort, refusing must mean touching nothing")
	}
	secrets, listErr := v.List()
	if listErr != nil {
		t.Fatalf("vault list: %v", listErr)
	}
	if len(secrets) != 0 {
		t.Errorf("vault contains %v after an aborted migration, want nothing written", secrets)
	}
}
