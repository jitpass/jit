// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/mount"
	"github.com/jitpass/jit/internal/profile"
	"github.com/jitpass/jit/internal/vault"
)

// realJWT is the bare token from the original bug: a JWT dropped in a plainly
// named file that matches no structured migrate category.
const realJWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
	"eyJlbWFpbCI6InVzZXJAZXhhbXBsZS5jb20iLCJpZCI6MX0." +
	"i-Bx9F2fjO5nvvo_hlUFY6bvnAOeTs68BiTBa-1zfoE"

func TestClassifyLooseSecretFile(t *testing.T) {
	dir := t.TempDir()

	cases := []struct {
		name     string
		content  string
		wantPure bool
		wantN    int
	}{
		{"bare token", realJWT, true, 1},
		{"bare token trailing newline", realJWT + "\n", true, 1},
		{"blank lines around", "\n\n" + realJWT + "\n\n", true, 1},
		{"two tokens each line", realJWT + "\nghp_1234567890123456789012345678901234ab\n", true, 2},
		{"labeled token is embedded", "token=" + realJWT + "\n", false, 1},
		{"token plus prose is embedded", realJWT + "\nsome notes here\n", false, 1},
		{"no secret", "just some ordinary notes, nothing here\n", false, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(dir, strings.ReplaceAll(tc.name, " ", "_")+".txt")
			writeFile(t, p, tc.content)
			tokens, pure, err := ClassifyLooseSecretFile(p)
			if err != nil {
				t.Fatalf("ClassifyLooseSecretFile: %v", err)
			}
			if pure != tc.wantPure {
				t.Errorf("pure = %v, want %v", pure, tc.wantPure)
			}
			if len(tokens) != tc.wantN {
				t.Errorf("tokens = %d, want %d", len(tokens), tc.wantN)
			}
		})
	}
}

func TestApplyLooseSecretFileEndToEnd(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "token.txt")
	writeFile(t, path, realJWT+"\n")

	v := newTestVault(t)
	result, err := ApplyLooseSecretFile(v, root, path)
	if err != nil {
		t.Fatalf("ApplyLooseSecretFile: %v", err)
	}

	if result.ProfileName != "token" {
		t.Errorf("ProfileName = %q, want %q (the file's basename)", result.ProfileName, "token")
	}
	if len(result.Variables) != 1 {
		t.Fatalf("Variables = %v, want 1", result.Variables)
	}

	// The token is retrievable from the vault under the profile.
	p, err := profile.Load(root, result.ProfileName)
	if err != nil {
		t.Fatalf("profile.Load: %v", err)
	}
	secretPath, ok := p[result.Variables[0]]
	if !ok {
		t.Fatalf("profile missing %q", result.Variables[0])
	}
	got, err := v.Get(secretPath)
	if err != nil {
		t.Fatalf("v.Get(%q): %v", secretPath, err)
	}
	if string(got) != realJWT {
		t.Errorf("vault value = %q, want the JWT", got)
	}

	// The value was stamped with the loose-file provenance class and the file
	// path as its origin.
	secInfo, err := v.Info(secretPath)
	if err != nil {
		t.Fatalf("v.Info: %v", err)
	}
	if secInfo.Class != vault.ClassLooseFile {
		t.Errorf("class = %q, want %q", secInfo.Class, vault.ClassLooseFile)
	}
	if secInfo.Origin != path {
		t.Errorf("origin = %q, want %q", secInfo.Origin, path)
	}

	// The file on disk is now a git-safe pointer, not the plaintext token, and
	// not a FIFO (vault-and-neutralize, no live mount).
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat(%q): %v", path, err)
	}
	if info.Mode()&os.ModeNamedPipe != 0 {
		t.Error("file should be a regular pointer file, not a FIFO")
	}
	content, err := os.ReadFile(path) // #nosec G304 -- test-controlled path under t.TempDir()
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if strings.Contains(string(content), realJWT) {
		t.Fatal("the plaintext token must be gone from the file")
	}
	if !LooksLikePointerContent(path) {
		t.Errorf("file should be a jit pointer file, got:\n%s", content)
	}

	// The original is recoverable from the vault backup.
	backup, err := v.Get(result.BackupPath)
	if err != nil {
		t.Fatalf("v.Get(backup %q): %v", result.BackupPath, err)
	}
	if string(backup) != realJWT+"\n" {
		t.Errorf("backup = %q, want the original file content", backup)
	}
}

func TestBuildLooseTemplate(t *testing.T) {
	dir := t.TempDir()

	t.Run("pure single token", func(t *testing.T) {
		p := filepath.Join(dir, "pure.txt")
		writeFile(t, p, realJWT+"\n")
		tokens, _, err := ClassifyLooseSecretFile(p)
		if err != nil {
			t.Fatal(err)
		}
		lines, _ := scanFileLines(p)
		names, _ := nameLooseTokens(tokens)
		got := string(buildLooseTemplate(lines, tokens, names))
		if strings.Contains(got, realJWT) {
			t.Errorf("template still contains the raw token: %q", got)
		}
		if !strings.Contains(got, "${"+names[0]+"}") {
			t.Errorf("template = %q, want a ${%s} placeholder", got, names[0])
		}
	})

	t.Run("embedded keeps surrounding text", func(t *testing.T) {
		p := filepath.Join(dir, "embedded.txt")
		writeFile(t, p, "key is sk-ant-api03-abcdefghijklmnopqrstuvwx here\nport=8080\n")
		tokens, _, err := ClassifyLooseSecretFile(p)
		if err != nil {
			t.Fatal(err)
		}
		lines, _ := scanFileLines(p)
		names, _ := nameLooseTokens(tokens)
		got := string(buildLooseTemplate(lines, tokens, names))
		if !strings.HasPrefix(got, "key is ${") || !strings.Contains(got, "} here") {
			t.Errorf("template did not preserve surrounding text: %q", got)
		}
		if !strings.Contains(got, "port=8080") {
			t.Errorf("template dropped the non-secret line: %q", got)
		}
		if strings.Contains(got, "sk-ant-api03") {
			t.Errorf("template still contains the raw token: %q", got)
		}
	})
}

func TestApplyLooseSecretFileMount(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "token.txt")
	writeFile(t, path, realJWT+"\n")

	v := newTestVault(t)
	result, err := ApplyLooseSecretFileMount(v, root, path)
	if err != nil {
		t.Fatalf("ApplyLooseSecretFileMount: %v", err)
	}
	if !result.Mounted {
		t.Error("Mounted = false, want true")
	}

	// The file is now a live FIFO, not a regular pointer file.
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat: %v", err)
	}
	if info.Mode()&os.ModeNamedPipe == 0 {
		t.Errorf("file mode = %v, want a named pipe (FIFO)", info.Mode())
	}

	// The template renders the value back, and doesn't hold the raw token.
	tmpl, err := os.ReadFile(result.TemplatePath) // #nosec G304 -- test path under t.TempDir()
	if err != nil {
		t.Fatalf("reading template: %v", err)
	}
	if strings.Contains(string(tmpl), realJWT) {
		t.Error("template must not contain the raw token")
	}
	if !strings.Contains(string(tmpl), "${"+result.Variables[0]+"}") {
		t.Errorf("template = %q, want a placeholder", tmpl)
	}

	// The value is retrievable from the vault.
	p, err := profile.Load(root, result.ProfileName)
	if err != nil {
		t.Fatalf("profile.Load: %v", err)
	}
	got, err := v.Get(p[result.Variables[0]])
	if err != nil {
		t.Fatalf("v.Get: %v", err)
	}
	if string(got) != realJWT {
		t.Errorf("vault value = %q, want the JWT", got)
	}
}

// TestApplyLooseSecretFileMultipleTokens: two JWTs get distinct, suffixed
// names so neither collides in the vault.
func TestApplyLooseSecretFileMultipleTokens(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "tokens.txt")
	writeFile(t, path, realJWT+"\n"+realJWT+"\n")

	v := newTestVault(t)
	result, err := ApplyLooseSecretFile(v, root, path)
	if err != nil {
		t.Fatalf("ApplyLooseSecretFile: %v", err)
	}
	if len(result.Variables) != 2 {
		t.Fatalf("Variables = %v, want 2 distinct names", result.Variables)
	}
	if result.Variables[0] == result.Variables[1] {
		t.Errorf("variable names collide: %v", result.Variables)
	}
}

// TestApplyLooseSecretFileMountTemplatesSecretShapedAssignments is the
// regression test for a security-relevant bug found in review (2026-07-28).
//
// The mount template was built only from vendor-pattern matches, so a real
// credential with no recognizable prefix — most of them: CrowdStrike, Datadog,
// Heroku, every internal API — was written into the on-disk template VERBATIM.
// jit relocated an unprotected secret from a file the user knew about into its
// own profile directory, reported success, and `jit scan` does not look there.
// Strictly worse than leaving the file alone.
func TestApplyLooseSecretFileMountTemplatesSecretShapedAssignments(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, "secrets.toml")
	writeFile(t, path, `OPENAI_API_KEY = "sk-proj-Ab3xKq9ZmPq2LrTvWn5cUd8eFg1hJk0uf4"
db_password = "Tr0ub4dor3xKq9ZmPq2Lr"
account = "ACME-PROD"
port = 443
`)

	v := newTestVault(t)
	result, err := ApplyLooseSecretFileMount(v, home, path)
	if err != nil {
		t.Fatalf("ApplyLooseSecretFileMount: %v", err)
	}

	tmpl, err := os.ReadFile(result.TemplatePath) // #nosec G304 -- test-controlled path
	if err != nil {
		t.Fatalf("reading template: %v", err)
	}
	content := string(tmpl)

	// The whole point: no secret survives into the template.
	for _, secret := range []string{"Tr0ub4dor3xKq9ZmPq2Lr", "sk-proj-Ab3xKq9ZmPq2LrTvWn5cUd8eFg1hJk0uf4"} {
		if strings.Contains(content, secret) {
			t.Errorf("template still contains the plaintext secret %q:\n%s", secret, content)
		}
	}
	// Quotes sit OUTSIDE the replaced span, so formats whose parser treats
	// them as part of the value (.pypirc) round-trip correctly.
	if !strings.Contains(content, `db_password = "${DB_PASSWORD}"`) {
		t.Errorf("db_password not templated with its quotes preserved:\n%s", content)
	}
	// Settings are not credentials and must pass through untouched — this is
	// what keeps the migrator from vaulting half a config file.
	for _, keep := range []string{`account = "ACME-PROD"`, "port = 443"} {
		if !strings.Contains(content, keep) {
			t.Errorf("non-secret line %q was rewritten:\n%s", keep, content)
		}
	}

	var sawDBPassword bool
	for _, name := range result.Variables {
		if name == "DB_PASSWORD" {
			sawDBPassword = true
		}
	}
	if !sawDBPassword {
		t.Errorf("Variables = %v, want DB_PASSWORD among them", result.Variables)
	}
}

// TestLooseSecretFileMountRoundTripsAndUndoes covers the two guarantees a
// mounted file has to make, for the assignment-templating path specifically:
// what the mount serves is byte-identical to what was there, and the migration
// is reversible. Both matter more since secretAssignmentTokens landed - it
// rewrites spans the vendor patterns never touched, so a span-arithmetic slip
// would corrupt a working config rather than merely miss a secret.
func TestLooseSecretFileMountRoundTripsAndUndoes(t *testing.T) {
	const original = `# a config that mixes secrets with settings
OPENAI_API_KEY = "sk-proj-Ab3xKq9ZmPq2LrTvWn5cUd8eFg1hJk0uf4"
db_password="Tr0ub4dor3xKq9ZmPq2Lr"
account = ACME-PROD
port = 443
timeout_seconds = 30
`
	home := t.TempDir()
	path := filepath.Join(home, "app.conf")
	writeFile(t, path, original)

	v := newTestVault(t)
	result, err := ApplyLooseSecretFileMount(v, home, path)
	if err != nil {
		t.Fatalf("ApplyLooseSecretFileMount: %v", err)
	}

	tmpl, err := os.ReadFile(result.TemplatePath) // #nosec G304 -- test-controlled path
	if err != nil {
		t.Fatalf("reading template: %v", err)
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

	// Undo: the FIFO is retired and the original bytes come back.
	if err := RestoreFromBackup(v, BackupRecord{OriginalPath: path, VaultPath: result.BackupPath}); err != nil {
		t.Fatalf("RestoreFromBackup: %v", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat after restore: %v", err)
	}
	if !info.Mode().IsRegular() {
		t.Errorf("after undo the path is %v, want a regular file", info.Mode())
	}
	restored, err := os.ReadFile(path) // #nosec G304 -- test-controlled path
	if err != nil {
		t.Fatalf("reading restored file: %v", err)
	}
	if string(restored) != original {
		t.Errorf("restored bytes differ.\ngot:  %q\nwant: %q", restored, original)
	}
}

// TestSecretAssignmentTokensStripInlineComments guards what gets VAULTED, not
// what gets served: the mount round-trips byte-identically either way (span
// substitution), but `jit run`/`jit export`/`jit vault get` deliver the vault
// entry alone — and before this, `api_password = hunter2abc # rotate
// quarterly` vaulted "hunter2abc # rotate quarterly", a credential no server
// accepts, failing auth in a way nothing traces back to the migration.
// Dotenv, INI and TOML parsers all cut an unquoted value at a
// whitespace-preceded "#"/";" — jit must agree with them.
func TestSecretAssignmentTokensStripInlineComments(t *testing.T) {
	cases := []struct {
		name string
		line string
		want string
	}{
		{"unquoted with # comment", "api_password = Tr0ub4dor3xKq9ZmPq2Lr # rotate quarterly", "Tr0ub4dor3xKq9ZmPq2Lr"},
		{"unquoted with ; comment", "api_password = Tr0ub4dor3xKq9ZmPq2Lr\t; legacy", "Tr0ub4dor3xKq9ZmPq2Lr"},
		{"quoted with trailing comment", `api_password = "Tr0ub4dor3xKq9ZmPq2Lr" # note`, "Tr0ub4dor3xKq9ZmPq2Lr"},
		// No whitespace before '#' means it is part of the value — every
		// parser that supports inline comments requires the separator.
		{"hash inside value", "api_password = Tr0ub4dor3#xKq9ZmPq2Lr", "Tr0ub4dor3#xKq9ZmPq2Lr"},
		{"hash inside quotes", `api_password = "Tr0ub4dor3 #xKq9ZmPq2Lr"`, "Tr0ub4dor3 #xKq9ZmPq2Lr"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tokens := secretAssignmentTokens([]string{c.line}, nil)
			if len(tokens) != 1 {
				t.Fatalf("got %d tokens from %q, want 1: %+v", len(tokens), c.line, tokens)
			}
			if tokens[0].Value != c.want {
				t.Errorf("value = %q, want %q", tokens[0].Value, c.want)
			}
		})
	}
}
