// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

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
