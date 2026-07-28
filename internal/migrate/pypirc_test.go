// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"os"
	"strings"
	"testing"
)

func TestDiscoverPypircFindsCredentials(t *testing.T) {
	home := t.TempDir()
	writeFile(t, PypircPath(home), `[distutils]
index-servers = pypi

[pypi]
username = __token__
password = pypi-AgEIcHlwaS5vcmcCJDk0YTUxZmE0
`)

	found, err := DiscoverPypirc(home)
	if err != nil {
		t.Fatalf("DiscoverPypirc: %v", err)
	}
	if len(found) != 1 || found[0] != PypircPath(home) {
		t.Errorf("found = %v, want [%s]", found, PypircPath(home))
	}
}

// TestDiscoverPypircQuietCases covers the three ways there is nothing to do:
// no file, a file with only non-secret content, and a file holding an empty
// password (a scaffolded-but-unused section).
func TestDiscoverPypircQuietCases(t *testing.T) {
	t.Run("no file", func(t *testing.T) {
		found, err := DiscoverPypirc(t.TempDir())
		if err != nil || len(found) != 0 {
			t.Errorf("got (%v, %v), want (nil, nil)", found, err)
		}
	})

	t.Run("no credentials", func(t *testing.T) {
		home := t.TempDir()
		writeFile(t, PypircPath(home), "[distutils]\nindex-servers = pypi\n\n[pypi]\nusername = __token__\n")
		found, err := DiscoverPypirc(home)
		if err != nil || len(found) != 0 {
			t.Errorf("got (%v, %v), want (nil, nil) — username alone is not a credential", found, err)
		}
	})

	t.Run("empty password", func(t *testing.T) {
		home := t.TempDir()
		writeFile(t, PypircPath(home), "[pypi]\nusername = __token__\npassword =\n")
		found, err := DiscoverPypirc(home)
		if err != nil || len(found) != 0 {
			t.Errorf("got (%v, %v), want (nil, nil) — an empty password is nothing to move", found, err)
		}
	})
}

// TestFindSecretPypircLines pins which lines count. [distutils] holds the
// index-servers list and never a credential; username is "__token__" for a
// token login and is not the secret either way.
func TestFindSecretPypircLines(t *testing.T) {
	lines := strings.Split(`[distutils]
index-servers =
    pypi
    internal

# a comment
[pypi]
username = __token__
password = pypi-RealTokenValue123

[internal]
repository = https://pypi.internal.example/simple
username = ci-publisher
password = Xk92QmPl4TzWhuCmu2qcwnu9PnWfMKNA
`, "\n")

	matches := findSecretPypircLines(lines)
	if len(matches) != 2 {
		t.Fatalf("got %d matches, want 2 (one password per repository section): %+v", len(matches), matches)
	}
	if matches[0].Section != "pypi" || matches[0].VarName != "PYPI_PASSWORD" {
		t.Errorf("matches[0] = %+v, want section pypi / PYPI_PASSWORD", matches[0])
	}
	if matches[1].Section != "internal" || matches[1].VarName != "INTERNAL_PASSWORD" {
		t.Errorf("matches[1] = %+v, want section internal / INTERNAL_PASSWORD", matches[1])
	}
	if matches[1].Value != "Xk92QmPl4TzWhuCmu2qcwnu9PnWfMKNA" {
		t.Errorf("value = %q, want the private index password", matches[1].Value)
	}
}

// TestPypircVarNameIncludesSection is the collision guard: two repositories in
// one file both have a key literally named "password", so the section is what
// keeps them on distinct vault paths.
func TestPypircVarNameIncludesSection(t *testing.T) {
	cases := []struct{ section, key, want string }{
		{"pypi", "password", "PYPI_PASSWORD"},
		{"blockaidpypi", "password", "BLOCKAIDPYPI_PASSWORD"},
		{"my-private.index", "password", "MY_PRIVATE_INDEX_PASSWORD"},
		{"2fa", "password", "_2FA_PASSWORD"}, // must not start with a digit
	}
	for _, c := range cases {
		if got := pypircVarName(c.section, c.key); got != c.want {
			t.Errorf("pypircVarName(%q, %q) = %q, want %q", c.section, c.key, got, c.want)
		}
	}
	if pypircVarName("pypi", "password") == pypircVarName("internal", "password") {
		t.Error("two sections must not collapse to one variable name")
	}
}

func TestApplyPypircMovesSecretsAndPreservesNonSecretLines(t *testing.T) {
	home := t.TempDir()
	path := PypircPath(home)
	writeFile(t, path, `[distutils]
index-servers =
    pypi
    internal

[pypi]
username = __token__
password = pypi-RealTokenValue123

[internal]
repository = https://pypi.internal.example/simple
username = ci-publisher
password = Xk92QmPl4TzWhuCmu2qcwnu9PnWfMKNA
`)

	v := newTestVault(t)
	result, err := ApplyPypirc(v, home, path)
	if err != nil {
		t.Fatalf("ApplyPypirc: %v", err)
	}
	if result.ProfileName != "pypirc" {
		t.Errorf("ProfileName = %q, want pypirc", result.ProfileName)
	}
	if len(result.Variables) != 2 {
		t.Fatalf("Variables = %v, want 2", result.Variables)
	}

	got, err := v.Get("pypirc/INTERNAL_PASSWORD")
	if err != nil || string(got) != "Xk92QmPl4TzWhuCmu2qcwnu9PnWfMKNA" {
		t.Errorf("vault secret = (%q, %v), want the private index password", got, err)
	}

	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat: %v", err)
	}
	if info.Mode()&os.ModeNamedPipe == 0 {
		t.Error("expected ~/.pypirc to be a FIFO after ApplyPypirc — twine reads the file directly, so it must stay live")
	}

	tmpl, err := os.ReadFile(result.TemplatePath) // #nosec G304 -- test-controlled path
	if err != nil {
		t.Fatalf("reading template: %v", err)
	}
	content := string(tmpl)
	for _, secret := range []string{"pypi-RealTokenValue123", "Xk92QmPl4TzWhuCmu2qcwnu9PnWfMKNA"} {
		if strings.Contains(content, secret) {
			t.Errorf("template must not contain the raw secret %q", secret)
		}
	}
	// Original spacing around "=" is preserved, so re-migrating an unchanged
	// file reproduces the same bytes.
	if !strings.Contains(content, "password = ${PYPI_PASSWORD}") {
		t.Errorf("template missing the pypi placeholder with original spacing, got:\n%s", content)
	}
	if !strings.Contains(content, "password = ${INTERNAL_PASSWORD}") {
		t.Errorf("template missing the private index placeholder, got:\n%s", content)
	}
	for _, keep := range []string{"[distutils]", "index-servers =", "repository = https://pypi.internal.example/simple", "username = ci-publisher"} {
		if !strings.Contains(content, keep) {
			t.Errorf("template lost non-secret line %q, got:\n%s", keep, content)
		}
	}

	backup, err := v.Get(result.BackupPath)
	if err != nil {
		t.Fatalf("reading backup from vault: %v", err)
	}
	if !strings.Contains(string(backup), "pypi-RealTokenValue123") {
		t.Error("backup should contain the original plaintext content")
	}
}

func TestApplyPypircNoCredentialsErrors(t *testing.T) {
	home := t.TempDir()
	path := PypircPath(home)
	writeFile(t, path, "[distutils]\nindex-servers = pypi\n\n[pypi]\nusername = __token__\n")

	v := newTestVault(t)
	if _, err := ApplyPypirc(v, home, path); err == nil {
		t.Error("ApplyPypirc should error when there is nothing to migrate")
	}
}
