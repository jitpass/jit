// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"os"
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/mount"
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

// TestApplyPypircPreservesQuotesVerbatim guards a correctness bug found in
// review (2026-07-28). .pypirc is read by Python's configparser, which does
// NOT strip surrounding quotes — `password = "abc"` is the five-character
// value `"abc"`. An earlier draft ran the value through unquoteEnvValue (the
// right call for npmrc, whose ini parser does strip them), which would have
// vaulted a value differing from the real credential at each end and served
// it back through the mount: uploads break, and the file still looks correct.
func TestApplyPypircPreservesQuotesVerbatim(t *testing.T) {
	home := t.TempDir()
	path := PypircPath(home)
	writeFile(t, path, "[pypi]\nusername = __token__\npassword = \"Xk92QmPl4TzWhu\"\n")

	v := newTestVault(t)
	if _, err := ApplyPypirc(v, home, path); err != nil {
		t.Fatalf("ApplyPypirc: %v", err)
	}
	got, err := v.Get("pypirc/PYPI_PASSWORD")
	if err != nil {
		t.Fatalf("vault get: %v", err)
	}
	if want := `"Xk92QmPl4TzWhu"`; string(got) != want {
		t.Errorf("vaulted %q, want %q — configparser keeps the quotes, so jit must too", got, want)
	}
}

// TestApplyPypircRoundTripsLosslessly is the guarantee that matters most for a
// mounted credential file: what the mount serves must be byte-identical to
// what was there before. If it isn't, `twine upload` fails against a file that
// looks perfectly correct, which is the hardest failure mode to diagnose.
//
// original -> ApplyPypirc -> FormatTemplate(template, vault values) == original
func TestApplyPypircRoundTripsLosslessly(t *testing.T) {
	const original = `[distutils]
index-servers =
    pypi
    internal

[pypi]
username = __token__
password = pypi-AgEIcHlwaS5vcmcCJDk0YTUxZmE0

# a comment, and an oddly-spaced assignment below
[internal]
repository = https://pypi.internal.example/simple
username = ci-publisher
password="Xk92QmPl4TzWhuCmu2qcwnu9PnWfMKNA"
`
	home := t.TempDir()
	path := PypircPath(home)
	writeFile(t, path, original)

	v := newTestVault(t)
	result, err := ApplyPypirc(v, home, path)
	if err != nil {
		t.Fatalf("ApplyPypirc: %v", err)
	}

	tmpl, err := os.ReadFile(result.TemplatePath) // #nosec G304 -- test-controlled path
	if err != nil {
		t.Fatalf("reading template: %v", err)
	}

	// Rebuild the value map the agent would serve from the vault.
	values := map[string]string{}
	for _, name := range result.Variables {
		got, err := v.Get(result.ProfileName + "/" + name)
		if err != nil {
			t.Fatalf("vault get %s: %v", name, err)
		}
		values[name] = string(got)
	}

	rendered := string(mount.FormatTemplate(tmpl, values))
	if rendered != original {
		t.Errorf("round-trip is lossy.\nrendered: %q\noriginal: %q", rendered, original)
	}
}

// TestApplyPypircIsUndoable pins that a migration can be reversed: the FIFO is
// replaced by a regular file holding the original bytes. An un-undoable
// migration of a credential file is the worst outcome this package has.
func TestApplyPypircIsUndoable(t *testing.T) {
	const original = "[pypi]\nusername = __token__\npassword = pypi-AgEIcHlwaS5vcmcCJDk0YTUx\n"
	home := t.TempDir()
	path := PypircPath(home)
	writeFile(t, path, original)

	v := newTestVault(t)
	result, err := ApplyPypirc(v, home, path)
	if err != nil {
		t.Fatalf("ApplyPypirc: %v", err)
	}
	if info, err := os.Lstat(path); err != nil || info.Mode()&os.ModeNamedPipe == 0 {
		t.Fatalf("expected a FIFO after migrate, got %v (err=%v)", info.Mode(), err)
	}

	if err := RestoreFromBackup(v, BackupRecord{OriginalPath: path, VaultPath: result.BackupPath}); err != nil {
		t.Fatalf("RestoreFromBackup: %v", err)
	}

	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat after restore: %v", err)
	}
	if !info.Mode().IsRegular() {
		t.Errorf("after undo the path is %v, want a regular file (the FIFO must be retired)", info.Mode())
	}
	restored, err := os.ReadFile(path) // #nosec G304 -- test-controlled path
	if err != nil {
		t.Fatalf("reading restored file: %v", err)
	}
	if string(restored) != original {
		t.Errorf("restored bytes differ.\ngot:  %q\nwant: %q", restored, original)
	}
}

// TestApplyPypircDisambiguatesCollidingSectionNames guards the collision
// found in review (2026-07-28): [my-index] and [my_index] are DISTINCT
// configparser sections, but both sanitize to MY_INDEX_PASSWORD. Before
// assignUniqueVarNames, the second section's password silently overwrote the
// first's in the vault and the template stamped the surviving value into both
// sections — the mount served repo B's password for repo A.
func TestApplyPypircDisambiguatesCollidingSectionNames(t *testing.T) {
	const original = `[distutils]
index-servers =
    my-index
    my_index

[my-index]
repository = https://a.example/simple
username = ci
password = FirstIndexPasswordQmPl4TzWhu

[my_index]
repository = https://b.example/simple
username = ci
password = SecondIndexPasswordu2qcwnu9P
`
	home := t.TempDir()
	path := PypircPath(home)
	writeFile(t, path, original)

	v := newTestVault(t)
	result, err := ApplyPypirc(v, home, path)
	if err != nil {
		t.Fatalf("ApplyPypirc: %v", err)
	}
	if len(result.Variables) != 2 {
		t.Fatalf("Variables = %v, want 2 — distinct sections must not merge onto one vault path", result.Variables)
	}

	// Both passwords must be in the vault, each under its own name.
	values := map[string]string{}
	for _, name := range result.Variables {
		got, err := v.Get(result.ProfileName + "/" + name)
		if err != nil {
			t.Fatalf("vault get %s: %v", name, err)
		}
		values[name] = string(got)
	}
	seen := map[string]bool{}
	for _, val := range values {
		seen[val] = true
	}
	if !seen["FirstIndexPasswordQmPl4TzWhu"] || !seen["SecondIndexPasswordu2qcwnu9P"] {
		t.Errorf("vault holds %v, want BOTH sections' passwords", values)
	}

	// And the template must render back the original bytes exactly, which is
	// only possible when the two sections carry distinct placeholders.
	tmpl, err := os.ReadFile(result.TemplatePath) // #nosec G304 -- test-controlled path
	if err != nil {
		t.Fatalf("reading template: %v", err)
	}
	if rendered := string(mount.FormatTemplate(tmpl, values)); rendered != original {
		t.Errorf("round-trip is lossy.\nrendered: %q\noriginal: %q", rendered, original)
	}
}

// TestApplyPypircRefusesLiteralPlaceholder ports ApplyNetrc's guard:
// mount.FormatTemplate is position-blind, so a file already containing the
// literal ${PYPI_PASSWORD} (a commented-out remnant of an undone migration, a
// pasted docs example) would get the real password substituted into that spot
// at serve time — the served bytes would diverge from the original. Refusal
// is the only safe answer.
func TestApplyPypircRefusesLiteralPlaceholder(t *testing.T) {
	home := t.TempDir()
	path := PypircPath(home)
	writeFile(t, path, `[pypi]
# password = ${PYPI_PASSWORD}
username = __token__
password = pypi-AgEIcHlwaS5vcmcCJDk0YTUx
`)

	v := newTestVault(t)
	_, err := ApplyPypirc(v, home, path)
	if err == nil {
		t.Fatal("ApplyPypirc should refuse a file already containing its own placeholder")
	}
	if !strings.Contains(err.Error(), "${PYPI_PASSWORD}") {
		t.Errorf("error should name the offending placeholder, got %v", err)
	}
	if info, statErr := os.Lstat(path); statErr != nil || !info.Mode().IsRegular() {
		t.Errorf("refusal must leave the original file untouched, got %v (err=%v)", info, statErr)
	}
}
