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

// Realistic vendor-format tokens: exact lengths, mixed characters so
// isPlaceholderToken never rejects them.
const (
	histGHToken  = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
	histGHToken2 = "ghp_" + "Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J3i2"
)

// zshHistoryFixture is a zsh extended_history file: every line timestamped,
// the GitHub token typed twice (two occurrences, one distinct value).
func zshHistoryFixture() string {
	return ": 1782826755:0;git status\n" +
		": 1782826756:0;curl -H 'Authorization: token " + histGHToken + "' https://api.github.com/user\n" +
		": 1782826757:0;echo hello\n" +
		": 1782826758:0;git clone https://x:" + histGHToken + "@github.com/o/r.git\n" +
		": 1782826759:2;go test ./...\n"
}

func TestApplyShellHistoryEndToEnd(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home) // profile.GlobalRoot and the backup index live here
	path := filepath.Join(home, ".zsh_history")
	original := zshHistoryFixture()
	writeFile(t, path, original)
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}

	v := newTestVault(t)
	result, err := ApplyShellHistory(v, path)
	if err != nil {
		t.Fatalf("ApplyShellHistory: %v", err)
	}

	if result.ProfileName != "zsh_history" {
		t.Errorf("ProfileName = %q, want %q", result.ProfileName, "zsh_history")
	}
	if len(result.Variables) != 1 {
		t.Fatalf("Variables = %v, want exactly one (one distinct value)", result.Variables)
	}
	if result.Occurrences != 2 {
		t.Errorf("Occurrences = %d, want 2", result.Occurrences)
	}

	// The token is retrievable from the vault under the recorded profile,
	// stamped with the shell_history class and the file as origin.
	p, err := profile.LoadFile(result.ProfilePath)
	if err != nil {
		t.Fatalf("profile.LoadFile: %v", err)
	}
	secretPath, ok := p[result.Variables[0]]
	if !ok {
		t.Fatalf("profile missing %q", result.Variables[0])
	}
	got, err := v.Get(secretPath)
	if err != nil {
		t.Fatalf("v.Get(%q): %v", secretPath, err)
	}
	if string(got) != histGHToken {
		t.Errorf("vault value = %q, want the token", got)
	}
	secInfo, err := v.Info(secretPath)
	if err != nil {
		t.Fatalf("v.Info: %v", err)
	}
	if secInfo.Class != vault.ClassShellHistory {
		t.Errorf("class = %q, want %q", secInfo.Class, vault.ClassShellHistory)
	}
	if !strings.HasSuffix(secInfo.Origin, ".zsh_history") {
		t.Errorf("origin = %q, want the history file", secInfo.Origin)
	}

	// The file: token gone, markers in, permission bits kept.
	content, err := os.ReadFile(path) // #nosec G304 -- test-controlled path under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(content), histGHToken) {
		t.Fatal("the plaintext token must be gone from the history file")
	}
	marker := historyRedactedPrefix + result.Variables[0] + historyRedactedSuffix
	if strings.Count(string(content), marker) != 2 {
		t.Errorf("want the marker twice, got:\n%s", content)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o644 {
		t.Errorf("permissions = %v, want 0644 preserved", info.Mode().Perm())
	}

	// Byte fidelity: swapping each marker back for its vault value must
	// reproduce the original file exactly — timestamps, spacing, everything.
	restored := strings.ReplaceAll(string(content), marker, histGHToken)
	if restored != original {
		t.Errorf("splice touched bytes outside the credential spans:\n%q\nwant\n%q", restored, original)
	}

	// The redacted file reads clean — no re-flag, no redaction loop.
	if secrets, occ, ok := PreviewShellHistory(path); !ok || secrets != 0 || occ != 0 {
		t.Errorf("redacted file still previews (%d secrets, %d occurrences, ok=%v)", secrets, occ, ok)
	}

	// The pre-redaction bytes are recoverable from the encrypted backup.
	backup, err := v.Get(result.BackupPath)
	if err != nil {
		t.Fatalf("v.Get(backup): %v", err)
	}
	if string(backup) != original {
		t.Error("backup does not hold the original bytes")
	}
}

func TestApplyShellHistoryFishFormat(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := filepath.Join(home, "fish_history")
	original := "- cmd: git status\n" +
		"  when: 1782826755\n" +
		"- cmd: curl -H 'Authorization: token " + histGHToken + "' https://api.github.com\n" +
		"  when: 1782826756\n" +
		"  paths:\n" +
		"    - /tmp/x\n"
	writeFile(t, path, original)

	v := newTestVault(t)
	result, err := ApplyShellHistory(v, path)
	if err != nil {
		t.Fatalf("ApplyShellHistory: %v", err)
	}
	content, err := os.ReadFile(path) // #nosec G304 -- test-controlled path under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(content), histGHToken) {
		t.Fatal("token still in fish history")
	}
	marker := historyRedactedPrefix + result.Variables[0] + historyRedactedSuffix
	if restored := strings.ReplaceAll(string(content), marker, histGHToken); restored != original {
		t.Errorf("fish metadata lines were altered:\n%q", restored)
	}
}

// A re-run after a shell's exit resurrects an already-vaulted token must land
// it back under the SAME variable, and a genuinely new token of the same
// vendor must get a fresh suffixed name instead of clobbering the first.
func TestApplyShellHistoryRerunIsIdempotentAndNeverClobbers(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := filepath.Join(home, ".zsh_history")
	writeFile(t, path, zshHistoryFixture())

	v := newTestVault(t)
	first, err := ApplyShellHistory(v, path)
	if err != nil {
		t.Fatalf("first ApplyShellHistory: %v", err)
	}

	// Resurrection: an open shell rewrote the file on exit with the same token.
	appendLine := ": 1782826760:0;echo " + histGHToken + "\n"
	content, _ := os.ReadFile(path) // #nosec G304 -- test-controlled path under t.TempDir()
	writeFile(t, path, string(content)+appendLine)

	second, err := ApplyShellHistory(v, path)
	if err != nil {
		t.Fatalf("second ApplyShellHistory: %v", err)
	}
	if len(second.Variables) != 1 || second.Variables[0] != first.Variables[0] {
		t.Errorf("resurrected token renamed: first %v, second %v", first.Variables, second.Variables)
	}

	// A different GitHub token now shows up: it must not overwrite the first.
	content, _ = os.ReadFile(path) // #nosec G304 -- test-controlled path under t.TempDir()
	writeFile(t, path, string(content)+": 1782826761:0;echo "+histGHToken2+"\n")
	third, err := ApplyShellHistory(v, path)
	if err != nil {
		t.Fatalf("third ApplyShellHistory: %v", err)
	}
	if len(third.Variables) != 1 || third.Variables[0] == first.Variables[0] {
		t.Fatalf("new token must get its own name, got %v", third.Variables)
	}
	p, err := profile.LoadFile(third.ProfilePath)
	if err != nil {
		t.Fatal(err)
	}
	v1, err := v.Get(p[first.Variables[0]])
	if err != nil {
		t.Fatal(err)
	}
	v2, err := v.Get(p[third.Variables[0]])
	if err != nil {
		t.Fatal(err)
	}
	if string(v1) != histGHToken || string(v2) != histGHToken2 {
		t.Errorf("vault holds %q/%q, want both tokens intact", v1, v2)
	}
}

func TestApplyShellHistoryRefusesSymlink(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	target := filepath.Join(home, "dotfiles", "zsh_history")
	writeFile(t, target, ": 1782826756:0;echo "+histGHToken+"\n")
	link := filepath.Join(home, ".zsh_history")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	v := newTestVault(t)
	if _, err := ApplyShellHistory(v, link); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("want a symlink refusal, got %v", err)
	}
	// The link and its target must be untouched.
	if info, err := os.Lstat(link); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Error("the symlink was replaced")
	}
	content, err := os.ReadFile(target) // #nosec G304 -- test-controlled path under t.TempDir()
	if err != nil || !strings.Contains(string(content), histGHToken) {
		t.Error("the link target was modified")
	}
}

func TestApplyShellHistoryNoTokensIsAnError(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := filepath.Join(home, ".zsh_history")
	writeFile(t, path, ": 1782826755:0;git status\n: 1782826756:0;ls -la\n")

	v := newTestVault(t)
	if _, err := ApplyShellHistory(v, path); err == nil {
		t.Fatal("want an error for a clean history file")
	}
}

func TestPreviewShellHistoryCounts(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, ".zsh_history")
	writeFile(t, path, zshHistoryFixture())

	secrets, occurrences, ok := PreviewShellHistory(path)
	if !ok || secrets != 1 || occurrences != 2 {
		t.Errorf("PreviewShellHistory = (%d, %d, %v), want (1, 2, true)", secrets, occurrences, ok)
	}
	if _, _, ok := PreviewShellHistory(filepath.Join(home, "missing")); ok {
		t.Error("a missing file must not preview ok")
	}
}
