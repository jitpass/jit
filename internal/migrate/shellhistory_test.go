// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"io"
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
	if secrets, occ, err := PreviewShellHistory(path); err != nil || secrets != 0 || occ != 0 {
		t.Errorf("redacted file still previews (%d secrets, %d occurrences, err=%v)", secrets, occ, err)
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

// Two vendors on one line, in the reverse of their declaration order in
// knownTokenPatterns (GitHub is declared before AWS). audit.HistoryLineTokens
// runs each pattern over the whole line in turn, so without a sort the spans
// come back descending and the splice's data[prev:start] panics — after the
// vault writes and the backup, on every retry, so the file could never be
// redacted. Regression test for that blocker.
func TestApplyShellHistoryMultipleVendorsOnOneLine(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := filepath.Join(home, ".zsh_history")
	awsKey := "AKIA" + "2E0ZQXV7MNBC4RTY"
	original := ": 1782826755:0;export AWS_ACCESS_KEY_ID=" + awsKey + " GITHUB_TOKEN=" + histGHToken + "\n"
	writeFile(t, path, original)

	v := newTestVault(t)
	result, err := ApplyShellHistory(v, path)
	if err != nil {
		t.Fatalf("ApplyShellHistory: %v", err)
	}
	if len(result.Variables) != 2 || result.Occurrences != 2 {
		t.Fatalf("got %d variables / %d occurrences, want 2 and 2", len(result.Variables), result.Occurrences)
	}
	content, err := os.ReadFile(path) // #nosec G304 -- test-controlled path under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(content), awsKey) || strings.Contains(string(content), histGHToken) {
		t.Fatalf("a credential survived redaction:\n%s", content)
	}
	// Both markers land in the right places: the line still reads as the
	// command it was, with each variable name where its own value stood.
	restored := string(content)
	for _, v := range result.Variables {
		marker := historyRedactedPrefix + v + historyRedactedSuffix
		if !strings.Contains(restored, marker) {
			t.Errorf("marker %q missing from:\n%s", marker, restored)
		}
	}
	if !strings.HasPrefix(restored, ": 1782826755:0;export AWS_ACCESS_KEY_ID=") {
		t.Errorf("the command line was mangled:\n%s", restored)
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

// The vault work between the read and the rename is not instantaneous (a
// Touch ID prompt is a human), and a shell with INC_APPEND_HISTORY appends
// throughout. Splicing the ORIGINAL bytes over the file would silently eat
// every command typed in that window; splicing CURRENT content preserves it.
func TestRedactCurrentContentPreservesConcurrentAppends(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, ".zsh_history")
	writeFile(t, path, zshHistoryFixture())

	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := io.ReadAll(f); err != nil { // the first pass, as ApplyShellHistory does it
		t.Fatal(err)
	}

	// Another shell appends while jit is busy with the vault.
	appended := ": 1782826761:0;npm run build\n: 1782826762:0;git push\n"
	af, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := af.WriteString(appended); err != nil {
		t.Fatal(err)
	}
	af.Close()

	nameOf := map[string]string{histGHToken: "GITHUB_PERSONAL_ACCESS_TOKEN"}
	current, out, occ, err := redactCurrentContent(f, path, nameOf)
	if err != nil {
		t.Fatalf("redactCurrentContent: %v", err)
	}
	// The bytes handed back for backup must be exactly what is on disk right
	// now — that is what makes `jit migrate undo` byte-for-byte after an
	// append during the run.
	onDisk, err := os.ReadFile(path) // #nosec G304 -- test-controlled path under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	if string(current) != string(onDisk) {
		t.Error("the bytes returned for backup are not the file's current content")
	}
	if occ != 2 {
		t.Errorf("occurrences = %d, want 2", occ)
	}
	if !strings.Contains(string(out), "npm run build") || !strings.Contains(string(out), "git push") {
		t.Error("commands appended during the run were dropped")
	}
	if strings.Contains(string(out), histGHToken) {
		t.Error("the token survived redaction")
	}
}

// A credential that appears only AFTER the vault writes has no vault entry to
// point a marker at. Writing anyway would either leave it in plaintext or
// destroy it behind a marker naming nothing, so the run refuses and the file
// is left untouched — a re-run covers both.
func TestRedactCurrentContentRefusesAValueItNeverVaulted(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, ".zsh_history")
	writeFile(t, path, zshHistoryFixture()+": 1782826761:0;echo "+histGHToken2+"\n")

	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	nameOf := map[string]string{histGHToken: "GITHUB_PERSONAL_ACCESS_TOKEN"}
	if _, _, _, err := redactCurrentContent(f, path, nameOf); err == nil {
		t.Fatal("want a refusal for a credential that was never vaulted")
	}
	content, err := os.ReadFile(path) // #nosec G304 -- test-controlled path under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), histGHToken2) {
		t.Error("the file was modified despite the refusal")
	}
}

// A hard-linked history file is refused: the rename replaces the path, so the
// other link would keep every credential while jit reported success and scan
// (which only knows the history file's own name) read clean.
func TestApplyShellHistoryRefusesHardLink(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := filepath.Join(home, ".zsh_history")
	writeFile(t, path, zshHistoryFixture())
	other := filepath.Join(home, "dotfiles-copy")
	if err := os.Link(path, other); err != nil {
		t.Skipf("cannot hard link here: %v", err)
	}

	v := newTestVault(t)
	if _, err := ApplyShellHistory(v, path); err == nil || !strings.Contains(err.Error(), "hard link") {
		t.Fatalf("want a hard-link refusal, got %v", err)
	}
	content, err := os.ReadFile(other) // #nosec G304 -- test-controlled path under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), histGHToken) {
		t.Error("the other link's content changed")
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

	secrets, occurrences, err := PreviewShellHistory(path)
	if err != nil || secrets != 1 || occurrences != 2 {
		t.Errorf("PreviewShellHistory = (%d, %d, %v), want (1, 2, nil)", secrets, occurrences, err)
	}
	if _, _, err := PreviewShellHistory(filepath.Join(home, "missing")); err == nil {
		t.Error("a missing file must report an error, not a clean preview")
	}
}
