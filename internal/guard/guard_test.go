// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package guard

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestInstallRemoveRoundTrip(t *testing.T) {
	home := t.TempDir()
	rc := filepath.Join(home, ".zshrc")
	original := "# my prompt\nexport EDITOR=vim\n"
	if err := os.WriteFile(rc, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}

	changed, err := Install(home)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if !changed {
		t.Error("first Install must report changed")
	}
	if !Installed(home) {
		t.Error("Installed() = false right after Install")
	}
	hook, err := os.ReadFile(HookPath(home))
	if err != nil {
		t.Fatalf("hook file: %v", err)
	}
	if string(hook) != HookScript() {
		t.Error("hook file does not hold the canonical script")
	}
	if info, _ := os.Stat(HookPath(home)); info.Mode().Perm() != 0o600 {
		t.Errorf("hook mode = %v, want 0600", info.Mode().Perm())
	}
	data, _ := os.ReadFile(rc)
	if !strings.Contains(string(data), RcLine()) {
		t.Errorf(".zshrc missing the source line:\n%s", data)
	}

	// Idempotent: nothing to do the second time.
	changed, err = Install(home)
	if err != nil || changed {
		t.Errorf("second Install = (%v, %v), want (false, nil)", changed, err)
	}

	// A stale hook (older jit wrote different content) is refreshed.
	if err := os.WriteFile(HookPath(home), []byte("# old hook\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	changed, err = Install(home)
	if err != nil || !changed {
		t.Errorf("refresh Install = (%v, %v), want (true, nil)", changed, err)
	}

	// Remove takes out exactly what Install added.
	changed, rcEdited, err := Remove(home)
	if err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if !changed || !rcEdited {
		t.Errorf("Remove = (%v, %v), want both true", changed, rcEdited)
	}
	if Installed(home) {
		t.Error("Installed() = true after Remove")
	}
	if _, err := os.Stat(HookPath(home)); !os.IsNotExist(err) {
		t.Error("hook file survived Remove")
	}
	data, _ = os.ReadFile(rc)
	if string(data) != original {
		t.Errorf(".zshrc not restored byte-for-byte:\n%q\nwant\n%q", data, original)
	}

	// Removing again is a safe no-op.
	changed, rcEdited, err = Remove(home)
	if err != nil || changed || rcEdited {
		t.Errorf("second Remove = (%v, %v, %v), want (false, false, nil)", changed, rcEdited, err)
	}
}

func TestInstallCreatesMissingZshrc(t *testing.T) {
	home := t.TempDir()
	if _, err := Install(home); err != nil {
		t.Fatalf("Install with no .zshrc: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(home, ".zshrc"))
	if err != nil {
		t.Fatalf(".zshrc was not created: %v", err)
	}
	if !strings.Contains(string(data), RcLine()) {
		t.Error("created .zshrc missing the source line")
	}
}

// runHook sources the canonical hook in a real zsh and feeds line to the
// hook function exactly as zshaddhistory would (trailing newline included).
// stubExit selects the stub jit's behavior: 0 = "credential found" (prints a
// vendor), 1 = clean, 127 = the binary is missing entirely.
func runHook(t *testing.T, line string, stubExit int) (rc int, stderr string, stubRan bool) {
	t.Helper()
	zsh, err := exec.LookPath("zsh")
	if err != nil {
		t.Skip("no zsh on this machine")
	}
	dir := t.TempDir()
	hookPath := filepath.Join(dir, "guard.zsh")
	if err := os.WriteFile(hookPath, []byte(HookScript()), 0o600); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(dir, "stub-ran")
	stub := filepath.Join(dir, "jit-stub")
	stubBody := "#!/bin/sh\n" +
		"cat > /dev/null\n" + // drain stdin like the real check does
		"touch " + marker + "\n"
	switch stubExit {
	case 0:
		stubBody += "echo 'GitHub Personal Access Token'\nexit 0\n"
	default:
		stubBody += "exit 1\n"
	}
	if err := os.WriteFile(stub, []byte(stubBody), 0o700); err != nil { // #nosec G306 -- a test stub that must be executable
		t.Fatal(err)
	}
	stubPath := stub
	if stubExit == 127 {
		stubPath = filepath.Join(dir, "does-not-exist")
	}

	script := `source ` + hookPath + `; _jit_history_guard "$1"$'\n'; print "rc=$?"`
	cmd := exec.Command(zsh, "-fc", script, "zsh", line) // #nosec G204 -- test-controlled zsh invocation
	cmd.Env = append(os.Environ(), "JIT_GUARD_BIN="+stubPath)
	var outBuf, errBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		t.Fatalf("zsh run: %v\nstderr: %s", err, errBuf.String())
	}
	out := strings.TrimSpace(outBuf.String())
	switch {
	case strings.HasSuffix(out, "rc=0"):
		rc = 0
	case strings.HasSuffix(out, "rc=2"):
		rc = 2
	default:
		t.Fatalf("unexpected hook output %q (stderr: %s)", out, errBuf.String())
	}
	_, statErr := os.Stat(marker)
	return rc, errBuf.String(), statErr == nil
}

func TestHookBlocksCredentialLines(t *testing.T) {
	line := "curl -H 'Authorization: token ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8'"
	rc, stderr, ran := runHook(t, line, 0)
	if !ran {
		t.Fatal("the stub check never ran; the admit test wrongly rejected a credential line")
	}
	if rc != 2 {
		t.Errorf("rc = %d, want 2 (keep in session memory, never write the file)", rc)
	}
	if !strings.Contains(stderr, "GitHub Personal Access Token") {
		t.Errorf("notice does not name the vendor: %q", stderr)
	}
}

func TestHookSavesCleanAdmittedLines(t *testing.T) {
	// "@" admits it past the prefilter; the check says clean; it must save.
	rc, _, ran := runHook(t, "git log --author=alice@example.com", 1)
	if !ran {
		t.Fatal("an @-carrying line must reach the check (prefilter parity)")
	}
	if rc != 0 {
		t.Errorf("rc = %d, want 0 for a clean line", rc)
	}
}

// The ~95% path: a short clean command must save WITHOUT forking anything —
// the whole cost story of the hook rests on this.
func TestHookNeverForksForOrdinaryCommands(t *testing.T) {
	rc, _, ran := runHook(t, "git status", 1)
	if rc != 0 {
		t.Errorf("rc = %d, want 0", rc)
	}
	if ran {
		t.Error("the check forked for a line the admit test should have rejected")
	}
}

// Admit parity with audit's historyLineMayHoldToken: one sample per admitting
// condition must reach the check. The Go prefilter's completeness against
// every vendor pattern is enforced in internal/audit
// (TestHistoryPrefilterNeverDropsAMatch); this pins the zsh transplant to the
// same four conditions.
func TestHookAdmitTestNeverDropsAMatch(t *testing.T) {
	for _, line := range []string{
		"cat id_rsa | head -1  # -----BEGIN OPENSSH PRIVATE KEY-----",
		"psql postgres://app:pw@db/app",                          // "@"
		"echo eyJa.b.c",                                          // degenerate JWT, no long run
		"export TOKEN=xoxb" + "-1234567890-AbCdEfGhIjKlMnOpQrSt", // 10+ run
	} {
		_, _, ran := runHook(t, line, 1)
		if !ran {
			t.Errorf("admit test dropped %q; the zsh prefilter is narrower than audit's", line)
		}
	}
}

// A hung check must not hang the prompt. The realistic cause is Gatekeeper's
// online notarization fetch on the first exec of a freshly upgraded binary,
// which no jit-side fix can make fast — so the hook has a deadline and fails
// open past it.
func TestHookFailsOpenWhenTheCheckHangs(t *testing.T) {
	zsh, err := exec.LookPath("zsh")
	if err != nil {
		t.Skip("no zsh on this machine")
	}
	dir := t.TempDir()
	hookPath := filepath.Join(dir, "guard.zsh")
	if err := os.WriteFile(hookPath, []byte(HookScript()), 0o600); err != nil {
		t.Fatal(err)
	}
	// A "jit" that never answers. If the hook waits for it, this test hangs
	// until the package timeout rather than failing politely — which is
	// exactly the user-visible symptom being guarded against.
	stub := filepath.Join(dir, "jit-hangs")
	if err := os.WriteFile(stub, []byte("#!/bin/sh\ncat > /dev/null\nsleep 30\n"), 0o700); err != nil { // #nosec G306 -- an executable test stub
		t.Fatal(err)
	}

	line := "curl -H 'Authorization: token ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8'"
	script := `source ` + hookPath + `; _jit_history_guard "$1"$'\n'; print "rc=$?"`
	cmd := exec.Command(zsh, "-fc", script, "zsh", line) // #nosec G204 -- test-controlled zsh invocation
	cmd.Env = append(os.Environ(), "JIT_GUARD_BIN="+stub)
	var outBuf, errBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	start := time.Now()
	if err := cmd.Run(); err != nil {
		t.Fatalf("zsh run: %v\nstderr: %s", err, errBuf.String())
	}
	elapsed := time.Since(start)

	if !strings.Contains(outBuf.String(), "rc=0") {
		t.Errorf("hook returned %q, want rc=0 (fail open on a hung check)", strings.TrimSpace(outBuf.String()))
	}
	if elapsed > 10*time.Second {
		t.Errorf("hook blocked for %v; the deadline did not fire", elapsed)
	}
	// Job-control chatter would land in the user's terminal on every guarded
	// command, which is its own bug.
	if strings.Contains(errBuf.String(), "suspended") || strings.Contains(errBuf.String(), "[1]") {
		t.Errorf("job-control noise leaked to stderr: %q", errBuf.String())
	}
	// The temp file holding the check's OUTPUT (never the command line) must
	// not survive the timeout.
	entries, err := os.ReadDir(os.TempDir())
	if err == nil {
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), ".jit-guard.") {
				t.Errorf("left a stray temp file behind: %s", e.Name())
			}
		}
	}
}

func TestHookFailsOpenWithoutJit(t *testing.T) {
	line := "curl -H 'Authorization: token ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8'"
	rc, _, _ := runHook(t, line, 127)
	if rc != 0 {
		t.Errorf("rc = %d, want 0: with jit missing the hook must fail open and save the line", rc)
	}
}
