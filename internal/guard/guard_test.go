// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package guard

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jitpass/jit/internal/audit"
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
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	// The stub is named "jit" and reached through PATH: the hook resolves the
	// binary with `command -v jit` and has no env-var override to abuse.
	stub := filepath.Join(bin, "jit")
	// The marker is touched FIRST, before stdin is drained.
	//
	// It used to be touched after, and that made `stubRan` mean "the check was
	// forked AND finished within the hook's 2s deadline" while every caller
	// read it as "the admit test let the line through". Those diverge under
	// load: the hook forks the check, waits 200x10ms, and on timeout does
	// `kill -9` and fails open (see guard.go). On a loaded machine — the
	// full suite under -race, on a 4-CPU VM — forking /bin/sh plus cat can
	// exceed 2s, the stub is killed before it ever reaches touch, and
	// TestHookBlocksCredentialLines fails with "the admit test wrongly
	// rejected a credential line" about an admit test that did its job. That
	// is the intermittent failure on the open-findings list, and the
	// misdiagnosis was in the assertion, not in the hook.
	//
	// Touching first makes stubRan mean exactly "the check was forked", which
	// is what every caller wants to know. A deadline hit now shows up as the
	// rc assertion failing instead, which is the truthful place for it.
	stubBody := "#!/bin/sh\n" +
		"touch " + marker + "\n" +
		"cat > /dev/null\n" // drain stdin like the real check does
	switch stubExit {
	case 0:
		stubBody += "echo 'GitHub Personal Access Token'\nexit 0\n"
	default:
		stubBody += "exit 1\n"
	}
	if err := os.WriteFile(stub, []byte(stubBody), 0o700); err != nil { // #nosec G306 -- a test stub that must be executable
		t.Fatal(err)
	}
	// The stubs are /bin/sh scripts that call cat, so the real system
	// directories must stay on PATH; only "jit" itself is controlled here.
	pathEnv := bin + ":/usr/bin:/bin"
	if stubExit == 127 {
		pathEnv = "/usr/bin:/bin" // nothing named jit anywhere on PATH
	}

	script := `source ` + hookPath + `; _jit_history_guard "$1"$'\n'; print "rc=$?"`
	cmd := exec.Command(zsh, "-fc", script, "zsh", line) // #nosec G204 -- test-controlled zsh invocation
	cmd.Env = append(os.Environ(), "PATH="+pathEnv)
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
		// Two causes, and the message used to assert the first one only, which
		// is what made the intermittent failure on the open-findings list read
		// as an admit-test bug. Admit parity is covered exhaustively and
		// separately by TestHookAdmitTestNeverDropsAMatch, so under parallel
		// load the second cause is by far the likelier of the two.
		t.Fatal("the stub check did not run. Either the admit test wrongly rejected a credential " +
			"line, or the hook's 2s deadline killed the check before the stub got to run at all " +
			"(fork storm under parallel -race load). Re-run this test alone to tell them apart: " +
			"if it passes in isolation it was the deadline, which is the hook behaving correctly")
	}
	if rc != 2 {
		t.Errorf("rc = %d, want 2 (keep in session memory, never write the file). "+
			"rc=0 with the stub confirmed to have run means the hook's 2s deadline fired and it "+
			"failed open — correct behaviour under load, not a detection failure", rc)
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

// admitCorpus loads the SAME file internal/audit's own admit tests read, so
// the two implementations of this test cannot be narrowed independently.
//
// "|" is a split marker (see the file's header): it sits where a contiguous
// vendor token would otherwise trip GitHub push protection.
func admitCorpus(t *testing.T) []string {
	t.Helper()
	path := filepath.Join("..", "audit", "testdata", "history-admit-samples.txt")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the shared admit corpus: %v", err)
	}
	var samples []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		samples = append(samples, strings.ReplaceAll(line, "|", ""))
	}
	if len(samples) == 0 {
		t.Fatal("the shared admit corpus yielded no samples; this test would pass vacuously")
	}
	return samples
}

// TestHookAdmitTestNeverDropsAMatch is the zsh transplant of the obligation
// CLAUDE.md, guard.go and shellhistory.go all state: the cheap in-shell admit
// test must never reject a line the real check would match.
//
// It used to check FOUR hand-written lines, one per admitting condition, while
// internal/audit checked its Go prefilter against every entry in
// knownTokenPatterns. That asymmetry is the whole bug: a vendor pattern whose
// shortest match is an 8-character run forces audit's constant down, audit's
// exhaustive test keeps passing, and the shipped zsh hook still rejects at 10 —
// so `jit guard history` silently stops protecting that vendor, and the
// guard's designed failure mode is silence.
//
// Now both read one corpus file. Driven through a REAL zsh against the
// SHIPPED hook, which is the only way this proves anything about the thing
// users actually run.
func TestHookAdmitTestNeverDropsAMatch(t *testing.T) {
	for _, sample := range admitCorpus(t) {
		line := "export TOKEN=" + sample
		_, _, ran := runHook(t, line, 1)
		if !ran {
			t.Errorf("the zsh admit test dropped %q; it is narrower than audit's prefilter, "+
				"so jit guard history silently stops protecting this format", sample)
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
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	stub := filepath.Join(bin, "jit")
	if err := os.WriteFile(stub, []byte("#!/bin/sh\ncat > /dev/null\nsleep 30\n"), 0o700); err != nil { // #nosec G306 -- an executable test stub
		t.Fatal(err)
	}

	line := "curl -H 'Authorization: token ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8'"
	script := `source ` + hookPath + `; _jit_history_guard "$1"$'\n'; print "rc=$?"`
	cmd := exec.Command(zsh, "-fc", script, "zsh", line) // #nosec G204 -- test-controlled zsh invocation
	cmd.Env = append(os.Environ(), "PATH="+bin+":/usr/bin:/bin")
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

// TestHookScriptRendersFromTheSpec is the linkage itself. The admit test used
// to be typed out in the zsh source beside audit's Go copy — both correct,
// nothing holding them together. These assertions fail if the hook stops
// tracking audit.HistoryAdmitRule(), which is the state that made the drift
// possible in the first place.
func TestHookScriptRendersFromTheSpec(t *testing.T) {
	spec := audit.HistoryAdmitRule()
	script := HookScript()

	if strings.Contains(script, "@@") {
		t.Errorf("an unsubstituted placeholder survived into the shipped hook:\n%s", script)
	}
	for _, lit := range spec.Literals {
		if !strings.Contains(script, "$line != *"+lit+"*") {
			t.Errorf("the hook has no clause for admit literal %q, so a line carrying it is dropped in the shell", lit)
		}
	}
	if want := spec.RunClass + "{" + strconv.Itoa(spec.RunLen) + ",}"; !strings.Contains(script, want) {
		t.Errorf("the hook's run test is not %q; it has stopped tracking the spec, "+
			"which is how a lowered RunLen leaves the shell hook rejecting what the scanner matches", want)
	}
}

// A literal is interpolated into a zsh GLOB pattern (`$line != *LIT*`), so a
// glob metacharacter in one silently changes what the clause matches — and in
// the admitting direction that means dropping lines. Cheap to check, and the
// alternative (quoting) would change the existing clauses' text.
func TestAdmitLiteralsAreGlobSafe(t *testing.T) {
	for _, lit := range audit.HistoryAdmitRule().Literals {
		if strings.ContainsAny(lit, `*?[]()|^~#`) {
			t.Errorf("admit literal %q carries a zsh glob metacharacter; interpolated bare into "+
				"`$line != *%s*` it would not match literally", lit, lit)
		}
	}
}
