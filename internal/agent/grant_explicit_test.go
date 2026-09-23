// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package agent

import (
	"bytes"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/jitpass/jit/internal/lineage"
)

// An explicit anchor is refused when the named pid is an interior process:
// only a session root (launchd's direct child) may be chosen from outside.
func TestExplicitAnchorMustBeASessionRoot(t *testing.T) {
	var calls int32
	s, socketPath, cleanup := startTestServer(t, time.Minute, &calls)
	defer cleanup()
	wireGrantResolver(s, sealGrantSecret(t, "jamf/api-pass", "mcp", bytes.Repeat([]byte{0x07}, 32)))

	child := exec.Command("sleep", "60")
	if err := child.Start(); err != nil {
		t.Fatalf("starting child: %v", err)
	}
	defer func() {
		_ = child.Process.Kill()
		_, _ = child.Process.Wait()
	}()

	c := NewClient(socketPath)
	_, err := c.GrantCreateUnderRoot(int32(child.Process.Pid), "sleep", []string{"jamf"}, "", time.Hour) // #nosec G115 -- test pid
	if err == nil || !strings.Contains(err.Error(), "session root") {
		t.Errorf("explicit anchor on an interior process = %v, want a session-root refusal", err)
	}
	if _, err := c.GrantCreateUnderRoot(1, "sleep", []string{"jamf"}, "", time.Hour); err == nil || !strings.Contains(err.Error(), "launchd") {
		t.Errorf("explicit anchor on launchd = %v, want a launchd refusal", err)
	}
	if got := atomic.LoadInt32(&calls); got != 0 {
		t.Errorf("refused explicit anchors reached the prompt %d times, want 0", got)
	}
}

// A session root the caller is NOT inside is accepted when named
// explicitly, and the prompt names the requester.
func TestExplicitAnchorOnAForeignSessionRootIsPromptedWithRequester(t *testing.T) {
	root, ok := foreignSessionRoot(t)
	if !ok {
		t.Skip("no other session root of this user is running")
	}
	var calls int32
	s, socketPath, cleanup := startTestServer(t, time.Minute, &calls)
	defer cleanup()
	wireGrantResolver(s, sealGrantSecret(t, "jamf/api-pass", "mcp", bytes.Repeat([]byte{0x07}, 32)))
	fetcher := &fakeFetcher{key: bytes.Repeat([]byte{0x42}, 32), calls: &calls}
	s.newFetcher = func() MEKFetcher { return fetcher }

	c := NewClient(socketPath)
	if _, err := c.GrantCreate(root, "claude", []string{"jamf"}, "", time.Hour); err == nil || !strings.Contains(err.Error(), "ancestor") {
		t.Fatalf("implicit anchor on a foreign root = %v, want the ancestry refusal (the rule is unchanged for ordinary callers)", err)
	}
	g, err := c.GrantCreateUnderRoot(root, "claude", []string{"jamf"}, "", time.Hour)
	if err != nil {
		t.Fatalf("GrantCreateUnderRoot: %v", err)
	}
	if g.Anchor == "" || g.Name != "claude" {
		t.Errorf("grant = %+v, want a tree grant named claude under a named anchor", g)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("prompted %d times, want 1", got)
	}
	fetcher.mu.Lock()
	reason := strings.Join(fetcher.reasons, " | ")
	fetcher.mu.Unlock()
	if !strings.Contains(reason, " asks: let claude under ") {
		t.Errorf("prompt = %q, want it to name the requester and the tree", reason)
	}
}

func TestGrantCreateReasonWithRequesterFitsTheBudget(t *testing.T) {
	r := grantCreateReason("claude-code-agent", "WezTerm-gui-app", []string{"jamf-production", "aws-ci"}, 12, 167*time.Hour+59*time.Minute, "JitPassApp", false)
	if n := utf8.RuneCountInString(r); n > maxReasonLen {
		t.Errorf("reason is %d runes, over maxReasonLen %d: %q", n, maxReasonLen, r)
	}
	if !strings.HasPrefix(r, "JitPass… asks: let claude-… under WezTerm… use 12 secrets") {
		t.Errorf("reason = %q", r)
	}
}

// foreignSessionRoot finds a same-user process that launchd started and
// that is NOT this test's own session root: any user agent will do.
func foreignSessionRoot(t *testing.T) (int32, bool) {
	t.Helper()
	own, _ := lineage.SessionRoot(int32(os.Getpid())) // #nosec G115 -- test pid
	out, err := exec.Command("ps", "-axo", "pid=,ppid=,uid=").Output()
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) != 3 || f[1] != "1" || f[2] != strconv.Itoa(os.Getuid()) {
			continue
		}
		pid, err := strconv.Atoi(f[0])
		if err != nil || int32(pid) == own.PID || pid == os.Getpid() { // #nosec G115 -- ps output
			continue
		}
		if lineage.IsSessionRoot(int32(pid)) { // #nosec G115 -- ps output
			return int32(pid), true // #nosec G115 -- ps output
		}
	}
	return 0, false
}
