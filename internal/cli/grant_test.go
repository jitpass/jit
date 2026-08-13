// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jitpass/jit/internal/agent"
	"github.com/jitpass/jit/internal/auditlog"
	"github.com/jitpass/jit/internal/vault"
)

func TestParseGrantFor(t *testing.T) {
	if _, err := parseGrantFor("banana"); err == nil {
		t.Error("parseGrantFor(banana) succeeded, want an error naming the grammar")
	}
	if _, err := parseGrantFor("30s"); err == nil {
		t.Error("parseGrantFor(30s) succeeded, want the 1m-minimum error")
	}
	if _, err := parseGrantFor("30d"); err == nil {
		t.Error("parseGrantFor(30d) succeeded, want the 7d-maximum error: a typo must fail loudly, not mint a month")
	}
	for in, want := range map[string]time.Duration{
		"45m": 45 * time.Minute,
		"8h":  8 * time.Hour,
		"3d":  3 * 24 * time.Hour,
		"1w":  7 * 24 * time.Hour,
	} {
		got, err := parseGrantFor(in)
		if err != nil || got != want {
			t.Errorf("parseGrantFor(%s) = %v, %v; want %v", in, got, err, want)
		}
	}
}

func TestGrantRemaining(t *testing.T) {
	now := time.Now()
	for want, at := range map[string]time.Time{
		"45m":   now.Add(45*time.Minute + 30*time.Second),
		"6h12m": now.Add(6*time.Hour + 12*time.Minute + 20*time.Second),
		"3d2h":  now.Add(3*24*time.Hour + 2*time.Hour + time.Minute),
		"0m":    now.Add(-time.Minute),
	} {
		if got := grantRemaining(at.Unix()); got != want {
			t.Errorf("grantRemaining(%s from now) = %q, want %q", time.Until(at).Round(time.Minute), got, want)
		}
	}
}

func TestResolveGrantSecretsResolvesProfilesToWrappedDEKs(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	root := filepath.Join(home, "Library", "Application Support", "jitpass")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}

	// A vault with two secrets and a global profile naming them both — one of
	// them twice, which must not produce a duplicate grant entry.
	deviceID, err := vault.EnsureDeviceID(root)
	if err != nil {
		t.Fatal(err)
	}
	v := &vault.Vault{Root: root, KeyWrapper: grantTestWrapper{}, RecipientID: deviceID}
	if err := v.SetWithMeta("jamf/api-user", []byte("u"), vault.Meta{Class: vault.ClassMCP}); err != nil {
		t.Fatal(err)
	}
	if err := v.SetWithMeta("jamf/api-pass", []byte("p"), vault.Meta{Class: vault.ClassMCP}); err != nil {
		t.Fatal(err)
	}
	profilesDir := filepath.Join(home, ".jit", "profiles")
	if err := os.MkdirAll(profilesDir, 0o700); err != nil {
		t.Fatal(err)
	}
	manifest := "JAMF_USER: jamf/api-user\nJAMF_PASS: jamf/api-pass\nJAMF_AGAIN: jamf/api-pass\n"
	if err := os.WriteFile(filepath.Join(profilesDir, "jamf.yaml"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := resolveGrantSecrets(root)([]string{"jamf"}, "")
	if err != nil {
		t.Fatalf("resolveGrantSecrets: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("resolved %d secrets, want 2 (deduplicated): %+v", len(got), got)
	}
	for _, sec := range got {
		if sec.Class != vault.ClassMCP {
			t.Errorf("%s: class %q, want %q", sec.Path, sec.Class, vault.ClassMCP)
		}
		if len(sec.Wrapped) == 0 {
			t.Errorf("%s: empty wrapped DEK", sec.Path)
		}
	}

	if _, err := resolveGrantSecrets(root)([]string{"nope"}, ""); err == nil {
		t.Error("unknown profile resolved, want an error naming the files checked")
	}
}

// grantTestWrapper is a no-op KeyWrapper: resolveGrantSecrets itself never
// unwraps (that is the point — resolution cannot prompt), so the test wrapper
// only has to let SetWithMeta write envelopes.
type grantTestWrapper struct{}

func (grantTestWrapper) WrapKey(dek []byte) ([]byte, error)       { return append([]byte("w:"), dek...), nil }
func (grantTestWrapper) UnwrapKey(wrapped []byte) ([]byte, error) { return wrapped[2:], nil }

func TestCompleteGrantProcessNamesReadsAuditTrails(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	root := filepath.Join(home, "Library", "Application Support", "jitpass")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}

	// One recent caller in each trail, one stale (outside 24h), and jit
	// itself (excluded always).
	logger := auditlog.New(root, io.Discard)
	logger.Append(auditlog.Record{UnixNano: time.Now().UnixNano(), Command: "jit run", LaunchedBy: "claude"})
	logger.Append(auditlog.Record{UnixNano: time.Now().Add(-30 * time.Hour).UnixNano(), Command: "jit run", LaunchedBy: "ancient-tool"})
	logger.Append(auditlog.Record{UnixNano: time.Now().UnixNano(), Command: "jit scan", LaunchedBy: "jit"})
	histLine, err := json.Marshal(agent.SessionEvent{UnixTime: time.Now().Unix(), Kind: agent.KindUse, LaunchedBy: "terraform"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, historyFileName), append(histLine, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	out, directive := completeGrantProcessNames(nil, nil, "")
	if directive != 4 { // cobra.ShellCompDirectiveNoFileComp
		t.Errorf("directive = %d, want NoFileComp", directive)
	}
	joined := strings.Join(out, "\n")
	for _, want := range []string{"claude\t", "terraform\t"} {
		if !strings.Contains(joined, want) {
			t.Errorf("completions missing %q:\n%s", want, joined)
		}
	}
	for _, reject := range []string{"ancient-tool", "jit\t"} {
		if strings.Contains(joined, reject) {
			t.Errorf("completions include %q (stale or jit itself):\n%s", reject, joined)
		}
	}
	// This test process is running, so its own name annotates as running —
	// covered implicitly; here just assert every entry carries a description.
	for _, entry := range out {
		if !strings.Contains(entry, "\tasked ") {
			t.Errorf("completion entry %q lacks a description", entry)
		}
	}
}

func TestGrantListRendering(t *testing.T) {
	var b strings.Builder
	// Rendering is exercised through the exported pieces it is made of; the
	// full command needs a live agent. Two grants: one live, one whose root
	// died, so both glyph rows exist.
	grants := []agent.GrantStatus{
		{ID: "g-7f3a2c81", Name: "claude", Profiles: []string{"jamf"}, Secrets: []string{"a", "b"},
			ExpiresUnix: time.Now().Add(6 * time.Hour).Unix(), Serves: 4, RootAlive: true},
		{ID: "g-2c91aa00", Name: "terraform", Profiles: []string{"aws-ci"}, Secrets: []string{"c"},
			ExpiresUnix: time.Now().Add(24 * time.Hour).Unix(), RootAlive: false},
		{ID: "g-55e01b2d", Name: "claude", Anchor: "iTerm2", Profiles: []string{"jamf"}, Secrets: []string{"a"},
			ExpiresUnix: time.Now().Add(time.Hour).Unix(), RootAlive: false},
	}
	renderGrantRows(&b, grants)
	out := b.String()
	// The dead-anchor wording depends on the grant's shape: an exact grant's
	// root is the process itself ("process exited"), a tree grant's is the
	// terminal it hangs under ("terminal closed").
	for _, want := range []string{"[Grants] 3", "g-7f3a2c81", "4 serves", "process exited, ending", "terminal closed, ending", "unused"} {
		if !strings.Contains(out, want) {
			t.Errorf("grant list output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\t") {
		t.Error("grant list uses tabs; columns are whitespace-padded in the house style")
	}
}

// TestResolveGrantTargetTreeMode: --process anchors to this session's root
// with the name as the filter — no live match required, no disambiguation —
// while --pid stays the exact-one-process mode.
func TestResolveGrantTargetTreeMode(t *testing.T) {
	grantPIDFlag, grantProcess = 0, "claude"
	defer func() { grantProcess = "" }()
	target, err := resolveGrantTarget()
	if err != nil {
		t.Skipf("no session root above this test process (bare runner): %v", err)
	}
	if target.name != "claude" {
		t.Errorf("tree target name = %q, want claude", target.name)
	}
	self := int32(os.Getpid()) // #nosec G115 -- test pid
	if target.anchor.PID <= 1 || target.anchor.PID == self {
		t.Errorf("tree anchor pid = %d, want a proper ancestor of the CLI", target.anchor.PID)
	}
}

// TestGrantCreatedShowsTreeScope: a tree grant's confirmation must state its
// perimeter (name under anchor) and the granting-ahead fact when nothing
// matches yet; an exact grant's must not carry a scope line at all.
func TestGrantCreatedShowsTreeScope(t *testing.T) {
	var b strings.Builder
	printGrantCreated(&b, agent.GrantStatus{ID: "g-1", Name: "claude", Anchor: "iTerm2",
		PID: 999999998, Profiles: []string{"jamf"}, Secrets: []string{"jamf/api"},
		ExpiresUnix: time.Now().Add(time.Hour).Unix()})
	out := b.String()
	if !strings.Contains(out, "covers claude under iTerm2") {
		t.Errorf("tree confirmation lacks the scope line:\n%s", out)
	}
	if !strings.Contains(out, "none running yet") {
		t.Errorf("tree confirmation with no live match must say it grants ahead:\n%s", out)
	}
	b.Reset()
	printGrantCreated(&b, agent.GrantStatus{ID: "g-2", Name: "claude", PID: 123,
		Profiles: []string{"jamf"}, Secrets: []string{"jamf/api"},
		ExpiresUnix: time.Now().Add(time.Hour).Unix()})
	if strings.Contains(b.String(), "covers") {
		t.Errorf("exact-grant confirmation must not carry a tree scope line:\n%s", b.String())
	}
}

// Double-tab on the bare command must surface the CREATE path next to the
// subcommands, and an id completion with nothing to offer must say why and
// what to do - both were real user reports: create was invisible at the
// moment of discovery, and `extend <Tab>` with no grants was dead silence.
func TestGrantCompletionSurfacesCreatePath(t *testing.T) {
	comps, _ := completeGrantCreateEntry(nil, nil, "")
	joined := strings.Join(comps, "\n")
	if !strings.Contains(joined, "--process\t") {
		t.Errorf("bare-command completion does not offer --process:\n%s", joined)
	}
	if !strings.Contains(joined, grantCreateUsage) {
		t.Errorf("bare-command completion lacks the create usage line:\n%s", joined)
	}
	if got, _ := completeGrantCreateEntry(nil, []string{"list"}, ""); got != nil {
		t.Errorf("completion after an argument = %v, want nothing", got)
	}
}

func TestGrantForCompletionSaysFreeForm(t *testing.T) {
	comps, _ := completeGrantFor(nil, nil, "")
	joined := strings.Join(comps, "\n")
	if !strings.Contains(joined, "7d") {
		t.Errorf("--for completion omits the 7d maximum:\n%s", joined)
	}
	if !strings.Contains(joined, "any duration up to 7d") {
		t.Errorf("--for completion reads as a closed list, missing the free-form hint:\n%s", joined)
	}
}

func TestGrantIDCompletionExplainsAnUnreachableService(t *testing.T) {
	t.Setenv("HOME", t.TempDir()) // no service socket under this root
	comps, _ := completeGrantIDs(nil, nil, "")
	joined := strings.Join(comps, "\n")
	if !strings.Contains(joined, "service is not running") {
		t.Errorf("id completion with no service = %q, want an active-help explanation", joined)
	}
}

// A bare `jit grant` is discovery, not a forgotten flag: the error must show
// the whole create shape, not just the first missing piece.
func TestBareGrantErrorShowsTheWholeShape(t *testing.T) {
	grantProcess, grantPIDFlag, grantProfileNames, grantFor = "", 0, nil, ""
	err := runGrantCreate(io.Discard)
	if err == nil || !strings.Contains(err.Error(), grantCreateUsage) {
		t.Errorf("bare grant error = %v, want it to quote %q", err, grantCreateUsage)
	}
}

func TestGrantClockAxes(t *testing.T) {
	now := time.Now()
	if now.Hour() >= 22 { // near midnight the "same day" fixture isn't; skip the ambiguity
		t.Skip("too close to midnight for stable same-day fixtures")
	}
	if got := grantClock(now.Add(time.Minute).Unix()); len(got) != 5 || !strings.Contains(got, ":") {
		t.Errorf("same-day expiry = %q, want bare clock time (15:04)", got)
	}
	if got := grantClock(now.Add(3 * 24 * time.Hour).Unix()); !strings.Contains(got, " ") {
		t.Errorf("multi-day expiry = %q, want a day marker before the clock", got)
	}
}
