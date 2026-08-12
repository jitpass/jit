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
	}
	renderGrantRows(&b, grants)
	out := b.String()
	for _, want := range []string{"[Grants] 2", "g-7f3a2c81", "4 serves", "process exited, ending", "unused"} {
		if !strings.Contains(out, want) {
			t.Errorf("grant list output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\t") {
		t.Error("grant list uses tabs; columns are whitespace-padded in the house style")
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
