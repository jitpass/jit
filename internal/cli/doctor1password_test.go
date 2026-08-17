// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/vault"
)

// withDoctorOp pins the op probe seams for one test.
func withDoctorOp(t *testing.T, verified func() (string, error), version func(string) string) {
	t.Helper()
	prevV, prevVer := doctorOpVerified, doctorOpVersion
	doctorOpVerified, doctorOpVersion = verified, version
	t.Cleanup(func() { doctorOpVerified, doctorOpVersion = prevV, prevVer })
}

func TestOnePasswordFindingsMissingCLI(t *testing.T) {
	// InstalledVerified fails AND op is genuinely absent from PATH (the
	// TestMain default probes the real PATH via onepassword.Installed, so
	// clear it for a deterministic "not installed").
	t.Setenv("PATH", t.TempDir())
	withDoctorOp(t, func() (string, error) { return "", errors.New("not installed") }, func(string) string { return "" })

	findings, okLines := onePasswordFindingsFor(3)
	if len(okLines) != 0 {
		t.Errorf("unexpected OK lines: %v", okLines)
	}
	if len(findings) != 1 || findings[0].Kind != kind1Password {
		t.Fatalf("findings = %+v, want one kind1Password", findings)
	}
	if !strings.Contains(findings[0].Detail, "not installed") || !strings.Contains(findings[0].Action, "brew install") {
		t.Errorf("finding %+v does not name the missing CLI and the install step", findings[0])
	}
}

func TestOnePasswordFindingsUnverifiedBinary(t *testing.T) {
	// A binary IS on PATH but fails the signature gate: plant a fake op so
	// onepassword.Installed() sees one.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "op"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil { // #nosec G306 -- a test's fake executable must be executable
		t.Fatalf("writing fake op: %v", err)
	}
	t.Setenv("PATH", dir)
	withDoctorOp(t, func() (string, error) { return "", errors.New("is not a signature-verified 1Password CLI") }, func(string) string { return "" })

	findings, _ := onePasswordFindingsFor(2)
	if len(findings) != 1 || findings[0].Kind != kind1Password {
		t.Fatalf("findings = %+v, want one kind1Password", findings)
	}
	if !strings.Contains(findings[0].Detail, "signature-verified") || !strings.Contains(findings[0].Action, "brew reinstall") {
		t.Errorf("finding %+v does not name the signature failure and the reinstall step", findings[0])
	}
}

func TestOnePasswordFindingsHealthyIsOKLine(t *testing.T) {
	withDoctorOp(t, func() (string, error) { return "/usr/local/bin/op", nil }, func(string) string { return "2.39.0" })

	findings, okLines := onePasswordFindingsFor(3)
	if len(findings) != 0 {
		t.Errorf("healthy setup produced findings: %+v", findings)
	}
	if len(okLines) != 1 {
		t.Fatalf("okLines = %v, want exactly one", okLines)
	}
	for _, want := range []string{"3 secrets linked to 1Password", "op 2.39.0 signature-verified", "--1password"} {
		if !strings.Contains(okLines[0], want) {
			t.Errorf("OK line %q missing %q", okLines[0], want)
		}
	}
}

func TestSweepOpLinks(t *testing.T) {
	stored := map[string]struct {
		ref     string
		storage string
	}{
		"myapp/GOOD":    {"op://v/i/f1", vault.StorageOpRef},
		"myapp/DEAD":    {"op://Personal/Gone/password", vault.StorageOpRef},
		"myapp/LITERAL": {"plain-value", ""},
	}
	var resolvedValue []byte
	getStored := func(p string) ([]byte, string, error) {
		if p == "myapp/UNREADABLE" {
			return nil, "", errors.New("corrupt envelope")
		}
		s := stored[p]
		return []byte(s.ref), s.storage, nil
	}
	resolve := func(ref string) ([]byte, error) {
		if strings.Contains(ref, "Gone") {
			return nil, errors.New(`"Gone" isn't an item in the "Personal" vault`)
		}
		resolvedValue = []byte("live-secret-value")
		return resolvedValue, nil
	}

	findings, checked, ok := sweepOpLinks([]string{"myapp/GOOD", "myapp/DEAD", "myapp/LITERAL", "myapp/UNREADABLE"}, getStored, resolve)

	// LITERAL was rotated to a plain value since the listing: not checked.
	if checked != 3 || ok != 1 {
		t.Errorf("checked=%d ok=%d, want 3 checked (literal skipped) and 1 ok", checked, ok)
	}
	if len(findings) != 2 {
		t.Fatalf("findings = %+v, want the dead link and the unreadable envelope", findings)
	}
	var dead *checkFinding
	for i := range findings {
		if findings[i].Path == "myapp/DEAD" {
			dead = &findings[i]
		}
	}
	if dead == nil || dead.Kind != kind1PasswordLink {
		t.Fatalf("no kind1PasswordLink finding for the dead link: %+v", findings)
	}
	if !strings.Contains(dead.Detail, "does not resolve") || !strings.Contains(dead.Action, "jit vault link myapp/DEAD") {
		t.Errorf("dead-link finding %+v missing the diagnosis or the relink action", *dead)
	}
	// The sweep proves resolvability and must not keep what it proved.
	if !bytes.Equal(resolvedValue, make([]byte, len(resolvedValue))) {
		t.Error("resolved value was not wiped after the check")
	}
}
