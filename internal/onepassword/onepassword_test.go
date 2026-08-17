// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package onepassword

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeOp writes an executable script standing in for the op binary and
// returns its path. Tests drive Resolver through a real exec, exactly as
// production does — only the binary and the signature check are fakes.
func fakeOp(t *testing.T, script string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "op")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script), 0o755); err != nil { // #nosec G306 -- a test's fake executable must be executable
		t.Fatalf("writing fake op: %v", err)
	}
	return path
}

func noVerify(string) error { return nil }

func TestResolveRefReturnsExactBytes(t *testing.T) {
	// printf, not echo: the whole point of `op read -n` is byte-exactness,
	// so the fake must not append a newline either.
	r := &Resolver{
		path: fakeOp(t, `
if [ "$1" != "read" ] || [ "$2" != "-n" ]; then
  echo "unexpected arguments: $*" >&2
  exit 2
fi
printf 'value-no-trailing-newline'
`),
		verify: noVerify,
	}
	got, err := r.ResolveRef("op://vaultid/itemid/fieldid")
	if err != nil {
		t.Fatalf("ResolveRef: %v", err)
	}
	if string(got) != "value-no-trailing-newline" {
		t.Errorf("ResolveRef = %q, want exact bytes with no trailing newline", got)
	}
}

func TestResolveRefSurfacesStderrFirstLine(t *testing.T) {
	r := &Resolver{
		path: fakeOp(t, `
echo '[ERROR] 2026/08/17 account is not signed in' >&2
echo 'second line of advice' >&2
exit 1
`),
		verify: noVerify,
	}
	_, err := r.ResolveRef("op://vaultid/itemid/fieldid")
	if err == nil {
		t.Fatal("ResolveRef succeeded, want op's failure surfaced")
	}
	if !strings.Contains(err.Error(), "not signed in") {
		t.Errorf("error %q does not carry op's stderr", err)
	}
	if strings.Contains(err.Error(), "second line") {
		t.Errorf("error %q carries more than the first stderr line", err)
	}
}

func TestResolveRefTimesOutOnAHungOp(t *testing.T) {
	r := &Resolver{
		path:    fakeOp(t, "sleep 10\n"),
		verify:  noVerify,
		timeout: 200 * time.Millisecond,
	}
	start := time.Now()
	_, err := r.ResolveRef("op://vaultid/itemid/fieldid")
	if err == nil {
		t.Fatal("ResolveRef succeeded, want a timeout")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("error %q does not name the timeout", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("ResolveRef took %s, the timeout did not bound the wait", elapsed)
	}
}

func TestResolveRefRejectsBadReferencesWithoutExec(t *testing.T) {
	// path points at a script that would fail loudly if run: a rejected
	// reference must never cost an exec.
	r := &Resolver{path: fakeOp(t, "echo 'must not run' >&2; exit 3\n"), verify: noVerify}
	for _, ref := range []string{
		"https://example.com/not/op",
		"op://",
		"op://vault-only",
		"op://vault/item-only",
		"not a reference at all",
		"",
	} {
		if _, err := r.ResolveRef(ref); err == nil {
			t.Errorf("ResolveRef(%q) succeeded, want a validation error", ref)
		} else if strings.Contains(err.Error(), "must not run") {
			t.Errorf("ResolveRef(%q) exec-ed op before validating", ref)
		}
	}
}

func TestValidateRefAcceptsRealShapes(t *testing.T) {
	for _, ref := range []string{
		"op://vault/item/field",
		"op://vaultid123/itemid456/fieldid789",
		"op://dev/GitHub/credentials/personal_token",       // section form
		"op://Private/Stripe/key?attribute=otp",            // query parameter
		"op://app-prod/ssh/private key?ssh-format=openssh", // space + query
	} {
		if err := ValidateRef(ref); err != nil {
			t.Errorf("ValidateRef(%q) = %v, want accepted", ref, err)
		}
	}
}

func TestVerifyFailsClosedBeforeFirstExec(t *testing.T) {
	ran := filepath.Join(t.TempDir(), "ran")
	r := &Resolver{
		path:   fakeOp(t, "touch "+ran+"\n"),
		verify: func(string) error { return os.ErrPermission },
	}
	if _, err := r.ResolveRef("op://vaultid/itemid/fieldid"); err == nil {
		t.Fatal("ResolveRef succeeded under a failing signature check")
	}
	if _, err := os.Stat(ran); err == nil {
		t.Fatal("op was exec-ed despite the signature check failing")
	}
}

func TestSignatureRequirementFormIsInline(t *testing.T) {
	req := signatureRequirement()
	if !strings.HasPrefix(req, "=") {
		t.Errorf("requirement %q lacks the leading '=' codesign needs for an inline requirement", req)
	}
	for _, want := range []string{
		"anchor apple generic",
		"1.2.840.113635.100.6.2.6",  // Developer ID intermediate CA marker
		"1.2.840.113635.100.6.1.13", // Developer ID Application leaf marker
		`subject.OU] = "` + opTeamID + `"`,
	} {
		if !strings.Contains(req, want) {
			t.Errorf("requirement %q is missing %q", req, want)
		}
	}
}

// TestRealOpBinaryPassesVerification pins the opTeamID constant against
// the actually-shipping 1Password CLI wherever one is installed (skipped
// elsewhere, including CI): if AgileBits ever re-issues under a new team,
// this is the test that says so.
func TestRealOpBinaryPassesVerification(t *testing.T) {
	path, err := exec.LookPath("op")
	if err != nil {
		t.Skip("op is not installed on this machine")
	}
	if err := verifySignature(path); err != nil {
		t.Errorf("the installed op at %s fails verification: %v", path, err)
	}
}
