// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"
)

// clissoJSON is byte-for-byte the shape clisso's OutputCredentialProcess
// prints: spaces inside the braces, no trailing newline.
const clissoJSON = `{ "Version": 1, "AccessKeyId": "ASIAEXAMPLE123", "SecretAccessKey": "secretexample456", "SessionToken": "tokexample789", "Expiration": "2026-07-29T19:00:11Z" }`

func TestCaptureFilterCapturesJSONAndEchoesPrompts(t *testing.T) {
	// The realistic stream: MFA prompt without a trailing newline, a menu,
	// then the JSON at EOF (clisso prints it with no newline).
	input := "Please choose an MFA device to authenticate with (1-2): " +
		"\nPlease enter the OTP from your MFA device: " +
		"\n" + clissoJSON
	var echoed bytes.Buffer
	session, captured, err := captureFilter(strings.NewReader(input), &echoed)
	if err != nil {
		t.Fatalf("captureFilter: %v", err)
	}
	if !captured {
		t.Fatal("expected the credential JSON captured")
	}
	if session.AccessKeyID != "ASIAEXAMPLE123" || session.SecretAccessKey != "secretexample456" ||
		session.SessionToken != "tokexample789" || session.Expiration != "2026-07-29T19:00:11Z" {
		t.Errorf("session = %+v, want the four JSON fields", session)
	}
	out := echoed.String()
	if !strings.Contains(out, "OTP from your MFA device") || !strings.Contains(out, "choose an MFA device") {
		t.Errorf("prompts must pass through, got: %q", out)
	}
	if strings.Contains(out, "secretexample456") || strings.Contains(out, "ASIAEXAMPLE123") {
		t.Errorf("credential JSON leaked to the terminal: %q", out)
	}
}

func TestCaptureFilterSurvivesOneBytereads(t *testing.T) {
	// Chunk boundaries are the state machine's whole risk; a one-byte
	// reader forces every boundary at once.
	input := "line one\n" + clissoJSON + "\nline two\n"
	var echoed bytes.Buffer
	_, captured, err := captureFilter(iotest.OneByteReader(strings.NewReader(input)), &echoed)
	if err != nil {
		t.Fatalf("captureFilter: %v", err)
	}
	if !captured {
		t.Fatal("expected capture across one-byte reads")
	}
	if got, want := echoed.String(), "line one\nline two\n"; got != want {
		t.Errorf("echoed = %q, want %q (JSON and its newline swallowed, everything else intact)", got, want)
	}
}

func TestCaptureFilterFlushesNonCredentialBraceLines(t *testing.T) {
	// A '{'-opening line that isn't the credential shape must reach the
	// terminal unchanged, newline included.
	input := "{\"not\": \"credentials\"}\nplain\n"
	var echoed bytes.Buffer
	_, captured, err := captureFilter(strings.NewReader(input), &echoed)
	if err != nil {
		t.Fatalf("captureFilter: %v", err)
	}
	if captured {
		t.Fatal("nothing to capture here")
	}
	if got := echoed.String(); got != input {
		t.Errorf("echoed = %q, want the input byte-for-byte %q", got, input)
	}
}

func TestClissoCaptureApp(t *testing.T) {
	cases := []struct {
		name string
		args []string
		app  string
		ok   bool
	}{
		{"plain get", []string{"get", "prod"}, "prod", true},
		{"flags with values skipped", []string{"get", "--mfa-device", "push", "prod"}, "prod", true},
		{"equals-form flag", []string{"get", "--log-level=debug", "stage"}, "stage", true},
		{"explicit output opts out", []string{"get", "prod", "-o", "environment"}, "", false},
		{"explicit output equals-form opts out", []string{"get", "--output=environment", "prod"}, "", false},
		{"help opts out", []string{"get", "-h"}, "", false},
		{"other subcommand", []string{"apps", "list"}, "", false},
		{"providers passwd", []string{"providers", "passwd", "acme"}, "", false},
		{"empty", nil, "", false},
	}
	for _, tc := range cases {
		app, ok := clissoCaptureApp(tc.args)
		if app != tc.app || ok != tc.ok {
			t.Errorf("%s: clissoCaptureApp(%v) = (%q, %v), want (%q, %v)", tc.name, tc.args, app, ok, tc.app, tc.ok)
		}
	}
}

func TestClissoCaptureAppSelectedAppFallback(t *testing.T) {
	// Bare `clisso get` uses the config's selected app; the capture must
	// resolve the same name for the vault profile. -c points at a custom
	// config and must be honored.
	dir := t.TempDir()
	cfg := filepath.Join(dir, "custom.yaml")
	if err := os.WriteFile(cfg, []byte("global:\n    selected-app: stage\n"), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}
	app, ok := clissoCaptureApp([]string{"get", "-c", cfg})
	if !ok || app != "stage" {
		t.Errorf("clissoCaptureApp(get -c %s) = (%q, %v), want (stage, true)", cfg, app, ok)
	}

	// No app anywhere: pass through, clisso's own error is the message.
	empty := filepath.Join(dir, "empty.yaml")
	if err := os.WriteFile(empty, []byte(""), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}
	if app, ok := clissoCaptureApp([]string{"get", "-c", empty}); ok {
		t.Errorf("expected passthrough with no app, got (%q, %v)", app, ok)
	}
}
