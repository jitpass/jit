// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/iotest"

	"github.com/jitpass/jit/internal/vault"
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

func TestClissoMutatesConfig(t *testing.T) {
	// The families whose subcommands call viper.WriteConfig in clisso —
	// after these run, ~/.clisso.yaml may hold a fresh plaintext secret
	// that the reconcile has to move into the vault.
	for _, args := range [][]string{
		{"apps", "create", "onelogin"},
		{"providers", "create", "onelogin"},
		{"providers", "passwd", "acme"},
		{"cp", "add"},
	} {
		if !parseClissoArgs(args).mutatesConfig() {
			t.Errorf("mutatesConfig(%v) = false, want true", args)
		}
	}
	for _, args := range [][]string{
		{"get", "prod"},
		{"status"},
		{"completion", "zsh"},
		nil,
	} {
		if parseClissoArgs(args).mutatesConfig() {
			t.Errorf("mutatesConfig(%v) = true, want false", args)
		}
	}
}

func TestClissoConfigPathHonorsTheUsersOwnFlag(t *testing.T) {
	// A user-passed -c is their own arrangement; the shim must not
	// override it with its own served config.
	for _, args := range [][]string{
		{"get", "-c", "/tmp/other.yaml"},
		{"get", "--config", "/tmp/other.yaml"},
		{"get", "--config=/tmp/other.yaml"},
		{"-c", "/tmp/other.yaml", "get", "prod"},
	} {
		if got := parseClissoArgs(args).configPath; got != "/tmp/other.yaml" {
			t.Errorf("parseClissoArgs(%v).configPath = %q, want /tmp/other.yaml", args, got)
		}
	}
	if got := parseClissoArgs([]string{"get", "prod", "--cache-enable"}).configPath; got != "" {
		t.Errorf("configPath = %q, want empty — nothing here is -c/--config", got)
	}
}

func TestParseClissoArgsFindsSubcommandPastGlobalFlags(t *testing.T) {
	// cobra lets persistent flags precede the subcommand — verified against
	// the real clisso binary (`clisso --log-level warn apps ls` works). A
	// `get` the shim fails to recognize passes through unwrapped and clisso
	// writes plaintext credentials, so this is the regression that matters
	// most in this file.
	cases := []struct {
		name string
		args []string
		sub  string
		app  string
	}{
		{"bare", []string{"get", "prod"}, "get", "prod"},
		{"global flag first", []string{"--log-level", "debug", "get", "prod"}, "get", "prod"},
		{"global equals-form first", []string{"--log-level=debug", "get", "prod"}, "get", "prod"},
		{"config first", []string{"-c", "/tmp/x.yaml", "get", "stage"}, "get", "stage"},
		{"two globals first", []string{"--log-file", "/tmp/l", "--log-level", "warn", "get", "prod"}, "get", "prod"},
		{"mutating past a global", []string{"--log-level", "warn", "providers", "create"}, "providers", "create"},
	}
	for _, tc := range cases {
		inv := parseClissoArgs(tc.args)
		if inv.sub != tc.sub || inv.app != tc.app {
			t.Errorf("%s: parseClissoArgs(%v) sub/app = (%q, %q), want (%q, %q)", tc.name, tc.args, inv.sub, inv.app, tc.sub, tc.app)
		}
	}

	// The whole point: these are now capturable.
	for _, args := range [][]string{
		{"--log-level", "debug", "get", "prod"},
		{"--log-level=debug", "get", "prod"},
	} {
		app, capturable := clissoCaptureApp(args)
		if !capturable || app != "prod" {
			t.Errorf("clissoCaptureApp(%v) = (%q, %v), want (prod, true)", args, app, capturable)
		}
	}
	// And a mutating family behind a global flag still reconciles.
	if !parseClissoArgs([]string{"--log-level", "warn", "providers", "create"}).mutatesConfig() {
		t.Error("providers behind a global flag must still count as config-mutating")
	}
}

func TestClissoCaptureAppEveryExplicitOutputOptsOut(t *testing.T) {
	// clisso marks --output, --write-to-file and --shell mutually
	// exclusive, so injecting our --output alongside one wouldn't override
	// the user's choice — clisso would refuse to run at all.
	for _, args := range [][]string{
		{"get", "prod", "-o", "environment"},
		{"get", "prod", "--output=environment"},
		{"get", "prod", "-w", "/tmp/creds"},
		{"get", "prod", "--write-to-file", "/tmp/creds"},
		{"get", "prod", "-s"},
		{"get", "prod", "--shell"},
	} {
		if _, capturable := clissoCaptureApp(args); capturable {
			t.Errorf("clissoCaptureApp(%v) = capturable, want passthrough (explicit output choice)", args)
		}
	}
}

func TestStripClissoCacheFlag(t *testing.T) {
	// clisso writes its cache file whenever --cache-enable is set, whatever
	// the output mode — so a captured run must not carry the flag, or it
	// leaves plaintext credentials in ~/.aws/credentials-cache.
	got := stripClissoCacheFlag([]string{"get", "prod", "--cache-enable", "--cache-path", "/tmp/c"})
	want := []string{"get", "prod", "--cache-path", "/tmp/c"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("stripClissoCacheFlag = %v, want %v", got, want)
	}
	if got := stripClissoCacheFlag([]string{"get", "--cache-enable=true", "prod"}); len(got) != 2 {
		t.Errorf("equals-form not stripped: %v", got)
	}
	// Detection drives the strip; =false needs neither.
	if !parseClissoArgs([]string{"get", "prod", "--cache-enable"}).cacheEnable {
		t.Error("bare --cache-enable must read as enabled")
	}
	if parseClissoArgs([]string{"get", "prod", "--cache-enable=false"}).cacheEnable {
		t.Error("--cache-enable=false must read as disabled")
	}
}

func TestMemoizedVaultOpenerOpensOnce(t *testing.T) {
	// Every openVault builds a fresh keychainwrap.Wrapper, and that cache
	// is per instance — so with the agent service unreachable, each extra
	// open is another Touch ID prompt for one `clisso get`. The capture
	// flow asks for the vault up to three times (render the served config,
	// store the session, reconcile); it must open once.
	calls := 0
	var once sync.Once
	var v *vault.Vault
	var err error
	opener := vaultOpener(func() (*vault.Vault, error) {
		once.Do(func() { calls++; v, err = &vault.Vault{}, nil })
		return v, err
	})
	for i := 0; i < 3; i++ {
		if _, oerr := opener(); oerr != nil {
			t.Fatalf("opener: %v", oerr)
		}
	}
	if calls != 1 {
		t.Errorf("underlying open called %d times, want 1", calls)
	}

	// And the real constructor must memoize the same way: three calls,
	// one result, identical pointer.
	real := memoizedVaultOpener()
	a, aErr := real()
	b, bErr := real()
	if a != b {
		t.Errorf("memoizedVaultOpener returned different vaults (%p vs %p); each open is a Touch ID prompt", a, b)
	}
	if (aErr == nil) != (bErr == nil) {
		t.Errorf("memoized opener disagreed with itself on error: %v vs %v", aErr, bErr)
	}
}
