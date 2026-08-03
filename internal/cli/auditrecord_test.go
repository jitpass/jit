// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"strings"
	"testing"
)

// TestSanitizeInvocationArgsVaultSet checks that `jit vault set` masks the
// value ONLY when a value was actually passed on the command line. With the
// value coming from the prompt or --stdin (one positional), the last token is
// the secret's PATH, and masking it would strip exactly the fact the audit log
// exists to keep: which secret was set.
func TestSanitizeInvocationArgsVaultSet(t *testing.T) {
	const cmd = "jit vault set"
	cases := []struct {
		name        string
		rawArgs     []string
		positionals []string
		parsedOK    bool
		wantLast    string // expected final recorded token
		wantMasked  bool
	}{
		{
			name:        "value on the command line is masked",
			rawArgs:     []string{"vault", "set", "stripe/live-key", "hunter2"},
			positionals: []string{"stripe/live-key", "hunter2"},
			parsedOK:    true,
			wantLast:    "<redacted>",
			wantMasked:  true,
		},
		{
			name:        "value from prompt or stdin keeps the path",
			rawArgs:     []string{"vault", "set", "stripe/live-key"},
			positionals: []string{"stripe/live-key"},
			parsedOK:    true,
			wantLast:    "stripe/live-key",
			wantMasked:  false,
		},
		{
			name:        "stdin flag before the path keeps the path",
			rawArgs:     []string{"vault", "set", "--stdin", "stripe/live-key"},
			positionals: []string{"stripe/live-key"},
			parsedOK:    true,
			wantLast:    "stripe/live-key",
			wantMasked:  false,
		},
		{
			name:        "value present with a trailing flag still masks the value",
			rawArgs:     []string{"vault", "set", "stripe/live-key", "hunter2", "--force"},
			positionals: []string{"stripe/live-key", "hunter2"},
			parsedOK:    true,
			wantLast:    "--force",
			wantMasked:  true,
		},
		{
			// A mistyped flag before the positionals fails parsing, so cobra
			// reports NO positionals even though a weak value is present. The
			// mask must still fire — inferring "no value" from the empty slice
			// would log the secret in the clear.
			name:        "parse error with a value still masks it",
			rawArgs:     []string{"vault", "set", "--stdim", "stripe/live-key", "hunter2"},
			positionals: nil,
			parsedOK:    false,
			wantLast:    "<redacted>",
			wantMasked:  true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitizeInvocationArgs(cmd, tc.rawArgs, tc.positionals, tc.parsedOK)
			if got[len(got)-1] != tc.wantLast {
				t.Errorf("last token = %q, want %q (got %v)", got[len(got)-1], tc.wantLast, got)
			}
			joined := strings.Join(got, " ")
			if tc.wantMasked && !strings.Contains(joined, "<redacted>") {
				t.Errorf("expected a masked value, got %v", got)
			}
			if !tc.wantMasked && strings.Contains(joined, "<redacted>") {
				t.Errorf("path was masked but no value was passed: %v", got)
			}
			// The path itself must never be the thing that got redacted.
			if !tc.wantMasked && !strings.Contains(joined, "stripe/live-key") {
				t.Errorf("the secret path was lost from the record: %v", got)
			}
		})
	}
}
