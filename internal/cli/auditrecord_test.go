// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"strings"
	"testing"

	"github.com/spf13/pflag"

	"github.com/jitpass/jit/internal/auditlog"
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

// auditlog.MaskVaultSetValues is the ONE vault-set grammar both producers
// share — sanitizeInvocationArgs for jit's own os.Args, RedactCommandLine
// for a recorded By. Its flag knowledge (VaultSetBooleanFlags) is what lets
// it keep real flags legible while masking a dash-prefixed value, so it must
// track the real command: every flag vault set defines (its own and the
// root's persistent ones) must be listed, boolean, and nothing extra may be
// listed. A non-boolean flag added to vault set would break the grammar's
// core assumption — fail loudly here, not silently over-mask in the log.
func TestVaultSetGrammarMatchesCommand(t *testing.T) {
	seen := map[string]bool{}
	collect := func(fs *pflag.FlagSet) {
		fs.VisitAll(func(f *pflag.Flag) {
			if f.Name == "help" {
				return
			}
			if f.Value.Type() != "bool" {
				t.Errorf("vault set flag --%s is %s, not bool: MaskVaultSetValues assumes every flag is boolean (a flag's detached value would be masked as a secret) — rethink the grammar before adding it", f.Name, f.Value.Type())
			}
			seen["--"+f.Name] = true
			if f.Shorthand != "" {
				seen["-"+f.Shorthand] = true
			}
		})
	}
	collect(vaultSetCmd.Flags())
	collect(vaultSetCmd.Root().PersistentFlags())
	for tok := range seen {
		if !auditlog.VaultSetBooleanFlags[tok] {
			t.Errorf("vault set defines %s but auditlog.VaultSetBooleanFlags does not list it — the grammar would mask it as a value (over-masking, but fix the list)", tok)
		}
	}
	for tok := range auditlog.VaultSetBooleanFlags {
		if !seen[tok] {
			t.Errorf("auditlog.VaultSetBooleanFlags lists %s but vault set defines no such flag — a value spelled like it would be kept in the clear", tok)
		}
	}
}

// The parse-error fallback and the shared grammar must agree that EVERY
// token past the path is masked — the first review caught them disagreeing
// on `hunter2 extra`, where only the last token was masked and the actual
// mis-pasted value survived into the durable log.
func TestSanitizeInvocationArgsMasksEveryValuePastThePath(t *testing.T) {
	got := sanitizeInvocationArgs("jit vault set",
		[]string{"vault", "set", "stripe/key", "hunter2", "extra"},
		nil, false)
	want := []string{"vault", "set", "stripe/key", "<redacted>", "<redacted>"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v — a mis-pasted value must not outlive the mask", got, want)
		}
	}
}
