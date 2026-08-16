// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package auditlog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAppendAndLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	l := New(dir, nil)

	l.Append(Record{UnixNano: 1, Command: "jit scan", User: "alice", UID: 501, PID: 10, Success: true})
	l.Append(Record{UnixNano: 2, Command: "jit vault get", User: "alice", UID: 501, PID: 11, Success: false, Error: "no secret"})

	got := l.Load(0)
	if len(got) != 2 {
		t.Fatalf("Load returned %d records, want 2", len(got))
	}
	if got[0].Command != "jit scan" || got[1].Command != "jit vault get" {
		t.Errorf("records out of append order: %+v", got)
	}
	if got[1].Success || got[1].Error != "no secret" {
		t.Errorf("failure record round-tripped wrong: %+v", got[1])
	}
}

func TestLoadReturnsNewestMax(t *testing.T) {
	dir := t.TempDir()
	l := New(dir, nil)
	for i := 0; i < 5; i++ {
		l.Append(Record{UnixNano: int64(i), Command: "jit status", PID: i})
	}
	got := l.Load(2)
	if len(got) != 2 {
		t.Fatalf("Load(2) returned %d records, want 2", len(got))
	}
	// Newest two, still oldest-first within the window.
	if got[0].PID != 3 || got[1].PID != 4 {
		t.Errorf("Load(2) returned the wrong window: pids %d,%d want 3,4", got[0].PID, got[1].PID)
	}
}

func TestLoadMissingFileIsEmptyNotError(t *testing.T) {
	l := New(t.TempDir(), nil)
	if got := l.Load(0); got != nil {
		t.Errorf("Load on a fresh dir returned %+v, want nil", got)
	}
}

func TestLoadSkipsTornFinalLine(t *testing.T) {
	dir := t.TempDir()
	l := New(dir, nil)
	l.Append(Record{UnixNano: 1, Command: "jit scan"})
	// Simulate a crash mid-append: a partial JSON line with no newline.
	f, err := os.OpenFile(filepath.Join(dir, FileName), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := f.WriteString(`{"command":"jit va`); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = f.Close()

	got := l.Load(0)
	if len(got) != 1 || got[0].Command != "jit scan" {
		t.Errorf("torn line was not skipped cleanly: %+v", got)
	}
}

func TestTrimBoundsTheFile(t *testing.T) {
	dir := t.TempDir()
	l := New(dir, nil)
	// Write well past maxBytes.
	for i := 0; i < 4000; i++ {
		l.Append(Record{UnixNano: int64(i), Command: "jit status", Error: strings.Repeat("x", 100)})
	}
	l.Trim()
	fi, err := os.Stat(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Size() > maxBytes {
		t.Errorf("after Trim the file is %d bytes, want <= %d", fi.Size(), maxBytes)
	}
	// The newest record must survive the trim.
	got := l.Load(0)
	if len(got) == 0 || got[len(got)-1].UnixNano != 3999 {
		t.Errorf("Trim dropped the newest record")
	}
}

func TestRedactMasksSecretLookingTokens(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{
			name: "known prefix, bare",
			in:   []string{"vault", "set", "stripe/live", "sk_FAKEfixture_notARealKeyXYZ0123"},
			want: []string{"vault", "set", "stripe/live", RedactToken},
		},
		{
			name: "flag=value with secret value",
			in:   []string{"--token=ghp_16charsAtLeastxxxxxxxxxxxxxxxxxx"},
			want: []string{"--token=" + RedactToken},
		},
		{
			name: "vault label and flags survive",
			in:   []string{"vault", "get", "stripe/live-key", "--format", "json"},
			want: []string{"vault", "get", "stripe/live-key", "--format", "json"},
		},
		{
			name: "path survives",
			in:   []string{"migrate", "path", "/Users/me/.aws/credentials"},
			want: []string{"migrate", "path", "/Users/me/.aws/credentials"},
		},
		{
			name: "high-entropy opaque token masked",
			in:   []string{"AKIAIOSFODNN7EXAMPLE"},
			want: []string{RedactToken},
		},
		{
			// A bare base64 token ending in '=' padding must not be misread as
			// KEY=VALUE (name=the token, value="=") and slip through unmasked.
			name: "padded base64 bare is masked, not misread as KEY=VALUE",
			in:   []string{"SGVsbG9Xb3JsZERlYWRiZWVmMDAxMjM0NQ=="},
			want: []string{RedactToken},
		},
		{
			// A base64 credential containing '/' must be masked when it is a
			// flag or env value; the path-shy whole-arg test used to wave it
			// through as if the '/' made it a file path.
			name: "flag value base64 containing slash is masked",
			in:   []string{"--token=aB3xKq9ZmQpLrStUvWxYz012+ab/cdEF"},
			want: []string{"--token=" + RedactToken},
		},
		{
			name: "env value base64 containing slash is masked",
			in:   []string{"AWS_SECRET=aB3xKq9ZmQpLrStUvWxYz012+ab/cdEF"},
			want: []string{"AWS_SECRET=" + RedactToken},
		},
		{
			// The path-safety the '/' masking must not cost: an absolute path
			// given as a flag value stays legible.
			name: "absolute path as a flag value survives",
			in:   []string{"--config=/etc/app/config.yaml"},
			want: []string{"--config=/etc/app/config.yaml"},
		},
		{
			name: "deep alnum path as a bare positional survives",
			in:   []string{"scan", "/Users/me/project7/config8/data9zzzzzz"},
			want: []string{"scan", "/Users/me/project7/config8/data9zzzzzz"},
		},
		{
			// A long env-var/flag name must not stop the value from being
			// masked: the value split, not the name's shape, decides.
			name: "long key name still masks a prefixed value",
			in:   []string{"MY_VERY_LONG_ENVIRONMENT_VARIABLE_NAME_XYZ=ghp_16charsAtLeastxxxxxxxxxxxxxxxxxx"},
			want: []string{"MY_VERY_LONG_ENVIRONMENT_VARIABLE_NAME_XYZ=" + RedactToken},
		},
		{
			// A legible key=value whose value is not a secret is left intact —
			// the whole-arg fallback must not over-mask an ordinary assignment.
			name: "ordinary key=value survives with its name",
			in:   []string{"commit=a1b2c3d4e5f6a7b8c9d0"},
			want: []string{"commit=a1b2c3d4e5f6a7b8c9d0"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Redact(tc.in)
			if len(got) != len(tc.want) {
				t.Fatalf("Redact(%v) = %v, want %v", tc.in, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("Redact(%v)[%d] = %q, want %q", tc.in, i, got[i], tc.want[i])
				}
			}
		})
	}
}

// TestRedactNeverLeaksTheSecretText is the load-bearing safety property: after
// redaction, no masked token's original text may appear anywhere in the output.
func TestRedactNeverLeaksTheSecretText(t *testing.T) {
	secret := "sk_FAKEfixture_notARealKeyXYZ0123"
	got := Redact([]string{"vault", "set", "k", secret})
	for _, tok := range got {
		if strings.Contains(tok, secret) {
			t.Fatalf("Redact leaked the secret text in %q", tok)
		}
	}
}

func TestRedactTextMasksPunctuationWrappedSecrets(t *testing.T) {
	secret := "sk_FAKEfixture_notARealKeyXYZ0123"
	cases := []string{
		`no secret stored at "` + secret + `"`, // quoted, the real error shape
		"context: (" + secret + ") failed",     // parenthesized
		"token=" + secret + " rejected",        // key=value inside a sentence
		secret,                                 // bare
	}
	for _, in := range cases {
		got := RedactText(in)
		if strings.Contains(got, secret) {
			t.Errorf("RedactText(%q) leaked the secret: %q", in, got)
		}
		if !strings.Contains(got, RedactToken) {
			t.Errorf("RedactText(%q) did not insert the mask: %q", in, got)
		}
	}
}

// TestRedactTextKeepsOrdinaryText makes sure the free-form masker doesn't eat
// normal words, paths, or short labels — over-redaction that swallowed every
// error message would make the log useless.
func TestRedactTextKeepsOrdinaryText(t *testing.T) {
	in := `jit vault get: no secret stored at "stripe/live-key" (/Users/me/.config)`
	got := RedactText(in)
	if got != in {
		t.Errorf("RedactText altered ordinary text:\n in: %q\nout: %q", in, got)
	}
}

// RedactCommandLine guards the one recorded shape Redact never sees: a whole
// command line stored as a single string — the agent's SessionEvent.By, the
// caller's argv joined with spaces. Its grammar pass must mask the value
// positionals of a `jit vault set <path> <value>` line unconditionally,
// because a weak value ("hunter2") is not credential-shaped and would sail
// through the entropy test — the exact reason cli/auditrecord.go masks the
// same position in jit's own recorded args.
func TestRedactCommandLineMasksVaultSetValues(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{
			"weak value masked, path kept",
			"jit vault set stripe/live-key hunter2",
			"jit vault set stripe/live-key " + RedactToken,
		},
		{
			"absolute jit path and boolean flags",
			"/opt/homebrew/bin/jit vault set -y stripe/live-key hunter2",
			"/opt/homebrew/bin/jit vault set -y stripe/live-key " + RedactToken,
		},
		{
			"multi-word value masked whole: one argv element rejoins as several fields",
			"jit vault set stripe/live-key my weak phrase",
			"jit vault set stripe/live-key " + RedactToken + " " + RedactToken + " " + RedactToken,
		},
		{
			"value after the -- terminator is still the value",
			"jit vault set stripe/live-key -- -hunter2",
			"jit vault set stripe/live-key -- " + RedactToken,
		},
	}
	for _, tc := range cases {
		if got := RedactCommandLine(tc.in); got != tc.want {
			t.Errorf("%s:\n in: %q\ngot: %q\nwant: %q", tc.name, tc.in, got, tc.want)
		}
	}
}

// The path-only form (value from the prompt or --stdin) has NO value on the
// line, and masking then would redact the secret's PATH — a non-secret the
// trail should keep. Same rule cli/auditrecord.go applies via cobra's
// positional count; here the count comes from the line itself.
func TestRedactCommandLineKeepsVaultSetPathWhenNoValuePresent(t *testing.T) {
	for _, in := range []string{
		"jit vault set stripe/live-key",
		"jit vault set --stdin stripe/live-key",
		"jit vault set stripe/live-key --stdin",
	} {
		if got := RedactCommandLine(in); got != in {
			t.Errorf("RedactCommandLine(%q) = %q, want unchanged: the only positional is the path", in, got)
		}
	}
}

// Everything that is not the vault-set grammar still gets the credential-
// shaped pass and nothing more: ordinary lines survive verbatim, shaped
// tokens are masked wherever they sit.
func TestRedactCommandLineOutsideVaultSetGrammar(t *testing.T) {
	secret := "sk_FAKEfixture_notARealKeyXYZ0123"
	cases := []struct{ name, in, want string }{
		{
			"ordinary command untouched",
			"jit run --profile deploy -- terraform plan",
			"jit run --profile deploy -- terraform plan",
		},
		{
			"vault get keeps its path",
			"jit vault get stripe/live-key",
			"jit vault get stripe/live-key",
		},
		{
			"a non-jit program is not vault-set even with the words",
			"vi jit vault set notes.txt",
			"vi jit vault set notes.txt",
		},
		{
			"shaped token masked in any command",
			"jit run -- curl -H " + secret,
			"jit run -- curl -H " + RedactToken,
		},
		{"empty line", "", ""},
	}
	for _, tc := range cases {
		if got := RedactCommandLine(tc.in); got != tc.want {
			t.Errorf("%s:\n in: %q\ngot: %q\nwant: %q", tc.name, tc.in, got, tc.want)
		}
	}
}
