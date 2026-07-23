// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

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
			want: []string{"vault", "set", "stripe/live", redactToken},
		},
		{
			name: "flag=value with secret value",
			in:   []string{"--token=ghp_16charsAtLeastxxxxxxxxxxxxxxxxxx"},
			want: []string{"--token=" + redactToken},
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
			want: []string{redactToken},
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
		if !strings.Contains(got, redactToken) {
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
