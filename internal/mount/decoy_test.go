// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package mount

import (
	"strings"
	"testing"
)

func TestDecoyValuesSameKeysDifferentValues(t *testing.T) {
	real := map[string]string{
		"STRIPE_KEY": "sk_live_real_secret",
		"DB_URL":     "postgres://real",
	}
	decoy := DecoyValues(real)

	if len(decoy) != len(real) {
		t.Fatalf("DecoyValues returned %d keys, want %d", len(decoy), len(real))
	}
	for name, realValue := range real {
		decoyValue, ok := decoy[name]
		if !ok {
			t.Errorf("decoy missing key %q present in real", name)
			continue
		}
		if decoyValue == realValue {
			t.Errorf("decoy value for %q equals the real value %q — must never coincide", name, realValue)
		}
		if decoyValue == "" {
			t.Errorf("decoy value for %q is empty — apps checking for a non-empty var would behave unexpectedly", name)
		}
	}
}

func TestDecoyValuesEmptyInput(t *testing.T) {
	decoy := DecoyValues(map[string]string{})
	if len(decoy) != 0 {
		t.Errorf("DecoyValues(empty) = %v, want empty", decoy)
	}
}

// TestDecoyNoticeSelfDiagnoses: the notice must be a comment line (safe
// in both dotenv and npmrc/ini content) naming the exact command — with
// the mount's own path — that fixes the situation, so a failing dev
// server explains itself the moment someone opens the file.
func TestDecoyNoticeSelfDiagnoses(t *testing.T) {
	notice := string(DecoyNotice("/Users/dev/proj/.env"))
	if !strings.HasPrefix(notice, "# ") {
		t.Errorf("DecoyNotice = %q, want a `# ` comment line — anything else risks breaking a dotenv/ini parser", notice)
	}
	if !strings.HasSuffix(notice, "\n") {
		t.Errorf("DecoyNotice = %q, want a trailing newline so the first real line isn't glued to it", notice)
	}
	if !strings.Contains(notice, "jit agent reveal /Users/dev/proj/.env") {
		t.Errorf("DecoyNotice = %q, want the exact fixing command including the mount's own path", notice)
	}
	if strings.Count(notice, "\n") != 1 {
		t.Errorf("DecoyNotice = %q, want exactly one line", notice)
	}
}
