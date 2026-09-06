// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"testing"
)

const cleanTestHome = "/Users/u"

func countedFinding(ftype, path string) Finding {
	return Finding{FindingType: ftype, FilePath: path, Severity: SeverityHigh}
}

func TestCleanClassOfMatrix(t *testing.T) {
	home := cleanTestHome
	key := "TOKEN"
	cases := []struct {
		name string
		f    Finding
		want CleanClass
	}{
		{"env in trash", func() Finding {
			f := countedFinding(FindingTypeEnvFilePresent, filepath.Join(home, ".Trash", "old", ".env"))
			f.Archived = true
			return f
		}(), CleanTrash},
		{"private key in trash still trash", func() Finding {
			f := countedFinding(FindingTypePrivateKeyRisk, filepath.Join(home, ".Trash", "sa-key.json"))
			f.Archived = true
			return f
		}(), CleanTrash},
		{"archived env copy", func() Finding {
			f := countedFinding(FindingTypeEnvFilePresent, filepath.Join(home, "old", "backup", ".env"))
			f.Archived = true
			return f
		}(), CleanArchivedCopy},
		{"archived private key excluded", func() Finding {
			f := countedFinding(FindingTypePrivateKeyRisk, filepath.Join(home, "backup", "id_rsa"))
			f.Archived = true
			return f
		}(), CleanNone},
		{"paste-cache leftover", countedFinding(FindingTypeExposedSecret,
			filepath.Join(home, ".claude", "paste-cache", "50440ea9.txt")), CleanAgentLeftover},
		{"shell snapshot leftover", countedFinding(FindingTypeExposedSecret,
			filepath.Join(home, ".claude", "shell-snapshots", "snap.sh")), CleanAgentLeftover},
		{"agent credential store is not a leftover", countedFinding(FindingTypeExposedSecret,
			filepath.Join(home, ".codex", "auth.json")), CleanNone},
		{"agent history file is not a leftover", countedFinding(FindingTypeExposedSecret,
			filepath.Join(home, ".claude", "history.jsonl")), CleanNone},
		{"agent cached copy stays redaction's job", func() Finding {
			f := countedFinding(FindingTypeAgentCachedSecret, filepath.Join(home, ".claude", "paste-cache", "aa.txt"))
			f.KeyName = &key
			return f
		}(), CleanNone},
		{"shell history stays redaction's job", countedFinding(FindingTypeShellHistorySecret,
			filepath.Join(home, ".zsh_history")), CleanNone},
		{"live env is none", countedFinding(FindingTypeEnvFilePresent,
			filepath.Join(home, "proj", ".env")), CleanNone},
		{"uncounted low severity", func() Finding {
			f := countedFinding(FindingTypeExposedSecret, filepath.Join(home, ".Trash", "x.txt"))
			f.Severity = SeverityLow
			return f
		}(), CleanNone},
		{"test fixture in trash", func() Finding {
			f := countedFinding(FindingTypeExposedSecret, filepath.Join(home, ".Trash", "x.txt"))
			f.TestFixture = true
			return f
		}(), CleanNone},
	}
	for _, tc := range cases {
		if got := CleanClassOf(home, tc.f); got != tc.want {
			t.Errorf("%s: CleanClassOf = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestCleanClassAgreesWithTriage pins CleanClassOf to manualAction's own
// precedence: a finding the clean pass calls trash must be one the red
// section files under kindTrash, and an archived-copy candidate must sit in
// the archived group. One classification, two consumers — the no-drift rule
// the design doc names D10.
func TestCleanClassAgreesWithTriage(t *testing.T) {
	home := cleanTestHome
	findings := []Finding{
		func() Finding {
			f := countedFinding(FindingTypeEnvFilePresent, filepath.Join(home, ".Trash", ".env"))
			f.Archived = true
			return f
		}(),
		func() Finding {
			f := countedFinding(FindingTypeEnvFilePresent, filepath.Join(home, "archive", ".env"))
			f.Archived = true
			return f
		}(),
		countedFinding(FindingTypeExposedSecret, filepath.Join(home, "proj", "notes.txt")),
	}
	for _, f := range findings {
		kind, _ := manualAction(f, manualContext{secrets: 1}, home)
		switch CleanClassOf(home, f) {
		case CleanTrash:
			if kind != kindTrash {
				t.Errorf("%s: CleanTrash but triage kind %q", f.FilePath, kind)
			}
		case CleanArchivedCopy:
			if kind != kindArchived {
				t.Errorf("%s: CleanArchivedCopy but triage kind %q", f.FilePath, kind)
			}
		}
	}
}

func TestSecretDigestsByFile(t *testing.T) {
	digest := func(v string) string {
		sum := sha256.Sum256([]byte(v))
		return hex.EncodeToString(sum[:])
	}
	valueF := countedFinding(FindingTypeExposedSecret, "/f/one")
	valueF.rawValueDigest = digest("sk-live-abc")
	envF := countedFinding(FindingTypeEnvFilePresent, "/f/env")
	envF.claimedRawValues = []claimedValue{{Key: "A", Value: "v1"}, {Key: "B", Value: "v2"}}
	bareF := countedFinding(FindingTypeEnvFilePresent, "/f/bare") // no values parsed
	lowF := countedFinding(FindingTypeExposedSecret, "/f/low")
	lowF.Severity = SeverityLow
	lowF.rawValueDigest = digest("ignored")

	got := SecretDigestsByFile([]Finding{valueF, envF, bareF, lowF})

	one := got["/f/one"]
	if !one.Complete || len(one.Digests) != 1 || one.Digests[0] != digest("sk-live-abc") {
		t.Errorf("/f/one: got %+v", one)
	}
	env := got["/f/env"]
	if !env.Complete || len(env.Digests) != 2 {
		t.Errorf("/f/env: got %+v", env)
	}
	if bare := got["/f/bare"]; bare.Complete {
		t.Errorf("/f/bare: a counted finding with no values must mark the file incomplete, got %+v", bare)
	}
	if _, ok := got["/f/low"]; ok {
		t.Error("/f/low: uncounted findings must not contribute")
	}
}
