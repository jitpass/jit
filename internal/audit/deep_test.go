// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A formatless value no pattern would ever match: only the vault knows it
// is a secret. Long and mixed enough for eligibleNeedle.
const deepProbeValue = "hunter2-Prod-Database-2026"

func deepHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	write := func(rel string, data []byte) {
		t.Helper()
		p := filepath.Join(home, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// A transcript: the copy on line 3.
	write(filepath.Join(".claude", "projects", "p", "s.jsonl"),
		[]byte("{\"a\":1}\n{\"b\":2}\n{\"cmd\":\"export PGPASSWORD="+deepProbeValue+"\"}\n"))
	// A binary store: an exact match needs no lines.
	write(filepath.Join(".claude", "projects", "p", "blob.bin"),
		append(append([]byte("SQLite format 3\x00\x00\x00\x00"), []byte(deepProbeValue)...), 0, 0, 1, 2))
	// A file the machine-wide walk opens by its name.
	write(filepath.Join("proj", "credentials.txt"), []byte("DB_PASSWORD="+deepProbeValue+"\n"))
	// A file no name rule opens: reachable only by naming it.
	write(filepath.Join("scripts", "backup.sh"), []byte("#!/bin/sh\nPGPASSWORD="+deepProbeValue+" pg_dump prod\n"))
	return home
}

func deepConfig(t *testing.T, home string, needles ...VaultNeedle) Config {
	t.Helper()
	cfg, err := NewConfig("test")
	if err != nil {
		t.Fatal(err)
	}
	cfg.HomeDir = home
	cfg.VaultNeedles = needles
	return cfg
}

func vaultCopies(findings []Finding) []Finding {
	var out []Finding
	for _, f := range findings {
		if f.FindingType == FindingTypeVaultCopy {
			out = append(out, f)
		}
	}
	return out
}

func byPath(findings []Finding, path string) *Finding {
	for i := range findings {
		if findings[i].FilePath == path {
			return &findings[i]
		}
	}
	return nil
}

// The acceptance test: a vaulted value with no format is found where it
// lies — a transcript with its line, a binary store without one, a
// name-gated file — and named by its vault path. A regular scan of the
// same home finds none of it, which is the whole reason deep exists.
func TestDeepScanFindsExactCopiesOfVaultedSecrets(t *testing.T) {
	home := deepHome(t)
	needle := VaultNeedle{Name: "db-prod/PASSWORD", Value: deepProbeValue}

	regular, _, err := Scan(deepConfig(t, home))
	if err != nil {
		t.Fatal(err)
	}
	if n := len(vaultCopies(regular)); n != 0 {
		t.Fatalf("a regular scan reported %d vault copies; it has no needles", n)
	}

	findings, summary, err := Scan(deepConfig(t, home, needle))
	if err != nil {
		t.Fatal(err)
	}
	copies := vaultCopies(findings)
	if !summary.Deep || summary.VaultSecretsChecked != 1 {
		t.Errorf("summary deep=%v checked=%d, want true/1", summary.Deep, summary.VaultSecretsChecked)
	}

	transcript := byPath(copies, filepath.Join(home, ".claude", "projects", "p", "s.jsonl"))
	if transcript == nil {
		t.Fatalf("no vault_copy in the transcript; got %+v", copies)
	}
	if transcript.Line == nil || *transcript.Line != 3 {
		t.Errorf("transcript line = %v, want 3", transcript.Line)
	}
	if transcript.KeyName == nil || *transcript.KeyName != "db-prod/PASSWORD" {
		t.Errorf("key_name = %v, want the vault path", transcript.KeyName)
	}
	if transcript.Agent != "Claude Code" || transcript.CacheArea == "" {
		t.Errorf("agent/area = %q/%q", transcript.Agent, transcript.CacheArea)
	}
	if transcript.OriginPath != "" {
		t.Errorf("origin_path = %q; the origin is the vault", transcript.OriginPath)
	}
	if !strings.Contains(transcript.Evidence, "vaulted secret db-prod/PASSWORD") || !strings.Contains(transcript.Evidence, "Claude Code") {
		t.Errorf("evidence = %q", transcript.Evidence)
	}
	if transcript.Remedy != RemedyManual || transcript.Severity != SeverityHigh {
		t.Errorf("remedy/severity = %s/%s", transcript.Remedy, transcript.Severity)
	}

	blob := byPath(copies, filepath.Join(home, ".claude", "projects", "p", "blob.bin"))
	if blob == nil {
		t.Fatal("no vault_copy in the binary store: an exact match needs no lines")
	}
	if blob.Line != nil {
		t.Errorf("binary store reported line %d; a line into a binary file is not a coordinate", *blob.Line)
	}

	if byPath(copies, filepath.Join(home, "proj", "credentials.txt")) == nil {
		t.Error("no vault_copy in the name-gated file the content sweep reads")
	}
	if byPath(copies, filepath.Join(home, "scripts", "backup.sh")) != nil {
		t.Error("the machine-wide scan opened a file no name rule admits; deep must not widen what is read")
	}

	// Naming the file is what reaches it.
	targeted, tsum, err := TargetedScan(deepConfig(t, home, needle), []string{filepath.Join(home, "scripts", "backup.sh")})
	if err != nil {
		t.Fatal(err)
	}
	if f := byPath(vaultCopies(targeted), filepath.Join(home, "scripts", "backup.sh")); f == nil || f.Line == nil || *f.Line != 2 {
		t.Errorf("targeted deep scan of backup.sh: %+v", vaultCopies(targeted))
	}
	if !tsum.Deep {
		t.Error("targeted summary is not marked deep")
	}
}

// A vaulted secret that also has a vendor shape is one finding per file:
// the vault_copy, which names it. In a cache the pattern sweep is told the
// value is already reported; in a name-gated file dropRedundantExposedSecrets
// removes the vendor match for the same masked value.
func TestDeepScanVaultCopyWinsOverTheVendorMatch(t *testing.T) {
	// Two homes, one file each: with both in one home the file would be
	// the copy's plaintext origin and the cross-reference would (rightly)
	// win — see the test below.
	for _, rel := range []string{
		filepath.Join(".claude", "projects", "p", "s.jsonl"),
		filepath.Join("proj", "credentials.txt"),
	} {
		home := t.TempDir()
		p := filepath.Join(home, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("NOTION_TOKEN="+cacheProbeToken+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		findings, _, err := Scan(deepConfig(t, home, VaultNeedle{Name: "notion/NOTION_TOKEN", Value: cacheProbeToken}))
		if err != nil {
			t.Fatal(err)
		}
		var types []string
		for _, f := range findings {
			if f.FilePath == p {
				types = append(types, f.FindingType)
			}
		}
		if strings.Join(types, ",") != FindingTypeVaultCopy {
			t.Errorf("%s: findings %v, want exactly one vault_copy", rel, types)
		}
	}
}

// Every copy of one vaulted secret is one exposed secret in the ledger, and
// the value itself never reaches the report.
func TestDeepScanCountsOneSecretPerValueAndLeaksNothing(t *testing.T) {
	home := deepHome(t)
	cfg := deepConfig(t, home, VaultNeedle{Name: "db-prod/PASSWORD", Value: deepProbeValue})
	findings, summary, err := Scan(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(vaultCopies(findings)); n != 3 {
		t.Fatalf("%d vault copies, want 3 (transcript, binary store, credentials.txt)", n)
	}
	cov := ComputeCoverage(home, "", findings)
	if cov.Exposed != 1 {
		t.Errorf("exposed = %d, want 1: three copies of one secret are one secret", cov.Exposed)
	}
	if summary.SecretsTotal != 1 || summary.SecretsProtected != 0 {
		t.Errorf("summary total/protected = %d/%d, want 1/0", summary.SecretsTotal, summary.SecretsProtected)
	}
	var out bytes.Buffer
	if err := WriteNDJSON(&out, findings, summary); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out.Bytes(), []byte(deepProbeValue)) {
		t.Fatal("the vaulted value reached the NDJSON output")
	}
	if !bytes.Contains(out.Bytes(), []byte(`"deep":true`)) || !bytes.Contains(out.Bytes(), []byte(`"vault_secrets_checked":1`)) {
		t.Error("the summary does not say the run was deep")
	}
	var human bytes.Buffer
	WriteHumanReport(&human, findings, summary, home)
	if bytes.Contains(human.Bytes(), []byte(deepProbeValue)) {
		t.Fatal("the vaulted value reached the human report")
	}
	if !bytes.Contains(human.Bytes(), []byte("deep scan: 1 vault secret checked")) {
		t.Errorf("the human report does not say the run was deep:\n%s", human.String())
	}
}

// An origin still in plaintext keeps its cross-reference finding: the copy
// is an agent_cached_secret naming its origin file, not a vault_copy — the
// vault needle for the same value is skipped, so nothing is reported twice.
func TestDeepScanKeepsTheCrossReferenceWhenTheOriginIsStillPlaintext(t *testing.T) {
	home := t.TempDir()
	for rel, body := range map[string]string{
		filepath.Join("proj", ".env"):                        "NOTION_TOKEN=" + cacheProbeToken + "\n",
		filepath.Join(".claude", "projects", "p", "s.jsonl"): "{\"cmd\":\"" + cacheProbeToken + "\"}\n",
	} {
		p := filepath.Join(home, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	findings, _, err := Scan(deepConfig(t, home, VaultNeedle{Name: "notion/NOTION_TOKEN", Value: cacheProbeToken}))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(home, ".claude", "projects", "p", "s.jsonl")
	var types []string
	for _, f := range findings {
		if f.FilePath == path {
			types = append(types, f.FindingType)
		}
	}
	if strings.Join(types, ",") != FindingTypeAgentCachedSecret {
		t.Errorf("transcript findings %v, want exactly one agent_cached_secret", types)
	}
}

// What the index will not search for is left out, and counted out.
func TestDeepScanNeedleEligibility(t *testing.T) {
	cfg := deepConfig(t, t.TempDir(),
		VaultNeedle{Name: "a/SHORT", Value: "short"},
		VaultNeedle{Name: "a/DIGITS", Value: "123456789012345"},
		VaultNeedle{Name: "a/OK", Value: deepProbeValue},
		VaultNeedle{Name: "a/DUP", Value: deepProbeValue},
	)
	got := cfg.vaultNeedles()
	if len(got) != 1 || got[0].Name != "a/OK" {
		t.Errorf("eligible needles = %+v, want only a/OK", got)
	}
}
