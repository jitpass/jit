// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A vendor-format token that passes isPlaceholderToken.
const cacheProbeToken = "ntn_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0"

func exposedAt(findings []Finding, path string) []Finding {
	var out []Finding
	for _, f := range findings {
		if f.FindingType == FindingTypeExposedSecret && f.FilePath == path {
			out = append(out, f)
		}
	}
	return out
}

// Every pattern the sweep covers has a needle, and the set it leaves out is
// exactly the shapes with no fixed bytes plus the private-key headers. A new
// entry in the table that lands in the left-out set by accident fails here,
// instead of silently going unswept.
func TestPatternSweepSkipsShapesWithoutLeads(t *testing.T) {
	wantSkipped := map[string]bool{
		"RSA Private Key": true, "OpenSSH Private Key": true, "EC Private Key": true, "PKCS8 Private Key": true,
		"Database connection string with embedded credentials (scheme-less)": true,
		"Telegram Bot Token": true, "Azure AD Client Secret": true, "Terraform Cloud API Token": true,
	}
	for _, tp := range knownTokenPatterns {
		swept := sweptByPattern(tp)
		if swept == wantSkipped[tp.vendor] {
			t.Errorf("%q: swept=%v, want %v", tp.vendor, swept, !wantSkipped[tp.vendor])
		}
		if !swept {
			continue
		}
		lits, _ := patternLeads(tp)
		if len(lits) == 0 {
			t.Errorf("%q is swept but has no literal lead", tp.vendor)
		}
		for _, l := range lits {
			if l == "" {
				t.Errorf("%q yields an empty needle", tp.vendor)
			}
		}
	}
	// The factored alternation must come back as full prefixes, never the
	// shared byte the parser pulls out.
	for _, tp := range knownTokenPatterns {
		if tp.vendor != "AWS Access Key ID" {
			continue
		}
		lits, _ := patternLeads(tp)
		got := strings.Join(lits, ",")
		if got != "ABIA,ACCA,AKIA,ASIA" {
			t.Errorf("AWS leads = %q, want ABIA,ACCA,AKIA,ASIA", got)
		}
	}
}

// The prefilter's one obligation: a match the full regex finds must begin at
// one of the pattern's leads (or contain its anchor), or the sweep drops it.
// Held over the shared admit corpus, like the shell-history prefilter.
func TestPatternLeadsNeverDropAMatch(t *testing.T) {
	for _, s := range historyAdmitSamples(t) {
		for _, tp := range knownTokenPatterns {
			if !sweptByPattern(tp) {
				continue
			}
			lits, anchor := patternLeads(tp)
			for _, m := range tp.pattern.FindAllStringIndex(s, -1) {
				match := s[m[0]:m[1]]
				covered := false
				for _, l := range lits {
					if anchor && strings.Contains(match, l) || !anchor && strings.HasPrefix(match, l) {
						covered = true
						break
					}
				}
				if !covered {
					t.Errorf("PREFILTER DROPS A REAL MATCH: %q matches %q at %d but begins with none of %q", tp.vendor, s, m[0], lits)
				}
			}
		}
	}
	// And the index agrees with FindFileTokens on a real file of samples.
	path := filepath.Join(t.TempDir(), "corpus.txt")
	if err := os.WriteFile(path, []byte(strings.Join(historyAdmitSamples(t), "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	full, err := FindFileTokens(path)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	swept := cachePatternIndex().matches(data)
	// Only the formats the sweep covers: a shape with no fixed bytes is
	// matched in files and deliberately not in transcripts.
	sweptVendor := map[string]bool{}
	for _, tp := range knownTokenPatterns {
		sweptVendor[tp.vendor] = sweptByPattern(tp)
	}
	fullSet := map[string]bool{}
	for _, tk := range full {
		if sweptVendor[tk.Vendor] {
			fullSet[tk.Vendor+"\x00"+tk.Value] = true
		}
	}
	for _, tk := range swept {
		if !fullSet[tk.Vendor+"\x00"+tk.Value] {
			t.Errorf("sweep reports %q %q which FindFileTokens does not", tk.Vendor, tk.Value)
		}
		delete(fullSet, tk.Vendor+"\x00"+tk.Value)
	}
	for k := range fullSet {
		v := strings.SplitN(k, "\x00", 2)
		t.Errorf("FindFileTokens finds %q %q which the sweep drops", v[0], v[1])
	}
}

// The acceptance test for the whole change. A .env holds a token and an
// agent cache holds a copy. Protect the .env (it becomes a pointer) and leave
// the copy: before, scan 2 said nothing about the cache (measured 2026-09-21);
// now the copy is an exposed_secret at the cache file, with its line, in
// every cache location — not only the three small dirs swept before.
func TestCachePatternsFindCopyAfterOriginProtected(t *testing.T) {
	locations := []struct{ rel, agent, area string }{
		{filepath.Join(".claude", "file-history", "s", "snap@v1"), "Claude Code", "edit history"},
		{filepath.Join(".claude", "projects", "p", "session.jsonl"), "Claude Code", "transcripts"},
		{filepath.Join(".cursor", "chat.txt"), "Cursor", ""},
		{filepath.Join(".codex", "sessions", "s.jsonl"), "Codex CLI", ""},
		{filepath.Join(".gemini", "tmp", "t.txt"), "Gemini CLI", ""},
	}
	for _, loc := range locations {
		t.Run(loc.rel, func(t *testing.T) {
			home := t.TempDir()
			envPath := filepath.Join(home, "proj", ".env")
			cachePath := filepath.Join(home, loc.rel)
			writeTree(t, envPath, "NOTION_TOKEN="+cacheProbeToken+"\n")
			writeTree(t, cachePath, "first line\nNOTION_TOKEN="+cacheProbeToken+"\n")
			cfg := Config{HomeDir: home, RunID: "r", ScannerVersion: "t"}

			// Control: with the origin in plaintext the copy is the
			// cross-reference's, and the content match is NOT reported
			// beside it — one copy, one finding.
			before, _, err := Scan(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if n := len(agentFindings(before)); n != 1 {
				t.Fatalf("control: %d agent_cached_secret findings, want 1", n)
			}
			if dup := exposedAt(before, cachePath); len(dup) != 0 {
				t.Fatalf("the cache copy is reported twice while its origin is in plaintext: %+v", dup)
			}

			// Protect the origin; the copy stays.
			writeTree(t, envPath, "NOTION_TOKEN=jit://vault/proj/NOTION_TOKEN\n")
			after, _, err := Scan(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if n := len(agentFindings(after)); n != 0 {
				t.Fatalf("no origin, yet %d agent_cached_secret findings", n)
			}
			got := exposedAt(after, cachePath)
			if len(got) != 1 {
				t.Fatalf("exposed_secret at the cache file = %d, want 1: %+v", len(got), got)
			}
			f := got[0]
			if f.KeyName == nil || *f.KeyName != "Notion Internal Integration Token" {
				t.Errorf("key_name = %v, want the vendor", f.KeyName)
			}
			if f.Line == nil || *f.Line != 2 {
				t.Errorf("line = %v, want 2", f.Line)
			}
			if f.Agent != loc.agent {
				t.Errorf("agent = %q, want %q", f.Agent, loc.agent)
			}
			if f.CacheArea != loc.area {
				t.Errorf("cache_area = %q, want %q", f.CacheArea, loc.area)
			}
			if f.Remedy != RemedyManual {
				t.Errorf("remedy = %q, want manual — an agent's cache is never jit's to rewrite", f.Remedy)
			}
			if f.ValuePreview == nil || strings.Contains(*f.ValuePreview, "A1b2C3d4E5f6") {
				t.Errorf("value_preview %v must be masked", f.ValuePreview)
			}
			if f.AssignedName != "NOTION_TOKEN" {
				t.Errorf("assigned name = %q, want NOTION_TOKEN", f.AssignedName)
			}
			if !strings.Contains(f.Evidence, loc.agent) {
				t.Errorf("evidence %q does not name the agent", f.Evidence)
			}
		})
	}
}

// Negative controls and boundaries in one fixture: a cache file with no
// token reports nothing; a binary store is left to the cross-reference; a
// vendored subtree is skipped; a placeholder is rejected; a file over the
// content scanner's 5 MiB cap is still swept here.
func TestCachePatternsBoundaries(t *testing.T) {
	home := t.TempDir()
	plain := filepath.Join(home, ".claude", "projects", "p", "plain.jsonl")
	writeTree(t, plain, `{"text":"nothing secret here, just words"}`+"\n")
	binary := filepath.Join(home, ".cursor", "state.vscdb")
	writeTree(t, binary, "SQLite format 3\x00\x00\x00"+cacheProbeToken)
	vendored := filepath.Join(home, ".claude", "plugins", "m", "README.md")
	writeTree(t, vendored, cacheProbeToken)
	filler := filepath.Join(home, ".claude", "projects", "p", "filler.jsonl")
	writeTree(t, filler, "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n")
	big := filepath.Join(home, ".claude", "projects", "p", "big.jsonl")
	pad := strings.Repeat(`{"text":"a long transcript line with nothing in it worth a second look"}`+"\n", (6<<20)/72)
	writeTree(t, big, pad+"TOKEN="+cacheProbeToken+"\n")
	if info, _ := os.Stat(big); info.Size() <= maxContentScanSize {
		t.Fatalf("fixture bug: big file is %d bytes, not over the %d cap", info.Size(), maxContentScanSize)
	}

	findings, _, err := Scan(Config{HomeDir: home, RunID: "r", ScannerVersion: "t"})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{plain, binary, vendored, filler} {
		if got := exposedAt(findings, p); len(got) != 0 {
			t.Errorf("%s: %d exposed_secret findings, want 0: %+v", filepath.Base(p), len(got), got)
		}
	}
	got := exposedAt(findings, big)
	if len(got) != 1 {
		t.Fatalf("over-cap transcript: %d exposed_secret findings, want 1 (the content scanner's 5 MiB cap must not apply here)", len(got))
	}
	if got[0].Line == nil || *got[0].Line != (6<<20)/72+1 {
		t.Errorf("line = %v, want the last line", got[0].Line)
	}
}

// A shape with no fixed bytes is matched in files, not in transcripts: the
// scheme-less connection string is reported from a name-gated file and not
// from a Claude Code transcript holding the same line (2026-09-21: a real
// transcript reported "sip:…@zoomcrc.com" and "from:…@calendly.com").
func TestSchemeLessConnStringIsFilesOnly(t *testing.T) {
	home := t.TempDir()
	line := "DB_URL=scanner_user:hunter2hunter2@db.example.com/postgres\n"
	transcript := filepath.Join(home, ".claude", "projects", "p", "s.jsonl")
	writeTree(t, transcript, `{"text":"`+strings.TrimSpace(line)+`"}`+"\n")
	file := filepath.Join(home, "proj", "credentials.txt")
	writeTree(t, file, line)
	findings, _, err := Scan(Config{HomeDir: home, RunID: "r", ScannerVersion: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if got := exposedAt(findings, transcript); len(got) != 0 {
		t.Errorf("scheme-less connection string reported from a transcript: %+v", got)
	}
	got := exposedAt(findings, file)
	if len(got) != 1 || got[0].KeyName == nil || !strings.HasPrefix(*got[0].KeyName, "Database connection string") {
		t.Errorf("scheme-less connection string not reported from the file: %+v", got)
	}
}

// The dirs the content scanner used to sweep on its own are now covered by
// this walk, once each: no record_id collision, no missing finding.
func TestSmallClaudeDirsSweptOnce(t *testing.T) {
	home := t.TempDir()
	paths := []string{
		filepath.Join(home, ".claude", "paste-cache", "abc.txt"),
		filepath.Join(home, ".claude", "shell-snapshots", "snap.sh"),
		filepath.Join(home, ".claude", "backups", "b.txt"),
		filepath.Join(home, ".claude", "history.jsonl"),
	}
	for _, p := range paths {
		writeTree(t, p, "X="+cacheProbeToken+"\n")
	}
	findings, _, err := Scan(Config{HomeDir: home, RunID: "r", ScannerVersion: "t"})
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]int{}
	for _, f := range findings {
		ids[f.RecordID]++
	}
	for _, p := range paths {
		got := exposedAt(findings, p)
		if len(got) != 1 {
			t.Errorf("%s: %d findings, want exactly 1", strings.TrimPrefix(p, home), len(got))
			continue
		}
		if ids[got[0].RecordID] != 1 {
			t.Errorf("%s: record_id reported %d times", strings.TrimPrefix(p, home), ids[got[0].RecordID])
		}
		if got[0].Agent != "Claude Code" {
			t.Errorf("%s: agent = %q", strings.TrimPrefix(p, home), got[0].Agent)
		}
	}
}

// The sweep must resolve overlapping patterns the SAME way FindFileTokens
// does — specific-over-generic — even though it orders candidates by position
// and FindFileTokens orders by table priority. If a generic pattern starts
// earlier than a nested specific one, position-order could pick the wrong
// vendor. These are the actual nested pairs in knownTokenPatterns.
func TestSweepOverlapMatchesFindFileTokens(t *testing.T) {
	body := "01QzR7bWpKmT4vXnA9dLcE2hJ01QzR7bW" // 33 base62, no filler run
	cases := []string{
		"KEY=sk-proj-" + body,                            // sk-proj- must win over sk-
		"KEY=sk-svcacct-" + body,                         // sk-svcacct- over sk-
		"URL=postgres://u:paSSwOrd12@db.example.com/app", // scheme'd over scheme-less
		"KEY=sk-or-v1-" + strings.Repeat("0a1b2c3d", 8),  // sk-or-v1- over sk-
		"AKIAABCDEFGHIJKLMNOP and ASIAABCDEFGHIJKLMNOP",  // both AWS forms
	}
	dir := t.TempDir()
	for i, line := range cases {
		path := filepath.Join(dir, "f")
		if err := os.WriteFile(path, []byte(line+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		full, err := FindFileTokens(path)
		if err != nil {
			t.Fatal(err)
		}
		data, _ := os.ReadFile(path)
		swept := cachePatternIndex().matches(data)

		fullKey := vendorSpanSet(full)
		sweptKey := vendorSpanSet(swept)
		if len(fullKey) != len(sweptKey) {
			t.Errorf("case %d %q: FindFileTokens=%v sweep=%v (count differs)", i, line, fullKey, sweptKey)
			continue
		}
		for k := range fullKey {
			if !sweptKey[k] {
				t.Errorf("case %d %q: FindFileTokens has %q, sweep does not (sweep=%v)", i, line, k, sweptKey)
			}
		}
	}
}

func vendorSpanSet(toks []FileToken) map[string]bool {
	m := map[string]bool{}
	for _, tk := range toks {
		m[tk.Vendor+"@"+tk.Value] = true
	}
	return m
}
