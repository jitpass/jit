// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// realKey is a vendor-format value used as the "real credential" throughout
// these tests. Shaped to pass isPlaceholderToken (no filler words, no run of
// eight identical characters) because the whole point of the needle gate is
// that placeholders do not become needles.
const realKey = "tok_51QzR7bWpKmT4vXnA9dLcE2hJ"

func writeTree(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func agentFindings(f []Finding) []Finding {
	var out []Finding
	for _, x := range f {
		if x.FindingType == FindingTypeAgentCachedSecret {
			out = append(out, x)
		}
	}
	return out
}

func TestSubstrIndexFindAll(t *testing.T) {
	idx := newSubstrIndex([]string{"alpha", "beta", "aardvark"})
	first, count := idx.findAll([]byte("xx alpha yy beta zz alpha"))

	if got, want := first[0], 3; got != want {
		t.Errorf("first offset of alpha = %d, want %d", got, want)
	}
	if got, want := count[0], 2; got != want {
		t.Errorf("alpha count = %d, want %d", got, want)
	}
	if got, want := count[1], 1; got != want {
		t.Errorf("beta count = %d, want %d", got, want)
	}
	if _, ok := first[2]; ok {
		t.Error("aardvark reported present in a buffer that does not contain it")
	}
}

// A needle at the very end of the buffer must still match: an off-by-one in
// the bounds check would silently drop the last credential in a file.
func TestSubstrIndexMatchesAtBufferEnd(t *testing.T) {
	idx := newSubstrIndex([]string{"tail"})
	first, _ := idx.findAll([]byte("head tail"))
	if got, ok := first[0]; !ok || got != 5 {
		t.Errorf("first[tail] = %d (present=%v), want 5", got, ok)
	}
}

func TestEligibleNeedle(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value string
		want  bool
	}{
		{"vendor token", realKey, true},
		{"long random", "Xk92QmPl4TzWhuR3", true},
		{"too short", "abc123XY", false},
		{"jit pointer", "jit://vault/project/API_KEY", false},
		{"placeholder word", "tok_51Qexample7bWpKmT4vXn", false},
		{"repeated run", "tok_51Qxxxxxxxxbwpkmt4vx", false},
		{"all lowercase word", "correcthorsebattery", false},
		{"all digits", "1234567890123456", false},
		{"contains a space", "hunter2 and friends", false},
	} {
		if got := eligibleNeedle(tc.value); got != tc.want {
			t.Errorf("%s: eligibleNeedle(%q) = %v, want %v", tc.name, tc.value, got, tc.want)
		}
	}
}

// The headline case: a credential in a .env, copied verbatim into an agent's
// file cache. env_file_present is a FILE-level finding with no value of its
// own, so this only works because the env scanner hands its parsed values up
// as claimedRawValues.
func TestCrossReferenceFindsEnvSecretCopiedIntoAgentCache(t *testing.T) {
	home := t.TempDir()
	writeTree(t, filepath.Join(home, "project", ".env"), "STRIPE_KEY="+realKey+"\n")
	writeTree(t, filepath.Join(home, ".claude", "file-history", "s1", "abc@v2"),
		"STRIPE_KEY="+realKey+"\n")
	writeTree(t, filepath.Join(home, ".claude", "projects", "p", "t.jsonl"),
		`{"role":"user","text":"my key is `+realKey+`"}`+"\n")

	findings, _, err := Scan(Config{HomeDir: home, RunID: "r", ScannerVersion: "t"})
	if err != nil {
		t.Fatal(err)
	}
	cached := agentFindings(findings)
	if len(cached) != 2 {
		t.Fatalf("got %d agent_cached_secret findings, want 2: %+v", len(cached), cached)
	}
	for _, f := range cached {
		if f.KeyName == nil || *f.KeyName != "STRIPE_KEY" {
			t.Errorf("key_name = %v, want STRIPE_KEY (the copy must name what it is a copy of)", f.KeyName)
		}
		if f.Remedy != RemedyManual {
			t.Errorf("remedy = %q, want %q — jit migrate does not clean these yet", f.Remedy, RemedyManual)
		}
		if f.originPath != filepath.Join(home, "project", ".env") {
			t.Errorf("originPath = %q, want the .env it was copied from", f.originPath)
		}
		if f.ValuePreview == nil || strings.Contains(*f.ValuePreview, "bWpKmT") {
			t.Errorf("value_preview %v must be masked, never the credential", f.ValuePreview)
		}
	}
}

// A copy is the same secret in another place. It must not add to the ledger,
// and it must stop jit claiming migrate will protect that secret — migrate
// rewrites the .env and leaves the cached copy untouched.
func TestAgentCopyDoesNotInflateLedgerAndBlocksMigratable(t *testing.T) {
	withCopy := t.TempDir()
	writeTree(t, filepath.Join(withCopy, "project", ".env"), "STRIPE_KEY="+realKey+"\n")
	writeTree(t, filepath.Join(withCopy, ".claude", "file-history", "s1", "a@v1"), realKey)

	noCopy := t.TempDir()
	writeTree(t, filepath.Join(noCopy, "project", ".env"), "STRIPE_KEY="+realKey+"\n")

	_, withSummary, err := Scan(Config{HomeDir: withCopy, RunID: "r", ScannerVersion: "t"})
	if err != nil {
		t.Fatal(err)
	}
	_, baseSummary, err := Scan(Config{HomeDir: noCopy, RunID: "r", ScannerVersion: "t"})
	if err != nil {
		t.Fatal(err)
	}

	if withSummary.SecretsTotal != baseSummary.SecretsTotal {
		t.Errorf("secrets_total %d with a cached copy vs %d without: a copy is not a new secret",
			withSummary.SecretsTotal, baseSummary.SecretsTotal)
	}
	if baseSummary.SecretsMigratable == 0 {
		t.Fatal("precondition: the .env alone should be migratable")
	}
	if withSummary.SecretsMigratable != 0 {
		t.Errorf("secrets_migratable = %d, want 0: migrate rewrites the .env and leaves the agent's copy",
			withSummary.SecretsMigratable)
	}
}

// jit's own test data is full of real-shaped credentials that belong to
// nobody. Reporting copies of them was the first thing this scanner did on a
// real machine, and CountedAsSecret is the gate that stops it.
func TestTestFixtureCredentialsNeverBecomeNeedles(t *testing.T) {
	home := t.TempDir()
	writeTree(t, filepath.Join(home, "repo", "testdata", "creds.env"), "STRIPE_KEY="+realKey+"\n")
	writeTree(t, filepath.Join(home, ".claude", "file-history", "s1", "a@v1"), realKey)

	findings, _, err := Scan(Config{HomeDir: home, RunID: "r", ScannerVersion: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if got := agentFindings(findings); len(got) != 0 {
		t.Errorf("got %d findings for copies of a test fixture, want 0: %+v", len(got), got)
	}
}

// A file the scan already reports on its own must not be re-reported as a
// copy of itself — the case ~/.gemini/oauth_creds.json hits, being both an
// agent root and a store another scanner owns.
func TestAlreadyReportedFileIsNotReportedAsItsOwnCopy(t *testing.T) {
	home := t.TempDir()
	writeTree(t, filepath.Join(home, ".claude", "settings", ".env"), "STRIPE_KEY="+realKey+"\n")

	findings, _, err := Scan(Config{HomeDir: home, RunID: "r", ScannerVersion: "t"})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range agentFindings(findings) {
		if f.FilePath == filepath.Join(home, ".claude", "settings", ".env") {
			t.Errorf("%s reported as a copy of itself", f.FilePath)
		}
	}
}

// Skipped subtrees are vendored third-party content, not the user's.
func TestAgentCacheSkipsVendoredSubtrees(t *testing.T) {
	home := t.TempDir()
	writeTree(t, filepath.Join(home, "project", ".env"), "STRIPE_KEY="+realKey+"\n")
	writeTree(t, filepath.Join(home, ".claude", "plugins", "market", "sample.md"), realKey)

	findings, _, err := Scan(Config{HomeDir: home, RunID: "r", ScannerVersion: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if got := agentFindings(findings); len(got) != 0 {
		t.Errorf("got %d findings under a skipped subtree, want 0: %+v", len(got), got)
	}
}

// The exact-match search does not need the file to be text, which is what
// lets it reach an agent that keeps its history in a binary store — the one
// place the line-oriented scanners cannot follow.
func TestAgentCacheMatchesInsideBinaryContent(t *testing.T) {
	home := t.TempDir()
	writeTree(t, filepath.Join(home, "project", ".env"), "STRIPE_KEY="+realKey+"\n")
	writeTree(t, filepath.Join(home, ".claude", "sessions.db"),
		"SQLite format 3\x00\x00\x01page\x00"+realKey+"\x00trailer")

	findings, _, err := Scan(Config{HomeDir: home, RunID: "r", ScannerVersion: "t"})
	if err != nil {
		t.Fatal(err)
	}
	cached := agentFindings(findings)
	if len(cached) != 1 {
		t.Fatalf("got %d findings in binary content, want 1", len(cached))
	}
	if cached[0].Line != nil {
		t.Errorf("line = %v, want nil: a line number inside a binary file is a coordinate nobody can use", *cached[0].Line)
	}
}

// "We could not look" must never render as "there is nothing there".
func TestOversizeAgentCacheFileIsReportedNotSkipped(t *testing.T) {
	home := t.TempDir()
	writeTree(t, filepath.Join(home, "project", ".env"), "STRIPE_KEY="+realKey+"\n")

	big := filepath.Join(home, ".claude", "huge.jsonl")
	if err := os.MkdirAll(filepath.Dir(big), 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(big) // #nosec G304 -- test temp dir
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxAgentCacheFileSize + 1); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	_, summary, err := Scan(Config{HomeDir: home, RunID: "r", ScannerVersion: "t"})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, d := range summary.DegradedScanners {
		if strings.Contains(d.Error, "huge.jsonl") {
			found = true
		}
	}
	if !found {
		t.Errorf("an unread over-size cache file must appear in degraded_scanners, got %+v", summary.DegradedScanners)
	}
}
