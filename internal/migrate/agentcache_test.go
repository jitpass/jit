// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const cacheKey = "tok_51QzR7bWpKmT4vXnA9dLcE2hJ"

func readCacheFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path) // #nosec G304 -- test temp dir
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func writeCacheTree(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestNeedleGateDropsOrdinaryEnvValues pins the #79 fix at the migrate
// layer: an env migration vaults EVERY variable, but neither the plan's
// needle preview nor the apply-time sweep may hunt values scan's cache hunt
// would not count as secrets. "jit-e2e-demo" is the shape that got through
// before — 12 chars, mixed character classes, a perfectly eligible needle
// and a perfectly ordinary application name.
func TestNeedleGateDropsOrdinaryEnvValues(t *testing.T) {
	dir := t.TempDir()
	env := filepath.Join(dir, ".env")
	writeCacheTree(t, env, "APP_NAME=jit-e2e-demo\nSTRIPE_KEY="+cacheKey+"\n")

	needles := PlanNeedles([]string{env}, nil)
	if len(needles) != 1 || needles[0].Value != cacheKey {
		t.Errorf("PlanNeedles = %+v, want only the credential", needles)
	}

	ordinary := EnvOrdinaryValues([]string{env})
	if !ordinary["jit-e2e-demo"] {
		t.Errorf("EnvOrdinaryValues = %v, want the app name captured", ordinary)
	}
	if ordinary[cacheKey] {
		t.Error("a claimed credential must never be classed ordinary")
	}

	// The OnSet capture holds env values AND other categories' credentials;
	// only the env-ordinary ones come out.
	vaulted := []AgentCacheSecret{
		{Value: "jit-e2e-demo", Var: "APP_NAME"},
		{Value: cacheKey, Var: "STRIPE_KEY"},
		{Value: "ghp_Fq8xW2mN5rTv7yZb3cJd1kLp9sAe4u", Var: "GIT_TOKEN"},
	}
	kept := DropOrdinaryValues(vaulted, ordinary)
	if len(kept) != 2 || kept[0].Value != cacheKey || kept[1].Value != "ghp_Fq8xW2mN5rTv7yZb3cJd1kLp9sAe4u" {
		t.Errorf("DropOrdinaryValues = %+v, want the app name gone and both credentials kept", kept)
	}
}

// The headline case: the agent's copy of a file it edited still holds the
// credential after the .env was migrated.
func TestCleanAgentCachesRedactsFileHistoryCopy(t *testing.T) {
	home := t.TempDir()
	copyPath := filepath.Join(home, ".claude", "file-history", "s1", "abc@v2")
	writeCacheTree(t, copyPath, "STRIPE_KEY="+cacheKey+"\nOTHER=keepme\n")

	got, err := CleanAgentCaches(newTestVault(t), home,
		[]AgentCacheSecret{{Value: cacheKey, Var: "STRIPE_KEY"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Edited) != 1 || got.Occurrences() != 1 {
		t.Fatalf("edited=%d occurrences=%d, want 1/1 (%+v)", len(got.Edited), got.Occurrences(), got)
	}
	if got.Edited[0].Area != "edit history" {
		t.Errorf("area = %q, want %q", got.Edited[0].Area, "edit history")
	}
	after := readCacheFile(t, copyPath)
	if strings.Contains(after, cacheKey) {
		t.Error("the credential is still in the file")
	}
	if !strings.Contains(after, "<jit:redacted:STRIPE_KEY>") {
		t.Errorf("no marker naming the vault variable: %q", after)
	}
	if !strings.Contains(after, "OTHER=keepme") {
		t.Error("non-secret content was not preserved")
	}
	if got.Edited[0].BackupPath == "" {
		t.Error("no encrypted backup recorded, so undo has nothing to restore")
	}
}

// A length-changing splice inside a SQLite page invalidates the offsets around
// it. OpenCode ships an opencode.db; Cursor keeps chat in a state.vscdb.
func TestCleanAgentCachesReportsBinaryStoresInsteadOfCorruptingThem(t *testing.T) {
	home := t.TempDir()
	db := filepath.Join(home, ".local", "share", "opencode", "sessions.db")
	original := "SQLite format 3\x00\x00\x01page\x00" + cacheKey + "\x00tail"
	writeCacheTree(t, db, original)

	got, err := CleanAgentCaches(newTestVault(t), home,
		[]AgentCacheSecret{{Value: cacheKey, Var: "STRIPE_KEY"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Edited) != 0 {
		t.Errorf("rewrote %d binary file(s); a length change corrupts the store", len(got.Edited))
	}
	if len(got.Skipped) != 1 || !strings.Contains(got.Skipped[0].Reason, "binary") {
		t.Fatalf("want one skip naming the binary reason, got %+v", got.Skipped)
	}
	if readCacheFile(t, db) != original {
		t.Error("the binary store was modified")
	}
}

// After a sweep the marker exists in every cleaned file. Admitting it as a
// needle later would have jit splicing markers into markers.
func TestMarkersAreNeverNeedles(t *testing.T) {
	got := eligibleAgentNeedles([]AgentCacheSecret{
		{Value: "<jit:redacted:STRIPE_KEY>", Var: "X"},
		{Value: cacheKey, Var: "STRIPE_KEY"},
		{Value: "short", Var: "S"},
		{Value: "has a space in it here", Var: "W"},
	})
	if len(got) != 1 || got[0].Value != cacheKey {
		t.Fatalf("eligible needles = %+v, want only the real credential", got)
	}
}

// A vaulted DATABASE_URL can contain a separately-vaulted password. Splicing
// the short one first leaves the long one's span pointing into a marker.
func TestOverlappingNeedlesSpliceLongestFirst(t *testing.T) {
	home := t.TempDir()
	pw := "Xk92QmPl4TzWhu"
	url := "postgres://app:" + pw + "@db.internal/prod"
	path := filepath.Join(home, ".claude", "file-history", "s1", "a@v1")
	writeCacheTree(t, path, "DATABASE_URL="+url+"\n")

	if _, err := CleanAgentCaches(newTestVault(t), home, []AgentCacheSecret{
		{Value: pw, Var: "DB_PASSWORD"},
		{Value: url, Var: "DATABASE_URL"},
	}); err != nil {
		t.Fatal(err)
	}
	after := readCacheFile(t, path)
	if !strings.Contains(after, "<jit:redacted:DATABASE_URL>") {
		t.Errorf("the longer credential did not win its span: %q", after)
	}
	if strings.Contains(after, pw) {
		t.Errorf("the password survived inside the URL: %q", after)
	}
	if strings.Count(after, "<jit:redacted:") != 1 {
		t.Errorf("want exactly one marker, got %q", after)
	}
}

// The rewrite lands by rename, which replaces the path. An agent still
// holding the old descriptor would keep appending to an unlinked inode —
// hence the live-writer check this test's fixture approaches but, as written,
// deliberately does not trigger (see the assertions below). Named for what it
// actually establishes rather than for the skip it never provokes.
func TestCleanAgentCachesKeepsContentAppendedBeforeTheSweep(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, ".claude", "projects", "p", "live.jsonl")
	writeCacheTree(t, path, `{"text":"`+cacheKey+`"}`+"\n")

	v := newTestVault(t)

	// Simulate the agent appending between jit's read and its rename by
	// growing the file after the discovery stat but before the swap: the
	// cheapest faithful proxy is to append here and confirm the sweep
	// declines rather than racing.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600) // #nosec G304 -- test temp dir
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"text":"later"}` + "\n"); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	got, err := CleanAgentCaches(v, home, []AgentCacheSecret{{Value: cacheKey, Var: "STRIPE_KEY"}})
	if err != nil {
		t.Fatal(err)
	}
	// The append happens BEFORE the sweep, so the live-writer check (which
	// compares a stat taken during the walk against one taken just before the
	// rename) must not fire: this run has to succeed outright. The mid-sweep
	// race the check actually guards sits between jit's read and its rename
	// and is not reproducible deterministically from outside the package, so
	// what is pinned here is the surrounding contract — the sweep edits the
	// file, the credential goes, and nothing written before it started is lost.
	//
	// The assertion used to be `credential still present && len(Edited) > 0`,
	// a conjunction no implementation can fail: a no-op sweep leaves Edited
	// empty (second clause false) and a working one removes the credential
	// (first clause false). Skipped — the record this test is named for — was
	// never inspected at all.
	after := readCacheFile(t, path)
	if strings.Contains(after, cacheKey) {
		t.Errorf("the credential survived the sweep: %q", after)
	}
	if !strings.Contains(after, "later") {
		t.Error("content appended before the sweep was lost")
	}
	if len(got.Edited) != 1 {
		t.Errorf("Edited = %+v, want exactly one edit", got.Edited)
	}
	if len(got.Skipped) != 0 {
		t.Errorf("Skipped = %+v, want none; the append preceded the sweep, so the "+
			"live-writer check must not fire — a stale stat comparison would "+
			"make every already-appended file permanently unsweepable", got.Skipped)
	}
}

// A preview must not touch anything, and must agree with what a real run does.
func TestPreviewAgentCachesTouchesNothing(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, ".claude", "paste-cache", "a.txt")
	writeCacheTree(t, path, cacheKey+"\n")
	before := readCacheFile(t, path)

	preview, err := PreviewAgentCaches(home, []AgentCacheSecret{{Value: cacheKey, Var: "STRIPE_KEY"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(preview.Edited) != 1 || preview.Edited[0].Occurrences != 1 {
		t.Fatalf("preview = %+v, want one file with one occurrence", preview)
	}
	if readCacheFile(t, path) != before {
		t.Error("preview modified the file")
	}

	real, err := CleanAgentCaches(newTestVault(t), home, []AgentCacheSecret{{Value: cacheKey, Var: "STRIPE_KEY"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(real.Edited) != len(preview.Edited) {
		t.Errorf("preview promised %d edits, the run made %d", len(preview.Edited), len(real.Edited))
	}
}

// Vendored subtrees are third-party content; the sweep must respect the same
// skip rules the scanner does.
func TestCleanAgentCachesSkipsVendoredSubtrees(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, ".claude", "plugins", "market", "sample.md")
	writeCacheTree(t, path, cacheKey+"\n")

	got, err := CleanAgentCaches(newTestVault(t), home,
		[]AgentCacheSecret{{Value: cacheKey, Var: "STRIPE_KEY"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Edited) != 0 {
		t.Errorf("rewrote %d file(s) under a skipped subtree", len(got.Edited))
	}
}

// The whole-vault collector must return every real secret and skip jit's own
// bookkeeping namespaces, or a _backups/ entry (a whole encrypted file) would
// become a redaction needle.
func TestCollectVaultSecretsSkipsBookkeeping(t *testing.T) {
	v := newTestVault(t)
	if err := v.Set("project/STRIPE_KEY", []byte(cacheKey)); err != nil {
		t.Fatal(err)
	}
	if err := v.Set("_backups/some-file-1699999999", []byte("STRIPE_KEY="+cacheKey+"\nlots of other file content\n")); err != nil {
		t.Fatal(err)
	}

	got, err := CollectVaultSecrets(v)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("collected %d secrets, want 1 (the _backups entry must be skipped): %+v", len(got), got)
	}
	if got[0].Value != cacheKey || got[0].Var != "STRIPE_KEY" {
		t.Errorf("collected %+v, want the project secret named STRIPE_KEY", got[0])
	}
}

// The breadcrumb is a count and a time, nothing else — and it round-trips,
// clears on a zero count, and is absent when nothing pends.
func TestCacheBreadcrumbRoundTrip(t *testing.T) {
	root := t.TempDir()
	if _, ok := ReadCacheBreadcrumb(root); ok {
		t.Fatal("a fresh root should have no breadcrumb")
	}
	WriteCacheBreadcrumb(root, 3, 1700000000000000000)
	c, ok := ReadCacheBreadcrumb(root)
	if !ok || c.Count != 3 {
		t.Fatalf("read %+v ok=%v, want count 3", c, ok)
	}
	// A zero count clears rather than persisting a meaningless note.
	WriteCacheBreadcrumb(root, 0, 1700000000000000001)
	if _, ok := ReadCacheBreadcrumb(root); ok {
		t.Error("a zero count should clear the breadcrumb")
	}
	// And it stores no path/value — the whole file is two numbers.
	WriteCacheBreadcrumb(root, 1, 1700000000000000002)
	data, _ := os.ReadFile(filepath.Join(root, cacheBreadcrumbName))
	if bytesContainsAny(data, []string{"/", "sk_", "STRIPE", ".claude"}) {
		t.Errorf("breadcrumb leaked more than a count+time: %s", data)
	}
	ClearCacheBreadcrumb(root)
	if _, ok := ReadCacheBreadcrumb(root); ok {
		t.Error("ClearCacheBreadcrumb should remove the note")
	}
}

func bytesContainsAny(b []byte, subs []string) bool {
	for _, s := range subs {
		if strings.Contains(string(b), s) {
			return true
		}
	}
	return false
}
