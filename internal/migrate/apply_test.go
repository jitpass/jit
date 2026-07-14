// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package migrate

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/jitpass/jit/internal/profile"
	"github.com/jitpass/jit/internal/vault"
)

// fakeKeyWrapper is a deterministic, fixed-key vault.KeyWrapper for tests.
type fakeKeyWrapper struct{ key []byte }

func newFakeKeyWrapper() *fakeKeyWrapper { return &fakeKeyWrapper{key: bytes.Repeat([]byte{0x42}, 32)} }

func (f *fakeKeyWrapper) WrapKey(dek []byte) ([]byte, error) {
	block, err := aes.NewCipher(f.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, dek, nil), nil
}

func (f *fakeKeyWrapper) UnwrapKey(wrapped []byte) ([]byte, error) {
	block, err := aes.NewCipher(f.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce, ciphertext := wrapped[:gcm.NonceSize()], wrapped[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func newTestVault(t *testing.T) *vault.Vault {
	t.Helper()
	return &vault.Vault{Root: t.TempDir(), KeyWrapper: newFakeKeyWrapper(), RecipientID: "test-device"}
}

func TestDiscoverEnvFiles(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, ".env"), "A=1\n")
	writeFile(t, filepath.Join(root, ".env.example"), "A=placeholder\n")
	writeFile(t, filepath.Join(root, "services", "api", ".env"), "B=2\n")
	writeFile(t, filepath.Join(root, "node_modules", "some-pkg", ".env"), "C=3\n")
	writeFile(t, filepath.Join(root, ".git", ".env"), "D=4\n")

	found, err := DiscoverEnvFiles(root)
	if err != nil {
		t.Fatalf("DiscoverEnvFiles: %v", err)
	}
	want := []string{
		filepath.Join(root, ".env"),
		filepath.Join(root, "services", "api", ".env"),
	}
	if len(found) != len(want) {
		t.Fatalf("found = %v, want %v", found, want)
	}
	for i := range want {
		if found[i] != want[i] {
			t.Errorf("found[%d] = %q, want %q", i, found[i], want[i])
		}
	}
}

// TestDiscoverEnvFilesToleratesUnreadableDirectory is a real bug's
// regression test: `jit migrate home` walks the whole $HOME tree
// (GAPS.md #26), which on a real machine routinely contains a
// permission-denied directory (~/.Trash is macOS-TCC-protected without
// Full Disk Access; app-sandboxed containers under ~/Library are common
// too) — filepath.WalkDir's callback previously returned that error
// straight through, aborting the ENTIRE scan rather than just skipping
// the one unreadable path. Confirmed against a real report: `jit
// migrate home --dry-run` failed outright with "open
// /Users/x/.Trash: operation not permitted" and found nothing at all.
func TestDiscoverEnvFilesToleratesUnreadableDirectory(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root ignores directory permissions, can't exercise this")
	}
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "myapp", ".env"), "A=1\n")

	blocked := filepath.Join(root, "blocked")
	if err := os.MkdirAll(blocked, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.Chmod(blocked, 0o000); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(blocked, 0o700) }) // so t.TempDir()'s own cleanup can remove it

	found, err := DiscoverEnvFiles(root)
	if err != nil {
		t.Fatalf("DiscoverEnvFiles must tolerate an unreadable subdirectory, not abort: %v", err)
	}
	want := filepath.Join(root, "myapp", ".env")
	if len(found) != 1 || found[0] != want {
		t.Errorf("found = %v, want [%s] — the unreadable dir must be skipped, not stop discovery of everything else", found, want)
	}
}

func TestDiscoverEnvFilesSkipsAlreadyMounted(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".env")
	writeFile(t, path, "A=1\n")

	v := newTestVault(t)
	if _, err := ApplyEnvFile(v, root, path); err != nil {
		t.Fatalf("ApplyEnvFile: %v", err)
	}

	found, err := DiscoverEnvFiles(root)
	if err != nil {
		t.Fatalf("DiscoverEnvFiles: %v", err)
	}
	if len(found) != 0 {
		t.Errorf("found = %v, want empty (the .env is now a FIFO, already migrated)", found)
	}
}

// TestDiscoverEnvFilesSkipsPointerFiles is a real, reported incident's
// regression test: DiscoverEnvFiles' wildcard `^\.env(\..+)?$` pattern
// (meant to catch .env.local/.env.production) also matched jit's own
// `<file>.pointers` companion written by WritePointerFile, since it's
// just ".env" followed by another suffix. Running `jit migrate local` a
// second time re-discovered ".env.pointers" as a "new" .env file, parsed
// its `KEY=jit://vault/...` lines as if they were real secrets, and
// converted the plain-text, git-safe companion itself into a
// live-mounted FIFO — destroying it and leaving a ".env.pointers.pointers"
// artifact behind.
func TestDiscoverEnvFilesSkipsPointerFiles(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".env")
	writeFile(t, path, "A=1\n")

	v := newTestVault(t)
	result, err := ApplyEnvFile(v, root, path)
	if err != nil {
		t.Fatalf("ApplyEnvFile: %v", err)
	}
	p, err := profile.LoadFile(result.ProfilePath)
	if err != nil {
		t.Fatalf("profile.LoadFile: %v", err)
	}
	if err := WritePointerFile(result.EnvPath, p, nil); err != nil {
		t.Fatalf("WritePointerFile: %v", err)
	}

	found, err := DiscoverEnvFiles(root)
	if err != nil {
		t.Fatalf("DiscoverEnvFiles: %v", err)
	}
	if len(found) != 0 {
		t.Errorf("found = %v, want empty — the .pointers companion must never be rediscovered as a new .env file", found)
	}
}

// TestDiscoverEnvFilesSkipsOwnBackupFiles caught a real regression the
// moment ApplyEnvFile started writing its own "<file>.jit-bak-<ts>"
// backup (GAPS.md #32): that backup's name ALSO matches
// envFileNamePattern's wildcard suffix (it's just ".env" followed by
// another suffix, the exact same shape as the .pointers bug above), so
// without isJitGeneratedEnvArtifact's second check it would have been
// rediscovered and destroyed exactly like the .pointers companion was.
func TestDiscoverEnvFilesSkipsOwnBackupFiles(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".env")
	writeFile(t, path, "A=1\n")

	v := newTestVault(t)
	if _, err := ApplyEnvFile(v, root, path); err != nil {
		t.Fatalf("ApplyEnvFile: %v", err)
	}

	found, err := DiscoverEnvFiles(root)
	if err != nil {
		t.Fatalf("DiscoverEnvFiles: %v", err)
	}
	if len(found) != 0 {
		t.Errorf("found = %v, want empty — the .jit-bak- backup must never be rediscovered as a new .env file", found)
	}
}

// TestDiscoverEnvFilesSkipsInPlacePointerFiles is the regression test for
// GAPS.md #66: a backup-suffixed .env file (.env.bak) is replaced IN PLACE
// with pointer content, keeping its original name, so the name-based
// isJitGeneratedEnvArtifact check can't skip it — DiscoverEnvFiles must
// recognize it by content instead, or a second migrate would re-migrate its
// jit://vault/... pointer strings as if they were real secrets.
func TestDiscoverEnvFilesSkipsInPlacePointerFiles(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".env.bak")
	writeFile(t, path, "API_KEY=realsecret\n")

	v := newTestVault(t)
	result, err := ApplyEnvFile(v, root, path)
	if err != nil {
		t.Fatalf("ApplyEnvFile: %v", err)
	}
	if result.Mounted {
		t.Fatalf("a .env.bak must be replaced in place with a pointer file, never mounted")
	}

	// Sanity: the file is now pointer content under its original .env.bak name.
	if !LooksLikePointerContent(path) {
		got, _ := os.ReadFile(path)
		t.Fatalf("expected .env.bak to hold pointer content after migrate, got:\n%s", got)
	}

	found, err := DiscoverEnvFiles(root)
	if err != nil {
		t.Fatalf("DiscoverEnvFiles: %v", err)
	}
	if len(found) != 0 {
		t.Errorf("found = %v, want empty — an in-place-replaced .env.bak pointer file must not be rediscovered as a real .env", found)
	}
}

func TestApplyEnvFileEndToEnd(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".env")
	writeFile(t, path, "# a comment\nDATABASE_URL=postgres://admin:secret@db/app\nAPI_KEY=\"sk_test_123\"\n\nEMPTY_LINE_ABOVE=1\n")

	v := newTestVault(t)
	result, err := ApplyEnvFile(v, root, path)
	if err != nil {
		t.Fatalf("ApplyEnvFile: %v", err)
	}

	// A root .env is named after the project directory itself (GAPS.md
	// #55) — never the old literal "root" that piled every project into
	// one shared vault namespace.
	wantName := filepath.Base(root)
	if result.ProfileName != wantName {
		t.Errorf("ProfileName = %q, want %q (the project directory's name)", result.ProfileName, wantName)
	}
	wantVars := []string{"API_KEY", "DATABASE_URL", "EMPTY_LINE_ABOVE"}
	if len(result.Variables) != len(wantVars) {
		t.Fatalf("Variables = %v, want %v", result.Variables, wantVars)
	}

	p, err := profile.Load(root, wantName)
	if err != nil {
		t.Fatalf("profile.Load: %v", err)
	}
	dbSecretPath, ok := p["DATABASE_URL"]
	if !ok {
		t.Fatal("profile missing DATABASE_URL")
	}
	got, err := v.Get(dbSecretPath)
	if err != nil {
		t.Fatalf("v.Get(%q): %v", dbSecretPath, err)
	}
	if string(got) != "postgres://admin:secret@db/app" {
		t.Errorf("DATABASE_URL vault value = %q, want %q", got, "postgres://admin:secret@db/app")
	}

	apiKeySecretPath := p["API_KEY"]
	got, err = v.Get(apiKeySecretPath)
	if err != nil {
		t.Fatalf("v.Get(%q): %v", apiKeySecretPath, err)
	}
	if string(got) != "sk_test_123" {
		t.Errorf("API_KEY vault value = %q, want %q (quotes should be stripped)", got, "sk_test_123")
	}

	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat: %v", err)
	}
	if info.Mode()&os.ModeNamedPipe == 0 {
		t.Errorf(".env at %s is not a named pipe after migration", path)
	}
}

// Issue #4: a live-mounted .env used to serve alphabetically because the
// manifest (a YAML map) forgot the source file's variable order. The
// manifest must now be written in source order, and LoadFileOrdered must
// hand that order back — it's what the agent's mount rendering and the
// .pointers companion consume.
func TestApplyEnvFilePreservesSourceOrder(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".env")
	writeFile(t, path, "DATABASE_URL=postgres://x\nPROD_DATABASE_URL=postgres://y\nSTRIPE_API_KEY=sk_test\nDEBUG=true\n")

	v := newTestVault(t)
	result, err := ApplyEnvFile(v, root, path)
	if err != nil {
		t.Fatalf("ApplyEnvFile: %v", err)
	}

	wantOrder := []string{"DATABASE_URL", "PROD_DATABASE_URL", "STRIPE_API_KEY", "DEBUG"}
	if strings.Join(result.Variables, ",") != strings.Join(wantOrder, ",") {
		t.Errorf("Variables = %v, want source order %v", result.Variables, wantOrder)
	}

	_, order, err := profile.LoadFileOrdered(result.ProfilePath)
	if err != nil {
		t.Fatalf("LoadFileOrdered: %v", err)
	}
	if strings.Join(order, ",") != strings.Join(wantOrder, ",") {
		t.Errorf("manifest key order = %v, want source order %v", order, wantOrder)
	}
}

// TestApplyEnvFileBackupNeverWritesPlaintextToDisk is GAPS.md #33's
// regression test: .env's own backup (added for GAPS.md #32 to close a
// real recovery gap) used to write its safety-net copy as a PLAINTEXT
// sibling file — an unencrypted copy of the exact secret jit migrate
// exists to get off disk, sitting right next to the live mount
// indefinitely. Confirms the backup is now an encrypted vault entry
// (recoverable via v.Get(result.BackupPath), matching every other
// secret) and that no "<path>.jit-bak-*" file ever touches disk.
func TestApplyEnvFileBackupNeverWritesPlaintextToDisk(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".env")
	original := "DATABASE_URL=postgres://admin:secret@db/app\n"
	writeFile(t, path, original)

	v := newTestVault(t)
	result, err := ApplyEnvFile(v, root, path)
	if err != nil {
		t.Fatalf("ApplyEnvFile: %v", err)
	}
	if result.BackupPath == "" {
		t.Fatal("expected a non-empty BackupPath")
	}

	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), "jit-bak") {
			t.Errorf("found a plaintext backup file on disk: %s — the backup must live only in the vault", e.Name())
		}
	}

	backup, err := v.Get(result.BackupPath)
	if err != nil {
		t.Fatalf("v.Get(%q): %v", result.BackupPath, err)
	}
	if string(backup) != original {
		t.Errorf("vault backup content = %q, want the original file content %q", backup, original)
	}
}

func TestApplyEnvFileNestedProfileName(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "services", "api", ".env")
	writeFile(t, path, "PORT=8080\n")

	v := newTestVault(t)
	result, err := ApplyEnvFile(v, root, path)
	if err != nil {
		t.Fatalf("ApplyEnvFile: %v", err)
	}
	if result.ProfileName != "services-api" {
		t.Errorf("ProfileName = %q, want %q", result.ProfileName, "services-api")
	}
}

// TestDeriveProfileNameUsesDirectoryBasename is GAPS.md #55's naming half:
// a .env at the migrate root derives the project directory's own name,
// never the old literal "root" that piled every project migrated from its
// own root into one flat, shared vault namespace. Directory names with
// characters profile.Path won't accept are sanitized rather than failing.
func TestDeriveProfileNameUsesDirectoryBasename(t *testing.T) {
	cases := []struct {
		root, env, want string
	}{
		{"/Users/x/Documents/notion", "/Users/x/Documents/notion/.env", "notion"},
		{"/Users/x/Documents/notion", "/Users/x/Documents/notion/.env.local", "notion-local"},
		{"/Users/x/Documents/My App", "/Users/x/Documents/My App/.env", "My-App"},
		{"/Users/x/Documents/notion", "/Users/x/Documents/notion/services/api/.env", "services-api"},
		{"/", "/.env", "root"}, // degenerate root keeps the last-resort literal
	}
	for _, c := range cases {
		if got := deriveProfileName(c.root, c.env); got != c.want {
			t.Errorf("deriveProfileName(%q, %q) = %q, want %q", c.root, c.env, got, c.want)
		}
	}
}

// TestApplyEnvFileRefusesToOverwriteAnotherProjectsSecrets is GAPS.md
// #55's guard half: the vault is machine-global while profile manifests
// are per-project, so two projects whose directories share a basename
// (every "api/" ever) derive the same profile name — and, before
// claimNamespace, the later migration silently overwrote the earlier
// project's live vault secret for any shared variable name. The second
// project must move to "<name>-2" instead, leaving the first untouched.
func TestApplyEnvFileRefusesToOverwriteAnotherProjectsSecrets(t *testing.T) {
	v := newTestVault(t)

	projectA := filepath.Join(t.TempDir(), "api")
	projectB := filepath.Join(t.TempDir(), "api") // same basename, different project
	writeFile(t, filepath.Join(projectA, ".env"), "API_KEY=from-project-a\n")
	writeFile(t, filepath.Join(projectB, ".env"), "API_KEY=from-project-b\n")

	resultA, err := ApplyEnvFile(v, projectA, filepath.Join(projectA, ".env"))
	if err != nil {
		t.Fatalf("ApplyEnvFile(A): %v", err)
	}
	if resultA.ProfileName != "api" || resultA.NamespaceMovedFrom != "" {
		t.Fatalf("A: (ProfileName, NamespaceMovedFrom) = (%q, %q), want (api, \"\")", resultA.ProfileName, resultA.NamespaceMovedFrom)
	}

	resultB, err := ApplyEnvFile(v, projectB, filepath.Join(projectB, ".env"))
	if err != nil {
		t.Fatalf("ApplyEnvFile(B): %v", err)
	}
	if resultB.ProfileName != "api-2" {
		t.Errorf("B ProfileName = %q, want api-2 — the second project must never claim the first one's namespace", resultB.ProfileName)
	}
	if resultB.NamespaceMovedFrom != "api" {
		t.Errorf("B NamespaceMovedFrom = %q, want %q so callers can explain the move", resultB.NamespaceMovedFrom, "api")
	}

	// The point of the whole mechanism: project A's live secret survives.
	if got, err := v.Get("api/API_KEY"); err != nil || string(got) != "from-project-a" {
		t.Errorf("api/API_KEY = (%q, %v), want (from-project-a, nil) — project B's migration must not touch it", got, err)
	}
	if got, err := v.Get("api-2/API_KEY"); err != nil || string(got) != "from-project-b" {
		t.Errorf("api-2/API_KEY = (%q, %v), want (from-project-b, nil)", got, err)
	}
}

// TestApplyEnvFileReRunRefreshesItsOwnNamespace pins the other side of the
// claimNamespace rule: a path the candidate profile's own manifest already
// maps is this migration's own earlier value — a re-run (e.g. after `jit
// migrate undo` put the file back) must refresh it in place, never fork
// off to "<name>-2" and orphan the original namespace.
func TestApplyEnvFileReRunRefreshesItsOwnNamespace(t *testing.T) {
	v := newTestVault(t)
	root := filepath.Join(t.TempDir(), "myapp")
	path := filepath.Join(root, ".env")
	writeFile(t, path, "API_KEY=v1\n")

	first, err := ApplyEnvFile(v, root, path)
	if err != nil {
		t.Fatalf("first ApplyEnvFile: %v", err)
	}

	// Put the plain file back (what `jit migrate undo` does) with an
	// updated value, then migrate again.
	if err := os.Remove(path); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	writeFile(t, path, "API_KEY=v2\n")

	second, err := ApplyEnvFile(v, root, path)
	if err != nil {
		t.Fatalf("second ApplyEnvFile: %v", err)
	}
	if second.ProfileName != first.ProfileName || second.NamespaceMovedFrom != "" {
		t.Errorf("re-run: (ProfileName, NamespaceMovedFrom) = (%q, %q), want (%q, \"\") — a re-run refreshes its own namespace, never forks", second.ProfileName, second.NamespaceMovedFrom, first.ProfileName)
	}
	if got, err := v.Get(first.ProfileName + "/API_KEY"); err != nil || string(got) != "v2" {
		t.Errorf("after re-run, %s/API_KEY = (%q, %v), want (v2, nil)", first.ProfileName, got, err)
	}
}

// TestApplyEnvFileVariantSuffixDisambiguatesProfile is a real, reported
// incident's regression test: before deriveProfileName incorporated the
// filename's own variant suffix, .env/.env.bak/.env.local in the SAME
// directory all derived the identical profile name ("root") and
// therefore the identical vault path per variable name — even though
// each is migrated independently. Confirmed on a real machine: this
// silently overwrote one file's vault value with another's for any
// shared variable name, and orphaned a vault secret entirely when a
// later file's profile write erased an earlier file's entry that the
// later file didn't also define.
func TestApplyEnvFileVariantSuffixDisambiguatesProfile(t *testing.T) {
	root := t.TempDir()
	v := newTestVault(t)

	writeFile(t, filepath.Join(root, ".env"), "SHARED=from-env\nONLY_IN_ENV=1\n")
	writeFile(t, filepath.Join(root, ".env.bak"), "SHARED=from-env-bak\n")

	envResult, err := ApplyEnvFile(v, root, filepath.Join(root, ".env"))
	if err != nil {
		t.Fatalf("ApplyEnvFile(.env): %v", err)
	}
	bakResult, err := ApplyEnvFile(v, root, filepath.Join(root, ".env.bak"))
	if err != nil {
		t.Fatalf("ApplyEnvFile(.env.bak): %v", err)
	}

	if envResult.ProfileName == bakResult.ProfileName {
		t.Fatalf(".env and .env.bak derived the SAME profile name %q — they must be distinct, or one silently overwrites the other's vault entries", envResult.ProfileName)
	}
	dirName := filepath.Base(root)
	if envResult.ProfileName != dirName {
		t.Errorf(".env ProfileName = %q, want %q (bare .env keeps its unsuffixed name)", envResult.ProfileName, dirName)
	}
	if bakResult.ProfileName != dirName+"-bak" {
		t.Errorf(".env.bak ProfileName = %q, want %q", bakResult.ProfileName, dirName+"-bak")
	}

	// The critical assertion: .env's own SHARED value must survive
	// .env.bak's migration untouched, since they're now different vault
	// paths (<dir>/SHARED vs <dir>-bak/SHARED) instead of colliding.
	envProfile, err := profile.LoadFile(envResult.ProfilePath)
	if err != nil {
		t.Fatalf("profile.LoadFile(.env): %v", err)
	}
	got, err := v.Get(envProfile["SHARED"])
	if err != nil {
		t.Fatalf("v.Get(%s): %v", envProfile["SHARED"], err)
	}
	if string(got) != "from-env" {
		t.Errorf(".env's SHARED = %q after .env.bak was migrated, want %q — .env.bak must not overwrite .env's vault value", got, "from-env")
	}
	if _, ok := envProfile["ONLY_IN_ENV"]; !ok {
		t.Error(".env's ONLY_IN_ENV entry is missing from its own profile after .env.bak was migrated")
	}
}

// TestApplyEnvFileBackupSuffixNeverMounted is GAPS.md #34's regression
// test: a backup-suffixed .env-family file (.bak/.old/.orig/.backup) is
// never read live by anything, so converting it into a FIFO the way a
// real .env is gains nothing and just creates a dead pipe — a real,
// reported problem (closing an editor with one of these open hung on
// its own crash-recovery backup step, since a named pipe blocks on read
// with no writer connected). Confirms the secrets still move into the
// vault (the whole point of migrating it at all), but the file itself
// is left as a plain, safe pointer file rather than becoming a mount.
func TestApplyEnvFileBackupSuffixNeverMounted(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".env.bak")
	writeFile(t, path, "DATABASE_URL=postgres://admin:secret@db/app\n")

	v := newTestVault(t)
	result, err := ApplyEnvFile(v, root, path)
	if err != nil {
		t.Fatalf("ApplyEnvFile: %v", err)
	}
	if result.Mounted {
		t.Error("Mounted = true, want false — a .bak file must never become a live mount")
	}

	got, err := v.Get(result.ProfileName + "/DATABASE_URL")
	if err != nil || string(got) != "postgres://admin:secret@db/app" {
		t.Errorf("vault value = (%q, %v), want (postgres://admin:secret@db/app, nil) — secrets must still be migrated even though the file isn't mounted", got, err)
	}

	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat: %v", err)
	}
	if info.Mode()&os.ModeNamedPipe != 0 {
		t.Error(".env.bak was converted into a named pipe — it must stay a regular file")
	}
	content, err := os.ReadFile(path) // #nosec G304 -- test-controlled path, confirmed not a FIFO above
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if strings.Contains(string(content), "postgres://admin:secret@db/app") {
		t.Error(".env.bak still contains the raw secret value after migration — it must be replaced with a pointer file")
	}
	if !strings.Contains(string(content), "jit://vault/") {
		t.Errorf(".env.bak was not replaced with pointer content, got:\n%s", content)
	}
}

// TestApplyEnvFileMergesIntoExistingProfile confirms the second, defense-
// in-depth layer: even when two ApplyEnvFile calls DO legitimately land
// on the same profile, the second write merges into what's already there
// rather than overwriting it outright — matching ApplyShellConfig/
// ApplyMCPConfig's existing convention for their own profiles.
func TestApplyEnvFileMergesIntoExistingProfile(t *testing.T) {
	root := t.TempDir()
	v := newTestVault(t)

	dirName := filepath.Base(root)
	profilePath, err := profile.Path(root, dirName)
	if err != nil {
		t.Fatalf("profile.Path: %v", err)
	}
	preexisting := profile.Profile{"PRE_EXISTING": dirName + "/PRE_EXISTING"}
	data, err := yaml.Marshal(preexisting)
	if err != nil {
		t.Fatalf("yaml.Marshal: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(profilePath), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(profilePath, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := v.Set(dirName+"/PRE_EXISTING", []byte("original-value")); err != nil {
		t.Fatalf("v.Set: %v", err)
	}

	writeFile(t, filepath.Join(root, ".env"), "NEW_VAR=1\n")
	if _, err := ApplyEnvFile(v, root, filepath.Join(root, ".env")); err != nil {
		t.Fatalf("ApplyEnvFile: %v", err)
	}

	merged, err := profile.LoadFile(profilePath)
	if err != nil {
		t.Fatalf("profile.LoadFile: %v", err)
	}
	if _, ok := merged["PRE_EXISTING"]; !ok {
		t.Error("PRE_EXISTING entry was dropped instead of merged")
	}
	if _, ok := merged["NEW_VAR"]; !ok {
		t.Error("NEW_VAR entry is missing after migration")
	}
}

func TestApplyEnvFileEmptyFileRejected(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".env")
	writeFile(t, path, "# nothing but comments\n\n")

	v := newTestVault(t)
	if _, err := ApplyEnvFile(v, root, path); err == nil {
		t.Fatal("expected an error migrating a .env file with no active KEY=value lines, got nil")
	}

	// The original file must survive untouched on failure — never destroy
	// the source before everything else has succeeded.
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat: %v", err)
	}
	if info.Mode()&os.ModeNamedPipe != 0 {
		t.Error(".env was replaced with a FIFO despite ApplyEnvFile failing")
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

func TestDiscoverEnvFilesSkipsGoModCache(t *testing.T) {
	root := t.TempDir()
	cache := filepath.Join(root, "gomodcache")
	t.Setenv("GOMODCACHE", cache)
	writeFile(t, filepath.Join(root, ".env"), "A=1\n")
	writeFile(t, filepath.Join(cache, "gotenv@v1.6.0", ".env"), "FIXTURE=1\n")

	found, err := DiscoverEnvFiles(root)
	if err != nil {
		t.Fatalf("DiscoverEnvFiles: %v", err)
	}
	if len(found) != 1 || found[0] != filepath.Join(root, ".env") {
		t.Errorf("found = %v, want only the project .env — the Go module cache is read-only, checksummed public source and must never be rewritten", found)
	}
}

func TestGoModCacheDirFallsBackToHome(t *testing.T) {
	t.Setenv("GOMODCACHE", "")
	t.Setenv("GOPATH", "")
	home := t.TempDir()
	t.Setenv("HOME", home)
	if got, want := goModCacheDir(), filepath.Join(home, "go", "pkg", "mod"); got != want {
		t.Errorf("goModCacheDir() = %q, want %q", got, want)
	}
}
