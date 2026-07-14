// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package migrate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRemoveRevealHooksRoundTrip pins RemoveRevealHooks as InstallRevealHook's
// true inverse: whatever install wired into an .envrc or a package.json
// pre-script, remove strips — and ONLY that, never a line or script the
// user authored themselves.
func TestRemoveRevealHooksRoundTrip(t *testing.T) {
	dir := t.TempDir()
	envrcPath := filepath.Join(dir, ".envrc")
	writeFile(t, envrcPath, "dotenv\nexport FOO=bar\n")
	pkgPath := filepath.Join(dir, "package.json")
	writeFile(t, pkgPath, `{"name":"demo","scripts":{"dev":"vite","predev":"echo user-hook"}}`)

	mountPath := filepath.Join(dir, ".env")
	if _, err := InstallRevealHook(dir, mountPath); err != nil {
		t.Fatalf("InstallRevealHook: %v", err)
	}
	installed, err := os.ReadFile(envrcPath) // #nosec G304 -- test-controlled path
	if err != nil || !strings.Contains(string(installed), "agent reveal") {
		t.Fatalf("precondition: hook not installed in .envrc (err %v):\n%s", err, installed)
	}

	edited, err := RemoveRevealHooks(dir)
	if err != nil {
		t.Fatalf("RemoveRevealHooks: %v", err)
	}
	if len(edited) != 1 || edited[0] != envrcPath {
		t.Errorf("edited = %v, want just the .envrc (direnv wins install, so only it holds a hook)", edited)
	}
	after, err := os.ReadFile(envrcPath) // #nosec G304 -- test-controlled path
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if strings.Contains(string(after), "agent reveal") {
		t.Errorf(".envrc still contains the reveal hook after removal:\n%s", after)
	}
	if !strings.Contains(string(after), "dotenv") || !strings.Contains(string(after), "export FOO=bar") {
		t.Errorf(".envrc lost a user-authored line:\n%s", after)
	}
}

// The npm variant: a predev that mixes jit's injected command with the
// user's own must keep the user's part; a predev that was entirely jit's
// must be deleted outright.
func TestRemoveRevealHooksNpmPreservesUserPreScript(t *testing.T) {
	dir := t.TempDir()
	pkgPath := filepath.Join(dir, "package.json")
	writeFile(t, pkgPath, `{"scripts":{"dev":"vite","predev":"echo user-hook","start":"node ."}}`)

	mountPath := filepath.Join(dir, ".env")
	if _, err := InstallRevealHook(dir, mountPath); err != nil {
		t.Fatalf("InstallRevealHook: %v", err)
	}

	if _, err := RemoveRevealHooks(dir); err != nil {
		t.Fatalf("RemoveRevealHooks: %v", err)
	}
	data, err := os.ReadFile(pkgPath) // #nosec G304 -- test-controlled path
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var pkg struct {
		Scripts map[string]string `json:"scripts"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		t.Fatalf("package.json is no longer valid JSON after removal: %v\n%s", err, data)
	}
	if pkg.Scripts["predev"] != "echo user-hook" {
		t.Errorf("predev = %q, want the user's own %q back", pkg.Scripts["predev"], "echo user-hook")
	}
	if _, exists := pkg.Scripts["prestart"]; exists {
		t.Errorf("prestart (entirely jit's) should be deleted, got %q", pkg.Scripts["prestart"])
	}
	if pkg.Scripts["dev"] != "vite" || pkg.Scripts["start"] != "node ." {
		t.Errorf("user scripts changed: %v", pkg.Scripts)
	}
}

// TestRestorePointerFileRoundTrip: an in-place pointer file (what a
// backup-suffixed .env.bak becomes, GAPS.md #34) restores to a plain
// dotenv file with the real vault values — `jit migrate remove`'s path for
// files that were never live mounts.
func TestRestorePointerFileRoundTrip(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".env.bak")
	writeFile(t, path, "API_KEY=sk_stale_but_real\n")

	v := newTestVault(t)
	if _, err := ApplyEnvFile(v, root, path); err != nil {
		t.Fatalf("ApplyEnvFile: %v", err)
	}
	if !IsPointerFile(path) {
		t.Fatal("precondition: .env.bak should be an in-place pointer file after migration")
	}

	names, err := RestorePointerFile(v, path)
	if err != nil {
		t.Fatalf("RestorePointerFile: %v", err)
	}
	if len(names) != 1 || names[0] != "API_KEY" {
		t.Errorf("names = %v, want [API_KEY]", names)
	}
	data, err := os.ReadFile(path) // #nosec G304 -- test-controlled path
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !strings.Contains(string(data), "API_KEY=sk_stale_but_real") {
		t.Errorf("restored content = %q, want the real value back", data)
	}
	if IsPointerFile(path) {
		t.Error("file still sniffs as a pointer file after restore")
	}
}

func TestDiscoverPointerArtifacts(t *testing.T) {
	root := t.TempDir()
	v := newTestVault(t)

	// An in-place pointer file (.env.bak) and a live mount whose .pointers
	// companion we plant by hand (ApplyEnvFile doesn't write companions —
	// that's the CLI's job).
	bakPath := filepath.Join(root, ".env.bak")
	writeFile(t, bakPath, "A=1\n")
	if _, err := ApplyEnvFile(v, root, bakPath); err != nil {
		t.Fatalf("ApplyEnvFile: %v", err)
	}
	companion := filepath.Join(root, ".env.pointers")
	writeFile(t, companion, "# jit pointer file\nA=jit://vault/x/A\n")
	writeFile(t, filepath.Join(root, ".env.example"), "A=placeholder\n") // ordinary file, matched by the wildcard but not a pointer file

	companions, inPlace, err := DiscoverPointerArtifacts(root)
	if err != nil {
		t.Fatalf("DiscoverPointerArtifacts: %v", err)
	}
	if len(companions) != 1 || companions[0] != companion {
		t.Errorf("companions = %v, want [%s]", companions, companion)
	}
	if len(inPlace) != 1 || inPlace[0] != bakPath {
		t.Errorf("inPlace = %v, want [%s]", inPlace, bakPath)
	}
}

func TestDropBackupRecords(t *testing.T) {
	root := t.TempDir()
	recA := BackupRecord{OriginalPath: "/proj/a/.env", VaultPath: "_backups/a", UnixTS: 1}
	recB := BackupRecord{OriginalPath: "/proj/b/.env", VaultPath: "_backups/b", UnixTS: 2}
	for _, r := range []BackupRecord{recA, recB} {
		if err := appendBackupRecord(root, r); err != nil {
			t.Fatalf("appendBackupRecord: %v", err)
		}
	}

	if err := DropBackupRecords(root, []BackupRecord{recA}); err != nil {
		t.Fatalf("DropBackupRecords: %v", err)
	}
	recs, err := LoadBackupRecords(root)
	if err != nil {
		t.Fatalf("LoadBackupRecords: %v", err)
	}
	if len(recs) != 1 || recs[0].VaultPath != "_backups/b" {
		t.Errorf("records after drop = %v, want just recB", recs)
	}

	// Dropping the last record removes the index file itself — an empty
	// index would make `jit migrate undo` half-fail confusingly, the same
	// reasoning vault clean already applies.
	if err := DropBackupRecords(root, []BackupRecord{recB}); err != nil {
		t.Fatalf("DropBackupRecords(last): %v", err)
	}
	if _, err := os.Stat(BackupIndexPath(root)); !os.IsNotExist(err) {
		t.Errorf("undo index should be gone once its last record is dropped (stat err: %v)", err)
	}
}
