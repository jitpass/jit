// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"os"
	"path/filepath"
	"testing"
)

func writeArtifactFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil { // #nosec G306 -- test fixture
		t.Fatalf("WriteFile %s: %v", path, err)
	}
}

// installFakeJit lays out a runnable binary at path and returns it.
func installFakeJit(t *testing.T, path string) string {
	t.Helper()
	writeArtifactFile(t, path, "#!/bin/sh\n", 0o755)
	return path
}

func TestDiscoverRecordedJitPathsEveryArtifact(t *testing.T) {
	home := t.TempDir()
	prefix, err := filepath.EvalSymlinks(home)
	if err != nil {
		t.Fatal(err)
	}
	stable := installFakeJit(t, filepath.Join(prefix, "bin", "jit"))
	versioned := installFakeJit(t, filepath.Join(prefix, "brew", "Caskroom", "jitpass", "0.84.0", "jit"))
	gone := "/nowhere/at/all/jit"

	writeArtifactFile(t, KubeconfigPath(home), "users:\n- name: u\n  user:\n    exec:\n      command: "+gone+"\n      args: [k8s-exec-credential]\n", 0o600)
	writeArtifactFile(t, AWSConfigPath(home), "[profile work]\ncredential_process = "+versioned+" aws-credential-process --profile aws-work\n", 0o600)
	writeArtifactFile(t, DockerHelperPath(home), "#!/bin/sh\n# this used to be /old/place/jit before the rewrite\nexec '"+stable+"' docker-credential \"$@\"\n", 0o755)
	writeArtifactFile(t, GitHelperPath(home), "#!/bin/sh\nexec '"+stable+"' git-credential \"$@\"\n", 0o755)
	// terraform helper absent on purpose: an artifact the user never
	// migrated must stay quiet.

	got := DiscoverRecordedJitPaths(home)
	want := map[string]struct {
		category, recorded, stale string
	}{
		KubeconfigPath(home):   {"kube", gone, StaleMissing},
		AWSConfigPath(home):    {"aws", versioned, StaleVersioned},
		DockerHelperPath(home): {"docker", stable, ""}, // the comment's /old/place/jit is not on the exec line
		GitHelperPath(home):    {"git", stable, ""},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d recorded paths, want %d:\n%+v", len(got), len(want), got)
	}
	for _, r := range got {
		w, ok := want[r.Path]
		if !ok {
			t.Errorf("unexpected artifact %s", r.Path)
			continue
		}
		if r.Category != w.category || r.Recorded != w.recorded || r.Stale() != w.stale {
			t.Errorf("%s = category %q recorded %q stale %q; want %q %q %q", r.Label, r.Category, r.Recorded, r.Stale(), w.category, w.recorded, w.stale)
		}
	}
}

func TestDiscoverRecordedJitPathsIsQuietOnAnEmptyHome(t *testing.T) {
	if got := DiscoverRecordedJitPaths(t.TempDir()); len(got) != 0 {
		t.Errorf("an empty home produced %d entries, want none: %+v", len(got), got)
	}
}

func TestRefreshRecordedLinesIsLineAnchoredAndByteExact(t *testing.T) {
	const from, to = "/opt/homebrew/Caskroom/jitpass/0.84.0/jit", "/opt/homebrew/bin/jit"
	for _, tc := range []struct {
		name, key, in, want string
	}{
		{"yaml exec command", "command:",
			"users:\n- name: u\n  user:\n    exec:\n      command: " + from + "\n      args: [\"k8s-exec-credential\"]\n",
			"users:\n- name: u\n  user:\n    exec:\n      command: " + to + "\n      args: [\"k8s-exec-credential\"]\n"},
		{"ini credential_process", "credential_process",
			"[profile work]\nregion = us-east-1\ncredential_process = " + from + " aws-credential-process --profile aws-work\n",
			"[profile work]\nregion = us-east-1\ncredential_process = " + to + " aws-credential-process --profile aws-work\n"},
		{"single-quoted shell exec, comment untouched", "exec ",
			"#!/bin/sh\n# was " + from + " once\nexec '" + from + "' git-credential \"$@\"\n",
			"#!/bin/sh\n# was " + from + " once\nexec '" + to + "' git-credential \"$@\"\n"},
		{"no trailing newline stays that way", "exec ",
			"exec '" + from + "' docker-credential \"$@\"",
			"exec '" + to + "' docker-credential \"$@\""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, changed := refreshRecordedLines(tc.in, tc.key, from, to)
			if !changed || got != tc.want {
				t.Errorf("changed=%v\n got: %q\nwant: %q", changed, got, tc.want)
			}
			// A second pass finds nothing to change: idempotent.
			if _, again := refreshRecordedLines(got, tc.key, from, to); again {
				t.Error("a refreshed file was changed again")
			}
		})
	}
	// A different recorded path on the anchored line is not touched: the
	// substitution is for the exact path the plan showed.
	if got, changed := refreshRecordedLines("exec '/usr/local/bin/jit' x\n", "exec ", from, to); changed || got != "exec '/usr/local/bin/jit' x\n" {
		t.Errorf("a non-matching path was rewritten: %q", got)
	}
}

func TestRefreshRecordedJitPathBacksUpAndKeepsMode(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	v := newTestVault(t)
	helper := GitHelperPath(home)
	stale := "/nowhere/at/all/jit"
	writeArtifactFile(t, helper, "#!/bin/sh\nexec '"+stale+"' git-credential \"$@\"\n", 0o755)

	var r RecordedJitPath
	for _, c := range DiscoverRecordedJitPaths(home) {
		if c.Path == helper {
			r = c
		}
	}
	if r.Recorded != stale || r.Stale() != StaleMissing {
		t.Fatalf("discovery = %+v, want the stale helper", r)
	}
	tracker := NewBackupTracker()
	res, err := RefreshRecordedJitPath(v, r, "/usr/local/bin/jit", tracker)
	if err != nil {
		t.Fatalf("RefreshRecordedJitPath: %v", err)
	}
	got, err := os.ReadFile(helper) // #nosec G304 -- test fixture
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "#!/bin/sh\nexec '/usr/local/bin/jit' git-credential \"$@\"\n" {
		t.Errorf("helper after refresh:\n%s", got)
	}
	info, err := os.Stat(helper)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Errorf("mode after refresh = %o, want 0755 — a helper that lost its execute bit fails the tool it serves", info.Mode().Perm())
	}
	if res.From != stale || res.To != "/usr/local/bin/jit" || res.Backup == "" {
		t.Errorf("result = %+v", res)
	}
	// The pristine bytes are in the vault, indexed for undo.
	backup, err := v.Get(res.Backup)
	if err != nil || string(backup) != "#!/bin/sh\nexec '"+stale+"' git-credential \"$@\"\n" {
		t.Errorf("backup = %q, %v; want the pre-refresh bytes", backup, err)
	}
	records, err := LoadBackupRecords(v.Root)
	if err != nil {
		t.Fatalf("LoadBackupRecords: %v", err)
	}
	var rec *BackupRecord
	for i := range records {
		if records[i].OriginalPath == helper {
			rec = &records[i]
		}
	}
	if rec == nil || rec.VaultPath != res.Backup || rec.Mode != "755" {
		t.Errorf("undo record for %s = %+v, want vault path %s with mode 755", helper, rec, res.Backup)
	}
	// And undo puts the stale line back, mode included.
	if err := RestoreFromBackup(v, *rec); err != nil {
		t.Fatalf("RestoreFromBackup: %v", err)
	}
	restored, err := os.ReadFile(helper) // #nosec G304 -- test fixture
	if err != nil {
		t.Fatal(err)
	}
	if string(restored) != "#!/bin/sh\nexec '"+stale+"' git-credential \"$@\"\n" {
		t.Errorf("undo did not restore the pristine helper:\n%s", restored)
	}
	// A second refresh in the same run (a category migration rewriting the
	// same file) must not re-back-up the already-modified file.
	if again, err := tracker.backupOnce(v, helper); err != nil || again != res.Backup {
		t.Errorf("second backupOnce = %q, %v; want the first backup reused", again, err)
	}
}

func TestRefreshRecordedJitPathRefusesAQuotedTarget(t *testing.T) {
	v := newTestVault(t)
	if _, err := RefreshRecordedJitPath(v, RecordedJitPath{Path: "/x", Key: "exec ", Recorded: "/a/jit"}, "/Applications/My Tools/jit", nil); err == nil {
		t.Error("a target with whitespace must be refused, not substituted into a helper's quoting")
	}
}
