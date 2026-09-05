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
