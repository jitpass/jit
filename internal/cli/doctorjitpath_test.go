// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeArtifact drops a file with its parent directories, for the fixed
// locations jitPathFindings probes.
func writeArtifact(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile %s: %v", path, err)
	}
}

// installFakeJit lays out a runnable binary at path.
func installFakeJit(t *testing.T, path string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil { // #nosec G306 -- a fake executable in a test fixture
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

// TestJitPathFindingsReportsAMissingBinary: the artifact is broken NOW, so it
// is a hard problem — the same verdict the MCP check gives, for the same
// reason. This is the gap that let a kubeconfig sit with a dead exec command
// while doctor reported every secret reference resolving cleanly.
func TestJitPathFindingsReportsAMissingBinary(t *testing.T) {
	home := t.TempDir()
	writeArtifact(t, filepath.Join(home, ".kube", "config"), `
users:
- name: docker-desktop
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      command: /usr/local/bin/jit
      args: ["k8s-exec-credential"]
`)

	findings := jitPathFindings(home)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Kind != kindJitPath {
		t.Errorf("Kind = %q, want %q — a binary that isn't there is breakage, not advice", f.Kind, kindJitPath)
	}
	if f.Kind.warning() {
		t.Error("a missing jit binary must fail the run, not warn")
	}
	if !strings.Contains(f.Detail, "/usr/local/bin/jit") || !strings.Contains(f.Detail, "isn't there") {
		t.Errorf("Detail = %q, want it to name the path and say it is missing", f.Detail)
	}
}

// TestJitPathFindingsWarnsBeforeTheUpgradeBreaksIt is the check's real point:
// a version-numbered Homebrew path works today and stops existing at the next
// `brew upgrade`. Reporting it only once it is missing means reporting it when
// the user is already mid-task on a tool that just broke.
func TestJitPathFindingsWarnsBeforeTheUpgradeBreaksIt(t *testing.T) {
	home := t.TempDir()
	prefix, err := filepath.EvalSymlinks(home)
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	versioned := installFakeJit(t, filepath.Join(prefix, "brew", "Caskroom", "jitpass", "0.84.0", "jit"))
	writeArtifact(t, filepath.Join(home, ".aws", "config"),
		"[profile work]\ncredential_process = "+versioned+" aws-credential-process --profile aws-work\n")

	findings := jitPathFindings(home)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Kind != kindJitPathUpgrade {
		t.Errorf("Kind = %q, want %q", f.Kind, kindJitPathUpgrade)
	}
	if !f.Kind.warning() {
		t.Error("nothing has failed yet, so this must be advisory rather than a hard problem")
	}
	if !strings.Contains(f.Detail, "version-pinned") {
		t.Errorf("Detail = %q, want it to say why the path is fragile", f.Detail)
	}
	if !strings.Contains(f.Action, "--only aws") {
		t.Errorf("Action = %q, want the aws-scoped re-migration", f.Action)
	}
}

// TestJitPathFindingsAcceptsADurablePath: the common healthy install must be
// silent, or the check is noise on every run.
func TestJitPathFindingsAcceptsADurablePath(t *testing.T) {
	home := t.TempDir()
	prefix, err := filepath.EvalSymlinks(home)
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	stable := installFakeJit(t, filepath.Join(prefix, "bin", "jit"))
	writeArtifact(t, filepath.Join(home, ".jit", "shims", "git-credential-jit"),
		"#!/bin/sh\nexec '"+stable+"' git-credential \"$@\"\n")

	if findings := jitPathFindings(home); len(findings) != 0 {
		t.Errorf("a durable path produced %d findings, want none: %+v", len(findings), findings)
	}
}

// TestJitPathFindingsIgnoresUnrelatedPaths: the scan is anchored to the line
// that actually carries the recorded command. Without that anchor a comment
// mentioning a jit path — or any other tool's absolute path — would be
// reported as a broken artifact the user cannot find.
func TestJitPathFindingsIgnoresUnrelatedPaths(t *testing.T) {
	home := t.TempDir()
	writeArtifact(t, filepath.Join(home, ".jit", "shims", "docker-credential-jit"),
		"#!/bin/sh\n# this used to be /nowhere/at/all/jit before the rewrite\nexec /bin/echo hi\n")

	if findings := jitPathFindings(home); len(findings) != 0 {
		t.Errorf("a path in a comment produced %d findings, want none: %+v", len(findings), findings)
	}
}

// TestJitPathFindingsToleratesAbsentArtifacts: probing all five locations
// unconditionally is only safe if the ones a user never migrated stay quiet.
func TestJitPathFindingsToleratesAbsentArtifacts(t *testing.T) {
	if findings := jitPathFindings(t.TempDir()); len(findings) != 0 {
		t.Errorf("an empty home produced %d findings, want none: %+v", len(findings), findings)
	}
}

// TestJitPathKindsRender guards the gap kindMCP fell into: a kind declared in
// one file and rendered in another shipped with no case in findingLabel, so
// its group header printed as a bare count with no name.
func TestJitPathKindsRender(t *testing.T) {
	for _, k := range []checkKind{kindJitPath, kindJitPathUpgrade} {
		label := findingLabel(checkFinding{Kind: k})
		if label == "" {
			t.Errorf("kind %q has no group label", k)
		}
		if !strings.Contains(label, "jit path") {
			t.Errorf("kind %q renders as %q, want a recognizable [jit path] group", k, label)
		}
		body := formatFinding(checkFinding{Kind: k, Detail: "some detail"})
		if body != "some detail" {
			t.Errorf("kind %q body = %q, want the detail rendered", k, body)
		}
	}
}
