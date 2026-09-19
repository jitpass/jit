// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/mount"
)

// A registered mount whose FILE is gone, with its manifest intact. Doctor
// stat'ed no mount path at all before this — only two counters in
// internal/audit did — so the state produced no finding while the service
// logged a skip for it on every unlock. The commonest cause is a project
// folder renamed or moved: its contents travelled, the registry did not
// (design/project-relocation.md).
func TestDoctorReportsAMountWhoseFileIsGone(t *testing.T) {
	home := withFixtureHome(t)
	cwd := withFixtureCwd(t)
	plantVaultSecret(t, home, "app/key")

	project := filepath.Join(home, "proj")
	manifest := filepath.Join(project, ".jit", "profiles", "app.yaml")
	if err := os.MkdirAll(filepath.Dir(manifest), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifest, []byte("APP_KEY: app/key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Registered, but nothing was ever created at the mount path.
	registerFixtureMount(t, home, filepath.Join(project, ".env"), manifest)
	_ = cwd

	outcome, err := gatherDoctorOutcome(nil, "", false)
	if err != nil {
		t.Fatal(err)
	}
	var found *checkFinding
	for i, f := range outcome.Findings {
		if f.Kind == kindMount && strings.Contains(f.Detail, "no file there") {
			found = &outcome.Findings[i]
		}
	}
	if found == nil {
		t.Fatalf("expected a finding for a mount with no file; got %+v", kindsOf(outcome.Findings))
	}
	if !strings.Contains(found.Detail, shortPath(filepath.Join(project, ".env"))) {
		t.Errorf("the finding must name the mount path: %q", found.Detail)
	}
	// The manifest loaded, so its references are real: a missing FILE must
	// never make the secrets that manifest names look unreferenced.
	for _, f := range outcome.Findings {
		if f.Kind == kindOrphan {
			t.Errorf("app/key is referenced by a manifest that loaded; it must not be reported orphaned: %+v", f)
		}
	}
}

// The same registry entry with its file present produces no such finding —
// the negative control for the check above.
func TestDoctorSaysNothingWhenTheMountFileIsThere(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)
	plantVaultSecret(t, home, "app/key")

	project := filepath.Join(home, "proj")
	manifest := filepath.Join(project, ".jit", "profiles", "app.yaml")
	if err := os.MkdirAll(filepath.Dir(manifest), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifest, []byte("APP_KEY: app/key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := filepath.Join(project, ".env")
	if err := mount.CreateFIFO(env); err != nil {
		t.Fatal(err)
	}
	registerFixtureMount(t, home, env, manifest)

	outcome, err := gatherDoctorOutcome(nil, "", false)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range outcome.Findings {
		if f.Kind == kindMount {
			t.Errorf("a served mount must produce no [mount] finding: %+v", f)
		}
	}
}

// A mount path with nothing at it is a SKIP, taken before the Serve
// goroutine exists. It used to enter served, fail ENOENT inside Serve, log in
// full and delete its own map entry — so every unlock and every refresh
// retried and logged again, forever, escaping the transition gate built for
// exactly that flood because the gate only covers mounts that never entered
// served. This asserts both halves: one line, and served stays empty.
func TestServiceSkipsAMountWithNoFileAndLogsItOnce(t *testing.T) {
	home := withFixtureHome(t)
	root := filepath.Join(home, "Library", "Application Support", "jitpass")
	project := filepath.Join(home, "proj")
	manifest := filepath.Join(project, ".jit", "profiles", "app.yaml")
	if err := os.MkdirAll(filepath.Dir(manifest), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifest, []byte("APP_KEY: app/key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := filepath.Join(project, ".env")

	var stdout, stderr bytes.Buffer
	m := &mountManager{root: root, stdout: &stdout, stderr: &stderr}
	entries := []mount.Entry{{MountPath: env, ProfilePath: manifest}}

	for i := 0; i < 5; i++ {
		m.ensureServing(entries)
	}
	if n := strings.Count(stderr.String(), "nothing at this path to serve"); n != 1 {
		t.Errorf("five passes must log once, got %d:\n%s", n, stderr.String())
	}
	m.mu.Lock()
	served := len(m.served)
	m.mu.Unlock()
	if served != 0 {
		t.Errorf("a mount with no file must never enter served, got %d", served)
	}

	// The file appearing closes the transition, exactly as any other skip.
	if err := mount.CreateFIFO(env); err != nil {
		t.Fatal(err)
	}
	m.ensureServing(entries)
	t.Cleanup(m.shutdown)
	if !strings.Contains(stdout.String(), "recovered, serving again") {
		t.Errorf("the file coming back must close the skip transition, got:\n%s", stdout.String())
	}
}

func kindsOf(findings []checkFinding) []checkKind {
	out := make([]checkKind, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.Kind)
	}
	return out
}
