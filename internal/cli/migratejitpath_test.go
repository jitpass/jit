// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/migrate"
)

// stubDurableJitPath pins the plan-time resolver: the test binary is
// volatile, so the real one refuses — the refusal path is the default here
// and needs no stub.
func stubDurableJitPath(t *testing.T, path string, err error) {
	t.Helper()
	orig := durableJitPath
	durableJitPath = func() (string, error) { return path, err }
	t.Cleanup(func() { durableJitPath = orig })
}

const staleKubeconfig = `apiVersion: v1
users:
- name: docker-desktop
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      command: /opt/homebrew/Caskroom/jitpass/0.84.0/jit
      args: ["k8s-exec-credential", "--profile", "k8s-docker-desktop"]
      interactiveMode: Never
`

// Doctor prescribes `jit migrate ~/.kube/config` for a stale exec line; on
// an already-migrated file that used to print "Nothing to migrate" and
// change nothing. It now plans the refresh — the same row --dry-run shows.
func TestMigrateNamedKubeconfigPlansAJitPathRefresh(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)
	stubDurableJitPath(t, "/opt/homebrew/bin/jit", nil)
	kube := migrate.KubeconfigPath(home)
	writeArtifact(t, kube, staleKubeconfig)

	out, err := execMigrate(t, kube, "--dry-run")
	if err != nil {
		t.Fatalf("jit migrate ~/.kube/config --dry-run: %v\n%s", err, out)
	}
	for _, want := range []string{
		"[recorded jit path] 1",
		"rewritten to /opt/homebrew/bin/jit",
		"~/.kube/config (was /opt/homebrew/Caskroom/jitpass/0.84.0/jit)",
		"1 change planned across 1 category",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("plan missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Nothing to migrate") {
		t.Errorf("a stale recorded path is something to migrate:\n%s", out)
	}
	if got := strings.Count(out, "[DRY RUN]"); got != 2 {
		t.Errorf("expected exactly 2 [DRY RUN] markers on a refresh-only dry run, got %d:\n%s", got, out)
	}
}

// --only scopes a refresh through the artifact's owning category: `aws`
// reaches ~/.aws/config, `env` leaves every artifact alone.
func TestMigrateOnlyScopesJitPathRefreshByCategory(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)
	stubDurableJitPath(t, "/opt/homebrew/bin/jit", nil)
	writeArtifact(t, migrate.KubeconfigPath(home), staleKubeconfig)
	writeArtifact(t, migrate.AWSConfigPath(home), "[profile work]\ncredential_process = /nowhere/jit aws-credential-process --profile aws-work\n")

	out, err := execMigrate(t, migrate.KubeconfigPath(home), migrate.AWSConfigPath(home), "--only", "aws", "--dry-run")
	if err != nil {
		t.Fatalf("--only aws: %v\n%s", err, out)
	}
	if !strings.Contains(out, "~/.aws/config (was /nowhere/jit)") || strings.Contains(out, "~/.kube/config") {
		t.Errorf("--only aws must plan the AWS config and nothing else:\n%s", out)
	}

	out, err = execMigrate(t, migrate.KubeconfigPath(home), "--only", "env", "--dry-run")
	if err != nil {
		t.Fatalf("--only env: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Nothing to migrate in the selected --only") {
		t.Errorf("--only env must leave the kubeconfig refresh out:\n%s", out)
	}
}

// A jit with no durable path — the real answer inside `go test` — turns
// the refresh into a note at plan time, never a failure after [y/N].
func TestMigrateJitPathRefusalIsANoteNotAFailure(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)
	stubDurableJitPath(t, "", errors.New("this jit is running from a temporary or removable location (~/Downloads/jit)"))
	kube := migrate.KubeconfigPath(home)
	writeArtifact(t, kube, staleKubeconfig)

	out, err := execMigrate(t, kube, "--dry-run")
	if err != nil {
		t.Fatalf("jit migrate ~/.kube/config --dry-run: %v\n%s", err, out)
	}
	if !strings.Contains(out, "can't refresh right now") || !strings.Contains(out, "~/Downloads/jit") {
		t.Errorf("expected the refusal note with its reason:\n%s", out)
	}
	if strings.Contains(out, "[recorded jit path]") {
		t.Errorf("a refused refresh must not be a plan row:\n%s", out)
	}
}

// A durable path is not stale: the common healthy install plans nothing.
func TestMigrateNamedArtifactWithDurablePathIsQuiet(t *testing.T) {
	home := withFixtureHome(t)
	withFixtureCwd(t)
	stubDurableJitPath(t, "/opt/homebrew/bin/jit", nil)
	prefix, err := filepath.EvalSymlinks(home)
	if err != nil {
		t.Fatal(err)
	}
	stable := installFakeJit(t, filepath.Join(prefix, "bin", "jit"))
	helper := migrate.GitHelperPath(home)
	writeArtifact(t, helper, "#!/bin/sh\nexec '"+stable+"' git-credential \"$@\"\n")

	out, err := execMigrate(t, helper, "--dry-run")
	if err != nil {
		t.Fatalf("jit migrate <helper> --dry-run: %v\n%s", err, out)
	}
	if strings.Contains(out, "[recorded jit path]") {
		t.Errorf("a durable path was planned for refresh:\n%s", out)
	}
}
