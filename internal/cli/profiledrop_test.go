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

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/migrate"
	"github.com/jitpass/jit/internal/mount"
	"github.com/jitpass/jit/internal/pointerfile"
	"github.com/jitpass/jit/internal/profile"
)

// execProfileDrop runs the command with its flags reset, in whatever
// directory the test has chdir'd into. --yes by default: the confirmation
// has its own test, and every other case is about the guards.
func execProfileDrop(t *testing.T, args ...string) (string, error) {
	t.Helper()
	profileDropYes = true
	profileDropDryRun = false

	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	if err := profileDropCmd.Flags().Parse(args); err != nil {
		t.Fatalf("parsing flags: %v", err)
	}
	// Run first, THEN read the buffer (see execProfileCreate).
	err := runProfileDrop(cmd, profileDropCmd.Flags().Args())
	return buf.String(), err
}

// readProfile is the manifest as jit will next read it, so a test asserts on
// the parsed result rather than on YAML formatting.
func readProfile(t *testing.T, path string) profile.Profile {
	t.Helper()
	p, err := profile.LoadFile(path)
	if err != nil {
		t.Fatalf("loading %s: %v", path, err)
	}
	return p
}

// The case the command exists for, and the exact shape the user hit: a
// manifest restored with six entries beside a vault holding two. The four
// the tool never needed go; the two that work stay.
func TestProfileDropRemovesTheEntriesTheVaultHasNoValueFor(t *testing.T) {
	home := withFixtureHome(t)
	cwd := inProject(t)
	writeFixtureProfile(t, cwd, "hibob",
		"HIBOB_SERVICE_USER_ID: hibob/HIBOB_SERVICE_USER_ID\n"+
			"HIBOB_SERVICE_USER_TOKEN: hibob/HIBOB_SERVICE_USER_TOKEN\n"+
			"HIBOB_BASE_URL: hibob/HIBOB_BASE_URL\n"+
			"HIBOB_FIELDS: hibob/HIBOB_FIELDS\n")
	plantVaultSecret(t, home, "hibob/HIBOB_SERVICE_USER_ID")
	plantVaultSecret(t, home, "hibob/HIBOB_SERVICE_USER_TOKEN")

	out, err := execProfileDrop(t, "hibob", "HIBOB_BASE_URL", "HIBOB_FIELDS")
	if err != nil {
		t.Fatalf("drop: %v\n%s", err, out)
	}
	got := readProfile(t, filepath.Join(cwd, ".jit", "profiles", "hibob.yaml"))
	want := profile.Profile{
		"HIBOB_SERVICE_USER_ID":    "hibob/HIBOB_SERVICE_USER_ID",
		"HIBOB_SERVICE_USER_TOKEN": "hibob/HIBOB_SERVICE_USER_TOKEN",
	}
	if len(got) != len(want) {
		t.Fatalf("manifest = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("manifest[%s] = %q, want %q", k, got[k], v)
		}
	}
	// Both names in one line, so the user can see what went without
	// re-reading the file.
	if !strings.Contains(out, "HIBOB_BASE_URL") || !strings.Contains(out, "HIBOB_FIELDS") {
		t.Errorf("expected both dropped names in the output, got:\n%s", out)
	}
}

// The guard that matters most: a variable whose vault path HOLDS a value is
// live. Dropping it would leave a real secret with nothing pointing at it —
// invisible to `jit run`, and an orphan to everything else.
func TestProfileDropRefusesAVariableTheVaultHasAValueFor(t *testing.T) {
	home := withFixtureHome(t)
	cwd := inProject(t)
	writeFixtureProfile(t, cwd, "app", "A_KEY: app/A_KEY\nB_KEY: app/B_KEY\n")
	plantVaultSecret(t, home, "app/A_KEY")

	_, err := execProfileDrop(t, "app", "A_KEY")
	if err == nil || !strings.Contains(err.Error(), "live, not left over") {
		t.Fatalf("err = %v, want a refusal naming the value that exists", err)
	}
	// And it says which command DOES mean "delete this secret".
	if err != nil && !strings.Contains(err.Error(), "jit vault rm") {
		t.Errorf("the refusal must name the command that deletes a secret, got: %v", err)
	}
	if got := readProfile(t, filepath.Join(cwd, ".jit", "profiles", "app.yaml")); len(got) != 2 {
		t.Errorf("the manifest must be untouched, got %v", got)
	}
}

// A refusal is all-or-nothing: naming one droppable and one live variable
// drops neither, so a multi-variable command can't half-apply.
func TestProfileDropIsAllOrNothing(t *testing.T) {
	home := withFixtureHome(t)
	cwd := inProject(t)
	writeFixtureProfile(t, cwd, "app", "A_KEY: app/A_KEY\nB_KEY: app/B_KEY\nC_KEY: app/C_KEY\n")
	plantVaultSecret(t, home, "app/A_KEY")

	if _, err := execProfileDrop(t, "app", "B_KEY", "A_KEY"); err == nil {
		t.Fatal("expected a refusal for the live variable")
	}
	if got := readProfile(t, filepath.Join(cwd, ".jit", "profiles", "app.yaml")); len(got) != 3 {
		t.Errorf("no variable may be dropped when one is refused, got %v", got)
	}
}

// A typo must not quietly succeed, and the refusal lists what the manifest
// does hold — the thing the user needs in order to retype it.
func TestProfileDropRefusesAVariableTheManifestDoesNotList(t *testing.T) {
	withFixtureHome(t)
	cwd := inProject(t)
	writeFixtureProfile(t, cwd, "app", "A_KEY: app/A_KEY\nB_KEY: app/B_KEY\n")

	_, err := execProfileDrop(t, "app", "A_TYPO")
	if err == nil || !strings.Contains(err.Error(), "does not list A_TYPO") {
		t.Fatalf("err = %v, want a refusal naming the unknown variable", err)
	}
	if !strings.Contains(err.Error(), "A_KEY") || !strings.Contains(err.Error(), "B_KEY") {
		t.Errorf("the refusal must list what the manifest holds, got: %v", err)
	}
}

// An empty manifest resolves to nothing AND reports nothing, so it reads as
// fixed while the tool is broken. Refused.
func TestProfileDropRefusesToEmptyTheManifest(t *testing.T) {
	withFixtureHome(t)
	cwd := inProject(t)
	writeFixtureProfile(t, cwd, "app", "A_KEY: app/A_KEY\n")

	_, err := execProfileDrop(t, "app", "A_KEY")
	if err == nil || !strings.Contains(err.Error(), "no variables") {
		t.Fatalf("err = %v, want a refusal for emptying the manifest", err)
	}
	if got := readProfile(t, filepath.Join(cwd, ".jit", "profiles", "app.yaml")); len(got) != 1 {
		t.Errorf("the manifest must survive, got %v", got)
	}
}

func TestProfileDropDryRunWritesNothing(t *testing.T) {
	withFixtureHome(t)
	cwd := inProject(t)
	writeFixtureProfile(t, cwd, "app", "A_KEY: app/A_KEY\nB_KEY: app/B_KEY\n")

	profileDropDryRun = true
	t.Cleanup(func() { profileDropDryRun = false })
	out, err := execProfileDrop(t, "--dry-run", "app", "A_KEY")
	if err != nil {
		t.Fatalf("dry run: %v\n%s", err, out)
	}
	if !strings.Contains(out, "would drop") || !strings.Contains(out, "A_KEY") {
		t.Errorf("a dry run must say what it would do, got:\n%s", out)
	}
	if got := readProfile(t, filepath.Join(cwd, ".jit", "profiles", "app.yaml")); len(got) != 2 {
		t.Errorf("a dry run must write nothing, got %v", got)
	}
}

// The companion beside a live mount is rewritten from the trimmed manifest.
// Nothing else in jit ever rewrites that file — migrate writes it once and
// every other caller only deletes it — so without this the .pointers file
// would keep listing the dropped variables for good, which is the drift
// that made this whole class of finding confusing in the first place.
func TestProfileDropRewritesALiveMountsCompanion(t *testing.T) {
	home := withFixtureHome(t)
	cwd := inProject(t)
	writeFixtureProfile(t, cwd, "app", "A_KEY: app/A_KEY\nB_KEY: app/B_KEY\n")
	manifest := filepath.Join(cwd, ".jit", "profiles", "app.yaml")

	mountPath := filepath.Join(cwd, ".env")
	companion := migrate.PointerFilePath(mountPath)
	if err := migrate.WritePointerFile(mountPath, profile.Profile{
		"A_KEY": "app/A_KEY", "B_KEY": "app/B_KEY",
	}, []string{"A_KEY", "B_KEY"}); err != nil {
		t.Fatalf("WritePointerFile: %v", err)
	}
	root := filepath.Join(home, "Library", "Application Support", "jitpass")
	if err := mount.AddMount(mount.RegistryPath(root), mount.Entry{
		MountPath: mountPath, ProfilePath: manifest,
	}); err != nil {
		t.Fatalf("AddMount: %v", err)
	}

	out, err := execProfileDrop(t, "app", "A_KEY")
	if err != nil {
		t.Fatalf("drop: %v\n%s", err, out)
	}
	data, err := os.ReadFile(companion)
	if err != nil {
		t.Fatalf("reading the companion: %v", err)
	}
	if strings.Contains(string(data), "A_KEY") {
		t.Errorf("the companion still lists the dropped variable:\n%s", data)
	}
	if !strings.Contains(string(data), "B_KEY") {
		t.Errorf("the companion lost the variable that stayed:\n%s", data)
	}
	// Still jit's own file afterwards, or `jit migrate forget` and the audit
	// scan would both stop recognising it.
	if !pointerfile.HasHeader(data) {
		t.Errorf("the rewritten companion lost its header:\n%s", data)
	}
	if !strings.Contains(out, "rewritten to match") {
		t.Errorf("the rewrite must be reported, got:\n%s", out)
	}
}

// A profile reached only through the mount registry — some other project's
// tree, which is how doctor sees one when it runs from the home directory,
// and therefore how the app's button will call this. Resolving by cwd alone
// would make the fix fail in exactly the case it was written for.
func TestProfileDropResolvesAProfileThroughTheMountRegistry(t *testing.T) {
	home := withFixtureHome(t)
	inProject(t)

	elsewhere := t.TempDir()
	writeFixtureProfile(t, elsewhere, "faraway", "A_KEY: faraway/A_KEY\nB_KEY: faraway/B_KEY\n")
	manifest := filepath.Join(elsewhere, ".jit", "profiles", "faraway.yaml")
	root := filepath.Join(home, "Library", "Application Support", "jitpass")
	if err := mount.AddMount(mount.RegistryPath(root), mount.Entry{
		MountPath: filepath.Join(elsewhere, ".env"), ProfilePath: manifest,
	}); err != nil {
		t.Fatalf("AddMount: %v", err)
	}

	out, err := execProfileDrop(t, "faraway", "A_KEY")
	if err != nil {
		t.Fatalf("drop: %v\n%s", err, out)
	}
	if got := readProfile(t, manifest); len(got) != 1 || got["B_KEY"] == "" {
		t.Errorf("manifest = %v, want only B_KEY", got)
	}
}

// A name that is nowhere says so, and says where it looked — otherwise the
// only signal is "not found" against a profile the user can see on disk.
func TestProfileDropNamesWhereItLooked(t *testing.T) {
	withFixtureHome(t)
	inProject(t)

	_, err := execProfileDrop(t, "nosuch", "A_KEY")
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("err = %v, want a not-found refusal", err)
	}
	if !strings.Contains(err.Error(), ".jit/profiles") || !strings.Contains(err.Error(), "registered mount") {
		t.Errorf("the refusal must say where it looked, got: %v", err)
	}
}

// Two variables on one vault path is a rename left half-done, and the
// leftover alias is exactly what this command is for. The secret cannot be
// stranded — the surviving variable still names it — so refusing would send
// the user back to hand-editing YAML.
func TestProfileDropAllowsAnAliasAnotherVariableStillNames(t *testing.T) {
	home := withFixtureHome(t)
	cwd := inProject(t)
	writeFixtureProfile(t, cwd, "app", "OLD_NAME: app/TOKEN\nNEW_NAME: app/TOKEN\nOTHER: app/OTHER\n")
	plantVaultSecret(t, home, "app/TOKEN")

	if out, err := execProfileDrop(t, "app", "OLD_NAME"); err != nil {
		t.Fatalf("drop: %v\n%s", err, out)
	}
	got := readProfile(t, filepath.Join(cwd, ".jit", "profiles", "app.yaml"))
	if got["NEW_NAME"] != "app/TOKEN" {
		t.Errorf("the surviving alias must keep the secret: %v", got)
	}
	if _, present := got["OLD_NAME"]; present {
		t.Errorf("OLD_NAME must be gone: %v", got)
	}
	// And dropping the LAST variable naming that path is still refused.
	if _, err := execProfileDrop(t, "app", "NEW_NAME"); err == nil {
		t.Error("dropping the only remaining reference must still be refused")
	}
}

// A path the vault can never hold anything at strands nothing. Doctor
// reports these as [bad path] with no action of its own, so refusing here
// left them removable by no jit command at all.
func TestProfileDropRemovesAnEntryWithAnUnusableVaultPath(t *testing.T) {
	withFixtureHome(t)
	cwd := inProject(t)
	writeFixtureProfile(t, cwd, "app", "BAD: /absolute/not/a/vault/path\nGOOD: app/GOOD\n")

	if out, err := execProfileDrop(t, "app", "BAD"); err != nil {
		t.Fatalf("drop: %v\n%s", err, out)
	}
	got := readProfile(t, filepath.Join(cwd, ".jit", "profiles", "app.yaml"))
	if _, present := got["BAD"]; present || got["GOOD"] != "app/GOOD" {
		t.Errorf("manifest = %v, want only GOOD", got)
	}
}

// A name that means two different files is refused, not guessed at: doctor
// names a mount-scope profile by its manifest's basename, so acting on a
// finding for another project's tree could otherwise edit the local
// manifest of the same name.
func TestProfileDropRefusesAnAmbiguousName(t *testing.T) {
	home := withFixtureHome(t)
	cwd := inProject(t)
	writeFixtureProfile(t, cwd, "api", "A_KEY: api/A_KEY\nB_KEY: api/B_KEY\n")

	elsewhere := t.TempDir()
	writeFixtureProfile(t, elsewhere, "api", "A_KEY: other/A_KEY\nB_KEY: other/B_KEY\n")
	root := filepath.Join(home, "Library", "Application Support", "jitpass")
	if err := mount.AddMount(mount.RegistryPath(root), mount.Entry{
		MountPath:   filepath.Join(elsewhere, ".env"),
		ProfilePath: filepath.Join(elsewhere, ".jit", "profiles", "api.yaml"),
	}); err != nil {
		t.Fatalf("AddMount: %v", err)
	}

	_, err := execProfileDrop(t, "api", "A_KEY")
	if err == nil || !strings.Contains(err.Error(), "more than one manifest") {
		t.Fatalf("err = %v, want a refusal naming both manifests", err)
	}
	if got := readProfile(t, filepath.Join(cwd, ".jit", "profiles", "api.yaml")); len(got) != 2 {
		t.Errorf("neither manifest may be touched, got %v", got)
	}
	// The path is the unambiguous form, and it resolves.
	if out, derr := execProfileDrop(t, filepath.Join(elsewhere, ".jit", "profiles", "api.yaml"), "A_KEY"); derr != nil {
		t.Fatalf("a manifest path must resolve: %v\n%s", derr, out)
	}
	if got := readProfile(t, filepath.Join(elsewhere, ".jit", "profiles", "api.yaml")); len(got) != 1 {
		t.Errorf("the named manifest = %v, want one variable", got)
	}
}

// Several mounts may share one manifest, and every companion must be
// rewritten — fixing one while reporting success left the others naming the
// dropped variable for good.
func TestProfileDropRewritesEveryCompanionSharingTheManifest(t *testing.T) {
	home := withFixtureHome(t)
	cwd := inProject(t)
	writeFixtureProfile(t, cwd, "app", "A_KEY: app/A_KEY\nB_KEY: app/B_KEY\n")
	manifest := filepath.Join(cwd, ".jit", "profiles", "app.yaml")
	root := filepath.Join(home, "Library", "Application Support", "jitpass")

	var companions []string
	for _, name := range []string{".env", ".env.local"} {
		mountPath := filepath.Join(cwd, name)
		if err := migrate.WritePointerFile(mountPath, profile.Profile{
			"A_KEY": "app/A_KEY", "B_KEY": "app/B_KEY",
		}, []string{"A_KEY", "B_KEY"}); err != nil {
			t.Fatalf("WritePointerFile: %v", err)
		}
		if err := mount.AddMount(mount.RegistryPath(root), mount.Entry{
			MountPath: mountPath, ProfilePath: manifest,
		}); err != nil {
			t.Fatalf("AddMount: %v", err)
		}
		companions = append(companions, migrate.PointerFilePath(mountPath))
	}

	out, err := execProfileDrop(t, "app", "A_KEY")
	if err != nil {
		t.Fatalf("drop: %v\n%s", err, out)
	}
	for _, c := range companions {
		data, rerr := os.ReadFile(c)
		if rerr != nil {
			t.Fatalf("reading %s: %v", c, rerr)
		}
		if strings.Contains(string(data), "A_KEY") {
			t.Errorf("%s still lists the dropped variable:\n%s", c, data)
		}
	}
}

// A hand-written manifest using a YAML merge key must not come back
// unloadable: "<<" is in the key order but never in the parsed profile.
func TestProfileDropSkipsAYAMLMergeKey(t *testing.T) {
	withFixtureHome(t)
	cwd := inProject(t)
	writeFixtureProfile(t, cwd, "app",
		"defaults: &defaults\n  A_KEY: app/A_KEY\n"+
			"<<: *defaults\nB_KEY: app/B_KEY\nC_KEY: app/C_KEY\n")

	manifest := filepath.Join(cwd, ".jit", "profiles", "app.yaml")
	if _, err := profile.LoadFile(manifest); err != nil {
		t.Skipf("this jit's parser rejects the fixture outright (%v), so the guard is unreachable", err)
	}
	if out, err := execProfileDrop(t, "app", "B_KEY"); err != nil {
		t.Fatalf("drop: %v\n%s", err, out)
	}
	if _, err := profile.LoadFile(manifest); err != nil {
		t.Errorf("the rewritten manifest must still load: %v", err)
	}
}
