// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// TestDoctorFixesClassifyEachKind pins `fixes` for the actions doctor really
// prints. The menu bar app runs these, so destructive and presence are the
// contract: a delete must never look like a harmless click.
func TestDoctorFixesClassifyEachKind(t *testing.T) {
	home := withFixtureHome(t)
	cases := []struct {
		name   string
		kind   checkKind
		action string
		want   []doctorFix
	}{
		{
			name:   "orphans: the listing is safe, the prune deletes",
			kind:   kindOrphan,
			action: "`jit vault orphans` to list them with origins, or `jit vault orphans --prune` to delete",
			want: []doctorFix{
				{Command: "jit vault orphans", Argv: []string{"vault", "orphans"}},
				{Command: "jit vault orphans --prune", Argv: []string{"vault", "orphans", "--prune"}, Destructive: true, Presence: true},
			},
		},
		{
			name: "stale mount: unmount only clears a registration",
			kind: kindMountStale,
			action: "`jit unmount ~/gone/.env` clears just this registration (no secret is touched); " +
				"`jit vault orphans --prune` clears every stale mount but also permanently deletes every orphaned secret",
			want: []doctorFix{
				{Command: "jit unmount ~/gone/.env", Argv: []string{"unmount", filepath.Join(home, "gone/.env")}},
				{Command: "jit vault orphans --prune", Argv: []string{"vault", "orphans", "--prune"}, Destructive: true, Presence: true},
			},
		},
		{
			name:   "a live mount's unmount writes plaintext back",
			kind:   kindMount,
			action: "fix the manifest, or `jit unmount ~/app/.env` to stop tracking it",
			want: []doctorFix{
				{Command: "jit unmount ~/app/.env", Argv: []string{"unmount", filepath.Join(home, "app/.env")}, Destructive: true, Presence: true},
			},
		},
		{
			name:   "install: both external commands remove something",
			kind:   kindInstall,
			action: "`brew uninstall jitpass` to keep /usr/local/bin/jit, or `sudo rm /usr/local/bin/jit` to switch to the Homebrew copy",
			want: []doctorFix{
				{Command: "brew uninstall jitpass", Argv: []string{"brew", "uninstall", "jitpass"}, External: true, Destructive: true},
				{Command: "sudo rm /usr/local/bin/jit", Argv: []string{"sudo", "rm", "/usr/local/bin/jit"}, External: true, Destructive: true},
			},
		},
		{
			name:   "completion: a shell append, quotes grouped",
			kind:   kindCompletion,
			action: "`echo 'source <(jit completion zsh)' >> ~/.zshrc` then restart your shell",
			want: []doctorFix{
				{Command: "echo 'source <(jit completion zsh)' >> ~/.zshrc",
					Argv: []string{"echo", "source <(jit completion zsh)", ">>", filepath.Join(home, ".zshrc")}, External: true},
			},
		},
		{
			name:   "1password link: a placeholder the caller must fill",
			kind:   kind1PasswordLink,
			action: "fix the item in 1Password, or `jit vault link okta/TOKEN <op://...>` to relink",
			want: []doctorFix{
				{Command: "jit vault link okta/TOKEN <op://...>", Argv: []string{"vault", "link", "okta/TOKEN", "<op://...>"}, Presence: true, Needs: "<op://...>"},
			},
		},
		{
			name:   "mcp: migrate undo restores plaintext, so it is destructive and asks for presence",
			kind:   kindMCP,
			action: "`jit migrate undo ~/ws/.mcp.json` to restore the original entry, or re-migrate it",
			want: []doctorFix{
				{Command: "jit migrate undo ~/ws/.mcp.json", Argv: []string{"migrate", "undo", filepath.Join(home, "ws/.mcp.json")}, Destructive: true, Presence: true},
			},
		},
		{
			name:   "jit path: migrate with a flag value is still migrate",
			kind:   kindJitPath,
			action: "`jit migrate --only aws`",
			want: []doctorFix{
				{Command: "jit migrate --only aws", Argv: []string{"migrate", "--only", "aws"}},
			},
		},
		{
			name:   "rekey asks for presence",
			kind:   kindRekey,
			action: "`jit vault rekey` to finish it",
			want:   []doctorFix{{Command: "jit vault rekey", Argv: []string{"vault", "rekey"}, Presence: true}},
		},
		{
			name:   "not logged in: clisso's own login, external, deletes nothing, asks for the user",
			kind:   kindNotLoggedIn,
			action: "`clisso get dev`",
			want: []doctorFix{
				{Command: "clisso get dev", Argv: []string{"clisso", "get", "dev"}, External: true, Presence: true},
			},
		},
		{
			name:   "an unknown jit command is destructive until classified",
			kind:   kindService,
			action: "`jit vault frobnicate x` or `jit frobnicate`",
			want: []doctorFix{
				{Command: "jit vault frobnicate x", Argv: []string{"vault", "frobnicate", "x"}, Destructive: true},
				{Command: "jit frobnicate", Argv: []string{"frobnicate"}, Destructive: true},
			},
		},
		{
			name:   "an unknown external command is destructive too",
			kind:   kindAudit,
			action: "`rm -rf ~/x`",
			want:   []doctorFix{{Command: "rm -rf ~/x", Argv: []string{"rm", "-rf", filepath.Join(home, "x")}, External: true, Destructive: true}},
		},
		{
			name:   "prose with no command has no fixes",
			kind:   kindAudit,
			action: "remove it, and the next jit command recreates the log",
			want:   nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := fixesFor(tc.kind, tc.action)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("fixesFor(%s, %q)\n got %+v\nwant %+v", tc.kind, tc.action, got, tc.want)
			}
		})
	}
}

// TestDoctorFixClassesNameRealCommands guards the table against a typo: a key
// that resolves to no command would silently never match, and its command
// would fall back to "unknown, destructive" with nobody noticing why.
func TestDoctorFixClassesNameRealCommands(t *testing.T) {
	for key := range jitFixClasses {
		words := strings.Fields(key)
		var flag string
		if last := words[len(words)-1]; slices.Contains(fixClassFlags, last) {
			flag, words = last, words[:len(words)-1]
		}
		path, ok := jitCommandPath(words)
		if !ok || path != strings.Join(words, " ") {
			t.Errorf("jitFixClasses key %q resolves to %q (ok=%v), not a jit command", key, path, ok)
			continue
		}
		if flag != "" {
			cmd, _, _ := rootCmd.Find(words)
			if cmd.Flags().Lookup(strings.TrimPrefix(flag, "--")) == nil {
				t.Errorf("jitFixClasses key %q: `jit %s` has no %s flag", key, path, flag)
			}
		}
	}
}

// TestDoctorVaultKeyFixIsOnlyTheImport: the action's prose names `jit vault
// export` as where a backup comes from, which with the key gone cannot run.
// Only the import is a step.
func TestDoctorVaultKeyFixIsOnlyTheImport(t *testing.T) {
	f := checkFinding{Kind: kindVaultKey, Action: "`jit vault import <file>` from a `jit vault export` backup",
		Fixes: fixesFor(kindVaultKey, "`jit vault import <file>`")}
	got := withFixes([]checkFinding{f})[0].Fixes
	want := []doctorFix{{Command: "jit vault import <file>", Argv: []string{"vault", "import", "<file>"}, Destructive: true, Presence: true, Needs: "<file>"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("fixes = %+v, want %+v", got, want)
	}
}

// TestServiceFindingsCarryTheirCommandAsAction: the missing-binary finding
// used to put `jit service restart` inside detail with no action, so it had
// no fix entry and the text report had no → line.
func TestServiceFindingsCarryTheirCommandAsAction(t *testing.T) {
	gone := filepath.Join(t.TempDir(), "jit")
	findings := agentFindingsFrom(t.TempDir(), statusAgent{Installed: true, Running: true, ExecutablePath: gone})
	if len(findings) == 0 {
		t.Fatal("expected a finding for a service running a deleted binary")
	}
	f := withFixes(findings)[0]
	if strings.Contains(f.Detail, "`") {
		t.Errorf("the command belongs in action, not detail: %q", f.Detail)
	}
	want := []doctorFix{{Command: "jit service restart", Argv: []string{"service", "restart"}}}
	if !reflect.DeepEqual(f.Fixes, want) {
		t.Errorf("fixes = %+v, want %+v", f.Fixes, want)
	}

	// The build-mismatch half needs a build id, which a `go test` binary
	// may not carry; when it has one, the same split applies.
	if detail, action := agentBuildMismatchParts("0000000"); detail != "" {
		if strings.Contains(detail, "`") || !strings.HasPrefix(action, "`jit service restart`") {
			t.Errorf("build mismatch: detail %q, action %q", detail, action)
		}
	}
}
