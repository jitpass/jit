// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// completeThrough drives the hidden __complete command the shells call, and
// returns its raw protocol output: one candidate per line, active help
// prefixed with _activeHelp_, and a trailing :<directive> line. Asserting on
// this rather than on the completion functions directly is what catches a
// registration that silently never fired (every RegisterFlagCompletionFunc
// call site discards its error).
func completeThrough(t *testing.T, args ...string) string {
	t.Helper()
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs(append([]string{cobra.ShellCompRequestCmd}, args...))
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("__complete %v: %v", args, err)
	}
	return buf.String()
}

// noFileCompDirective reports whether completion output ends in a directive
// that keeps the shell from falling back to listing the user's files.
func noFileCompDirective(out string) bool {
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if strings.HasPrefix(line, ":") {
			return strings.TrimSpace(line) == ":4"
		}
	}
	return false
}

// Every flag whose accepted values are a fixed set jit already knows must
// complete them. Cobra's fallback for an unregistered flag is FILE
// completion, so `jit audit --kind <TAB>` answered a closed vocabulary with a
// directory listing — which reads as "this flag wants a path". The table is
// deliberately the full list rather than a sample: a flag rename silently
// unregisters its completion (RegisterFlagCompletionFunc's error is discarded
// at every call site), and this is what notices.
func TestFixedValueFlagsCompleteTheirValues(t *testing.T) {
	withFixtureHome(t)
	cases := []struct {
		args []string
		want string // a value that must appear among the candidates
	}{
		{[]string{"audit", "--kind", ""}, "serve"},
		{[]string{"audit", "--status", ""}, "denied"},
		{[]string{"audit", "--format", ""}, "logfmt"},
		{[]string{"audit", "--since", ""}, "24h"},
		{[]string{"audit", "--until", ""}, "24h"},
		{[]string{"audit", "--limit", ""}, "200"},
		{[]string{"scan", "--format", ""}, "ndjson"},
		{[]string{"scan", "--fail-on", ""}, "critical"},
		{[]string{"status", "--format", ""}, "json"},
		{[]string{"doctor", "--format", ""}, "json"},
		{[]string{"vault", "list", "--format", ""}, "json"},
		{[]string{"vault", "list", "--by", ""}, "origin"},
		{[]string{"vault", "get", "--format", ""}, "json"},
		{[]string{"vault", "history", "--format", ""}, "json"},
		{[]string{"vault", "orphans", "--format", ""}, "json"},
		{[]string{"grant", "list", "--format", ""}, "json"},
		{[]string{"service", "status", "--format", ""}, "json"},
		{[]string{"service", "log", "--lines", ""}, "200"},
		{[]string{"service", "run", "--ttl", ""}, "8h"},
		{[]string{"service", "ttl", ""}, "8h"},
		{[]string{"service", "consent", ""}, "off"},
		{[]string{"migrate", "--only", ""}, "env"},
	}
	for _, tc := range cases {
		name := strings.Join(tc.args[:len(tc.args)-1], " ")
		t.Run(name, func(t *testing.T) {
			out := completeThrough(t, tc.args...)
			if !strings.Contains(out, tc.want) {
				t.Errorf("`jit %s <TAB>` does not offer %q:\n%s", name, tc.want, out)
			}
			if !noFileCompDirective(out) {
				t.Errorf("`jit %s <TAB>` falls back to file completion, want NoFileComp:\n%s", name, out)
			}
		})
	}
}

// A command that accepts no arguments must not answer TAB with the user's
// filenames. Cobra never consults Args to decide that — declaring
// cobra.NoArgs changes nothing — so silenceFileCompletionForNoArgCommands
// fills in the completion, and this pins the result for every command in the
// tree, including ones added later.
func TestNoArgCommandsDoNotFileComplete(t *testing.T) {
	silenceFileCompletionForNoArgCommands(rootCmd)
	var walk func(*cobra.Command)
	walk = func(c *cobra.Command) {
		for _, sub := range c.Commands() {
			walk(sub)
		}
		// The root itself completes its own subcommands, which is cobra's job
		// and not this rule's.
		if c == rootCmd || c.Args == nil || c.Name() == cobra.ShellCompRequestCmd {
			return
		}
		takesNone := c.Args(c, []string{}) == nil && c.Args(c, []string{"unexpected"}) != nil
		if !takesNone {
			return
		}
		if c.ValidArgsFunction == nil {
			t.Errorf("%q takes no arguments but has no completion, so TAB lists the user's files", c.CommandPath())
			return
		}
		_, directive := c.ValidArgsFunction(c, nil, "")
		if directive&cobra.ShellCompDirectiveNoFileComp == 0 {
			t.Errorf("%q takes no arguments but its completion directive still allows file completion", c.CommandPath())
		}
	}
	walk(rootCmd)
}

// A command whose Use line names no argument placeholder must reject
// arguments. `jit wrap list bogus` printed the normal report and exited 0
// because wrapListCmd declared no Args at all, which is cobra's
// accept-anything default — the silent-typo failure root.go's own arg
// validator exists to prevent for `jit <typo>`.
func TestCommandsWithoutArgumentPlaceholdersRejectArguments(t *testing.T) {
	skip := map[string]bool{"help": true, "completion": true, cobra.ShellCompRequestCmd: true, "jit": true}
	var walk func(*cobra.Command)
	walk = func(c *cobra.Command) {
		for _, sub := range c.Commands() {
			walk(sub)
		}
		if skip[c.Name()] || len(c.Commands()) > 0 {
			return // groups delegate to subcommands, which cobra checks itself
		}
		// Anything past the command word in the Use line documents an
		// argument (`<path>`, `[value]`, and grant's bare `ID`), so taking one
		// is the point.
		if len(strings.Fields(c.Use)) > 1 {
			return
		}
		if c.Args == nil || c.Args(c, []string{"unexpected"}) == nil {
			t.Errorf("%q names no argument in its Use line (%q) but accepts one, add Args: cobra.NoArgs", c.CommandPath(), c.Use)
		}
	}
	walk(rootCmd)
}

// The missing ARGUMENT must be named, not counted. Cobra's stock message is
// "accepts 1 arg(s), received 0", and SilenceUsage (global) means it arrives
// with no usage block behind it, so it was the whole answer a bare `jit vault
// set` got — the command `jit vault list`'s own empty state recommends.
func TestBareCommandsNameTheMissingArgument(t *testing.T) {
	withFixtureHome(t)
	cases := []struct{ args, want []string }{
		{[]string{"vault", "set"}, []string{"expects a secret path"}},
		{[]string{"vault", "get"}, []string{"expects a secret path", "jit vault list"}},
		{[]string{"vault", "rm"}, []string{"at least one secret path"}},
		{[]string{"vault", "history"}, []string{"expects a secret path"}},
		{[]string{"vault", "restore"}, []string{"expects a secret path"}},
		{[]string{"vault", "export"}, []string{"a file to write the backup to"}},
		{[]string{"vault", "import"}, []string{"file to read"}},
		{[]string{"wrap", "add"}, []string{"expects a tool to wrap"}},
		{[]string{"wrap", "undo"}, []string{"expects a wrapped tool", "jit wrap list"}},
		{[]string{"unmount"}, []string{"expects a mounted path"}},
	}
	for _, tc := range cases {
		name := strings.Join(tc.args, " ")
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			rootCmd.SetOut(&buf)
			rootCmd.SetErr(&buf)
			rootCmd.SetArgs(tc.args)
			err := rootCmd.Execute()
			if err == nil {
				t.Fatalf("`jit %s` with no argument succeeded, want an error", name)
			}
			for _, want := range tc.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("`jit %s` error = %q, want it to contain %q", name, err, want)
				}
			}
			if strings.Contains(err.Error(), "arg(s)") {
				t.Errorf("`jit %s` still counts arguments instead of naming one: %q", name, err)
			}
		})
	}
}

// Too many arguments quotes the command's own shape rather than a count, and
// takes it from cobra so the message cannot drift from the command.
func TestTooManyArgumentsQuotesTheShape(t *testing.T) {
	withFixtureHome(t)
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs([]string{"vault", "get", "one", "two"})
	err := rootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "jit vault get <path>") {
		t.Errorf("error = %v, want it to quote `jit vault get <path>`", err)
	}
}

// `vault rm` documents several paths under one approval, and its completion
// stopped after the first: the len(args) guard was written for `set`, whose
// second positional is the VALUE, and silenced rm's whole repeat form.
func TestVaultPathCompletionServesRepeatablePositionals(t *testing.T) {
	withFixtureHome(t)
	seedFixtureVault(t, "stripe/dev-key")
	seedFixtureVault(t, "aws/s3-access-key")

	out := completeThrough(t, "vault", "rm", "stripe/dev-key", "")
	if !strings.Contains(out, "aws/s3-access-key") {
		t.Errorf("second path of `vault rm` offers nothing:\n%s", out)
	}
	if strings.Contains(out, "stripe/dev-key") {
		t.Errorf("second path re-offers the path already named:\n%s", out)
	}
	// set's second positional is a value, not a path: still nothing to offer.
	if out := completeThrough(t, "vault", "set", "stripe/dev-key", ""); strings.Contains(out, "aws/s3-access-key") {
		t.Errorf("`vault set <path> <TAB>` offers a secret path for the VALUE position:\n%s", out)
	}
}

// An empty vault completed to nothing at all — no candidates, no reason, no
// way forward, the defect `jit grant extend` had.
func TestVaultPathCompletionExplainsAnEmptyVault(t *testing.T) {
	withFixtureHome(t)
	out := completeThrough(t, "vault", "get", "")
	if !strings.Contains(out, "_activeHelp_") || !strings.Contains(out, "jit migrate") {
		t.Errorf("completion on an empty vault = %q, want active help naming the way forward", out)
	}
}

// Completions must stop at the last positional their command accepts.
func TestSinglePositionalCompletionsStopAfterTheirArgument(t *testing.T) {
	withFixtureHome(t)
	cases := [][]string{
		{"unmount", "/tmp/already-named.env", ""},
		{"wrap", "undo", "gh", ""},
	}
	for _, args := range cases {
		name := strings.Join(args[:len(args)-1], " ")
		out := completeThrough(t, args...)
		for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
			// The trailing "Completion ended with directive:" line is cobra's
			// own debug echo, not a candidate.
			if line == "" || strings.HasPrefix(line, ":") || strings.HasPrefix(line, "_activeHelp_") ||
				strings.HasPrefix(line, "Completion ended with") {
				continue
			}
			t.Errorf("`jit %s <TAB>` offers %q past the command's only argument", name, line)
		}
	}
}

// `jit wrap add <tool>` alone is not a valid command: one of --env/--grant is
// required, and neither ever appeared on TAB — the tool position simply
// re-offered the whole catalog.
func TestWrapAddCompletionSurfacesTheRequiredFlag(t *testing.T) {
	withFixtureHome(t)
	out := completeThrough(t, "wrap", "add", "gh", "")
	for _, want := range []string{"--env", "--grant", wrapAddUsage} {
		if !strings.Contains(out, want) {
			t.Errorf("`wrap add gh <TAB>` omits %q:\n%s", want, out)
		}
	}
}

// A flag already typed must move the offer forward, never repeat: --grant
// and --env exclude each other, and only --env is repeatable. Same class as
// the grant report (`--process bash <Tab>` offered --process again).
func TestWrapAddCompletionWalksForwardFromTypedFlags(t *testing.T) {
	withFixtureHome(t)
	t.Cleanup(func() {
		wrapAddEnv, wrapAddGrant = nil, ""
		wrapAddCmd.Flags().Lookup("env").Changed = false
		wrapAddCmd.Flags().Lookup("grant").Changed = false
	})

	out := completeThrough(t, "wrap", "add", "gh", "--env", "GH_TOKEN=wrap-gh/GH_TOKEN", "")
	if strings.Contains(out, "--grant") {
		t.Errorf("--env excludes --grant, yet it is still offered:\n%s", out)
	}
	if !strings.Contains(out, "--env\t") {
		t.Errorf("--env is repeatable and must stay on offer:\n%s", out)
	}

	wrapAddEnv = nil
	out = completeThrough(t, "wrap", "add", "gcloud", "--grant", "gcp", "")
	if strings.Contains(out, "--env") || strings.Contains(out, "--grant\t") {
		t.Errorf("`wrap add gcloud --grant gcp` is complete, no more flags belong on offer:\n%s", out)
	}
}

// A filter already on the line must drop out of the bare-command offer;
// --kind stays because it is repeatable.
func TestAuditCompletionDropsTypedFilters(t *testing.T) {
	withFixtureHome(t)
	// Other tests run `jit audit` with filters through the same rootCmd, and
	// a flag's Changed survives Execute - a fresh process per TAB in real
	// life, so only this suite needs the reset.
	for _, name := range []string{"status", "kind", "since", "secret", "follow"} {
		auditCmd.Flags().Lookup(name).Changed = false
	}
	t.Cleanup(func() {
		auditStatus = ""
		auditKinds = nil
		auditCmd.Flags().Lookup("status").Changed = false
		auditCmd.Flags().Lookup("kind").Changed = false
	})
	out := completeThrough(t, "audit", "--status", "ok", "--kind", "use", "")
	if strings.Contains(out, "--status\t") {
		t.Errorf("--status already typed but offered again:\n%s", out)
	}
	if !strings.Contains(out, "--kind\t") {
		t.Errorf("--kind is repeatable and must stay on offer:\n%s", out)
	}
	if !strings.Contains(out, "--since\t") {
		t.Errorf("untyped filters must stay on offer:\n%s", out)
	}
}

func TestExportCompletionDropsTypedFlags(t *testing.T) {
	withFixtureHome(t)
	t.Cleanup(func() {
		exportProfile = ""
		exportCmd.Flags().Lookup("profile").Changed = false
	})
	out := completeThrough(t, "export", "--profile", "dev", "")
	if strings.Contains(out, "--profile\t") {
		t.Errorf("--profile already typed but offered again:\n%s", out)
	}
	if !strings.Contains(out, "--mode\t") {
		t.Errorf("--mode must stay on offer:\n%s", out)
	}
}

// The bare command must show the filters that are the whole point of it.
func TestAuditCompletionSurfacesItsFilters(t *testing.T) {
	withFixtureHome(t)
	out := completeThrough(t, "audit", "")
	for _, want := range []string{"--kind", "--since", "--status", "_activeHelp_"} {
		if !strings.Contains(out, want) {
			t.Errorf("`jit audit <TAB>` omits %q:\n%s", want, out)
		}
	}
}

// ~/.jit is jit's machine-level store, not a project, so it must never be
// offered as the enclosing project root to cd into: that advice resolves no
// profile and creates none either.
func TestFindEnclosingProjectRootExcludesHome(t *testing.T) {
	home := withFixtureHome(t)
	if err := os.MkdirAll(filepath.Join(home, ".jit", "profiles"), 0o755); err != nil {
		t.Fatalf("seeding home store: %v", err)
	}
	work := filepath.Join(home, "work")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if root, ok := findEnclosingProjectRoot(work); ok {
		t.Errorf("findEnclosingProjectRoot(%q) = %q, want no root: home is not a project", work, root)
	}

	project := filepath.Join(home, "proj")
	if err := os.MkdirAll(filepath.Join(project, ".jit", "profiles"), 0o755); err != nil {
		t.Fatalf("seeding project: %v", err)
	}
	src := filepath.Join(project, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	root, ok := findEnclosingProjectRoot(src)
	if !ok || root != project {
		t.Errorf("findEnclosingProjectRoot(%q) = %q/%v, want %q", src, root, ok, project)
	}
}
