// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/migrate"
	"github.com/jitpass/jit/internal/vault"
	"github.com/jitpass/jit/internal/wrap"
)

// Thin cobra wiring only — flag parsing and output formatting; the actual
// wrap flow lives in internal/wrap (docs/internal/WRAP-PLAN.md §4). The catalog flow
// (`jit wrap gh` with no flags, discovery + scrub) is plan M2 and not
// implemented yet; wrapCmd's own RunE says so instead of guessing.

var wrapCmd = &cobra.Command{
	Use:     "wrap",
	GroupID: groupWorkflow,
	Short:   "Wrap CLI tools so their tokens are injected just-in-time",
	Long: "jit wrap puts a shim first on PATH for each wrapped tool: you keep typing\n" +
		"`gh` exactly as before, and the token materializes only inside that one\n" +
		"process (via `jit run --profile wrap-<tool>`), never in a plaintext config\n" +
		"file. Works in scripts, Makefiles, and tools spawning tools, anywhere the\n" +
		"binary is invoked, not just interactive shells.\n\n" +
		"Store the secret first (`jit vault set`), then describe the tool:\n" +
		"`jit wrap add <tool> --env VAR=<vault-path>`. See docs/wrap/ for the\n" +
		"catalog of known tools with automatic discovery.",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return cmd.Help()
		}
		if len(args) > 1 {
			return fmt.Errorf("jit wrap: one tool at a time, `jit wrap %s`", args[0])
		}
		// `jit wrap doctor` was a real subcommand until it was folded into
		// `jit doctor --wrap`. Deleting it without this would drop the old
		// spelling through to the catalog lookup below, which answers
		// `"doctor" isn't in the catalog … jit wrap add doctor` — advice to
		// wrap a tool named "doctor", which is worse than no answer at all.
		if args[0] == "doctor" {
			return errors.New("jit wrap doctor has moved: run `jit doctor --wrap` for the shim checks, or `jit doctor` for the full health report")
		}
		return runCatalogWrap(cmd, args[0])
	},
}

// runCatalogWrap is `jit wrap <tool>` (docs/internal/WRAP-PLAN.md §3.3): look the
// tool up in the catalog, discover its live token, vault it, install
// profile + shim, scrub the plaintext source (backed up encrypted first),
// and say how to verify.
func runCatalogWrap(cmd *cobra.Command, tool string) error {
	entry, ok := wrap.Lookup(tool)
	if !ok {
		return fmt.Errorf("jit wrap: %q isn't in the catalog (%s), `jit wrap add %s --env VAR=<vault-path>` wraps any tool by hand",
			tool, strings.Join(wrap.CatalogTools(), ", "), tool)
	}
	out := cmd.OutOrStdout()
	// One vault for the whole wrap, not one per step: openVault builds a
	// fresh keychainwrap.Wrapper whose master-key cache is per instance,
	// so each extra open is another Touch ID prompt when the agent
	// service isn't reachable. This flow opens for up to three reasons
	// (store the token, move a config secret, back up the scrubbed file).
	openV := memoizedVaultOpener()

	// Native tools delegate to the migrate flow that already hooks their
	// own credential mechanism — stronger than a shim (SDKs, login/logout).
	if entry.Kind == wrap.KindNative {
		d, err := wrap.Delegation(entry)
		if err != nil {
			return fmt.Errorf("jit wrap: %w", err)
		}
		fmt.Fprintf(out, "%s: %s.\n", entry.Tool, entry.Doc)
		fmt.Fprint(out, hlCmds(fmt.Sprintf("Running `jit %s`, no shim needed or installed.\n\n", strings.Join(d.Command, " "))))
		self, err := os.Executable()
		if err != nil {
			return fmt.Errorf("jit wrap: %w", err)
		}
		sub := exec.Command(self, d.Command...) // #nosec G204 -- self + compiled-in catalog args
		sub.Stdin, sub.Stdout, sub.Stderr = cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr()
		return sub.Run()
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("jit wrap: %w", err)
	}
	if _, err := exec.LookPath(tool); err != nil {
		return fmt.Errorf("jit wrap: %s isn't installed (not on PATH), install it first", tool)
	}

	// Run-grant tools carry no token and read no credential file jit could
	// scrub — the k8s-secret migration owns the vaulting. The wrap is just
	// the shim that puts every invocation inside a `jit run` grant.
	if entry.Kind == wrap.KindRunGrant {
		exe, err := os.Executable()
		if err != nil {
			return fmt.Errorf("jit wrap: %w", err)
		}
		jitBinary, err := stableBinaryPath(exe)
		if err != nil {
			return fmt.Errorf("jit wrap: %w", err)
		}
		res, err := wrap.AddRunGrant(home, tool, jitBinary)
		if err != nil {
			return fmt.Errorf("jit wrap: %w", err)
		}
		fmt.Fprintf(out, "Wrapped %s (%s):\n  shim  %s\n", tool, entry.Doc, res.ShimPath)
		wrapBody(out, 0, "", hlCmds(fmt.Sprintf("From now on `%s` runs inside a jit run grant: a Secret manifest migrated with "+
			"`jit migrate <secret.yaml>` serves %s the real manifest, while anything not "+
			"launched through jit reads decoys kubectl rejects.", tool, tool)))
		if err := ensureShimOnPath(cmd, home, tool); err != nil {
			return fmt.Errorf("jit wrap: %w", err)
		}
		if entry.VerifyHint != "" {
			fmt.Fprint(out, hlCmds(fmt.Sprintf("Check it: open a new shell and run `%s`.\n", entry.VerifyHint)))
		}
		return nil
	}

	// Capture tools mint credentials rather than carrying one, so there is
	// no token to discover and no profile to write — just the shim that
	// reroutes each mint into the vault (`jit <tool>-capture`).
	if entry.Kind == wrap.KindCapture {
		exe, err := os.Executable()
		if err != nil {
			return fmt.Errorf("jit wrap: %w", err)
		}
		jitBinary, err := stableBinaryPath(exe)
		if err != nil {
			return fmt.Errorf("jit wrap: %w", err)
		}
		res, err := wrap.AddCapture(home, tool, jitBinary)
		if err != nil {
			return fmt.Errorf("jit wrap: %w", err)
		}
		fmt.Fprintf(out, "Wrapped %s (%s):\n  shim  %s\n", tool, entry.Doc, res.ShimPath)
		wrapBody(out, 0, "", hlCmds(fmt.Sprintf("From now on `%s get <app>` stores the minted credentials in the vault "+
			"(profile aws-<app>, served via credential_process) instead of writing ~/.aws/credentials; "+
			"your MFA prompts appear exactly as before.", tool)))

		// The tool's own long-lived secret moves too: clisso keeps a
		// OneLogin client-secret in ~/.clisso.yaml, and the shim serves
		// the real value back per run — so the plaintext can leave now.
		// Discovery first, so the vault (and its unlock prompt) is only
		// opened when there is actually a secret to move.
		found, err := migrate.DiscoverClissoSecrets(home)
		if err != nil {
			return fmt.Errorf("jit wrap: reading ~/.clisso.yaml: %w", err)
		}
		if len(found) > 0 {
			v, err := openV()
			if err != nil {
				return fmt.Errorf("jit wrap: %w", err)
			}
			mig, err := migrate.ApplyClissoConfig(v, home)
			if err != nil {
				return fmt.Errorf("jit wrap: %w", err)
			}
			for _, p := range mig.Providers {
				wrapBody(out, 0, "", hlCmds(fmt.Sprintf("Moved provider %q's client-secret into the vault (%s); %s now holds a pointer "+
					"(original backed up encrypted, `jit migrate undo` restores it).",
					p, migrate.ClissoVaultPath(p), mig.ConfigPath)))
			}
			for _, p := range mig.Skipped {
				fmt.Fprintf(out, "Provider %q has a name that can't map to a vault path; its client-secret\nwas left in place.\n", p)
			}
		}
		if err := ensureShimOnPath(cmd, home, tool); err != nil {
			return fmt.Errorf("jit wrap: %w", err)
		}
		if entry.VerifyHint != "" {
			fmt.Fprint(out, hlCmds(fmt.Sprintf("Check it: open a new shell and run `%s`.\n", entry.VerifyHint)))
		}
		return nil
	}

	discovery, found, err := wrap.DiscoverToken(home, entry)
	if err != nil {
		return fmt.Errorf("jit wrap: %w", err)
	}
	primary := entry.PrimaryVar()
	vaultPath := entry.VaultPath(primary)

	if found {
		v, err := openV()
		if err != nil {
			return fmt.Errorf("jit wrap: %w", err)
		}
		gid, err := vault.NewGroupID()
		if err != nil {
			return fmt.Errorf("jit wrap: %w", err)
		}
		origin := ""
		if discovery.Source != nil {
			origin = discovery.Source.Path // already ~-form (see wrap.ExpandHome)
		}
		// The docs tell users to `jit vault set wrap-<tool>/VAR` by hand
		// for tools with nothing discoverable on disk. If discovery later
		// finds something anyway — a short-lived OAuth token where they
		// vaulted a long-lived key — say so instead of just replacing it.
		if c := migrate.InspectOriginConflict(v, vaultPath, vault.ClassWrap, origin); c != nil {
			prose, command := c.ReplacingNote()
			wrapBody(cmd.ErrOrStderr(), 0, "    ", prose)
			fmt.Fprintf(cmd.ErrOrStderr(), "    %s\n", hlCmds(command))
		}
		if err := v.SetWithMeta(vaultPath, []byte(discovery.Value), vault.Meta{Class: vault.ClassWrap, GroupID: gid, Origin: origin}); err != nil {
			return fmt.Errorf("jit wrap: storing %s: %w", vaultPath, err)
		}
		if discovery.Source != nil {
			fmt.Fprintf(out, "Found the %s in %s, moved into the vault at %s.\n", entry.Doc, discovery.Source.Path, vaultPath)
		} else {
			fmt.Fprintf(out, "Exported the %s from the tool's own keyring, copied into the vault at %s.\n", entry.Doc, vaultPath)
		}
	} else {
		wrapBody(out, 0, "", hlCmds(fmt.Sprintf("No %s found on this machine, store it first: `jit vault set %s`, "+
			"then re-run `jit wrap %s`. Installing the shim and profile now anyway.",
			entry.Doc, vaultPath, tool)))
	}

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("jit wrap: %w", err)
	}
	jitBinary, err := stableBinaryPath(exe)
	if err != nil {
		return fmt.Errorf("jit wrap: %w", err)
	}
	env := make(map[string]string, len(entry.EnvVars))
	for varName := range entry.EnvVars {
		env[varName] = entry.VaultPath(varName)
	}
	res, err := wrap.Add(home, wrap.AddRequest{Tool: tool, Env: env, Order: entry.Order, JitBinary: jitBinary})
	if err != nil {
		return fmt.Errorf("jit wrap: %w", err)
	}
	fmt.Fprintf(out, "Wrapped %s:\n  profile  %s (%s)\n  shim     %s\n", tool, res.ProfileName, res.ProfilePath, res.ShimPath)

	// Scrub only after the vault holds the value and the profile+shim are
	// in place, and only after an encrypted byte-for-byte backup — the
	// same order-of-operations discipline as every migrate category.
	if found && discovery.Source != nil {
		v, err := openV()
		if err != nil {
			return fmt.Errorf("jit wrap: %w", err)
		}
		srcPath := wrap.ExpandHome(home, discovery.Source.Path)
		if _, err := migrate.BackupSecretFile(v, srcPath); err != nil {
			return fmt.Errorf("jit wrap: backing up %s: %w", srcPath, err)
		}
		if err := wrap.ScrubToken(home, *discovery.Source, discovery.Value); err != nil {
			return fmt.Errorf("jit wrap: %w", err)
		}
		wrapBody(out, 0, "", hlCmds(fmt.Sprintf("Scrubbed the plaintext from %s (original backed up encrypted, "+
			"`jit migrate undo %s` restores it byte-for-byte).",
			discovery.Source.Path, srcPath)))
	}

	if err := ensureShimOnPath(cmd, home, tool); err != nil {
		return fmt.Errorf("jit wrap: %w", err)
	}
	if entry.VerifyHint != "" {
		fmt.Fprint(out, hlCmds(fmt.Sprintf("Check it: open a new shell and run `%s`.\n", entry.VerifyHint)))
	}
	return nil
}

var wrapAddEnv []string
var wrapAddGrant string

var wrapAddCmd = &cobra.Command{
	Use:   "add <tool> --env VAR=<vault-path> [--env ...] | --grant <name>",
	Short: "Wrap a tool by hand: a shim on PATH that injects a profile or grants a global mount",
	Long: "jit wrap add installs a shim so a tool works by its native name. Two forms:\n" +
		"--env wraps a tool that reads a token from an ENV VAR (gh, stripe): the shim\n" +
		"injects a wrap-<tool> profile. --grant wraps a tool that reads a machine-wide\n" +
		"credential FILE (gcloud reads the gcp ADC): the shim runs `jit run --with\n" +
		"<name>` so the tool gets the real file, gated by a disclosed challenge.",
	Example: "  jit vault set wrap-gh/GH_TOKEN\n" +
		"  jit wrap add gh --env GH_TOKEN=wrap-gh/GH_TOKEN\n" +
		"  jit wrap add gcloud --grant gcp",
	Args:              cobra.ExactArgs(1),
	ValidArgsFunction: completeWrapCatalog,
	RunE: func(cmd *cobra.Command, args []string) error {
		tool := args[0]
		if wrapAddEnv != nil && wrapAddGrant != "" {
			return fmt.Errorf("jit wrap add: use either --env (inject a token) or --grant (grant a global mount), not both")
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("jit wrap add: %w", err)
		}
		exe, err := os.Executable()
		if err != nil {
			return fmt.Errorf("jit wrap add: %w", err)
		}
		jitBinary, err := stableBinaryPath(exe)
		if err != nil {
			return fmt.Errorf("jit wrap add: %w", err)
		}
		out := cmd.OutOrStdout()

		if wrapAddGrant != "" {
			res, err := wrap.AddGrant(home, tool, wrapAddGrant, jitBinary)
			if err != nil {
				return fmt.Errorf("jit wrap add: %w", err)
			}
			fmt.Fprintf(out, "Grant-wrapped %s:\n", tool)
			fmt.Fprintf(out, "  grants   the %q global mount (jit run --with %s)\n", wrapAddGrant, wrapAddGrant)
			fmt.Fprintf(out, "  shim     %s\n", res.ShimPath)
			fmt.Fprint(cmd.ErrOrStderr(), hlCmds(fmt.Sprintf("note: %s must be migrated first (name its file: `jit migrate <path-to-%s-file>`); each run prompts a disclosed Touch ID for the credential.\n", wrapAddGrant, wrapAddGrant)))
			return ensureShimOnPath(cmd, home, tool)
		}

		env, order, err := parseWrapEnv(wrapAddEnv)
		if err != nil {
			return fmt.Errorf("jit wrap add: %w", err)
		}
		// A missing secret is a warning, not an error: wrapping before
		// storing is a legal order of operations, and jit doctor verifies
		// profile references anyway.
		if v, vErr := openVaultReadOnly(); vErr == nil {
			for _, name := range order {
				if exists, exErr := v.Exists(env[name]); exErr == nil && !exists {
					fmt.Fprint(cmd.ErrOrStderr(), hlCmds(fmt.Sprintf("warning: nothing stored at %s yet, `jit vault set %s` before running %s\n", env[name], env[name], tool)))
				}
			}
		}

		res, err := wrap.Add(home, wrap.AddRequest{Tool: tool, Env: env, Order: order, JitBinary: jitBinary})
		if err != nil {
			return fmt.Errorf("jit wrap add: %w", err)
		}
		fmt.Fprintf(out, "Wrapped %s:\n", tool)
		fmt.Fprintf(out, "  profile  %s (%s)\n", res.ProfileName, res.ProfilePath)
		fmt.Fprintf(out, "  shim     %s\n", res.ShimPath)

		return ensureShimOnPath(cmd, home, tool)
	},
}

// ensureShimOnPath puts the one shim PATH line in the user's rc file (once)
// and tells them how to apply it to the current shell — shared by the
// catalog flow and `wrap add`.
func ensureShimOnPath(cmd *cobra.Command, home, tool string) error {
	out := cmd.OutOrStdout()
	rc := wrap.RcFile(home, os.Getenv("SHELL"))
	changed, err := wrap.EnsurePathLine(rc)
	if err != nil {
		return err
	}
	if changed {
		fmt.Fprintf(out, "Added to %s: %s\n", rc, wrap.PathLine())
		fmt.Fprint(out, hlCmds(fmt.Sprintf("Open a new shell (or run `%s` in this one) and %s is wrapped.\n", wrap.PathLine(), tool)))
	} else {
		fmt.Fprintf(out, "%s is wrapped for new shells (shim PATH line already present).\n", tool)
	}
	return nil
}

var wrapListCmd = &cobra.Command{
	Use:   "list",
	Short: "Show wrapped tools and their shim health",
	RunE: func(cmd *cobra.Command, args []string) error {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("jit wrap list: %w", err)
		}
		manifest, err := wrap.LoadManifest(home)
		if err != nil {
			return fmt.Errorf("jit wrap list: %w", err)
		}
		if len(manifest.Tools) == 0 {
			fmt.Fprintln(cmd.OutOrStdout(), hlCmds("No wrapped tools. `jit wrap add <tool> --env VAR=<vault-path>` wraps one."))
			return nil
		}

		shims, err := wrap.InstalledShims(home)
		if err != nil {
			return fmt.Errorf("jit wrap list: %w", err)
		}
		installed := make(map[string]bool, len(shims))
		for _, s := range shims {
			installed[s] = true
		}

		w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "TOOL\tKIND\tINJECTS/GRANTS\tSHIM")
		for _, tool := range sortedTools(manifest) {
			entry := manifest.Tools[tool]
			health := "ok"
			if !installed[tool] {
				health = "missing, re-run `jit wrap add " + tool + " ...`"
			}
			kind, detail := "env", strings.Join(entry.Vars, ",")
			if entry.IsGrant() {
				kind, detail = "grant", "--with "+entry.With
			}
			if entry.IsCapture() {
				kind, detail = "capture", "jit "+entry.Capture+"-capture"
			}
			if entry.IsRunGrant() {
				kind, detail = "run-grant", "project mounts at the tool's cwd"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", tool, kind, detail, health)
		}
		return w.Flush()
	},
}

var wrapUndoCmd = &cobra.Command{
	Use:               "undo <tool>",
	Short:             "Unwrap a tool: remove its shim and wrap profile",
	Args:              cobra.ExactArgs(1),
	ValidArgsFunction: completeWrappedTools,
	RunE: func(cmd *cobra.Command, args []string) error {
		tool := args[0]
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("jit wrap undo: %w", err)
		}
		res, err := wrap.Undo(home, tool)
		if err != nil {
			return fmt.Errorf("jit wrap undo: %w", err)
		}

		out := cmd.OutOrStdout()
		fmt.Fprintf(out, "Unwrapped %s (shim removed: %v, profile removed: %v).\n", tool, res.RemovedShim, res.RemovedProfile)
		if len(res.VaultPaths) > 0 {
			fmt.Fprint(out, hlCmds(fmt.Sprintf("Vault secrets were kept: %s, `jit vault rm <path>` removes one for good.\n", strings.Join(res.VaultPaths, ", "))))
		}
		if res.Remaining == 0 {
			rc := wrap.RcFile(home, os.Getenv("SHELL"))
			changed, err := wrap.RemovePathLine(rc)
			if err != nil {
				return fmt.Errorf("jit wrap undo: %w", err)
			}
			if changed {
				fmt.Fprintf(out, "Last wrapped tool gone, removed the shim PATH line from %s.\n", rc)
			}
		}
		return nil
	},
}

// parseWrapEnv turns repeated --env VAR=<vault-path> flags into the map +
// order wrap.Add wants. Order is the flags' own order, which becomes the
// profile manifest's variable order.
func parseWrapEnv(flags []string) (map[string]string, []string, error) {
	if len(flags) == 0 {
		return nil, nil, fmt.Errorf("at least one --env VAR=<vault-path> is required")
	}
	env := make(map[string]string, len(flags))
	order := make([]string, 0, len(flags))
	for _, f := range flags {
		name, vaultPath, ok := strings.Cut(f, "=")
		if !ok || name == "" || vaultPath == "" {
			return nil, nil, fmt.Errorf("--env %q must look like VAR=<vault-path>", f)
		}
		if _, dup := env[name]; !dup {
			order = append(order, name)
		}
		env[name] = vaultPath // last flag wins, matching shell semantics
	}
	return env, order, nil
}

func sortedTools(m wrap.Manifest) []string {
	tools := make([]string, 0, len(m.Tools))
	for t := range m.Tools {
		tools = append(tools, t)
	}
	sort.Strings(tools)
	return tools
}

// completeWrapCatalog offers every tool jit knows how to wrap, for `jit
// wrap add <tool>` — turning the catalog buried in the docs into a
// tab-completable list. It intentionally offers all cataloged tools, not
// only unwrapped ones: re-running `wrap add` on an already-wrapped tool is
// how you change its env/grant, so hiding it would remove a real workflow.
func completeWrapCatalog(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	var out []string
	for _, tool := range wrap.CatalogTools() {
		if strings.HasPrefix(tool, toComplete) {
			out = append(out, tool)
		}
	}
	return out, cobra.ShellCompDirectiveNoFileComp
}

// completeWrappedTools offers only the tools CURRENTLY wrapped, for `jit
// wrap undo <tool>` — undo can only act on those, so completing from the
// full catalog (as add does) would offer names undo would just reject.
func completeWrappedTools(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	m, err := wrap.LoadManifest(home)
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	var out []string
	for _, tool := range sortedTools(m) {
		if strings.HasPrefix(tool, toComplete) {
			out = append(out, tool)
		}
	}
	return out, cobra.ShellCompDirectiveNoFileComp
}

func init() {
	wrapAddCmd.Flags().StringArrayVar(&wrapAddEnv, "env", nil, "environment variable to inject, as VAR=<vault-path> (repeatable)")
	wrapAddCmd.Flags().StringVar(&wrapAddGrant, "grant", "", "grant a global file-delivered mount by name (gcp, sops, npm, netrc, pypi) instead of injecting an env var - for tools that read a credential file")
	_ = wrapAddCmd.RegisterFlagCompletionFunc("grant", completeGlobalMountNames)
	wrapCmd.AddCommand(wrapAddCmd, wrapListCmd, wrapUndoCmd)
	rootCmd.AddCommand(wrapCmd)
}
