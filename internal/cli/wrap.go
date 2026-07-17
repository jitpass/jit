// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/migrate"
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

	// Native tools delegate to the migrate flow that already hooks their
	// own credential mechanism — stronger than a shim (SDKs, login/logout).
	if entry.Kind == wrap.KindNative {
		d, err := wrap.Delegation(entry)
		if err != nil {
			return fmt.Errorf("jit wrap: %w", err)
		}
		fmt.Fprintf(out, "%s: %s.\n", entry.Tool, entry.Doc)
		fmt.Fprintf(out, "Running `jit %s`, no shim needed or installed.\n\n", strings.Join(d.Command, " "))
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

	discovery, found, err := wrap.DiscoverToken(home, entry)
	if err != nil {
		return fmt.Errorf("jit wrap: %w", err)
	}
	primary := entry.PrimaryVar()
	vaultPath := entry.VaultPath(primary)

	if found {
		v, err := openVault()
		if err != nil {
			return fmt.Errorf("jit wrap: %w", err)
		}
		if err := v.Set(vaultPath, []byte(discovery.Value)); err != nil {
			return fmt.Errorf("jit wrap: storing %s: %w", vaultPath, err)
		}
		if discovery.Source != nil {
			fmt.Fprintf(out, "Found the %s in %s, moved into the vault at %s.\n", entry.Doc, discovery.Source.Path, vaultPath)
		} else {
			fmt.Fprintf(out, "Exported the %s from the tool's own keyring, copied into the vault at %s.\n", entry.Doc, vaultPath)
		}
	} else {
		fmt.Fprintf(out, "No %s found on this machine, store it first:\n  jit vault set %s\nthen re-run `jit wrap %s`. Installing the shim and profile now anyway.\n",
			entry.Doc, vaultPath, tool)
	}

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("jit wrap: %w", err)
	}
	jitBinary, err := filepath.EvalSymlinks(exe)
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
		v, err := openVault()
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
		fmt.Fprintf(out, "Scrubbed the plaintext from %s (original backed up encrypted, `jit migrate undo %s` restores it byte-for-byte).\n",
			discovery.Source.Path, srcPath)
	}

	if err := ensureShimOnPath(cmd, home, tool); err != nil {
		return fmt.Errorf("jit wrap: %w", err)
	}
	if entry.VerifyHint != "" {
		fmt.Fprintf(out, "Check it: open a new shell and run `%s`.\n", entry.VerifyHint)
	}
	return nil
}

var wrapAddEnv []string

var wrapAddCmd = &cobra.Command{
	Use:   "add <tool> --env VAR=<vault-path> [--env ...]",
	Short: "Wrap a tool by hand: shim on PATH + a wrap-<tool> profile",
	Example: "  jit vault set wrap-gh/GH_TOKEN\n" +
		"  jit wrap add gh --env GH_TOKEN=wrap-gh/GH_TOKEN",
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		tool := args[0]
		env, order, err := parseWrapEnv(wrapAddEnv)
		if err != nil {
			return fmt.Errorf("jit wrap add: %w", err)
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("jit wrap add: %w", err)
		}
		exe, err := os.Executable()
		if err != nil {
			return fmt.Errorf("jit wrap add: %w", err)
		}
		jitBinary, err := filepath.EvalSymlinks(exe)
		if err != nil {
			return fmt.Errorf("jit wrap add: %w", err)
		}

		// A missing secret is a warning, not an error: wrapping before
		// storing is a legal order of operations, and jit doctor verifies
		// profile references anyway.
		if v, vErr := openVaultReadOnly(); vErr == nil {
			for _, name := range order {
				if exists, exErr := v.Exists(env[name]); exErr == nil && !exists {
					fmt.Fprintf(cmd.ErrOrStderr(), "warning: nothing stored at %s yet, `jit vault set %s` before running %s\n", env[name], env[name], tool)
				}
			}
		}

		res, err := wrap.Add(home, wrap.AddRequest{Tool: tool, Env: env, Order: order, JitBinary: jitBinary})
		if err != nil {
			return fmt.Errorf("jit wrap add: %w", err)
		}

		out := cmd.OutOrStdout()
		fmt.Fprintf(out, "Wrapped %s:\n", tool)
		fmt.Fprintf(out, "  profile  %s (%s)\n", res.ProfileName, res.ProfilePath)
		fmt.Fprintf(out, "  shim     %s\n", res.ShimPath)

		if err := ensureShimOnPath(cmd, home, tool); err != nil {
			return fmt.Errorf("jit wrap add: %w", err)
		}
		return nil
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
		fmt.Fprintf(out, "Open a new shell (or run `%s` in this one) and %s is wrapped.\n", wrap.PathLine(), tool)
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
			fmt.Fprintln(cmd.OutOrStdout(), "No wrapped tools. `jit wrap add <tool> --env VAR=<vault-path>` wraps one.")
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
		fmt.Fprintln(w, "TOOL\tPROFILE\tVARS\tSHIM")
		for _, tool := range sortedTools(manifest) {
			entry := manifest.Tools[tool]
			health := "ok"
			if !installed[tool] {
				health = "missing, re-run `jit wrap add " + tool + " ...`"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", tool, entry.Profile, strings.Join(entry.Vars, ","), health)
		}
		return w.Flush()
	},
}

var wrapUndoCmd = &cobra.Command{
	Use:   "undo <tool>",
	Short: "Unwrap a tool: remove its shim and wrap profile",
	Args:  cobra.ExactArgs(1),
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
			fmt.Fprintf(out, "Vault secrets were kept: %s, `jit vault rm <path>` removes one for good.\n", strings.Join(res.VaultPaths, ", "))
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

var wrapDoctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Verify every wrapped tool's shim, PATH entry, and profile",
	RunE: func(cmd *cobra.Command, args []string) error {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("jit wrap doctor: %w", err)
		}
		checks := wrap.Doctor(home, os.Getenv("PATH"), os.Getenv("SHELL"))
		out := cmd.OutOrStdout()
		failed := 0
		for _, c := range checks {
			mark := "✓"
			if !c.OK {
				mark = "✗"
				failed++
			}
			fmt.Fprintf(out, "%s %-12s %s\n", mark, c.Name, c.Detail)
		}
		if failed > 0 {
			return fmt.Errorf("jit wrap doctor: %d check(s) failed", failed)
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

func init() {
	wrapAddCmd.Flags().StringArrayVar(&wrapAddEnv, "env", nil, "environment variable to inject, as VAR=<vault-path> (repeatable)")
	wrapCmd.AddCommand(wrapAddCmd, wrapListCmd, wrapUndoCmd, wrapDoctorCmd)
	rootCmd.AddCommand(wrapCmd)
}
