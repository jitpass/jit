// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

//go:build darwin

package cli

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/agent"
	"github.com/jitpass/jit/internal/inject"
	"github.com/jitpass/jit/internal/profile"
	"github.com/jitpass/jit/internal/vault"
)

var (
	runProfile string
	runMode    string
)

var runCmd = &cobra.Command{
	Use:     "run [--profile <name>] [--mode <mode>] [--] <command> [args...]",
	GroupID: groupSecrets,
	Short:   "Execute a command with a profile's secrets injected into its environment",
	Long: "jit run decrypts every secret a profile references and replaces the jit\n" +
		"process entirely with the target command (execve), jit itself is gone\n" +
		"from memory the instant the target starts. The target process still holds\n" +
		"the plaintext once running: jit narrows the exposure window, it doesn't\n" +
		"sandbox what the target does with it.\n\n" +
		"Without --profile, jit resolves the project's migrated .env layers (looking\n" +
		"upward from the current directory, like git) and injects their merged\n" +
		"result in dotenv order, .env overridden by .env.local, printing exactly\n" +
		"what it merged. --mode <m> additionally layers .env.<m> and .env.<m>.local\n" +
		"in (.env < .env.<m> < .env.local < .env.<m>.local); a mode layer is never\n" +
		"merged without being asked for. --profile names one profile verbatim and\n" +
		"disables merging entirely.\n\n" +
		"The -- separating jit's own flags from the command is optional, jit stops\n" +
		"reading its flags at the first non-flag argument, so `jit run npm start`\n" +
		"works (jit's flags, if any, come before the command).",
	Example: "  jit run -- npm start\n" +
		"  jit run --mode production -- npm start\n" +
		"  jit run --profile aws-admin -- terraform plan",
	// A custom validator instead of cobra.MinimumNArgs(1) so a missing
	// command gets jit's own error voice ("jit run: %w") instead of
	// cobra's generic "requires at least 1 arg(s), only received 0" —
	// which doesn't mention the -- separator this command's whole usage
	// depends on.
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return fmt.Errorf("jit run: no command given, usage: jit run [--profile <name>] [--] <command> [args...]")
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("jit run: %w", err)
		}

		// Announce lines go to stderr, not stdout: stdout belongs
		// entirely to the target command.
		p, grantMounts, err := resolveInjectionProfile("jit run", cwd, runProfile, runMode, cmd.ErrOrStderr())
		if err != nil {
			return fmt.Errorf("jit run: %w", err)
		}

		v, err := openVault()
		if err != nil {
			return fmt.Errorf("jit run: %w", err)
		}

		binary, argv, env, err := resolveRunPlan(v, p, args)
		if err != nil {
			return fmt.Errorf("jit run: %w", err)
		}

		// Last thing before the exec: ask the agent to serve real content
		// on this run's mounts to this very process's tree. execve keeps
		// the pid, so the grant registered on os.Getpid() lands on exactly
		// the command about to run.
		requestRunGrant(cmd.ErrOrStderr(), grantMounts)

		// syscall.Exec never returns on success — it replaces this
		// process's image entirely — so an error here always means it
		// failed to start, never that the target already ran.
		return syscall.Exec(binary, argv, env) // #nosec G204 -- args[0] is the command the user themselves asked `jit run --` to execute
	},
}

// requestRunGrant asks the running agent for a run-scoped reveal grant
// (mountgrants.go): the mounts backing this run's injected values serve
// real content to this process tree — so a script that re-reads its
// mounted .env mid-run gets the same values jit run just put in its
// environment, instead of decoys that a clobbering loader would export
// over them (a real dogfood incident: int('jit-hidden-KEEP_REPORTS')).
//
// Every skip is silent, matching the wired reveal hooks' best-effort
// contract (`... --quiet 2>/dev/null || true`): no agent, or an agent
// that refuses, leaves behavior exactly as it was before grants existed.
// The one deliberate guard: never proceed unless the session is ALREADY
// unlocked — a grant request must not conjure a Touch ID prompt the user's
// command didn't require (if resolution just unlocked via the agent, the
// session is unlocked here; if it unlocked via the keychain directly, the
// locked agent stays undisturbed).
func requestRunGrant(w io.Writer, mountPaths []string) {
	if len(mountPaths) == 0 {
		return
	}
	c, err := agentClient()
	if err != nil {
		return
	}
	requestRunGrantVia(c, w, mountPaths, int32(os.Getpid())) // #nosec G115 -- getpid always fits int32
}

// requestRunGrantVia is requestRunGrant minus the ambient client/pid — the
// testable core, exercised against a real in-process agent.Server.
func requestRunGrantVia(c *agent.Client, w io.Writer, mountPaths []string, pid int32) {
	if !c.Reachable() {
		return
	}
	st, err := c.Status()
	if err != nil || !st.Unlocked {
		return
	}
	if err := c.RevealForPID(mountPaths, pid); err != nil {
		return
	}
	names := make([]string, 0, len(mountPaths))
	for _, p := range mountPaths {
		names = append(names, filepath.Base(p))
	}
	fmt.Fprintf(w, "jit run: %s serving real values to this run's processes only (until it exits)\n", strings.Join(names, ", "))
}

// resolveRunPlan does everything jit run needs before the actual
// syscall.Exec call — resolving the profile's secrets and the target
// binary's path, merging the environment — kept separate from RunE so it's
// testable with a fake vault.KeyWrapper, without ever invoking
// syscall.Exec (which would replace the test binary's own process) or
// needing a real Touch ID/passcode approval.
func resolveRunPlan(v *vault.Vault, p profile.Profile, args []string) (binary string, argv []string, env []string, err error) {
	values, err := inject.Resolve(v, p)
	if err != nil {
		return "", nil, nil, err
	}
	binary, err = exec.LookPath(args[0])
	if err != nil {
		return "", nil, nil, err
	}
	// argv[0] is kept as the original command name (not the resolved full
	// path), matching normal shell/exec convention.
	return binary, args, inject.MergeEnv(os.Environ(), values), nil
}

func init() {
	runCmd.Flags().StringVar(&runProfile, "profile", "", "profile to inject verbatim (default: merge this project's migrated .env layers)")
	runCmd.Flags().StringVar(&runMode, "mode", "", "also merge .env.<mode> and .env.<mode>.local layers (e.g. production)")
	// Stop parsing jit's own flags at the first non-flag argument, so the
	// target command's flags (`npm start --port 3000`) pass straight
	// through without needing a -- separator. jit's flags come before the
	// command; -- still works and is still shown in usage for the explicit
	// case.
	runCmd.Flags().SetInterspersed(false)
	rootCmd.AddCommand(runCmd)
}
