// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

//go:build darwin

package cli

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/spf13/cobra"

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
		"process entirely with the target command (execve) — jit itself is gone\n" +
		"from memory the instant the target starts. The target process still holds\n" +
		"the plaintext once running: jit narrows the exposure window, it doesn't\n" +
		"sandbox what the target does with it.\n\n" +
		"Without --profile, jit resolves the project's migrated .env layers (looking\n" +
		"upward from the current directory, like git) and injects their merged\n" +
		"result in dotenv order — .env overridden by .env.local — printing exactly\n" +
		"what it merged. --mode <m> additionally layers .env.<m> and .env.<m>.local\n" +
		"in (.env < .env.<m> < .env.local < .env.<m>.local); a mode layer is never\n" +
		"merged without being asked for. --profile names one profile verbatim and\n" +
		"disables merging entirely.\n\n" +
		"The -- separating jit's own flags from the command is optional — jit stops\n" +
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
			return fmt.Errorf("jit run: no command given — usage: jit run [--profile <name>] [--] <command> [args...]")
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
		p, err := resolveInjectionProfile("jit run", cwd, runProfile, runMode, cmd.ErrOrStderr())
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

		// syscall.Exec never returns on success — it replaces this
		// process's image entirely — so an error here always means it
		// failed to start, never that the target already ran.
		return syscall.Exec(binary, argv, env) // #nosec G204 -- args[0] is the command the user themselves asked `jit run --` to execute
	},
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
