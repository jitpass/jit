// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
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
	runLive    bool
	runWith    []string
	runTrust   bool
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
		"When the service is running and unlocked, jit run also makes this run's\n" +
		"mounted files compatible with the command reading them, for the run's\n" +
		"lifetime only. By default it swaps each mount to a plain inert pointer\n" +
		"file, so `[ -f .env ]`/is_file() guards pass and re-reading the file\n" +
		"sets nothing (the real values are in the environment). --live instead\n" +
		"keeps the live mount and grants this run's process tree real file reads,\n" +
		"for tools that read values from the .env file itself (docker compose\n" +
		"env_file), which jit run also auto-detects. Either way the mount returns\n" +
		"to its decoy state the moment the command exits; no service, or a locked\n" +
		"one, skips this silently and injection works the same regardless.\n" +
		"A project whose tools always read the file itself can pin live mode by\n" +
		"putting `read_as_file: true` in its .jit/config.yaml, instead of --live\n" +
		"on every run.\n\n" +
		"--with names a global, file-delivered credential to grant this run:\n" +
		"gcp (gcloud ADC), sops, npm (~/.npmrc), or netrc (~/.netrc), for a tool\n" +
		"that reads a machine-wide credential file, e.g. `jit run --with gcp\n" +
		"terraform apply`.\n" +
		"It takes explicit intent by design: a global credential is never\n" +
		"granted by a project's config, only by a --with you type.\n\n" +
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
		p, grantMounts, err := injectionProfileForRun(cwd, runProfile, runMode, len(runWith) > 0, cmd.ErrOrStderr())
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

		// --with names global, file-delivered mounts (gcp, sops, npm, netrc) to
		// grant for this run. Resolved here (not in the best-effort compat
		// path) because a --with the user typed must fail loudly if the
		// name is unknown or its mount isn't migrated.
		withMounts, err := withMountPaths(runWith)
		if err != nil {
			return fmt.Errorf("jit run: %w", err)
		}

		// Last thing before the exec: ask the agent to make this run's
		// mounts compatible with the command about to read them. execve
		// keeps the pid, so whatever we register on os.Getpid() lands on
		// exactly that command. The project's .env layers swap by default
		// (or grant with --live); project template mounts and any --with
		// global mounts are granted (see requestRunCompat). The return reports
		// whether the disclosed --with grant was actually approved.
		globalGranted := requestRunCompat(cmd.ErrOrStderr(), grantMounts, runWith, withMounts, args, cwd, runLive)

		// Only once that --with grant is approved do we point sops at its
		// native SOPS_AGE_KEY_CMD hook, so sops v3.10+ fetches the age key
		// through the broker (jit sops-age-key) with nothing on disk. A
		// declined grant must leave the run no path to the key, the hook
		// included, not just the mount. Older sops falls back to the still-
		// granted keys.txt mount.
		if globalGranted {
			env = withSopsAgeKeyCmd(env, runWith)
		}

		// --trust pre-authorizes this run's whole process tree for any
		// credential, so per-process consent (when the service enforces it)
		// serves without a prompt for anything launched under this run. The
		// agent anchors it to this pid's fork-time, and it lasts only until the
		// next re-lock. Best-effort: no agent, or one not enforcing consent,
		// just means the run prompts per credential as usual — register before
		// the exec, since after it this process IS the command.
		// Registering it takes a Touch ID of its own now (the agent will not
		// let a process declare itself trusted just by asking), so a decline
		// is a thing the user did and has to be told about: the run still
		// proceeds, it just prompts per credential the way it would without
		// the flag. Silence there would read as "--trust didn't work".
		if runTrust {
			if ac, err := agentClient(); err == nil {
				if err := ac.Trust(); err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "jit run: --trust not applied (%v); this run will prompt per credential\n", err)
				}
			}
		}

		// syscall.Exec never returns on success — it replaces this
		// process's image entirely — so an error here always means it
		// failed to start, never that the target already ran.
		return syscall.Exec(binary, argv, env) // #nosec G204 -- args[0] is the command the user themselves asked `jit run --` to execute
	},
}

// withSopsAgeKeyCmd sets SOPS_AGE_KEY_CMD for a run whose --with sops grant was
// approved, so sops (v3.10+) fetches the age key through jit's broker hook
// instead of reading the granted keys.txt mount, keeping the key off disk
// entirely. The caller only invokes it after the disclosed grant succeeds, so a
// declined grant leaves no hook behind. It is a no-op unless sops is among the
// --with names, and it never overrides a SOPS_AGE_KEY_CMD the user already set
// (theirs wins). The value mirrors the documented `jit sops-age-key` usage;
// sops runs it via `sh -c`, so the absolute executable path plus the subcommand
// is a valid command string.
func withSopsAgeKeyCmd(env, withNames []string) []string {
	if !slices.Contains(withNames, "sops") {
		return env
	}
	for _, e := range env {
		if strings.HasPrefix(e, "SOPS_AGE_KEY_CMD=") {
			return env
		}
	}
	exe, err := os.Executable()
	if err != nil || exe == "" {
		exe = "jit" // fall back to a PATH lookup, as the command's own docs show
	}
	return append(env, fmt.Sprintf("SOPS_AGE_KEY_CMD=%s sops-age-key", exe))
}

// requestRunCompat makes this run's mounts compatible with the command
// about to read them. Two modes:
//
//   - SWAP (default): each mount becomes a regular comment-only pointer
//     file for the run's lifetime, so `[ -f .env ]`/is_file() guards pass
//     and a `source`/dotenv re-read parses to nothing. Real values reach
//     the command through the environment jit run already injected. This
//     fits the overwhelming majority — shell scripts, dotenv loaders.
//   - LIVE (--live, or an auto-detected file-value tool): the FIFO stays
//     and this run's process tree is granted real per-read content, for a
//     tool that reads real values FROM the file itself (docker compose
//     env_file:, which copies the file's contents into containers and
//     ignores our injected environment). A swap would feed such a tool
//     comments; the grant feeds it the real file.
//
// Every skip is silent, best-effort: no agent, or an agent that refuses,
// leaves behavior exactly as before. The deliberate guard: never proceed
// unless the session is
// ALREADY unlocked, so a compat request can't conjure a Touch ID prompt the
// command didn't require.
// The return reports whether the disclosed global (--with) grant was approved,
// so the caller can gate hook wiring (SOPS_AGE_KEY_CMD) on a real yes.
func requestRunCompat(w io.Writer, mountPaths, withNames, withMounts, argv []string, cwd string, live bool) bool {
	templateMounts := projectTemplateMounts(cwd)
	if len(mountPaths) == 0 && len(templateMounts) == 0 && len(withMounts) == 0 {
		return false
	}
	// This run actually has a mount to make compatible, so it needs the agent
	// that serves it. Set one up silently on first use rather than leaving the
	// mount unserved and the user to discover `jit service restart` — the agent
	// is part of the app, not a separate setup step. Best-effort: a failed
	// install just leaves the compat request on its existing no-agent no-op
	// path below (agentClient's calls already degrade to "as before").
	ensureAgentInstalled()
	c, err := agentClient()
	if err != nil {
		return false
	}
	// Live mode (keep the FIFO + grant) for the dotenv layers is chosen only
	// on explicit intent, never a guess: the --live flag, a project that
	// pinned read_as_file in its .jit/config.yaml, or a command jit
	// recognizes as reading values from the file itself. Everything else
	// takes the safe default swap — guessing live wrong reintroduces the
	// regular-file-guard trap.
	dotenvMode := agent.MountModeSwap
	if live || readAsFilePinned(cwd) || commandReadsEnvFile(argv) {
		dotenvMode = agent.MountModeGrant
	}
	// The project's own mounts (dotenv layers swapped-or-granted, project
	// template mounts always granted) ride the run's own unlock. The --with
	// global mounts are handled separately, behind a disclosed challenge.
	runMounts := make([]agent.RunMount, 0, len(mountPaths)+len(templateMounts))
	runMounts = append(runMounts, agent.RunMounts(mountPaths, dotenvMode)...)
	runMounts = append(runMounts, agent.RunMounts(templateMounts, agent.MountModeGrant)...)
	global := agent.RunMounts(withMounts, agent.MountModeGrant)
	return requestRunCompatVia(c, w, runMounts, global, withNames, int32(os.Getpid())) // #nosec G115 -- getpid always fits int32
}

// requestRunCompatVia is requestRunCompat minus the ambient client/pid —
// the testable core, exercised against a real in-process agent.Server. It
// makes two agent calls: the project's own mounts ride the run's unlock,
// while the global --with mounts go through a separate disclosed challenge
// naming the credentials — so declining a global grant drops only that,
// never the run's own .env swap.
// It returns true only when a disclosed global (--with) grant was requested and
// approved, so the caller can wire a native hook only on a real yes.
func requestRunCompatVia(c *agent.Client, w io.Writer, runMounts, global []agent.RunMount, withNames []string, pid int32) bool {
	if !c.Reachable() {
		return false
	}
	st, err := c.Status()
	if err != nil || !st.Unlocked {
		return false
	}

	if len(runMounts) > 0 {
		if err := c.RunForPID(runMounts, pid); err == nil {
			var swapped, granted []string
			for _, m := range runMounts {
				name := filepath.Base(m.Path)
				if m.Mode == agent.MountModeSwap {
					swapped = append(swapped, name)
				} else {
					granted = append(granted, name)
				}
			}
			if len(swapped) > 0 {
				fmt.Fprintf(w, "jit run: %s is a compatibility file for this run (real values are in the environment; the file itself is inert)\n", strings.Join(swapped, ", "))
			}
			if len(granted) > 0 {
				fmt.Fprintf(w, "jit run: %s serving real values to this run's processes only (until it exits)\n", strings.Join(granted, ", "))
			}
		}
	}

	if len(global) > 0 {
		// No reason string: the agent words this prompt itself, from the mounts
		// (agent.Server.OnDescribeGrant). withNames below is only for jit run's
		// own stdout, which nobody authorizes anything on the strength of.
		if err := c.GrantGlobalForPID(global, pid); err != nil {
			// Declined or failed: the global grant is dropped, the run
			// proceeds (the tool will get decoys and fail if it needed them).
			fmt.Fprintf(w, "jit run: global grant for %s not applied (%v)\n", strings.Join(withNames, ", "), err)
			return false
		}
		fmt.Fprintf(w, "jit run: granted this run your global %s credential(s) until it exits\n", strings.Join(withNames, ", "))
		return true
	}
	return false
}

// commandReadsEnvFile recognizes the small set of tools that read real
// values FROM a .env file rather than from the environment — for those a
// swap (comment-only file) would silently starve them, so jit run
// auto-selects live mode. Deliberately narrow and name-based: the cost of a
// false negative is one `--live` the user adds; the cost of guessing swap
// wrong is a confusing empty-config failure, so only clear file-readers
// belong here. docker/docker-compose/podman with compose all support
// `env_file:`.
func commandReadsEnvFile(argv []string) bool {
	if len(argv) == 0 {
		return false
	}
	switch filepath.Base(argv[0]) {
	case "docker", "docker-compose", "podman", "podman-compose", "nerdctl":
		return true
	}
	return false
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
	_ = runCmd.RegisterFlagCompletionFunc("profile", completeProfileNames)
	runCmd.Flags().StringVar(&runMode, "mode", "", "also merge .env.<mode> and .env.<mode>.local layers (e.g. production)")
	runCmd.Flags().BoolVar(&runLive, "live", false, "keep the live mount and grant this run real file reads, for tools that read values from the .env file itself (docker compose env_file); default swaps in a compatibility file")
	runCmd.Flags().StringArrayVar(&runWith, "with", nil, "also grant this run a global file-delivered mount by name (gcp, sops, npm, netrc) - for tools that read a machine-wide credential file, e.g. `jit run --with gcp gcloud storage ls` (repeatable)")
	runCmd.Flags().BoolVar(&runTrust, "trust", false, "pre-authorize this run's whole process tree for any credential, so per-process consent prompts don't fire under it")
	_ = runCmd.RegisterFlagCompletionFunc("with", completeGlobalMountNames)
	// Stop parsing jit's own flags at the first non-flag argument, so the
	// target command's flags (`npm start --port 3000`) pass straight
	// through without needing a -- separator. jit's flags come before the
	// command; -- still works and is still shown in usage for the explicit
	// case.
	runCmd.Flags().SetInterspersed(false)
	rootCmd.AddCommand(runCmd)
}
