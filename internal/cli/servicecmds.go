// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/agent"
	"github.com/jitpass/jit/internal/keychainwrap"
)

// This file is the service subcommands a human types: the `jit service`
// group and its ttl/consent/restart members, plus top-level `jit unlock` and
// `jit lock`, and the init() that wires them onto the root command. They all
// run in a short-lived CLI process; the daemon they manage is servicerun.go
// and the launchd mechanics they call are servicelaunchd.go.

var serviceCmd = &cobra.Command{
	Use:     "service",
	GroupID: groupService,
	// See runCommandGroup: without a Run of its own, `jit service consnt
	// off` printed help and exited 0, leaving per-process consent silently
	// ON when a script believed it had turned it off.
	RunE:        runCommandGroup,
	Annotations: commandGroupAnnotations(),
	Short:       "Manage jit's background service (the daemon that holds your session and serves mounts)",
	Long: "jit runs a small background service: a login-time daemon that keeps one\n" +
		"unlocked session other jit commands share, instead of each one prompting\n" +
		"Touch ID separately, and that serves any live-mounted .env files jit migrate\n" +
		"has created.\n\n" +
		"It is a solid part of jit, not an optional add-on: it sets itself up the\n" +
		"first time a command needs it (a `jit run` that serves a mount, a `jit\n" +
		"migrate`, or `jit unlock`), starts at every login, and restarts itself if it\n" +
		"crashes. There is no install step. These subcommands are for the rare times\n" +
		"you want to manage it by hand: `jit service ttl` shows or changes how long a\n" +
		"session stays unlocked, `jit service status` reports its health, `jit service\n" +
		"restart` restarts it (and brings it back if it ever stopped), and `jit\n" +
		"service log` shows its own output. It goes away when you remove jit itself.\n" +
		"The service process itself needs no Touch ID just to keep running, only your\n" +
		"unlocked session inside it locks after the TTL of inactivity (default 5m),\n" +
		"prompting again on next use.\n\n" +
		"To control the session itself, use the top-level `jit unlock` and `jit lock`.\n" +
		"To see what the service has done (unlocks, denials, mount reads), use\n" +
		"`jit audit`.\n\n" +
		"A live-mounted file shows fake-looking values by default. Real values flow\n" +
		"only to a `jit run` grant's own process tree: `jit run --live` for a project\n" +
		"mount, `jit run --with` for a global credential. Unlocking the vault never\n" +
		"makes a mount serve real values on its own.",
}

// serviceTTLCmd shows or changes the session TTL. It replaces the old
// `jit service install --ttl`: there is no "install" step anymore (the service
// is a solid part of the app and sets itself up on first use, GAPS.md #18), so
// the one thing the install command uniquely offered — picking the session
// length — lives here as its own discoverable verb. Setting a value also
// creates the login item if it somehow wasn't there yet, so this doubles as
// "make sure the service exists, with this TTL."
var serviceTTLCmd = &cobra.Command{
	Use:   "ttl [duration]",
	Short: "Show or change how long a session stays unlocked before it auto-locks",
	Long: "With no argument, prints the session TTL the background service is currently\n" +
		"configured with. With a duration (e.g. 30s, 10m, 1h), changes it.\n\n" +
		"The TTL is how long an unlocked session stays cached after your last Touch\n" +
		"ID prompt before it locks itself, so the next use prompts again (default\n" +
		"5m). It is baked into the service's login item, so a change persists across\n" +
		"logins and reboots, not just this one.\n\n" +
		"It is an INACTIVITY timeout, so use pushes it back — and a session also ends\n" +
		"8 hours after the unlock that started it, however busy it has been. Values\n" +
		"above that ceiling are refused rather than accepted and quietly ignored: an\n" +
		"idle timeout longer than the maximum session age could never be reached.\n\n" +
		"Changing it restarts the background service, so the current session is\n" +
		"dropped and the next vault use prompts Touch ID once. Your vault and the\n" +
		"session history are untouched.",
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			ttl, ok := configuredAgentTTL()
			if !ok {
				fmt.Fprintf(cmd.OutOrStdout(), "The background service isn't running yet, so no TTL is set; the default %s applies once it starts (it starts on its own the first time you use jit).\n", agentInstallDefaultTTL)
				return nil
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Session TTL: %s (a session locks this long after your last Touch ID prompt).\n", ttl)
			return nil
		}
		d, err := time.ParseDuration(args[0])
		if err != nil {
			return fmt.Errorf("jit service ttl: %q is not a duration, try 30s, 10m, or 1h: %w", args[0], err)
		}
		// Validated before it reaches the plist: a zero or negative TTL bakes a
		// service that re-prompts on every use, and the error would otherwise
		// surface only in the service log at the next launchd start.
		if err := validateAgentTTLSetting(d); err != nil {
			return fmt.Errorf("jit service ttl: %w", err)
		}
		// installAgentService writes the plist with the new --ttl and reloads
		// it, creating the login item if it wasn't there yet. Preserve the
		// consent setting across the TTL change.
		_, running, err := installAgentService(d, configuredAgentConsent())
		if err != nil {
			return fmt.Errorf("jit service ttl: %w", err)
		}
		if !running {
			// The TTL itself IS saved — say so before failing on the
			// restart half, so the error can't read as "nothing happened".
			fmt.Fprintf(cmd.OutOrStdout(), "Session TTL set to %s.\n", d)
			return fmt.Errorf("jit service ttl: the TTL is written, but %s; retry `jit service restart`", restartedServiceClause())
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Session TTL set to %s. The background service restarted, so the next vault use prompts Touch ID once.\n", d)
		return nil
	},
}

// serviceConsentCmd shows or sets per-process credential consent. Like
// serviceTTLCmd it reinstalls the plist (preserving the TTL) so the setting
// survives restarts and logins, then reloads the service so it takes effect now.
var serviceConsentCmd = &cobra.Command{
	Use:   "consent [on|off]",
	Short: "Show or set per-process credential consent",
	Long: "Per-process credential consent (on by default): the background service\n" +
		"prompts a fresh Touch ID the first time each tool reaches for a credential\n" +
		"(AWS, git, docker, kube, gcloud/sops/npm/netrc/pypi keys), naming who is\n" +
		"asking, and remembers your answer for the session. It closes the window\n" +
		"where any process running as you can use a migrated credential silently\n" +
		"while your vault is unlocked.\n\n" +
		"Saying no is meant to be cheap. A refused prompt is not remembered as a\n" +
		"lasting \"no\" — it can't be, since a decline and a keychain failure look the\n" +
		"same from here — so instead it pauses that caller for a few seconds, then\n" +
		"longer if it keeps asking, and the prompt tells you how many times it has\n" +
		"already been refused. Nothing is locked out: the next genuine attempt still\n" +
		"asks, and an approval (or a fresh `jit unlock`) clears the pause.\n\n" +
		"With no argument, prints whether it's on. `on`/`off` set it and restart the\n" +
		"service; turning it OFF requires a fresh Touch ID/passcode, since disabling\n" +
		"the guard reopens the window it closes. Use `jit run --trust -- <cmd>` to\n" +
		"pre-authorize a whole run's tree so it isn't prompted.",
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			if configuredAgentConsent() {
				fmt.Fprintln(cmd.OutOrStdout(), "Per-process credential consent is ON.")
			} else {
				fmt.Fprintln(cmd.OutOrStdout(), hlCmds("Per-process credential consent is OFF. Turn it on with `jit service consent on`."))
			}
			return nil
		}
		var on bool
		switch strings.ToLower(args[0]) {
		case "on", "true", "enable", "enabled":
			on = true
		case "off", "false", "disable", "disabled":
			on = false
		default:
			return fmt.Errorf("jit service consent: expected 'on' or 'off', got %q", args[0])
		}
		// Turning consent OFF reopens the exact window the feature exists to
		// close, so it must prove a human is present — never ride an unlocked
		// agent session. Turning it ON (or reading state) only strengthens the
		// guard and needs no gate. Auth BEFORE writing the plist: a declined
		// gesture must leave the setting untouched.
		if !on {
			if err := requireConsentOffPresence(); err != nil {
				return fmt.Errorf("jit service consent off: %w", err)
			}
		}
		ttl, ok := configuredAgentTTL()
		if !ok {
			ttl = agentInstallDefaultTTL
		}
		_, running, err := installAgentService(ttl, on)
		if err != nil {
			return fmt.Errorf("jit service consent: %w", err)
		}
		state := "OFF"
		if on {
			state = "ON"
		}
		if !running {
			// The setting IS saved (a Touch ID gated one, when turning off) —
			// but "The service restarted" was printed unconditionally here,
			// exit 0, for a service that may never have come back. Say what
			// happened and fail on the restart half.
			fmt.Fprintf(cmd.OutOrStdout(), "Per-process credential consent is now %s.\n", state)
			return fmt.Errorf("jit service consent: the setting is written, but %s; retry `jit service restart`", restartedServiceClause())
		}
		if on {
			fmt.Fprintln(cmd.OutOrStdout(), "Per-process credential consent is now ON. The service restarted; the next credential use prompts Touch ID.")
		} else {
			fmt.Fprintln(cmd.OutOrStdout(), "Per-process credential consent is now OFF. The service restarted.")
		}
		return nil
	},
}

// requireConsentOffPresence forces a fresh Touch ID/passcode gesture before
// per-process consent can be DISABLED. Disabling consent reopens the exact
// window it exists to close — any process running as you using a migrated
// credential silently while the vault is unlocked — so flipping it off must
// prove a human is present, not merely inherit an unlocked agent session.
// Mirrors requireUninstallPresence: challenge through the vault's
// biometric-gated MEK fetch when there are secrets to protect (which also
// audit-stamps the fresh auth), falling back to a bare LocalAuthentication
// prompt when the vault is empty or unreadable.
//
// Honest limit: this gates the `jit service consent off` COMMAND, not the plist
// it writes. An attacker with code execution as you could rewrite the LaunchAgent
// plist and reload it directly, exactly as they could `rm` the files uninstall
// guards — the gate is anti-footgun and defense-in-depth over a scripted flip,
// not a hard boundary (RFC.md B6/GAPS.md #1 already concede that adversary).
func requireConsentOffPresence() error {
	const reason = "authorize turning off per-process credential consent"
	if vaultSecretCount() > 0 {
		v, err := openVaultFreshAuth()
		if err != nil {
			return err
		}
		return requireFreshUserPresence(v, reason)
	}
	return keychainwrap.Challenge(reason)
}

var agentRestartCmd = &cobra.Command{
	Use:   "restart",
	Short: "Restart the background service (picks up a new binary, or brings a stopped one back)",
	Long: "Restarts jit's background service. Two uses: the immediate fix when\n" +
		"`jit service status` warns that the running service predates the jit binary\n" +
		"on disk (the service also retires itself onto the new binary automatically,\n" +
		"but only once its session is locked and no prompt is pending; restart is for\n" +
		"wanting it now), and the way to bring the service back if it stopped.\n\n" +
		"If the login item is missing entirely (it was never started, or was\n" +
		"removed), this recreates it — jit keeps the service installed as a matter of\n" +
		"course, so there is no separate install step.\n\n" +
		"The in-memory session is lost, so the next vault use prompts Touch ID\n" +
		"again, and live-mounted files serve placeholder values until then.\n" +
		"Session history survives, it's durable.",
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		plistPath, err := agentPlistPath()
		if err != nil {
			return fmt.Errorf("jit service restart: %w", err)
		}
		plistData, readErr := os.ReadFile(plistPath) // #nosec G304 -- jit's own launchd plist under the user's LaunchAgents dir
		if readErr != nil && !os.IsNotExist(readErr) {
			return fmt.Errorf("jit service restart: %w", readErr)
		}
		if os.IsNotExist(readErr) {
			// No login item yet (never started, or uninstalled). Rather than
			// dead-end, create it: restart is the single "get the service
			// running" command, and the service is meant to always be present.
			// Default TTL and default (on) consent, since a missing plist has no
			// configured value to preserve — `jit service ttl <d>` and
			// `jit service consent off` change them afterward. Branching on the
			// ReadFile error alone (no separate Stat) keeps this race-free
			// against a concurrent session's install, and installAgentService
			// already waited for the socket — its result is the answer, a
			// second wait would only double the worst-case silence.
			if _, running, ierr := installAgentService(agentInstallDefaultTTL, true); ierr != nil {
				return fmt.Errorf("jit service restart: %w", ierr)
			} else if !running {
				return fmt.Errorf("jit service restart: %w", agentStartFailure())
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Started the background service. The next vault use will prompt Touch ID.")
			return nil
		}
		// bootout + bootstrap (reloadAgentService) restarts a running agent
		// AND recovers one launchd has dropped (the plist on disk with no live
		// service, e.g. after a crash loop launchd gave up on or an upgrade
		// that unloaded the old one) in a single unconditional sequence. It
		// replaced a kickstart -k that only worked while the service was still
		// bootstrapped and otherwise dead-ended on "Could not find service" —
		// and it needs no fragile parsing of launchctl's undocumented,
		// localizable error text to decide which state we're in.
		// A plist naming a DIFFERENT binary is the case a plain reload cannot
		// fix, and the case where the success line below would otherwise lie.
		// Rewrite it — preserving the TTL and consent the user configured —
		// so "running the current binary" is a statement about what happened
		// rather than a hope. This is the command `jit service status` sends
		// people to when it reports a version mismatch; it has to be able to
		// resolve one.
		if agentPlistNeedsRepoint(plistData) {
			ttl := agentInstallDefaultTTL
			if d, ok := configuredAgentTTL(); ok {
				ttl = d
			}
			if _, running, ierr := installAgentService(ttl, configuredAgentConsent()); ierr != nil {
				return fmt.Errorf("jit service restart: %w", ierr)
			} else if !running {
				return fmt.Errorf("jit service restart: %w", agentStartFailure())
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Restarted, the service is now running the current binary. The next vault use will prompt Touch ID.")
			return nil
		}
		if out, err := reloadAgentService(plistPath); err != nil {
			return fmt.Errorf("jit service restart: reloading the launchd service failed: %w (%s); `jit service log` shows recent output", err, strings.TrimSpace(string(out)))
		}
		root, err := vaultRootDir()
		if err != nil {
			return fmt.Errorf("jit service restart: %w", err)
		}
		// Same wait as install, same reason: "Restarted" must mean the new
		// process is actually answering, or status contradicts us moments
		// later.
		if !waitForAgentBuild(root, agentStartWait) {
			return fmt.Errorf("jit service restart: %w", agentStartFailure())
		}
		fmt.Fprintln(cmd.OutOrStdout(), "Restarted, the service is now running the current binary. The next vault use will prompt Touch ID.")
		return nil
	},
}

var unlockCmd = &cobra.Command{
	Use:     "unlock",
	GroupID: groupService,
	Short:   "Unlock jit's session now (prompts Touch ID if needed)",
	Long: "Unlocks the shared session jit's background service holds, prompting Touch ID\n" +
		"or your device passcode if it isn't already unlocked. Pre-warms it so a\n" +
		"following jit run / vault get / export doesn't stop to prompt. It locks\n" +
		"itself again after the session --ttl of inactivity, at the 8-hour maximum\n" +
		"session age whichever comes first, or on `jit lock` sooner.\n\n" +
		"An unlock that actually prompts you also clears any consent pauses: a\n" +
		"refused credential prompt holds that caller off for a few seconds, and you\n" +
		"standing at the keyboard is exactly the \"now\" that refusal withheld. An\n" +
		"unlock while the session is already open prompts nobody, so it clears\n" +
		"nothing — otherwise any process could reset the pause by asking for one.\n\n" +
		"If the background service isn't set up yet, this sets it up first: `unlock`\n" +
		"is the \"get me a session\" intent, so there's nothing extra to run by hand.",
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		// No service yet? Set one up silently rather than erroring with "run
		// starting the service first — `unlock` IS the "get me a session"
		// intent, so absence is a setup step to do, not a failure to report.
		ensureAgentInstalled()
		c, err := agentClient()
		if err != nil {
			return fmt.Errorf("jit unlock: %w", err)
		}
		_, remaining, err := c.Unlock()
		if err != nil {
			return fmt.Errorf("jit unlock: %w", notRunningHint(err))
		}
		fmt.Fprint(cmd.OutOrStdout(), hlCmds(fmt.Sprintf("Unlocked, locks automatically after %s of inactivity (or `jit lock` sooner).\n", remaining.Round(time.Second))))
		return nil
	},
}

var lockCmd = &cobra.Command{
	Use:     "lock",
	GroupID: groupService,
	Short:   "Lock jit's session immediately, without waiting for the TTL",
	Long: "Locks the shared session jit's background service holds, right now, instead\n" +
		"of waiting out whichever bound would end it first — the idle --ttl or the\n" +
		"8-hour maximum session age. The next vault use prompts Touch ID again, and\n" +
		"live-mounted files serve placeholder values until then.",
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := agentClient()
		if err != nil {
			return fmt.Errorf("jit lock: %w", err)
		}
		if err := c.Lock(); err != nil {
			// A not-running service holds no session: the state `lock` wants
			// is already true. Telling the user "may have crashed... try
			// restart" here sent them on a repair errand to lock a session
			// that didn't exist (observed doing exactly that in the
			// 2026-08-17 incident, where the restart couldn't work either).
			if errors.Is(err, agent.ErrNotRunning) {
				fmt.Fprintln(cmd.OutOrStdout(), "Already locked: the service isn't running, so no session exists.")
				return nil
			}
			return fmt.Errorf("jit lock: %w", notRunningHint(err))
		}
		fmt.Fprintln(cmd.OutOrStdout(), "Locked.")
		return nil
	},
}

func init() {
	agentRunCmd.Flags().DurationVar(&agentTTL, "ttl", 5*time.Minute, "how long an unlocked session stays cached before auto-locking (values above the 8h maximum session age are clamped to it)")
	agentRunCmd.Flags().BoolVar(&agentConsent, "consent", true, "prompt for per-process consent (Touch ID) the first time each tool reaches for a credential (on by default; use --consent=false to disable)")
	agentStatusCmd.Flags().StringVar(&agentStatusFormat, "format", "text", `output format: "text" (default) or "json"`)
	agentLogCmd.Flags().IntVarP(&agentLogLines, "lines", "n", 50, "how many trailing lines to print (0 for the whole file)")
	registerPagerFlag(agentLogCmd)
	agentLogCmd.Flags().BoolVarP(&agentLogFollow, "follow", "f", false, "keep printing new lines as the service writes them (Ctrl-C to stop)")
	agentLogCmd.Flags().BoolVar(&agentLogRaw, "raw", false, "print the log file's bytes exactly as written, without the formatted view")

	// Fixed value sets: --format, a count, a duration and an on/off word all
	// answered TAB with the user's filenames. The TTL ceiling comes from the
	// same constant the server clamps to, so the hint cannot outlive it.
	_ = agentStatusCmd.RegisterFlagCompletionFunc("format", completeOutputFormat)
	_ = agentLogCmd.RegisterFlagCompletionFunc("lines", completeCounts(20, 50, 200, 1000))
	ttlComp := completeDurations(humanAgo(agent.DefaultMaxSessionAge), "1m", "5m", "30m", "1h", "8h")
	_ = agentRunCmd.RegisterFlagCompletionFunc("ttl", ttlComp)
	serviceTTLCmd.ValidArgsFunction = firstArgOnly(ttlComp)
	serviceConsentCmd.ValidArgsFunction = firstArgOnly(completeValues(
		"on\tprompt once per process for each secret (default)",
		"off\tno per-process prompt; the session unlock is the only gate"))

	serviceCmd.AddCommand(agentRunCmd, serviceTTLCmd, serviceConsentCmd, agentRestartCmd, agentStatusCmd, agentLogCmd)

	// The old plist's `agent run --ttl <d>` needs the same --ttl flag bound to
	// the same target var; only one of the two run commands executes per
	// process, so sharing agentTTL is safe.
	agentCompatRunCmd.Flags().DurationVar(&agentTTL, "ttl", 5*time.Minute, "how long an unlocked session stays cached before auto-locking (values above the 8h maximum session age are clamped to it)")
	agentCompatCmd.AddCommand(agentCompatRunCmd)

	rootCmd.AddCommand(serviceCmd, unlockCmd, lockCmd, agentCompatCmd)
}
