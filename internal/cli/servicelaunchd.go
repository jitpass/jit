// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jitpass/jit/internal/agent"
	"github.com/jitpass/jit/internal/selfpath"
)

// This file is the launchd seam and its mechanics: writing the LaunchAgent
// plist, reading values back out of it, (re)loading it, demanding a spawn,
// and waiting for the result — plus the one place that parses `launchctl
// print`. Two callers compose launchctl verbs remotely through the seam
// rather than through a helper here: the self-retire kickstart (servicerun.go,
// which must run inside the daemon) and uninstall's bootout (uninstall.go,
// which tears down rather than manages). The plist path/existence probes live
// in un-gated agentinstalled.go so the portable status surface can ask.
//
// Two rules govern all of it, both learned from the 2026-08-17 incident
// (design/service-reliability.md):
//
//   - Every spawn jit asks for is an explicit DEMAND. bootstrap only
//     registers a job; launchd can defer a RunAtLoad or KeepAlive spawn
//     indefinitely, so a kickstart follows.
//   - launchctl's text is never a decision input. queryLaunchdJobState parses
//     it to phrase advice and nothing else, degrading to "unknown" on any
//     surprise; what counts as success is always the socket answering on the
//     expected build.

// configuredAgentTTL reads the session TTL baked into the installed launchd
// plist's ProgramArguments (the `--ttl <value>` pair installAgentService
// wrote). Returns ok=false when the service isn't installed or the plist has no
// readable --ttl, so a caller can tell "not set up" from a real value rather
// than reporting a misleading zero.
func configuredAgentTTL() (time.Duration, bool) {
	plistPath, err := agentPlistPath()
	if err != nil {
		return 0, false
	}
	data, err := os.ReadFile(plistPath) // #nosec G304 -- jit's own launchd plist under the user's LaunchAgents dir
	if err != nil {
		return 0, false
	}
	values := plistStringValues(data)
	for i := 0; i+1 < len(values); i++ {
		if values[i] == "--ttl" {
			if d, perr := time.ParseDuration(values[i+1]); perr == nil {
				return d, true
			}
			return 0, false
		}
	}
	return 0, false
}

// configuredAgentConsent reports whether per-process consent is baked into the
// installed plist. Consent is ON by default, so this returns true unless the
// plist EXPLICITLY carries `--consent=false` (what `jit service consent off`
// writes). An absent flag — a fresh install, or a plist written before consent
// existed — reads as the default: on. Callers use it to preserve a user's
// explicit choice across a TTL change or an upgrade.
func configuredAgentConsent() bool {
	plistPath, err := agentPlistPath()
	if err != nil {
		return true
	}
	data, err := os.ReadFile(plistPath) // #nosec G304 -- jit's own launchd plist under the user's LaunchAgents dir
	if err != nil {
		return true
	}
	for _, v := range plistStringValues(data) {
		switch v {
		case "--consent=false":
			return false
		case "--consent", "--consent=true":
			return true
		}
	}
	return true
}

// plistStringValues returns the text of every <string>…</string> element in a
// plist, in order — enough to walk ProgramArguments without a full XML parser.
// The values it's used to match (the literal "--ttl" and a duration) carry no
// XML entities, so it deliberately does not unescape.
func plistStringValues(data []byte) []string {
	const open, closing = "<string>", "</string>"
	var out []string
	s := string(data)
	for {
		i := strings.Index(s, open)
		if i < 0 {
			return out
		}
		s = s[i+len(open):]
		j := strings.Index(s, closing)
		if j < 0 {
			return out
		}
		out = append(out, s[:j])
		s = s[j+len(closing):]
	}
}

// agentInstallDefaultTTL is the session TTL used whenever the service is set
// up without a TTL chosen explicitly: the silent first-use auto-install
// (ensureAgentInstalled) and `jit service restart` recreating a missing login
// item. `jit service ttl <d>` overrides it. One constant so those paths can't
// drift on the default.
const agentInstallDefaultTTL = 5 * time.Minute

// agentBinaryPath is the path launchd should re-exec: this binary, with the
// /usr/local/bin install symlink (or any shim) resolved. launchd runs this
// exact path at every login, so a path that later moves out from under it
// leaves the service pointing at nothing — which is exactly why a
// Homebrew-managed jit keeps the bin symlink rather than resolving through
// it into the version-numbered Caskroom copy `brew upgrade` deletes (see
// selfpath.Stable).
func agentBinaryPath() (string, error) {
	exePath, err := os.Executable()
	if err != nil {
		return "", err
	}
	return selfpath.Stable(exePath)
}

// plistProgramPath returns the binary an installed plist actually runs — the
// first ProgramArguments entry. It reads that array specifically rather than
// taking the document's first <string>, which is the Label.
//
// This exists because `jit service restart` used to reload whatever plist was
// on disk and then report "the service is now running the current binary",
// which is only true if the plist happens to name that binary. It was found
// false in the field (2026-08-06): the plist pointed at a build in a temp
// directory, restart claimed success, and `jit service status` contradicted it
// on the very next command — while still advising the restart that could not
// fix it.
func plistProgramPath(data []byte) (string, bool) {
	const key = "<key>ProgramArguments</key>"
	i := strings.Index(string(data), key)
	if i < 0 {
		return "", false
	}
	values := plistStringValues(data[i+len(key):])
	if len(values) == 0 {
		return "", false
	}
	// Unescape what install escaped: a path containing `&` (common in real
	// directory names, as the install-side comment notes) round-trips through
	// the plist as `&amp;`, and returning the escaped form made every
	// comparison and stat against it wrong — agentPlistNeedsRepoint
	// permanently true, and agentPlistOrphaned calling a healthy install
	// orphaned because it stat'ed a path that doesn't exist.
	return xmlUnescape(values[0]), true
}

// agentPlistNeedsRepoint reports whether the installed plist runs a different
// binary than this process, i.e. whether reloading it would leave the service
// on the old build. Any uncertainty (unreadable plist, unresolvable
// executable) answers false: reloading in place is what restart did for its
// whole life, so an unknown state keeps the old behaviour rather than
// rewriting a plist on a guess.
func agentPlistNeedsRepoint(data []byte) bool {
	installed, ok := plistProgramPath(data)
	if !ok {
		return false
	}
	want, err := agentBinaryPath()
	if err != nil {
		return false
	}
	return installed != want
}

// installAgentService writes the launchd LaunchAgent plist that runs
// `jit service run --ttl <ttl>` and (re)loads it, returning the plist path and
// whether the socket answered within a short wait. It is the shared core of
// every path that creates or reconfigures the service — the silent first-use
// auto-install (ensureAgentInstalled), `jit service ttl` changing the session
// length, and `jit service restart` recreating a missing login item — so none
// of them can drift on how the service is written or bootstrapped. It performs
// NO consent prompt of its own: the service is a solid part of the app that
// sets itself up on first use, and the plist is a low-privilege, fully
// reversible user LaunchAgent.
func installAgentService(ttl time.Duration, consent bool) (plistPath string, running bool, err error) {
	return installAgentServiceReady(ttl, consent, sameBuildAsThisProcess)
}

// installAgentServiceReady is installAgentService with the "it's up" test
// injected, for the one caller whose new build is not its own: `jit upgrade`
// (see restartServiceOntoCurrentBinary). Everything else wants the default.
func installAgentServiceReady(ttl time.Duration, consent bool, ready agentReady) (plistPath string, running bool, err error) {
	exePath, err := agentBinaryPath()
	if err != nil {
		return "", false, err
	}
	plistPath, err = agentPlistPath()
	if err != nil {
		return "", false, err
	}
	root, err := vaultRootDir()
	if err != nil {
		return plistPath, false, err
	}
	logPath := filepath.Join(root, "agent.log")

	// exePath/logPath are filesystem paths and can legally contain XML
	// metacharacters (& is common in directory names) — splicing one into the
	// plist unescaped produces a file launchctl rejects, or worse, misparses.
	// Consent is ON by default, so its state is baked into ProgramArguments
	// EXPLICITLY (`--consent` on, `--consent=false` off) — that's what lets a
	// user who turned it off keep it off across a reinstall/upgrade, instead of
	// an absent flag being ambiguous between "off" and "never set". A plist with
	// neither (one written before consent existed) reads as the default: on.
	consentArg := "\n\t\t<string>--consent</string>"
	if !consent {
		consentArg = "\n\t\t<string>--consent=false</string>"
	}
	plist := fmt.Sprintf(agentPlistTemplate, agentPlistLabel, xmlEscape(exePath), ttl.String(), consentArg, xmlEscape(logPath), xmlEscape(logPath))
	if err := os.MkdirAll(filepath.Dir(plistPath), 0o700); err != nil {
		return plistPath, false, err
	}
	// Temp+rename, not a plain WriteFile: launchd or a concurrent session's
	// configuredAgentTTL() read can catch a half-written plist otherwise.
	tmp := plistPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(plist), 0o600); err != nil {
		return plistPath, false, err
	}
	if err := os.Rename(tmp, plistPath); err != nil {
		return plistPath, false, err
	}

	// reloadAgentService boots out any previously-running instance before
	// bootstrapping the just-written plist — bootstrap on an already-loaded
	// label fails outright, and a re-install to change --ttl must take effect
	// now, not at next login. The same helper `jit service restart` uses, so
	// so those callers can't drift on how they (re)load.
	out, err := reloadAgentService(plistPath)
	if err != nil {
		return plistPath, false, fmt.Errorf("launchctl bootstrap failed: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	// launchctl bootstrap returns before the service process has spawned and
	// bound its socket — a real, observed confusion where `jit service status`
	// typed right after a successful install said "not running" for the ~2s
	// launchd took to actually start it. Wait briefly so "installed" also
	// means "answering, on this build."
	running = waitForAgentReady(root, agentStartWait, ready)
	return plistPath, running, nil
}

// ensureAgentInstalled silently sets up and starts the launchd agent the first
// time a command that actually needs a live agent finds none installed — so
// the service is always just there. It is a solid part of "the app" (the same
// jit binary in daemon mode), not a separate setup step, so this path does NOT
// prompt: the caller already ran something (a `jit run` that needs a mount
// served, a `jit migrate` that just produced one, `jit unlock`) that can't
// proceed without it, and the plist is a low-privilege user LaunchAgent that
// goes away when jit itself is removed.
//
// Best-effort and idempotent. An already-installed agent is left untouched
// (didInstall false): running/crashed/mid-restart is the callers' existing
// territory — dial retry, restart advice — not ours. Any install failure is
// swallowed so the caller falls back to its own no-agent path (an independent
// unlock, or notRunningHint's advice) rather than failing the user's real
// command because a background convenience didn't take. Returns whether it just
// installed the service, and whether the service is answering now.
//
// One exception to "installed means leave it alone": a plist whose program
// binary is no longer on disk. That service can never come back by itself —
// launchd has nothing to exec at next login, and the stale-binary
// self-retire deliberately doesn't fire on a vanished file (agentbinary.go).
// In the field this is what `brew upgrade` left behind before
// stableBinaryPath: a plist recording the version-numbered Caskroom path the
// upgrade then deleted. Repoint it at this binary, preserving the plist's
// configured TTL and consent — but only when no agent is answering, because
// an agent still running from a deleted binary keeps serving its session,
// and booting it out would trade a live session for a repair that works just
// as well once that agent is gone.
func ensureAgentInstalled() (didInstall, running bool) {
	if agentInstalled() {
		if !agentPlistOrphaned() {
			return false, false
		}
		root, err := vaultRootDir()
		if err != nil || agent.NewClient(agent.SocketPath(root)).Reachable() {
			return false, false
		}
		ttl := agentInstallDefaultTTL
		if configured, ok := configuredAgentTTL(); ok {
			ttl = configured
		}
		_, running, err := installAgentService(ttl, configuredAgentConsent())
		if err != nil {
			return false, false
		}
		return true, running
	}
	_, running, err := installAgentService(agentInstallDefaultTTL, true)
	if err != nil {
		return false, false
	}
	return true, running
}

// agentPlistOrphaned reports whether the installed plist names a program
// binary that no longer exists on disk. Only a definite "not there" counts —
// an unreadable plist or a stat error that isn't NotExist answers false, so
// uncertainty never triggers a reinstall.
func agentPlistOrphaned() bool {
	plistPath, err := agentPlistPath()
	if err != nil {
		return false
	}
	data, err := os.ReadFile(plistPath) // #nosec G304 -- jit's own launchd plist under the user's LaunchAgents dir
	if err != nil {
		return false
	}
	program, ok := plistProgramPath(data)
	if !ok {
		return false
	}
	_, err = os.Stat(program) // #nosec G703 -- stat-only existence probe of the binary named by jit's own plist
	return os.IsNotExist(err)
}

// notRunningHint rewrites a Client call's dial failure into the actionable
// message the service commands print — the raw error says the socket didn't
// answer, but the thing a human can DO about that differs: an installed
// agent that isn't answering wants a restart (and its log), one that was
// never installed wants installing.
// launchdJobState is the slice of `launchctl print` the health surfaces
// phrase advice from: whether the job is loaded, how many times launchd has
// run it, and how the last run ended. Parsing launchctl's undocumented,
// localizable output is deliberately confined to queryLaunchdJobState, is
// best-effort (any surprise degrades to the unknown state), and NEVER gates
// behaviour — the restart comment's warning about launchctl text as a
// decision input still stands. It only turns "installed but not running"
// into the right sentence: the 2026-08-17 incident's job sat loaded with
// runs = 0 ("pended nondemand spawn") while every surface said "may have
// crashed or be mid-restart", both halves of which were false.
type launchdJobState struct {
	loaded      bool
	runs        int
	lastExit    int
	hasLastExit bool
}

// queryLaunchdJobState asks launchd about the service's job record. known is
// false when the state could not be read at all; "could not find service" is
// a KNOWN answer (the job is definitively not loaded), not a read failure.
func queryLaunchdJobState() (st launchdJobState, known bool) {
	out, err := launchctlRun("print", agentServiceTarget())
	if err != nil {
		if bytes.Contains(bytes.ToLower(out), []byte("could not find service")) {
			return launchdJobState{}, true
		}
		return launchdJobState{}, false
	}
	st.loaded = true
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if v, ok := strings.CutPrefix(line, "runs = "); ok {
			if n, aerr := strconv.Atoi(strings.TrimSpace(v)); aerr == nil {
				st.runs = n
			}
		} else if v, ok := strings.CutPrefix(line, "last exit code = "); ok {
			// "(never exited)" and other non-numeric values simply leave
			// hasLastExit false — exactly the never-spawned shape.
			if n, aerr := strconv.Atoi(strings.TrimSpace(v)); aerr == nil {
				st.lastExit, st.hasLastExit = n, true
			}
		}
	}
	return st, true
}

// xmlEscape escapes the five XML metacharacters for splicing a string
// into a plist <string> element.
func xmlEscape(s string) string {
	return xmlEscaper.Replace(s)
}

var xmlEscaper = strings.NewReplacer(
	"&", "&amp;",
	"<", "&lt;",
	">", "&gt;",
	`"`, "&quot;",
	"'", "&apos;",
)

// xmlUnescape reverses xmlEscape for values read back OUT of a plist.
// plistStringValues deliberately does not unescape (its literal matches,
// "--ttl" and durations, carry no entities); a PATH read through
// plistProgramPath must be unescaped before it is compared or stat'ed.
// `&amp;` is listed first so an escaped-escape (`&amp;lt;`) resolves the
// way the escaper produced it.
func xmlUnescape(s string) string {
	return xmlUnescaper.Replace(s)
}

var xmlUnescaper = strings.NewReplacer(
	"&amp;", "&",
	"&lt;", "<",
	"&gt;", ">",
	"&quot;", `"`,
	"&apos;", "'",
)

// agentDomainTarget and agentServiceTarget name the service to launchctl's
// modern verbs (bootstrap/bootout/kickstart): the per-user GUI domain, and
// the service's service inside it.
func agentDomainTarget() string {
	return fmt.Sprintf("gui/%d", os.Getuid())
}

func agentServiceTarget() string {
	return agentDomainTarget() + "/" + agentPlistLabel
}

// launchctlRun runs launchctl with fixed, jit-controlled arguments and
// returns its combined output. A package var (not a direct exec) purely so
// tests can substitute a fake and drive install/restart's recovery logic
// without spawning real launchd — the exec'd path was otherwise untestable.
var launchctlRun = func(args ...string) ([]byte, error) {
	return exec.Command("launchctl", args...).CombinedOutput() // #nosec G204 -- fixed subcommands with jit's own label/domain/plist path, never external input
}

// reloadAgentService (re)loads the service's launchd service from plistPath:
// boot out any currently-loaded instance, then bootstrap the plist back in.
// This one unconditional sequence recovers EVERY installed-but-not-running
// state without having to detect which it is — a healthy running agent
// (booted out, then restarted onto the current binary), a crash loop launchd
// gave up on, or a service launchd dropped entirely (the plist on disk with
// no live record, where the old kickstart -k dead-ended on "Could not find
// service"). The bootout is best-effort: nothing to boot out on a first-ever
// load or an already-dropped service, and its failure there is expected, so
// only bootstrap's result decides success. bootout/bootstrap are the modern
// verbs; load/unload have been deprecated since 10.11.
//
// bootout returns before launchd has finished tearing the old service down,
// and a bootstrap that lands in that window fails with "Input/output error"
// (EIO, launchctl exit 5) — observed on real hardware. The previous install
// code happened to dodge it by writing the plist between bootout and
// bootstrap, which gave launchd that beat; doing the two back-to-back exposed
// it. So retry through the teardown window rather than surfacing a transient
// race as a hard failure — and retry the bootout+bootstrap PAIR, not
// bootstrap alone: a bootout that genuinely failed leaves every bootstrap
// answering "already bootstrapped", which bootstrapRaceError classifies as
// transient, and without a fresh bootout the loop could never converge. A
// non-transient error (bad plist, permissions) is returned on the first try.
//
// A successful bootstrap is followed by a best-effort kickstart, because
// bootstrap only REGISTERS the job — it does not guarantee a spawn. launchd
// can defer a RunAtLoad spawn indefinitely: observed 2026-08-17 on real
// hardware as `pended nondemand spawn = speculative`, runs = 0, twice, 30s+
// each — and the same machine's KeepAlive equally never respawned a cleanly
// exited agent, leaving the broker dead for 71 minutes while restart
// reported success. kickstart is the one launchctl verb that creates an
// explicit demand; in those experiments it spawned the job instantly, 3 of
// 3. Its error is ignored the way bootout's is: in the healthy case
// RunAtLoad has already spawned the process and kickstart merely reports it
// running. The exit-113 "Could not find service" that got kickstart dropped
// in 660ce2c cannot recur here — the job was registered one line earlier,
// and this kickstart never uses -k, so it cannot kill a just-spawned
// process either.
func reloadAgentService(plistPath string) ([]byte, error) {
	var out []byte
	var err error
	for attempt := 0; attempt < 15; attempt++ {
		if attempt > 0 {
			time.Sleep(200 * time.Millisecond)
		}
		_, _ = launchctlRun("bootout", agentServiceTarget())
		out, err = launchctlRun("bootstrap", agentDomainTarget(), plistPath)
		if err == nil || !bootstrapRaceError(out) {
			break
		}
	}
	if err != nil {
		return out, err
	}
	_, _ = launchctlRun("kickstart", agentServiceTarget())
	return out, nil
}

// bootstrapRaceError reports whether a failed bootstrap is the transient
// "the service this is replacing is still being torn down" state that a
// retry clears — EIO right after a bootout, or launchd still reporting the
// old instance as loaded. Anything else is a real error to surface.
func bootstrapRaceError(launchctlOutput []byte) bool {
	l := bytes.ToLower(launchctlOutput)
	return bytes.Contains(l, []byte("input/output error")) ||
		bytes.Contains(l, []byte("already loaded")) ||
		bytes.Contains(l, []byte("service already bootstrapped"))
}

// agentStartWait is how long install/restart wait for the just-(re)loaded
// service to answer before declaring the start unconfirmed. A package var so
// tests don't spend real wall-clock on the give-up path.
var agentStartWait = 5 * time.Second

// agentReady decides when a just-(re)started service counts as up. Two
// implementations exist because the caller's relationship to the new build
// differs, and getting that backwards makes the success message lie in one
// direction or the other:
//
//   - sameBuildAsThisProcess: the ordinary case. The CLI doing the restart IS
//     the binary the service will run, so build equality is exactly the
//     postcondition, and it rules out the old process still answering while
//     it drains its shutdown.
//   - movedOffBuild: `jit upgrade`. The CLI doing the restart is the OLD
//     binary — the new one was just written to disk and is what the service
//     will exec — so equality can NEVER hold, and demanding it made every
//     successful upgrade wait out the full timeout and then report a failure
//     over a perfectly healthy service. What upgrade can honestly verify is
//     that the service came back and is no longer the build it was.
type agentReady func(st agent.Status) bool

func sameBuildAsThisProcess(st agent.Status) bool { return st.Build == agent.BuildID() }

func movedOffBuild(previous string) agentReady {
	return func(st agent.Status) bool {
		// Nothing was running before (or its build was unreadable): any agent
		// answering now is the one this restart produced.
		return previous == "" || st.Build != previous
	}
}

// waitForAgentBuild polls until an agent running THIS build answers the
// socket, or gives up.
func waitForAgentBuild(root string, timeout time.Duration) bool {
	return waitForAgentReady(root, timeout, sameBuildAsThisProcess)
}

// waitForAgentReady polls until an answering agent satisfies ready, so a
// success message never races launchd's actual spawn.
func waitForAgentReady(root string, timeout time.Duration, ready agentReady) bool {
	client := agent.NewClient(agent.SocketPath(root))
	for deadline := time.Now().Add(timeout); time.Now().Before(deadline); {
		if st, err := client.Status(); err == nil && ready(st) {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

// runningAgentBuild reports the build of whatever agent is answering now, ""
// when none is. `jit upgrade` captures it BEFORE restarting so it can verify
// the service actually moved off it.
func runningAgentBuild(root string) string {
	st, err := agent.NewClient(agent.SocketPath(root)).Status()
	if err != nil {
		return ""
	}
	return st.Build
}

const agentPlistTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>%s</string>
	<key>ProgramArguments</key>
	<array>
		<string>%s</string>
		<string>service</string>
		<string>run</string>
		<string>--ttl</string>
		<string>%s</string>%s
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>StandardOutPath</key>
	<string>%s</string>
	<key>StandardErrorPath</key>
	<string>%s</string>
</dict>
</plist>
`
