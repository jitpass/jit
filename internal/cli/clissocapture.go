// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/jitpass/jit/internal/migrate"
	"github.com/jitpass/jit/internal/mount"
	"github.com/jitpass/jit/internal/pointerfile"
	"github.com/jitpass/jit/internal/vault"
)

// The capture half of `jit wrap clisso` (docs/wrap/clisso.md). clisso is an
// SSO CLI: `clisso get <app>` logs into OneLogin/Okta (MFA and all) and
// writes freshly minted temporary AWS credentials to ~/.aws/credentials in
// plaintext — re-creating, twice a day, exactly the exposure `jit migrate`
// just cleaned. The shim routes every clisso invocation here instead.
//
// Why capture rather than have jit mint on demand from credential_process:
// minting needs the IdP, and the IdP needs the user — OneLogin's OTP prompt
// and password fallback read from the terminal. credential_process runs as
// a background child of whatever SDK wanted credentials, with no terminal
// to prompt on. Capturing at `clisso get` keeps the login exactly where the
// user already does it, in a terminal that can show an MFA prompt, and only
// reroutes where the result lands: the vault, not the file.
//
// Mechanics: run the real clisso with `--output credential_process`
// appended — clisso's own flag for printing the credentials as one JSON
// line to stdout instead of writing any file — and filter its stdout.
// Everything flows through to the terminal except the credential JSON,
// which is captured (see captureFilter: clisso's interactive prompts —
// OTP entry, MFA device menus, role selection — print to stdout too, some
// without a trailing newline, so the filter must pass bytes through as
// they arrive, not buffer lines). Anything that isn't a plain `get`, or
// carries an explicit output choice (-o/--output, -w/--write-to-file,
// -s/--shell), passes through untouched: the user asked for clisso's own
// behavior, and a wrapper that second-guesses explicit flags is a wrapper
// nobody can predict. Everything jit itself prints goes to stderr, so
// clisso's stdout stays exactly what a caller would have captured.

var clissoCaptureReal string

var clissoCaptureCmd = &cobra.Command{
	Use:     "clisso-capture --real <path> -- [clisso args]",
	GroupID: groupPlumbing,
	// Hidden only from shell tab-completion, like aws-credential-process:
	// helpVisibleAnnotation keeps it in the root help and generated docs.
	Hidden:      true,
	Annotations: map[string]string{helpVisibleAnnotation: "1"},
	Short:       "Run clisso, capturing minted AWS credentials into the vault",
	Long: "Not typically run by hand: the shim `jit wrap clisso` installs execs this\n" +
		"around every clisso invocation. A `clisso get` runs with clisso's own\n" +
		"--output credential_process flag and the minted credentials are stored in\n" +
		"the vault (profile aws-<app>, served back via credential_process) instead\n" +
		"of written to ~/.aws/credentials in plaintext. Every other invocation\n" +
		"passes through to the real clisso unchanged.",
	Args: cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if clissoCaptureReal == "" {
			return fmt.Errorf("jit clisso-capture: --real is required (the shim supplies it)")
		}
		return runClissoCapture(clissoCaptureReal, args)
	},
}

// vaultOpener hands out THE vault for one clisso invocation. It exists
// because openVault builds a fresh keychainwrap.Wrapper each call, and a
// Wrapper caches the master key per INSTANCE — so with the agent service
// unreachable, every extra openVault is another Touch ID prompt for one
// `clisso get`. A capture opens the vault for up to three reasons (render
// the served config, store the session, reconcile the config); memoized,
// that is one prompt instead of three.
type vaultOpener func() (*vault.Vault, error)

func memoizedVaultOpener() vaultOpener {
	var (
		once sync.Once
		v    *vault.Vault
		err  error
	)
	return func() (*vault.Vault, error) {
		once.Do(func() { v, err = openVault() })
		return v, err
	}
}

func runClissoCapture(real string, args []string) error {
	inv := parseClissoArgs(args)
	app, capturable := clissoCaptureApp(args)
	isGet := inv.sub == "get"
	openV := memoizedVaultOpener()

	// `clisso status` reads ~/.aws/credentials — the file this wrap keeps
	// empty — so passed through it denies every session the vault holds,
	// and a script that reuses a session by grepping it re-logins with
	// full MFA each time. Answer it from the vault instead: metadata only,
	// no unlock. Not when the user named a file with -r (their own
	// arrangement, the same rule -o applies to get), and not when the
	// config isn't wrapped at all (clisso's own answer is honest then).
	if inv.sub == "status" && !inv.help && !inv.explicitRead {
		wrapped, err := clissoConfigWrapped()
		if err != nil {
			return fmt.Errorf("jit clisso-capture: %w", err)
		}
		if wrapped {
			return runClissoStatus(os.Stdout, os.Stderr, time.Now())
		}
	}

	// Any `get` needs the REAL config: after `jit wrap clisso` the on-disk
	// ~/.clisso.yaml holds a jit://vault pointer where the OneLogin
	// client-secret was, and clisso would send that pointer to the IdP.
	// The rendered config is served over a FIFO passed via -c — memory and
	// a pipe, never a file. A user-passed -c is their own arrangement and
	// is never overridden.
	var configArgs []string
	cleanup := func() {}
	if isGet && inv.configPath == "" {
		fifo, serving, stop, err := serveClissoConfig(openV)
		if err != nil {
			return fmt.Errorf("jit clisso-capture: %w", err)
		}
		if serving {
			cleanup = stop
			defer cleanup()
			configArgs = []string{"-c", fifo}
		}
	}
	// exitAfterCleanup propagates clisso's exit code. os.Exit does NOT run
	// deferred functions, so the FIFO's temp directory has to be removed
	// here explicitly or every failed login (a mistyped OTP is enough)
	// leaves one behind. cleanup is idempotent, so the deferred call that
	// never happens costs nothing.
	exitAfterCleanup := func(code int) {
		cleanup()
		os.Exit(code)
	}

	if !capturable {
		// Config-mutating families fork+wait so the file can be reconciled
		// afterward — `clisso providers create onelogin` writes a fresh
		// plaintext client-secret into the decoy, and the reconcile moves
		// it to the vault before the prompt returns. A non-capturable get
		// (explicit output choice, or no app to name) also forks: it still
		// needs the FIFO config alive for the child's lifetime.
		if isGet || inv.mutatesConfig() {
			passArgs := append(append([]string{}, args...), configArgs...)
			return clissoPassthrough(real, passArgs, inv, exitAfterCleanup, openV)
		}
		// Everything else (status, completion, --help, version): exec
		// straight through, terminal untouched. Returns only on failure.
		argv := append([]string{filepath.Base(real)}, args...)
		return syscall.Exec(real, argv, os.Environ()) // #nosec G204 -- real comes from the shim's own PATH resolution, args are the user's command line
	}

	captureArgs := args
	if inv.cacheEnable {
		captureArgs = stripClissoCacheFlag(captureArgs)
		// Says why the flag went, and stops there. An earlier draft ended
		// "the vault holds them instead" — a promise about a capture that
		// hasn't happened yet and might still fail on a mistyped OTP.
		wrapBody(os.Stderr, 0, "    ", hlCmds(
			"jit: dropped --cache-enable — clisso writes that cache file in plaintext whatever "+
				"the output mode. Run with an explicit `-o` if you need it."))
	}
	runArgs := append(append([]string{}, captureArgs...), "--output", "credential_process")
	runArgs = append(runArgs, configArgs...)
	run := exec.Command(real, runArgs...) // #nosec G204 -- same provenance as the exec above
	run.Stdin = os.Stdin
	run.Stderr = os.Stderr
	stdout, err := run.StdoutPipe()
	if err != nil {
		return fmt.Errorf("jit clisso-capture: %w", err)
	}
	if err := run.Start(); err != nil {
		return fmt.Errorf("jit clisso-capture: starting %s: %w", real, err)
	}
	session, captured, filterErr := captureFilter(stdout, os.Stdout)
	waitErr := run.Wait()
	if waitErr != nil {
		// clisso failed (bad MFA, network, its own usage errors) and has
		// already said so on the terminal; propagate its exit code without
		// wrapping noise on top.
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			exitAfterCleanup(exitErr.ExitCode())
		}
		return fmt.Errorf("jit clisso-capture: %w", waitErr)
	}
	if filterErr != nil {
		return fmt.Errorf("jit clisso-capture: reading clisso output: %w", filterErr)
	}
	if !captured {
		return fmt.Errorf("jit clisso-capture: clisso exited cleanly but printed no credentials — run `%s get %s --output credential_process` to see its raw output", filepath.Base(real), app)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("jit clisso-capture: %w", err)
	}
	v, err := openV()
	if err != nil {
		return fmt.Errorf("jit clisso-capture: %w", err)
	}
	// Warn BEFORE the write: an AWS profile that already holds a key from
	// somewhere else (a static IAM key `jit migrate` moved out of
	// ~/.aws/credentials) and a clisso app can share a name, and the
	// capture replaces it.
	if c := migrate.InspectOriginConflict(v, "aws-"+app+"/SECRET_ACCESS_KEY", vault.ClassAWS, migrate.ClissoConfigPath(home)); c != nil {
		prose, command := c.ReplacingNote()
		wrapBody(os.Stderr, 0, "    ", prose)
		fmt.Fprintf(os.Stderr, "    %s\n", hlCmds(command))
	}
	res, err := migrate.StoreAWSSession(v, home, app, session)
	if err != nil {
		return fmt.Errorf("jit clisso-capture: %w", err)
	}
	// Every line jit adds goes to STDERR, not stdout. clisso's stdout is
	// its own output channel — a script doing `creds=$(clisso get prod
	// --output credential_process)` still works through the shim only if
	// the wrapper keeps its commentary off that stream.
	out := os.Stderr
	fmt.Fprintf(out, "jit: captured temporary AWS credentials for profile %q into the vault", app)
	if session.Expiration != "" {
		fmt.Fprintf(out, " (expire %s)", session.Expiration)
	}
	fmt.Fprintf(out, ".\naws and every SDK fetch them via credential_process; nothing was written in plaintext.\n")
	if res.CredentialsBackup != "" {
		fmt.Fprintf(out, "Also stripped the old plaintext %q section from %s (backed up encrypted first).\n", app, res.CredentialsPath)
	}
	return nil
}

// clissoInvocation is what the shim needs to know about one clisso command
// line. It comes from a single pass (parseClissoArgs) rather than a set of
// independent scans, because every question here depends on the same fact:
// where the subcommand actually is.
type clissoInvocation struct {
	sub          string // the subcommand ("get", "apps", …), "" if none
	app          string // first bare argument after the subcommand
	configPath   string // the user's own -c/--config, if any
	explicitOut  bool   // -o/--output, -w/--write-to-file, or -s/--shell
	explicitRead bool   // status's -r/--read-from-file: the user named the file
	help         bool
	cacheEnable  bool
}

// clissoValueFlags are the flags that consume the NEXT argument — root
// persistent flags plus `get`'s own. Skipping their values is what keeps a
// value from being mistaken for the subcommand or the app name.
var clissoValueFlags = map[string]bool{
	"-c": true, "--config": true,
	"--log-file": true, "--log-level": true,
	"-m": true, "--mfa-device": true,
	"-o": true, "--output": true,
	"--cache-path":     true,
	"-w":               true,
	"--write-to-file":  true,
	"-r":               true,
	"--read-from-file": true,
}

// clissoOutputFlags are the ways a user explicitly chooses where
// credentials go. Any of them opts the run out of capture: the user asked
// for clisso's own behavior. clisso marks all three mutually exclusive
// with --output, so injecting ours alongside one wouldn't just override
// the choice — it would make clisso refuse to run at all.
var clissoOutputFlags = map[string]bool{
	"-o": true, "--output": true,
	"-w": true, "--write-to-file": true,
	"-s": true, "--shell": true,
}

// parseClissoArgs walks a clisso command line the way cobra does: global
// flags may appear BEFORE the subcommand (`clisso --log-level debug get
// prod` runs get, verified against the real binary), so the subcommand is
// the first bare argument, not args[0]. Getting this wrong is not cosmetic
// — a `get` the shim fails to recognize passes through unwrapped, and
// clisso writes plaintext credentials to ~/.aws/credentials, which is the
// exposure this whole wrap exists to prevent.
func parseClissoArgs(args []string) clissoInvocation {
	var inv clissoInvocation
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "" {
			continue
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			switch {
			case inv.sub == "":
				inv.sub = a
			case inv.app == "":
				inv.app = a
			}
			continue
		}
		name, val, hasEq := strings.Cut(a, "=")
		switch {
		case name == "-h" || name == "--help":
			inv.help = true
		case name == "-c" || name == "--config":
			if hasEq {
				inv.configPath = val
			} else if i+1 < len(args) {
				inv.configPath = args[i+1]
			}
		case name == "--cache-enable":
			// A bool flag: bare means true, and only an explicit
			// =false turns it off.
			inv.cacheEnable = !hasEq || !strings.EqualFold(val, "false")
		case name == "-r" || name == "--read-from-file":
			inv.explicitRead = true
		}
		if clissoOutputFlags[name] {
			inv.explicitOut = true
		}
		if !hasEq && clissoValueFlags[name] {
			i++ // this flag's value is not the subcommand or the app
		}
	}
	return inv
}

// mutatesConfig reports whether this invocation is one of the subcommand
// families that rewrite ~/.clisso.yaml (viper.WriteConfig call sites in
// clisso: apps, providers, cp). Family-level on purpose: `apps ls`
// mutates nothing, but a reconcile after it is a cheap read that finds
// nothing, and a family list can't drift when clisso adds `apps delete`.
func (inv clissoInvocation) mutatesConfig() bool {
	switch inv.sub {
	case "apps", "providers", "cp":
		return true
	}
	return false
}

// clissoPassthrough runs the real clisso with inherited stdio, then — for
// config-mutating families — reconciles ~/.clisso.yaml: any plaintext
// client-secret the run just wrote moves to the vault and a pointer takes
// its place, before the user's prompt returns. clisso's exit code is
// propagated; the reconcile runs even after a failure (a partial write is
// exactly when a stray secret is most likely to be left behind).
func clissoPassthrough(real string, args []string, inv clissoInvocation, exitAfterCleanup func(int), openV vaultOpener) error {
	run := exec.Command(real, args...) // #nosec G204 -- real comes from the shim's own PATH resolution, args are the user's command line
	run.Stdin, run.Stdout, run.Stderr = os.Stdin, os.Stdout, os.Stderr
	runErr := run.Run()

	if inv.mutatesConfig() {
		if err := reconcileClissoConfig(openV); err != nil {
			// The user's clisso command already succeeded or failed on its
			// own terms; a reconcile problem must be visible but not
			// masquerade as clisso failing.
			fmt.Fprintf(os.Stderr, "jit: reconciling ~/.clisso.yaml: %v\n", err)
		}
		if inv.sub == "cp" {
			warnClissoCredentialProcess()
		}
	}

	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			exitAfterCleanup(exitErr.ExitCode())
		}
		return fmt.Errorf("jit clisso-capture: %w", runErr)
	}
	return nil
}

// reconcileClissoConfig vaults any plaintext client-secret found in
// ~/.clisso.yaml. Discovery runs first so the vault (and its unlock
// prompt) is only touched when there is actually something to move.
func reconcileClissoConfig(openV vaultOpener) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	found, err := migrate.DiscoverClissoSecrets(home)
	if err != nil || len(found) == 0 {
		return err
	}
	v, err := openV()
	if err != nil {
		return err
	}
	res, err := migrate.ApplyClissoConfig(v, home)
	if err != nil {
		return err
	}
	for _, p := range res.Providers {
		fmt.Fprintf(os.Stderr, "jit: moved provider %q's client-secret into the vault (%s); the file now holds a pointer.\n", p, migrate.ClissoVaultPath(p))
	}
	for _, p := range res.Skipped {
		fmt.Fprintf(os.Stderr, "jit: provider %q has a name that can't map to a vault path; its client-secret was left in place.\n", p)
	}
	return nil
}

// serveClissoConfig renders ~/.clisso.yaml with its jit://vault pointers
// resolved and serves the result over a FIFO for clisso to read via -c.
// serving is false when the config holds no pointers (never wrapped, or
// missing) — then clisso reads its own file as always. The writer
// goroutine re-serves on every open, so a config read more than once
// still works; it dies with this process, which outlives clisso by only
// the capture bookkeeping.
func serveClissoConfig(openV vaultOpener) (fifo string, serving bool, cleanup func(), err error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", false, nil, err
	}
	data, err := os.ReadFile(migrate.ClissoConfigPath(home)) // #nosec G304 -- fixed ~/.clisso.yaml under the user's home
	if err != nil {
		if os.IsNotExist(err) {
			return "", false, nil, nil
		}
		return "", false, nil, err
	}
	// Cheap gate before any vault (and unlock prompt) involvement.
	if !bytes.Contains(data, []byte(pointerfile.ValuePrefix)) {
		return "", false, nil, nil
	}
	v, err := openV()
	if err != nil {
		return "", false, nil, err
	}
	rendered, resolved, err := migrate.RenderClissoConfig(v, data)
	if err != nil {
		return "", false, nil, err
	}
	if !resolved {
		return "", false, nil, nil
	}

	dir, err := os.MkdirTemp("", "jit-clisso-*")
	if err != nil {
		return "", false, nil, err
	}
	// The extension matters: clisso's -c hands the path to viper, which
	// picks its parser from the file extension.
	fifo = filepath.Join(dir, "config.yaml")
	if err := mount.CreateFIFO(fifo); err != nil {
		_ = os.RemoveAll(dir)
		return "", false, nil, err
	}
	// mount.Serve, not a hand-rolled open/write/close loop: with a reader
	// still holding the pipe, an immediate re-open writes a SECOND copy
	// into the same reader, and viper parses the concatenation as
	// duplicate YAML keys and panics ("mapping key "apps" already
	// defined") — reproduced against the real clisso binary. Serve's
	// default path swaps in a fresh pipe object per cycle, which is
	// precisely the isolation that prevents it.
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		_ = mount.Serve(ctx, fifo, func() []byte { return rendered }, nil, nil, nil, nil)
	}()
	// Idempotent: the caller both defers this and calls it explicitly
	// before propagating clisso's exit code (os.Exit skips defers).
	var once sync.Once
	return fifo, true, func() {
		once.Do(func() {
			cancel()
			_ = os.RemoveAll(dir)
		})
	}, nil
}

// clissoConfigWrapped reports whether ~/.clisso.yaml is the wrap's: it
// holds a jit://vault pointer where a client-secret was. A missing config
// is simply not wrapped.
func clissoConfigWrapped() (bool, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return false, err
	}
	data, err := os.ReadFile(migrate.ClissoConfigPath(home)) // #nosec G304 -- fixed ~/.clisso.yaml under the user's home
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return bytes.Contains(data, []byte(pointerfile.ValuePrefix)), nil
}

// runClissoStatus is the wrapped `clisso status`: clisso's own sessions,
// from the vault, in clisso's own table. Read-only vault, so it never
// prompts — the whole point of stamping expiry as metadata. jit's one
// line of attribution goes to stderr; stdout stays what a script expects.
func runClissoStatus(stdout, stderr io.Writer, now time.Time) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("jit clisso-capture: %w", err)
	}
	v, err := openVaultReadOnly()
	if err != nil {
		return fmt.Errorf("jit clisso-capture: %w", err)
	}
	sessions, err := migrate.ListSessions(v, home, now)
	if err != nil {
		return fmt.Errorf("jit clisso-capture: listing sessions: %w", err)
	}
	fmt.Fprintln(stderr, "jit: answered from the vault; the wrap keeps ~/.aws/credentials empty")
	renderClissoStatusTable(stdout, clissoStatusRows(sessions, clissoApps(), now))
	return nil
}

// clissoCaptureApp decides whether args are a capturable `clisso get` and,
// if so, which app is being fetched — the name that becomes the AWS profile
// (clisso writes credentials under the app's name, so app name == profile
// name). Not capturable: any other subcommand, help, or an explicit output
// choice (the user picked a destination; honor it).
//
// With no app argument clisso falls back to its config's
// global.selected-app; the capture needs the same answer for the vault
// profile name, so it reads the same config (honoring -c/--config). If no
// app can be determined the invocation passes through — clisso's own error
// message beats a guess.
func clissoCaptureApp(args []string) (app string, capturable bool) {
	inv := parseClissoArgs(args)
	if inv.sub != "get" || inv.help || inv.explicitOut {
		return "", false
	}
	app = inv.app
	if app == "" {
		app = clissoSelectedApp(inv.configPath)
	}
	if app == "" {
		return "", false
	}
	return app, true
}

// stripClissoCacheFlag removes --cache-enable from a captured run's args.
// clisso writes its cache file whenever that flag is set, independent of
// --output (processCredentials calls writeCredentialsToFile before the
// output switch is consulted) — so leaving it on would let a captured
// login ALSO drop plaintext credentials in ~/.aws/credentials-cache,
// silently reopening the hole the capture closes. A bool flag with no
// shorthand, so matching the name is the whole job.
func stripClissoCacheFlag(args []string) []string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		if name, _, _ := strings.Cut(a, "="); name == "--cache-enable" {
			continue
		}
		out = append(out, a)
	}
	return out
}

// warnClissoCredentialProcess looks for credential_process entries in
// ~/.aws/credentials that invoke clisso — what `clisso cp configure`
// writes — and warns, naming the profiles.
//
// This matters because of AWS's own precedence: the credentials file wins
// over the config file, so clisso's entries silently shadow the
// `credential_process` jit wrote to ~/.aws/config. The shadowing command
// (`clisso -o credential_process get <app>`) then runs with no terminal to
// show an MFA prompt on. jit does not edit the file here — undoing a
// command the user just deliberately ran would be its own surprise — it
// says what happened and leaves the choice with them.
func warnClissoCredentialProcess() {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	path := filepath.Join(home, ".aws", "credentials")
	data, err := os.ReadFile(path) // #nosec G304 -- fixed ~/.aws/credentials under the user's home
	if err != nil {
		return
	}
	var profiles []string
	section := ""
	for _, line := range strings.Split(string(data), "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "#") || strings.HasPrefix(t, ";") {
			continue
		}
		if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
			section = strings.TrimSpace(t[1 : len(t)-1])
			continue
		}
		k, v, ok := strings.Cut(t, "=")
		if !ok || strings.TrimSpace(k) != "credential_process" || !strings.Contains(v, "clisso") {
			continue
		}
		profiles = append(profiles, section)
	}
	if len(profiles) == 0 {
		return
	}
	wrapBody(os.Stderr, 0, "    ", hlCmds(fmt.Sprintf(
		"jit: warning — clisso wrote credential_process entries into ~/.aws/credentials (%s). "+
			"That file outranks ~/.aws/config, so they shadow jit's wiring and run clisso with "+
			"no terminal for MFA. Delete those lines to restore `clisso get <app>`.",
		strings.Join(profiles, ", "))))
}

// clissoSelectedApp reads global.selected-app from clisso's config —
// configPath if the user passed -c, ~/.clisso.yaml otherwise. Best effort:
// any failure returns "", and the caller passes through to clisso, whose
// own "no app specified" error is the right message.
func clissoSelectedApp(configPath string) string {
	return readClissoConfig(configPath).Global.SelectedApp
}

// clissoConfig is the little of ~/.clisso.yaml the shim reads: the default
// app, and which apps clisso knows at all — the rule for "is this vaulted
// session clisso's". Origin cannot answer that: a profile first migrated
// out of ~/.aws/credentials and re-minted by clisso ever after keeps its
// birth origin, and would never count.
type clissoConfig struct {
	Global struct {
		SelectedApp string `yaml:"selected-app"`
	} `yaml:"global"`
	Apps map[string]any `yaml:"apps"`
}

// readClissoConfig parses configPath ("" for ~/.clisso.yaml). Unreadable
// or unparsable reads as an empty config — every caller's fallback is
// "clisso's own answer wins", never an error.
func readClissoConfig(configPath string) clissoConfig {
	var cfg clissoConfig
	if configPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return cfg
		}
		configPath = filepath.Join(home, ".clisso.yaml")
	}
	data, err := os.ReadFile(configPath) // #nosec G304 -- clisso's own config path: the fixed ~/.clisso.yaml or the -c value the user themselves passed
	if err != nil {
		return cfg
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return clissoConfig{}
	}
	return cfg
}

// clissoApps is the set of app names ~/.clisso.yaml defines.
func clissoApps() map[string]bool {
	cfg := readClissoConfig("")
	apps := make(map[string]bool, len(cfg.Apps))
	for name := range cfg.Apps {
		apps[name] = true
	}
	return apps
}

// captureFilter streams clisso's stdout to the terminal while intercepting
// the credential JSON. The stream is interactive — OTP prompts and menus
// arrive without trailing newlines and must appear immediately — so bytes
// pass through as they are read, with one exception: a line that begins
// with '{' is held back until its newline (or EOF; clisso prints the JSON
// with no trailing newline) and parsed. If it parses as the
// credential_process shape it is captured and never echoed — it holds the
// secret. Anything else held is flushed unchanged, so a hypothetical
// '{'-opening message costs at most its own buffering, never bytes.
func captureFilter(r io.Reader, w io.Writer) (migrate.AWSSession, bool, error) {
	var (
		session   migrate.AWSSession
		captured  bool
		held      []byte
		holding   bool
		lineStart = true
		buf       = make([]byte, 4096)
	)
	// tryCapture parses the held line, reporting whether it was the
	// credential JSON (captured, never echoed) or ordinary output
	// (flushed through unchanged, without a newline — the caller owns
	// the newline decision, since EOF-held lines never had one).
	tryCapture := func() bool {
		var out struct {
			Version         int
			AccessKeyId     string
			SecretAccessKey string
			SessionToken    string
			Expiration      string
		}
		hit := json.Unmarshal(held, &out) == nil && out.AccessKeyId != "" && out.SecretAccessKey != ""
		if hit {
			session = migrate.AWSSession{
				AccessKeyID:     out.AccessKeyId,
				SecretAccessKey: out.SecretAccessKey,
				SessionToken:    out.SessionToken,
				Expiration:      out.Expiration,
			}
			captured = true
		} else {
			_, _ = w.Write(held)
		}
		held = held[:0]
		holding = false
		return hit
	}
	for {
		n, err := r.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			for len(chunk) > 0 {
				if holding {
					idx := bytes.IndexByte(chunk, '\n')
					if idx < 0 {
						held = append(held, chunk...)
						chunk = nil
						continue
					}
					held = append(held, chunk[:idx]...)
					if !tryCapture() {
						// The held line was flushed, not captured — its
						// newline belongs with it.
						_, _ = w.Write([]byte{'\n'})
					}
					chunk = chunk[idx+1:]
					lineStart = true
					continue
				}
				if lineStart && chunk[0] == '{' {
					holding = true
					continue
				}
				// Pass through up to (and including) the next newline, or
				// the whole chunk — partial prompt lines must not wait.
				idx := bytes.IndexByte(chunk, '\n')
				if idx < 0 {
					_, _ = w.Write(chunk)
					lineStart = false
					chunk = nil
					continue
				}
				_, _ = w.Write(chunk[:idx+1])
				chunk = chunk[idx+1:]
				lineStart = true
			}
		}
		if err == io.EOF {
			if holding {
				tryCapture()
			}
			return session, captured, nil
		}
		if err != nil {
			return session, captured, err
		}
	}
}

func init() {
	clissoCaptureCmd.Flags().StringVar(&clissoCaptureReal, "real", "", "absolute path to the real clisso binary (supplied by the shim)")
	rootCmd.AddCommand(clissoCaptureCmd)
}
