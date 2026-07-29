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
	"syscall"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/jitpass/jit/internal/migrate"
	"github.com/jitpass/jit/internal/mount"
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
// carries an explicit --output, passes through untouched: the user asked
// for clisso's own behavior, and a wrapper that second-guesses explicit
// flags is a wrapper nobody can predict.

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

func runClissoCapture(real string, args []string) error {
	app, capturable := clissoCaptureApp(args)
	isGet := len(args) > 0 && args[0] == "get"

	// Any `get` needs the REAL config: after `jit wrap clisso` the on-disk
	// ~/.clisso.yaml holds a jit://vault pointer where the OneLogin
	// client-secret was, and clisso would send that pointer to the IdP.
	// The rendered config is served over a FIFO passed via -c — memory and
	// a pipe, never a file. A user-passed -c is their own arrangement and
	// is never overridden.
	var configArgs []string
	if isGet && !clissoHasConfigFlag(args) {
		fifo, serving, cleanup, err := serveClissoConfig()
		if err != nil {
			return fmt.Errorf("jit clisso-capture: %w", err)
		}
		if serving {
			defer cleanup()
			configArgs = []string{"-c", fifo}
		}
	}

	if !capturable {
		// Config-mutating families fork+wait so the file can be reconciled
		// afterward — `clisso providers create onelogin` writes a fresh
		// plaintext client-secret into the decoy, and the reconcile moves
		// it to the vault before the prompt returns. A non-capturable get
		// (explicit --output, or no app to name) also forks: it still
		// needs the FIFO config alive for the child's lifetime.
		if isGet || clissoMutatesConfig(args) {
			return clissoPassthrough(real, append(args, configArgs...), clissoMutatesConfig(args))
		}
		// Everything else (status, completion, --help, version): exec
		// straight through, terminal untouched. Returns only on failure.
		argv := append([]string{filepath.Base(real)}, args...)
		return syscall.Exec(real, argv, os.Environ()) // #nosec G204 -- real comes from the shim's own PATH resolution, args are the user's command line
	}

	runArgs := append(append([]string{}, args...), "--output", "credential_process")
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
			os.Exit(exitErr.ExitCode())
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
	v, err := openVault()
	if err != nil {
		return fmt.Errorf("jit clisso-capture: %w", err)
	}
	res, err := migrate.StoreAWSSession(v, home, app, session)
	if err != nil {
		return fmt.Errorf("jit clisso-capture: %w", err)
	}
	fmt.Printf("jit: captured temporary AWS credentials for profile %q into the vault", app)
	if session.Expiration != "" {
		fmt.Printf(" (expire %s)", session.Expiration)
	}
	fmt.Printf(".\naws and every SDK fetch them via credential_process; nothing was written in plaintext.\n")
	if res.CredentialsBackup != "" {
		fmt.Printf("Also stripped the old plaintext %q section from %s (backed up encrypted first).\n", app, res.CredentialsPath)
	}
	return nil
}

// clissoHasConfigFlag reports whether the user passed their own
// -c/--config anywhere in args.
func clissoHasConfigFlag(args []string) bool {
	for _, a := range args {
		if a == "-c" || a == "--config" || strings.HasPrefix(a, "-c=") || strings.HasPrefix(a, "--config=") {
			return true
		}
	}
	return false
}

// clissoMutatesConfig reports whether args invoke one of the subcommand
// families that rewrite ~/.clisso.yaml (viper.WriteConfig call sites in
// clisso: apps, providers, cp). Family-level on purpose: `apps list`
// mutates nothing, but a reconcile after it is a cheap read that finds
// nothing, and a family list can't drift when clisso adds `apps delete`.
func clissoMutatesConfig(args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch args[0] {
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
func clissoPassthrough(real string, args []string, reconcile bool) error {
	run := exec.Command(real, args...) // #nosec G204 -- real comes from the shim's own PATH resolution, args are the user's command line
	run.Stdin, run.Stdout, run.Stderr = os.Stdin, os.Stdout, os.Stderr
	runErr := run.Run()

	if reconcile {
		if err := reconcileClissoConfig(); err != nil {
			// The user's clisso command already succeeded or failed on its
			// own terms; a reconcile problem must be visible but not
			// masquerade as clisso failing.
			fmt.Fprintf(os.Stderr, "jit: reconciling ~/.clisso.yaml: %v\n", err)
		}
	}

	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			os.Exit(exitErr.ExitCode())
		}
		return fmt.Errorf("jit clisso-capture: %w", runErr)
	}
	return nil
}

// reconcileClissoConfig vaults any plaintext client-secret found in
// ~/.clisso.yaml. Discovery runs first so the vault (and its unlock
// prompt) is only touched when there is actually something to move.
func reconcileClissoConfig() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	found, err := migrate.DiscoverClissoSecrets(home)
	if err != nil || len(found) == 0 {
		return err
	}
	v, err := openVault()
	if err != nil {
		return err
	}
	res, err := migrate.ApplyClissoConfig(v, home)
	if err != nil {
		return err
	}
	for _, p := range res.Providers {
		fmt.Printf("jit: moved provider %q's client-secret into the vault (%s); the file now holds a pointer.\n", p, migrate.ClissoVaultPath(p))
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
func serveClissoConfig() (fifo string, serving bool, cleanup func(), err error) {
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
	if !bytes.Contains(data, []byte("jit://vault/")) {
		return "", false, nil, nil
	}
	v, err := openVault()
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
		_ = mount.Serve(ctx, fifo, func() []byte { return rendered }, nil, nil, nil)
	}()
	return fifo, true, func() { cancel(); _ = os.RemoveAll(dir) }, nil
}

// clissoCaptureApp decides whether args are a capturable `clisso get` and,
// if so, which app is being fetched — the name that becomes the AWS profile
// (clisso writes credentials under the app's name, so app name == profile
// name). Not capturable: any other subcommand, help, or an explicit
// -o/--output (the user chose a destination; honor it).
//
// With no app argument clisso falls back to its config's
// global.selected-app; the capture needs the same answer for the vault
// profile name, so it reads the same config (honoring -c/--config). If no
// app can be determined the invocation passes through — clisso's own error
// message beats a guess.
func clissoCaptureApp(args []string) (app string, capturable bool) {
	if len(args) == 0 || args[0] != "get" {
		return "", false
	}
	// clisso get's value-taking flags, both "--flag value" and "--flag=value"
	// forms; booleans (--cache-enable, -h) need no skip.
	valueFlags := map[string]bool{
		"-c": true, "--config": true,
		"--log-file": true, "--log-level": true,
		"-m": true, "--mfa-device": true,
		"-o": true, "--output": true,
		"--cache-path": true,
	}
	configPath := ""
	for i := 1; i < len(args); i++ {
		a := args[i]
		if a == "-o" || a == "--output" || strings.HasPrefix(a, "-o=") || strings.HasPrefix(a, "--output=") {
			return "", false
		}
		if a == "-h" || a == "--help" {
			return "", false
		}
		if strings.HasPrefix(a, "-") {
			name, val, hasEq := strings.Cut(a, "=")
			if name == "-c" || name == "--config" {
				if hasEq {
					configPath = val
				} else if i+1 < len(args) {
					configPath = args[i+1]
				}
			}
			if !hasEq && valueFlags[name] {
				i++ // skip the flag's value
			}
			continue
		}
		if app == "" {
			app = a
		}
	}
	if app == "" {
		app = clissoSelectedApp(configPath)
	}
	if app == "" {
		return "", false
	}
	return app, true
}

// clissoSelectedApp reads global.selected-app from clisso's config —
// configPath if the user passed -c, ~/.clisso.yaml otherwise. Best effort:
// any failure returns "", and the caller passes through to clisso, whose
// own "no app specified" error is the right message.
func clissoSelectedApp(configPath string) string {
	if configPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		configPath = filepath.Join(home, ".clisso.yaml")
	}
	data, err := os.ReadFile(configPath) // #nosec G304 -- clisso's own config path: the fixed ~/.clisso.yaml or the -c value the user themselves passed
	if err != nil {
		return ""
	}
	var cfg struct {
		Global struct {
			SelectedApp string `yaml:"selected-app"`
		} `yaml:"global"`
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return ""
	}
	return cfg.Global.SelectedApp
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
