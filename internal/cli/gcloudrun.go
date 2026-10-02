// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/lineage"
	"github.com/jitpass/jit/internal/migrate"
	"github.com/jitpass/jit/internal/sealstore"
	"github.com/jitpass/jit/internal/vault"
	"github.com/jitpass/jit/internal/wrap"
)

// The run half of a store-wrap (design/gcloud-sealed-store.md). The five
// gcloud-family shims exec this; it unseals gcloud's login store from the
// vault into a private dir, runs the real tool there through CLOUDSDK_CONFIG,
// and seals the store again if the run changed it. It forks and waits, like
// clisso-capture, because the cleanup has to happen after the tool exits —
// the one thing an exec'ing shim cannot do (D1).

var gcloudRunReal string

var gcloudRunCmd = &cobra.Command{
	Use:     "gcloud-run --real <path> -- [args]",
	GroupID: groupPlumbing,
	// Hidden from tab-completion only, like clisso-capture: the shim is its
	// one caller, but the root help and generated docs still list it.
	Hidden:      true,
	Annotations: map[string]string{helpVisibleAnnotation: "1"},
	Short:       "Run a Google Cloud CLI with its login unsealed for that one run",
	Long: "Not typically run by hand: the shims `jit wrap gcloud` installs (gcloud, bq,\n" +
		"gsutil, docker-credential-gcloud, git-credential-gcloud) exec this around\n" +
		"every invocation. gcloud's login store lives in the vault; this unpacks it\n" +
		"into a private folder for the one run, points the tool at it with\n" +
		"CLOUDSDK_CONFIG, and seals it again afterwards if the run changed it (a\n" +
		"login, an activate, a revoke). Your settings stay in ~/.config/gcloud.\n" +
		"The tool's exit status is passed through unchanged.",
	Args: cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if gcloudRunReal == "" {
			return fmt.Errorf("jit gcloud-run: --real is required (the shim supplies it)")
		}
		code, err := runGcloudRun(cmd, gcloudRunReal, args)
		if err != nil {
			return err
		}
		if code != 0 {
			// The tool's own status, passed through. Its run is recorded
			// already (recordRunInvocation), and the cleanup is done.
			os.Exit(code)
		}
		return nil
	},
}

func init() {
	gcloudRunCmd.Flags().StringVar(&gcloudRunReal, "real", "", "absolute path to the real tool (supplied by the shim)")
	rootCmd.AddCommand(gcloudRunCmd)
}

// gcloudRunBase is where run dirs live: inside jit's own root, never
// $TMPDIR (D6, newJobScratch's reasoning).
func gcloudRunBase(root string) string { return filepath.Join(root, "gcloud-run") }

// runGcloudRun returns the tool's exit status. A path that hands over to
// the tool with exec never returns on success; its error is the exec's.
func runGcloudRun(cmd *cobra.Command, real string, args []string) (int, error) {
	stderr := cmd.ErrOrStderr()
	tool := filepath.Base(real)
	home, err := os.UserHomeDir()
	if err != nil {
		return 0, fmt.Errorf("jit gcloud-run: %w", err)
	}
	root, err := vaultRootDir()
	if err != nil {
		return 0, fmt.Errorf("jit gcloud-run: %w", err)
	}
	base := gcloudRunBase(root)
	dir := migrate.GcloudConfigDir(home)

	if cfg := os.Getenv("CLOUDSDK_CONFIG"); cfg != "" {
		// Already inside a run: a gcloud the GKE auth plugin started, a
		// helper gcloud spawned. The outer run's store is unsealed and
		// serving; a second unseal would be a second prompt for nothing.
		if inRunDir(base, cfg) {
			return 0, execRealTool(real, args, tool)
		}
		// The user's own config dir elsewhere. Only the default is sealed
		// (D7), so the tool runs as it would without jit — and says so.
		if filepath.Clean(cfg) != filepath.Clean(dir) {
			fmt.Fprintf(stderr, "jit: CLOUDSDK_CONFIG names %s, not the sealed %s; running %s without jit\n", cfg, dir, tool)
			return 0, execRealTool(real, args, tool)
		}
	}

	// Application-default credentials are not the store: they are the gcp
	// mount, and `gcloud auth application-default …` is the only gcloud
	// command that reads them. It keeps the old grant-wrap behaviour (D9).
	if tool == "gcloud" && isADCCommand(args) {
		return 0, execADCGrant(real, args, tool)
	}

	secrets, ephemeral, err := splitPlaintext(dir)
	if err != nil {
		return 0, fmt.Errorf("jit gcloud-run: %w", err)
	}
	if len(secrets) > 0 {
		// Something logged in without the shim (an IDE calling gcloud by
		// absolute path). Use what is there rather than swap in an older
		// vaulted login behind the user's back (D7), and say how to fix it.
		fmt.Fprintln(stderr, hlCmds("jit: gcloud's login is back in plaintext in "+dir+"; run `jit wrap gcloud` to seal it again"))
		return 0, execRealTool(real, args, tool)
	}
	for _, name := range ephemeral {
		// An access-token cache a passthrough run left behind: an hour-long
		// bearer token in plaintext, and gcloud rebuilds it (D3).
		_ = os.RemoveAll(filepath.Join(dir, name))
	}

	v, err := openVault()
	if err != nil {
		return 0, fmt.Errorf("jit gcloud-run: %w", err)
	}
	var blob []byte
	sealed, err := migrate.GcloudStoreSealed(v)
	if err != nil {
		return 0, fmt.Errorf("jit gcloud-run: %w", err)
	}
	if sealed {
		// The consent prompt happens here: one unwrap of a gcp-class value.
		if blob, err = v.Get(migrate.GcloudStorePath); err != nil {
			return 0, fmt.Errorf("jit: gcloud's login stays sealed: %w", err)
		}
	}

	sweepGcloudRuns(base)
	start, _ := lineage.ProcessStartTime(int32(os.Getpid())) // #nosec G115 -- a pid always fits in int32 on darwin
	runDir, err := sealstore.NewRunDir(base, os.Getpid(), start)
	if err != nil {
		return 0, fmt.Errorf("jit gcloud-run: %w", err)
	}
	baseline, err := materializeGcloud(blob, dir, runDir)
	if err != nil {
		_ = os.RemoveAll(runDir)
		return 0, fmt.Errorf("jit gcloud-run: %w", err)
	}

	// os.Exit below skips Execute's own audit hook, as syscall.Exec does for
	// `jit run`.
	recordRunInvocation(cmd)
	code, runErr := forkAndWait(real, args, gcloudChildEnv(os.Environ(), tool, runDir))

	resealGcloudRun(stderr, gcloudVault{v}, home, dir, runDir, baseline)
	if _, err := sealstore.Gcloud.Adopt(runDir, dir); err != nil {
		fmt.Fprintf(stderr, "jit: %s settings not carried back to %s: %v\n", tool, dir, err)
	}
	_ = os.RemoveAll(runDir)

	if runErr != nil {
		return 0, fmt.Errorf("jit gcloud-run: starting %s: %w", real, runErr)
	}
	return code, nil
}

// materializeGcloud fills runDir with the unsealed store and links to the
// settings, returning the store's packed bytes as they stand before the
// tool runs — the baseline the reseal compares against.
func materializeGcloud(blob []byte, dir, runDir string) ([]byte, error) {
	if len(blob) > 0 {
		if err := sealstore.Gcloud.Unpack(blob, runDir); err != nil {
			return nil, err
		}
	}
	if err := sealstore.Gcloud.Link(dir, runDir); err != nil {
		return nil, err
	}
	return sealstore.Gcloud.Pack(runDir)
}

// resealGcloudRun vaults the store if the run changed it (D4). If the vault
// write fails — a Touch ID declined after a long login — the new login is
// moved into the config dir in plaintext rather than deleted with the run
// dir: losing a login the user just completed is worse than one plaintext
// file the next run will name.
func resealGcloudRun(stderr io.Writer, v vaultSetter, home, dir, runDir string, baseline []byte) {
	after, err := sealstore.Gcloud.Pack(runDir)
	if err != nil {
		fmt.Fprintf(stderr, "jit: could not read gcloud's login store after the run: %v\n", err)
		rescueGcloudStore(stderr, dir, runDir)
		return
	}
	if bytes.Equal(after, baseline) {
		return
	}
	if err := v.reseal(home, runDir, after); err != nil {
		fmt.Fprintf(stderr, "jit: could not seal gcloud's new login: %v\n", err)
		rescueGcloudStore(stderr, dir, runDir)
		return
	}
	if sealstore.Empty(after) {
		fmt.Fprintln(stderr, "jit: gcloud is signed out; the vault holds no gcloud login now")
		return
	}
	fmt.Fprintln(stderr, "jit: sealed gcloud's login into the vault; nothing was left in plaintext")
}

// vaultSetter is the one vault operation resealGcloudRun needs, so a test
// can make it fail.
type vaultSetter interface {
	reseal(home, runDir string, blob []byte) error
}

// gcloudVault is the real vaultSetter.
type gcloudVault struct{ v *vault.Vault }

func (g gcloudVault) reseal(home, runDir string, blob []byte) error {
	return migrate.ResealGcloudStore(g.v, home, runDir, blob)
}

// rescueGcloudStore moves the run's secrets into the config dir.
func rescueGcloudStore(stderr io.Writer, dir, runDir string) {
	for _, name := range sealstore.Gcloud.Secrets {
		src := filepath.Join(runDir, name)
		if _, err := os.Lstat(src); err != nil {
			continue
		}
		dst := filepath.Join(dir, name)
		if _, err := os.Lstat(dst); err == nil {
			continue
		}
		if err := os.Rename(src, dst); err != nil {
			fmt.Fprintf(stderr, "jit: could not keep %s: %v\n", name, err)
		}
	}
	fmt.Fprintln(stderr, hlCmds("jit: gcloud's login is in plaintext in "+dir+" for now; run `jit wrap gcloud` to seal it"))
}

// splitPlaintext reports which of the store's secret and ephemeral entries
// sit in dir in plaintext.
func splitPlaintext(dir string) (secrets, ephemeral []string, err error) {
	found, err := sealstore.Gcloud.Plaintext(dir)
	if err != nil {
		return nil, nil, err
	}
	for _, name := range found {
		if isOneOf(name, sealstore.Gcloud.Secrets) {
			secrets = append(secrets, name)
		} else {
			ephemeral = append(ephemeral, name)
		}
	}
	return secrets, ephemeral, nil
}

func isOneOf(s string, list []string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// inRunDir reports whether cfg is one of the run dirs under base.
func inRunDir(base, cfg string) bool {
	rel, err := filepath.Rel(filepath.Clean(base), filepath.Clean(cfg))
	return err == nil && rel != "." && !strings.HasPrefix(rel, "..") && !strings.Contains(rel, string(filepath.Separator))
}

// isADCCommand reports whether a gcloud command line is `auth
// application-default …`, wherever global flags put it.
func isADCCommand(args []string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "--" {
			return false
		}
		if args[i] == "auth" && args[i+1] == "application-default" {
			return true
		}
	}
	return false
}

// gcloudChildEnv is the tool's environment: the caller's, pointed at the
// run dir, without the shim's recursion guard for this tool (a gcloud the
// run itself starts is a nested call, not a loop; see wrap.GuardVar).
func gcloudChildEnv(environ []string, tool, runDir string) []string {
	guard := wrap.GuardVar(tool) + "="
	out := make([]string, 0, len(environ)+1)
	for _, kv := range environ {
		if strings.HasPrefix(kv, guard) || strings.HasPrefix(kv, "CLOUDSDK_CONFIG=") {
			continue
		}
		out = append(out, kv)
	}
	if runDir != "" {
		out = append(out, "CLOUDSDK_CONFIG="+runDir)
	}
	return out
}

// execRealTool replaces this process with the real tool, unchanged apart
// from the recursion guard. Returns only on failure.
func execRealTool(real string, args []string, tool string) error {
	argv := append([]string{real}, args...)
	return syscall.Exec(real, argv, gcloudChildEnv(os.Environ(), tool, os.Getenv("CLOUDSDK_CONFIG"))) // #nosec G204 -- real comes from the shim's own PATH resolution, args are the user's command line
}

// execADCGrant runs an ADC command the way the grant-wrap did: inside
// `jit run --with gcp` when the ADC file is migrated, plain otherwise.
func execADCGrant(real string, args []string, tool string) error {
	if _, err := withMountPaths([]string{"gcp"}); err != nil {
		return execRealTool(real, args, tool)
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	self, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return err
	}
	argv := append([]string{"jit", "run", "--with", "gcp", "--", real}, args...)
	return syscall.Exec(self, argv, gcloudChildEnv(os.Environ(), tool, os.Getenv("CLOUDSDK_CONFIG"))) // #nosec G204 -- self is this binary; real and args as above
}

// forkAndWait runs the tool as a child sharing this terminal and returns
// its exit status (128+signal when a signal ended it, the shell's
// convention). The terminal's own SIGINT and SIGQUIT reach the child
// directly (same process group); this process only has to survive them to
// reseal, so it catches and drops them. SIGTERM and SIGHUP are sent to this
// process alone, so they are passed on.
func forkAndWait(real string, args []string, env []string) (int, error) {
	c := exec.Command(real, args...) // #nosec G204 -- see execRealTool
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	c.Env = env
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigs)
	if err := c.Start(); err != nil {
		return 0, err
	}
	done := make(chan struct{})
	go func() {
		for {
			select {
			case s := <-sigs:
				if s == syscall.SIGTERM || s == syscall.SIGHUP {
					_ = c.Process.Signal(s)
				}
			case <-done:
				return
			}
		}
	}()
	err := c.Wait()
	close(done)
	return exitStatus(err)
}

func exitStatus(err error) (int, error) {
	if err == nil {
		return 0, nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return 128 + int(ws.Signal()), nil
		}
		return ee.ExitCode(), nil
	}
	return 1, err
}

// sweepGcloudRuns removes the run dirs of runs that died before cleaning up
// (D1). Best effort: a sweep failure must not stop this run.
func sweepGcloudRuns(base string) {
	_, _ = sealstore.Sweep(base, gcloudRunOwnerAlive)
}

// gcloudRunOwnerAlive reports whether the run that made a dir is still
// running: the same pid, forked at the same moment (a recycled pid is a
// different process).
func gcloudRunOwnerAlive(pid int, start int64) bool {
	got, ok := lineage.ProcessStartTime(int32(pid)) // #nosec G115 -- parsed from a dir name NewRunDir wrote from a real pid
	return ok && got == start
}
