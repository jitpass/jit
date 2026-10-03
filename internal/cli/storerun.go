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
	"slices"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/lineage"
	"github.com/jitpass/jit/internal/migrate"
	"github.com/jitpass/jit/internal/sealstore"
	"github.com/jitpass/jit/internal/vault"
	"github.com/jitpass/jit/internal/wrap"
)

// The run half of a store-wrap (design/gcloud-sealed-store.md,
// design/azure-sealed-store.md). A store family's shims exec `jit
// <store>-run`; it unseals the tool's login store from the vault into a
// private dir, runs the real tool there through the tool's own config-dir
// variable, and seals the store again if the run changed it. It forks and
// waits, like clisso-capture, because the cleanup has to happen after the
// tool exits — the one thing an exec'ing shim cannot do (D1).

// runStoreRunCommand is a store run command's body: the run, then the
// tool's own exit status.
func runStoreRunCommand(cmd *cobra.Command, s migrate.ToolStore, real string, args []string) error {
	if real == "" {
		return fmt.Errorf("jit %s-run: --real is required (the shim supplies it)", s.Name)
	}
	code, err := runStoreRun(cmd, s, real, args)
	if err != nil {
		return err
	}
	if code != 0 {
		// The tool's own status, passed through. Its run is recorded
		// already (recordRunInvocation), and the cleanup is done.
		os.Exit(code)
	}
	return nil
}

// storeRunBase is where a store's run dirs live: inside jit's own root,
// never $TMPDIR (D6, newJobScratch's reasoning).
func storeRunBase(root string, s migrate.ToolStore) string {
	return filepath.Join(root, s.Name+"-run")
}

// runStoreRun returns the tool's exit status. A path that hands over to
// the tool with exec never returns on success; its error is the exec's.
func runStoreRun(cmd *cobra.Command, s migrate.ToolStore, real string, args []string) (int, error) {
	stderr := cmd.ErrOrStderr()
	tool := filepath.Base(real)
	fail := func(err error) (int, error) { return 0, fmt.Errorf("jit %s-run: %w", s.Name, err) }
	home, err := os.UserHomeDir()
	if err != nil {
		return fail(err)
	}
	root, err := vaultRootDir()
	if err != nil {
		return fail(err)
	}
	base := storeRunBase(root, s)
	dir := s.ConfigDir(home)

	if cfg := os.Getenv(s.ConfigEnv); cfg != "" {
		// Already inside a run: a gcloud the GKE auth plugin started, a
		// helper the tool spawned. The outer run's store is unsealed and
		// serving; a second unseal would be a second prompt for nothing.
		if inRunDir(base, cfg) {
			return 0, execRealTool(s, real, args, tool)
		}
		// The user's own config dir elsewhere. Only the default is sealed
		// (D7), so the tool runs as it would without jit — and says so.
		if filepath.Clean(cfg) != filepath.Clean(dir) {
			fmt.Fprintf(stderr, "jit: %s is %s, not %s; %s runs without jit\n", s.ConfigEnv, displayPath(home, cfg), displayPath(home, dir), tool)
			return 0, execRealTool(s, real, args, tool)
		}
	}

	// Application-default credentials are not gcloud's store: they are the
	// gcp mount, and `gcloud auth application-default …` is the only
	// gcloud command that reads them. It keeps the old grant-wrap
	// behaviour (D9).
	if s.Name == migrate.GcloudStore.Name && tool == "gcloud" && isADCCommand(args) {
		return 0, execADCGrant(real, args, tool)
	}

	secrets, ephemeral, err := splitPlaintext(s, dir)
	if err != nil {
		return fail(err)
	}
	if len(secrets) > 0 {
		// Something logged in without the shim (an IDE calling the tool by
		// absolute path). Use what is there rather than swap in an older
		// vaulted login behind the user's back (D7), and say how to fix it.
		fmt.Fprintln(stderr, hlCmds("jit: "+s.Label+" is in plaintext in "+displayPath(home, dir)+"; `jit wrap "+s.Name+"` seals it"))
		return 0, execRealTool(s, real, args, tool)
	}
	for _, name := range ephemeral {
		// An access-token cache a passthrough run left behind: an hour-long
		// bearer token in plaintext, and the tool rebuilds it (D3).
		_ = os.RemoveAll(filepath.Join(dir, name))
	}

	v, err := openVault()
	if err != nil {
		return fail(err)
	}
	// The consent prompt happens here: one unwrap of the store's class.
	blob, dek, err := s.ReadSealed(v)
	if err != nil {
		return 0, fmt.Errorf("jit: %s stays sealed: %w", s.Label, err)
	}

	sweepStoreRuns(base)
	start, _ := lineage.ProcessStartTime(int32(os.Getpid())) // #nosec G115 -- a pid always fits in int32 on darwin
	runDir, err := sealstore.NewRunDir(base, os.Getpid(), start)
	if err != nil {
		return fail(err)
	}
	baseline, err := materializeStore(s, blob, dir, runDir)
	if err != nil {
		_ = os.RemoveAll(runDir)
		return fail(err)
	}

	// os.Exit below skips Execute's own audit hook, as syscall.Exec does for
	// `jit run`.
	recordRunInvocation(cmd)
	code, runErr := forkAndWait(real, args, storeChildEnv(s, os.Environ(), tool, runDir))

	resealStoreRun(stderr, s, toolStoreVault{v, s}, home, dir, runDir, baseline, dek)
	if _, err := s.Layout.Adopt(runDir, dir); err != nil {
		fmt.Fprintf(stderr, "jit: %s settings not carried back to %s: %v\n", tool, dir, err)
	}
	_ = os.RemoveAll(runDir)

	if runErr != nil {
		return 0, fmt.Errorf("jit %s-run: starting %s: %w", s.Name, real, runErr)
	}
	return code, nil
}

// materializeStore fills runDir with the unsealed store and links to the
// settings, returning the store's packed bytes as they stand before the
// tool runs — the baseline the reseal compares against.
func materializeStore(s migrate.ToolStore, blob []byte, dir, runDir string) ([]byte, error) {
	if len(blob) > 0 {
		if err := s.Layout.Unpack(blob, runDir); err != nil {
			return nil, err
		}
	}
	if err := s.Layout.Link(dir, runDir); err != nil {
		return nil, err
	}
	return s.Layout.Pack(runDir)
}

// resealStoreRun vaults the store if the run changed it (D4). If the vault
// write fails — a Touch ID declined after a long login — the new login is
// moved into the config dir in plaintext rather than deleted with the run
// dir: losing a login the user just completed is worse than one plaintext
// file the next run will name.
//
// A store that Rotates changes on every refresh, so its reseal is silent
// unless a login came or went.
func resealStoreRun(stderr io.Writer, s migrate.ToolStore, v vaultSetter, home, dir, runDir string, baseline, dek []byte) {
	if _, err := os.Lstat(runDir); err != nil {
		// The run's folder is gone (swept under it): packing nothing would
		// read as a sign-out and seal an empty store over the login.
		fmt.Fprintf(stderr, "jit: %s run folder went missing; the vault keeps the login it had\n", s.Tool)
		return
	}
	after, err := s.Layout.Pack(runDir)
	if err != nil {
		fmt.Fprintf(stderr, "jit: could not read %s store after the run: %v\n", s.Label, err)
		rescueStore(stderr, s, dir, runDir)
		return
	}
	if bytes.Equal(after, baseline) {
		return
	}
	refresh := s.Rotates && sameAccounts(s, baseline, after)
	sealed, err := v.reseal(home, runDir, baseline, dek, after)
	switch {
	case errors.Is(err, migrate.ErrResealBackup):
		fmt.Fprintf(stderr, "jit: sealed %s; %v\n", s.Label, err)
	case err != nil && refresh:
		// Only a refreshed token was lost (a Touch ID declined after the
		// screen locked mid-run): the vault still holds the login, and
		// writing a 90-day refresh token to disk to save an hourly one is
		// the wrong trade. The next run refreshes again.
		fmt.Fprintf(stderr, "jit: the refreshed %s was not sealed (%v); the vault keeps the previous one\n", s.Label, err)
		return
	case err != nil:
		fmt.Fprintf(stderr, "jit: could not seal %s: %v\n", s.Label, err)
		rescueStore(stderr, s, dir, runDir)
		return
	}
	switch {
	case sealstore.Empty(sealed):
		fmt.Fprintf(stderr, "jit: %s is signed out; the vault holds no %s login now\n", s.Tool, s.Tool)
	case refresh:
		// A refresh: routine, and said nothing about before jit either.
	default:
		fmt.Fprintf(stderr, "jit: sealed %s into the vault; nothing was left in plaintext\n", s.Label)
	}
}

// sameAccounts reports whether two stores are signed in to the same
// accounts: a refresh rewrites tokens, a login or sign-out adds or drops
// an account. An empty store is no account at all.
func sameAccounts(s migrate.ToolStore, a, b []byte) bool {
	if sealstore.Empty(a) || sealstore.Empty(b) || s.Accounts == nil {
		return false
	}
	return slices.Equal(s.Accounts(a), s.Accounts(b))
}

// vaultSetter is the one vault operation resealStoreRun needs, so a test
// can make it fail. It returns the store as sealed (merged, for a store
// that merges).
type vaultSetter interface {
	reseal(home, runDir string, base, dek, after []byte) ([]byte, error)
}

// toolStoreVault is the real vaultSetter.
type toolStoreVault struct {
	v *vault.Vault
	s migrate.ToolStore
}

func (t toolStoreVault) reseal(home, runDir string, base, dek, after []byte) ([]byte, error) {
	return t.s.Reseal(t.v, home, runDir, base, dek, after)
}

// rescueStore moves the run's secrets into the config dir.
func rescueStore(stderr io.Writer, s migrate.ToolStore, dir, runDir string) {
	for _, name := range s.Layout.Secrets {
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
	home, _ := os.UserHomeDir()
	fmt.Fprintln(stderr, hlCmds("jit: "+s.Label+" is in plaintext in "+displayPath(home, dir)+" for now; `jit wrap "+s.Name+"` seals it"))
}

// splitPlaintext reports which of the store's secret and ephemeral entries
// sit in dir in plaintext.
func splitPlaintext(s migrate.ToolStore, dir string) (secrets, ephemeral []string, err error) {
	found, err := s.Layout.Plaintext(dir)
	if err != nil {
		return nil, nil, err
	}
	for _, name := range found {
		if isOneOf(name, s.Layout.Secrets) {
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

// storeChildEnv is the tool's environment: the caller's, pointed at the
// run dir, without the shim's recursion guard for this tool (a tool the
// run itself starts is a nested call, not a loop; see wrap.GuardVar).
func storeChildEnv(s migrate.ToolStore, environ []string, tool, runDir string) []string {
	guard := wrap.GuardVar(tool) + "="
	out := make([]string, 0, len(environ)+1)
	for _, kv := range environ {
		if strings.HasPrefix(kv, guard) || strings.HasPrefix(kv, s.ConfigEnv+"=") {
			continue
		}
		out = append(out, kv)
	}
	if runDir != "" {
		out = append(out, s.ConfigEnv+"="+runDir)
		for _, kv := range s.RunEnv {
			name, _, _ := strings.Cut(kv, "=")
			if !slices.ContainsFunc(environ, func(e string) bool { return strings.HasPrefix(e, name+"=") }) {
				out = append(out, kv)
			}
		}
	}
	return out
}

// execRealTool replaces this process with the real tool, unchanged apart
// from the recursion guard. Returns only on failure.
func execRealTool(s migrate.ToolStore, real string, args []string, tool string) error {
	argv := append([]string{real}, args...)
	return syscall.Exec(real, argv, storeChildEnv(s, os.Environ(), tool, os.Getenv(s.ConfigEnv))) // #nosec G204 -- real comes from the shim's own PATH resolution, args are the user's command line
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

// sweepStoreRuns removes the run dirs of runs that died before cleaning up
// (D1). Best effort: a sweep failure must not stop this run.
func sweepStoreRuns(base string) {
	_, _ = sealstore.Sweep(base, runOwnerAlive)
}

// runOwnerAlive reports whether the run that made a dir is still running:
// the same pid, forked at the same moment (a recycled pid is a different
// process).
func runOwnerAlive(pid int, start int64) bool {
	got, ok := lineage.ProcessStartTime(int32(pid)) // #nosec G115 -- parsed from a dir name NewRunDir wrote from a real pid
	return ok && got == start
}
