// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"slices"
	"strings"
	"syscall"

	"github.com/jitpass/jit/internal/migrate"
	"github.com/jitpass/jit/internal/profile"
	"github.com/jitpass/jit/internal/vault"
	"github.com/jitpass/jit/internal/wrap"
)

// A wrapped tool's account commands (internal/wrap/accounts.go says why
// they need answering at all, catalog_accounts.go which commands they are).
// The shim asks AccountShim before injecting anything; a command it
// doesn't handle takes the normal wrapped path.

// accountWrap is the env-wrap an account command acts on.
type accountWrap struct {
	home      string
	entry     wrap.CatalogEntry
	realTool  string
	vaultPath string // what the wrap-<tool> profile injects the token from
	tokenVars []string
	// execFn replaces the process with the unwrapped tool; a field so a
	// test can observe the call instead of being replaced by it.
	execFn func(args []string) error
}

// AccountShim answers a wrapped tool's account command. handled=false
// leaves the command to the normal wrapped path; handled=true means it ran
// here (or was refused) and code is the exit status.
func AccountShim(tool string, args []string) (handled bool, code int) {
	if tool == "gh" {
		return GhAuthShim(args)
	}
	entry, ok := wrap.Lookup(tool)
	if !ok {
		return false, 0
	}
	m, ok := entry.MatchAccount(args)
	if !ok {
		return false, 0
	}
	w, ok := loadAccountWrap(entry)
	if !ok {
		return false, 0
	}
	return true, w.answer(os.Stderr, m, args, openVault, openVaultReadOnly)
}

// loadAccountWrap finds tool's env-wrap; ok=false when the tool isn't
// env-wrapped (a grant- or capture-wrap has no injected token to get in
// the way) or its profile doesn't carry the catalog's variable.
func loadAccountWrap(entry wrap.CatalogEntry) (*accountWrap, bool) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, false
	}
	manifest, err := wrap.LoadManifest(home)
	if err != nil || manifest.Tools[entry.Tool].Profile == "" {
		return nil, false
	}
	path, err := profile.Path(home, manifest.Tools[entry.Tool].Profile)
	if err != nil {
		return nil, false
	}
	p, err := profile.LoadFile(path)
	if err != nil || p[entry.PrimaryVar()] == "" {
		return nil, false
	}
	realTool, err := wrap.RealTool(home, entry.Tool)
	if err != nil {
		return nil, false
	}
	vars := entry.TokenVars()
	for name := range p {
		if !slices.Contains(vars, name) {
			vars = append(vars, name)
		}
	}
	return &accountWrap{home: home, entry: entry, realTool: realTool, vaultPath: p[entry.PrimaryVar()], tokenVars: vars}, true
}

func (w *accountWrap) answer(out io.Writer, m wrap.AccountMatch, args []string, open, openRO func() (*vault.Vault, error)) int {
	tool := w.entry.Tool
	switch m.Rule.Action {
	case wrap.AccountSwitch:
		cmd := tool + " " + strings.Join(m.Rule.Command, " ")
		msg := fmt.Sprintf("`%s` can't change the account: %s is wrapped with one token.", cmd, tool)
		if m.Rule.Hint != "" {
			msg += " " + upperFirst(m.Rule.Hint) + "."
		}
		msg += fmt.Sprintf(" `jit vault set %s` swaps in another account's token.", w.vaultPath)
		wrapBody(out, 0, "", hlCmds(msg))
		return 1

	case wrap.AccountProfile:
		wrapBody(out, 0, "", hlCmds(fmt.Sprintf("jit: `%s %s` uses %s's own saved login for that profile, not the wrapped token.",
			m.Flag, m.Profile, tool)))
		exec := w.execUnwrapped
		if w.execFn != nil {
			exec = w.execFn
		}
		err := exec(args)
		fmt.Fprintf(os.Stderr, "jit shim %s: %v\n", tool, err)
		return 127

	case wrap.AccountLogout:
		code := w.runUnwrapped(args)
		if w.vaulted(openRO) {
			wrapBody(out, 0, "", hlCmds(fmt.Sprintf("%s still uses the token in the vault. `jit vault rm %s` deletes it; "+
				"`jit wrap undo %s` stops the wrap.", tool, w.vaultPath, tool)))
		}
		return code

	case wrap.AccountLogin:
		if code := w.runUnwrapped(args); code != 0 {
			return code
		}
		if err := w.revault(out, open); err != nil {
			fmt.Fprintln(os.Stderr, FormatError(fmt.Errorf("jit: %w", err)))
			return 1
		}
		return 0
	}
	return 1
}

// revault moves the token a login just saved into the vault, where the
// wrap reads it, and scrubs the plaintext copy — `jit wrap <tool>`'s
// discovery, run again.
func (w *accountWrap) revault(out io.Writer, open func() (*vault.Vault, error)) error {
	discovery, found, err := wrap.DiscoverToken(w.home, w.entry)
	if err != nil {
		return err
	}
	if !found || discovery.Source == nil {
		wrapBody(out, 0, "", hlCmds(fmt.Sprintf("jit: %s saved no token jit can pick up, so the wrap still uses the one in the vault. "+
			"`jit vault set %s` replaces it.", w.entry.Tool, w.vaultPath)))
		return nil
	}
	v, err := open()
	if err != nil {
		return err
	}
	gid, err := vault.NewGroupID()
	if err != nil {
		return err
	}
	if err := v.SetWithMeta(w.vaultPath, []byte(discovery.Value), vault.Meta{Class: vault.ClassWrap, GroupID: gid, Origin: discovery.Source.Path}); err != nil {
		return fmt.Errorf("storing %s: %w", w.vaultPath, err)
	}
	srcPath := wrap.ExpandHome(w.home, discovery.Source.Path)
	if _, err := migrate.BackupSecretFile(v, srcPath); err != nil {
		return fmt.Errorf("backing up %s: %w", srcPath, err)
	}
	if err := wrap.ScrubToken(w.home, *discovery.Source, discovery.Value); err != nil {
		return err
	}
	wrapBody(out, 0, "", fmt.Sprintf("jit: moved the new token into the vault and removed it from %s. %s uses it from now on.",
		discovery.Source.Path, w.entry.Tool))
	return nil
}

// vaulted reports whether the wrap's token is still in the vault: a stat,
// no unlock.
func (w *accountWrap) vaulted(openRO func() (*vault.Vault, error)) bool {
	ro, err := openRO()
	if err != nil {
		return false
	}
	ok, err := ro.Exists(w.vaultPath)
	return err == nil && ok
}

// env is this process's environment minus every variable the wrap
// injects: with one of them set, the tool's account commands act on it
// (refuse, keep using it, or revoke it) instead of on the tool's own login.
func (w *accountWrap) env() []string {
	return slices.DeleteFunc(os.Environ(), func(kv string) bool {
		name, _, _ := strings.Cut(kv, "=")
		return slices.Contains(w.tokenVars, name)
	})
}

// runUnwrapped runs the real tool on the user's command line with no token
// injected, terminal and all, and returns its exit status.
func (w *accountWrap) runUnwrapped(args []string) int {
	c := exec.Command(w.realTool, args...) // #nosec G204 -- realTool is the user's own tool from PATH; args are the user's command line
	c.Env = w.env()
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := c.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode()
		}
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

// execUnwrapped replaces this process with the real tool, no token
// injected. Returns only on failure.
func (w *accountWrap) execUnwrapped(args []string) error {
	return syscall.Exec(w.realTool, append([]string{w.entry.Tool}, args...), w.env()) // #nosec G204 -- same provenance as runUnwrapped
}

func upperFirst(s string) string {
	if s == "" {
		return s
	}
	if s[0] == '`' {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
