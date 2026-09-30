// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"slices"
	"strings"

	"github.com/jitpass/jit/internal/profile"
	"github.com/jitpass/jit/internal/vault"
	"github.com/jitpass/jit/internal/wrap"
)

// gh's account commands under an env-wrap (the why is in
// internal/wrap/ghauth.go). The wrap decides the account, so jit answers
// them against the wrap instead of letting gh refuse:
//
//   - switch points the wrap-gh profile at that account's vault secret,
//     wrap-gh/accounts/<login>. An account gh is signed in to but the vault
//     doesn't hold yet is copied in first, from gh's own keyring — the same
//     export `jit wrap gh` uses. Moving between accounts the vault already
//     holds opens nothing and asks for nothing: it changes which secret the
//     next gh call asks for, and that call raises the prompt as usual.
//   - login and refresh run the real gh with no token injected (the only
//     way either can run), then copy the resulting token into the vault and
//     use it, since gh itself makes a fresh login the active account.
//   - logout runs the real gh, then says so when the wrap still serves the
//     account from the vault: gh can only forget its keyring copy.
//
// Everything else — and these commands for an enterprise host, or a gh
// wrapped some other way — takes the normal wrapped path.

// ghTokenVars are the variables gh reads a github.com token from, in gh's
// own precedence order. A catalog wrap injects GH_TOKEN; a hand-made
// `jit wrap add gh --env GITHUB_TOKEN=…` works the same way.
var ghTokenVars = []string{"GH_TOKEN", "GITHUB_TOKEN"}

// ghWrap is the env-wrap an account command acts on.
type ghWrap struct {
	home        string
	realGh      string
	profilePath string
	profile     profile.Profile
	order       []string
	tokenVar    string
}

// current is the account the wrap serves, or "" when its vault path names
// none (the single wrap-gh/GH_TOKEN `jit wrap gh` writes).
func (w *ghWrap) current() string { return wrap.GhAccountFromVaultPath(w.profile[w.tokenVar]) }

// GhAuthShim answers a wrapped `gh auth switch|login|logout|refresh`. It
// reports handled=false for anything it leaves to the normal wrapped path;
// handled=true means the command ran here and code is the exit status.
func GhAuthShim(args []string) (handled bool, code int) {
	cmd, ok := wrap.ParseGhAuth(args)
	if !ok || cmd.OtherHost() {
		return false, 0
	}
	w, ok := loadGhWrap()
	if !ok {
		return false, 0
	}
	var err error
	switch cmd.Sub {
	case "switch":
		err = ghSwitch(os.Stderr, w, cmd.User, openVaultReadOnly, openVault)
	case "login", "refresh":
		code, err = ghLoginOrRefresh(os.Stderr, w, cmd.Sub, args)
	case "logout":
		code, err = ghLogout(os.Stderr, w, cmd.User, args)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, FormatError(fmt.Errorf("gh auth %s: %w", cmd.Sub, err)))
		if code == 0 {
			code = 1
		}
	}
	return true, code
}

// loadGhWrap finds gh's env-wrap; ok=false when gh isn't env-wrapped, or its
// profile carries no github.com token variable, so nothing here applies.
func loadGhWrap() (*ghWrap, bool) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, false
	}
	manifest, err := wrap.LoadManifest(home)
	if err != nil || manifest.Tools["gh"].Profile == "" {
		return nil, false
	}
	path, err := profile.Path(home, manifest.Tools["gh"].Profile)
	if err != nil {
		return nil, false
	}
	p, order, err := profile.LoadFileOrdered(path)
	if err != nil {
		return nil, false
	}
	w := &ghWrap{home: home, profilePath: path, profile: p, order: order}
	for _, v := range ghTokenVars {
		if _, ok := p[v]; ok {
			w.tokenVar = v
			break
		}
	}
	if w.tokenVar == "" {
		return nil, false
	}
	if w.realGh, err = wrap.RealTool(home, "gh"); err != nil {
		return nil, false
	}
	return w, true
}

// ghSwitch points the wrap at login, or with login "" at the one other
// account there is.
func ghSwitch(out io.Writer, w *ghWrap, login string, openRO, open func() (*vault.Vault, error)) error {
	keyring, active, err := wrap.GhKeyringAccounts(w.home)
	if err != nil {
		return err
	}
	ro, err := openRO()
	if err != nil {
		return err
	}
	paths, err := ro.List()
	if err != nil {
		return err
	}
	vaulted := wrap.GhAccountsInVault(paths)
	current := w.current()

	if login == "" {
		known := slices.Compact(slices.Sorted(slices.Values(append(slices.Clone(vaulted), keyring...))))
		if login, err = wrap.PickGhSwitchTarget(known, current); err != nil {
			return err
		}
	}
	if !wrap.ValidGhLogin(login) {
		return fmt.Errorf("%q isn't a GitHub username", login)
	}
	if login == current {
		fmt.Fprintf(out, "gh already uses %s.\n", login)
		return nil
	}

	vaultPath := wrap.GhAccountVaultPath(login)
	copied := false
	if !slices.Contains(vaulted, login) {
		if !slices.Contains(keyring, login) {
			return fmt.Errorf("%s isn't signed in on this machine: `gh auth login`, then `gh auth switch --user %s`", login, login)
		}
		if err := ghCopyToVault(w, login, open); err != nil {
			return err
		}
		copied = true
	}
	if err := w.pointAt(vaultPath); err != nil {
		return err
	}
	// Keep gh's own idea of the active account in step, so gh run outside
	// the shim (a script calling it by full path) agrees. Best-effort: the
	// wrap is what every normal gh call uses, and it has already moved.
	if slices.Contains(keyring, login) && login != active {
		_ = w.runGh(io.Discard, "auth", "switch", "--hostname", wrap.GhHost, "--user", login)
	}

	if copied {
		fmt.Fprintf(out, "Copied %s's token from gh's keyring into the vault.\n", login)
	}
	fmt.Fprintf(out, "gh now uses %s.\n", login)
	return nil
}

// ghLoginOrRefresh runs the real `gh auth login|refresh`, then vaults the
// token it produced and points the wrap at it.
func ghLoginOrRefresh(out io.Writer, w *ghWrap, sub string, args []string) (int, error) {
	// refresh works on gh's active keyring account; make that the account
	// the wrap uses, so the scopes land where the user's gh calls go.
	if sub == "refresh" {
		if current := w.current(); current != "" {
			keyring, active, err := wrap.GhKeyringAccounts(w.home)
			if err != nil {
				return 1, err
			}
			if !slices.Contains(keyring, current) {
				return 1, fmt.Errorf("%s isn't signed in to gh on this machine, `gh auth login` signs it in again", current)
			}
			if current != active {
				if err := w.runGh(io.Discard, "auth", "switch", "--hostname", wrap.GhHost, "--user", current); err != nil {
					return 1, err
				}
			}
		}
	}
	if code := w.passthrough(args); code != 0 {
		return code, nil
	}
	_, active, err := wrap.GhKeyringAccounts(w.home)
	if err != nil {
		return 1, err
	}
	if active == "" {
		return 0, nil // signed in somewhere gh doesn't record per account; nothing to follow
	}
	if err := ghCopyToVault(w, active, openVault); err != nil {
		return 1, err
	}
	if err := w.pointAt(wrap.GhAccountVaultPath(active)); err != nil {
		return 1, err
	}
	fmt.Fprintf(out, "Copied %s's token into the vault. gh now uses %s.\n", active, active)
	return 0, nil
}

// ghLogout runs the real `gh auth logout`. gh forgets its keyring copy;
// the vault's is jit's, and removing it is a separate, deliberate step.
func ghLogout(out io.Writer, w *ghWrap, login string, args []string) (int, error) {
	before, _, err := wrap.GhKeyringAccounts(w.home)
	if err != nil {
		return 1, err
	}
	// An account only the vault holds is one gh would answer "not logged
	// in" for, which reads as if it were already gone.
	if login != "" && !slices.Contains(before, login) && wrap.ValidGhLogin(login) {
		if ro, err := openVaultReadOnly(); err == nil {
			if ok, _ := ro.Exists(wrap.GhAccountVaultPath(login)); ok {
				wrapBody(out, 0, "", hlCmds(fmt.Sprintf("gh isn't signed in to %s, but the jit vault holds its token: "+
					"`jit vault rm %s` removes it.", login, wrap.GhAccountVaultPath(login))))
				return 1, nil
			}
		}
	}
	if code := w.passthrough(args); code != 0 {
		return code, nil
	}
	after, _, err := wrap.GhKeyringAccounts(w.home)
	if err != nil {
		return 0, nil // gh's logout succeeded; the note below is all this could add
	}
	if current := w.current(); current != "" && slices.Contains(before, current) && !slices.Contains(after, current) {
		wrapBody(out, 0, "", hlCmds(fmt.Sprintf("gh still uses %s, from the jit vault. `gh auth switch` picks another account; "+
			"`jit vault rm %s` removes the vault's copy.", current, wrap.GhAccountVaultPath(current))))
	}
	return 0, nil
}

// ghCopyToVault exports login's token from gh's keyring into the vault.
func ghCopyToVault(w *ghWrap, login string, open func() (*vault.Vault, error)) error {
	var token bytes.Buffer
	if err := w.runGh(&token, "auth", "token", "--hostname", wrap.GhHost, "--user", login); err != nil {
		return fmt.Errorf("reading %s's token from gh: %w", login, err)
	}
	value := strings.TrimSpace(token.String())
	if value == "" {
		return fmt.Errorf("gh has no token for %s", login)
	}
	v, err := open()
	if err != nil {
		return err
	}
	gid, err := vault.NewGroupID()
	if err != nil {
		return err
	}
	path := wrap.GhAccountVaultPath(login)
	if err := v.SetWithMeta(path, []byte(value), vault.Meta{Class: vault.ClassWrap, GroupID: gid}); err != nil {
		return fmt.Errorf("storing %s: %w", path, err)
	}
	return nil
}

// pointAt rewrites the wrap-gh profile so the token variable reads path.
func (w *ghWrap) pointAt(path string) error {
	w.profile[w.tokenVar] = path
	data, err := profile.MarshalOrdered(w.profile, w.order)
	if err != nil {
		return err
	}
	if err := vault.AtomicWriteFile(w.profilePath, data); err != nil {
		return fmt.Errorf("writing %s: %w", w.profilePath, err)
	}
	return nil
}

// ghEnv is the environment the real gh gets here: this process's own, minus
// every token variable. A token in the environment is exactly what stops
// gh's account commands, and under a wrap no gh call ever sees the user's
// own anyway — the profile's value replaces it.
func ghEnv() []string {
	env := os.Environ()
	return slices.DeleteFunc(env, func(kv string) bool {
		name, _, _ := strings.Cut(kv, "=")
		return slices.Contains(ghTokenVars, name)
	})
}

// runGh runs the real gh quietly: stdout to out, stderr kept for the error.
func (w *ghWrap) runGh(out io.Writer, args ...string) error {
	c := exec.Command(w.realGh, args...) // #nosec G204 -- realGh is the user's own gh from PATH; args are fixed subcommands plus a validated login
	c.Env = ghEnv()
	c.Stdout = out
	var stderr bytes.Buffer
	c.Stderr = &stderr
	if err := c.Run(); err != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return errors.New(msg)
		}
		return err
	}
	return nil
}

// passthrough runs the real gh on the user's own command line, terminal
// and all, and returns its exit status.
func (w *ghWrap) passthrough(args []string) int {
	c := exec.Command(w.realGh, args...) // #nosec G204 -- realGh is the user's own gh from PATH; args are the user's command line
	c.Env = ghEnv()
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
