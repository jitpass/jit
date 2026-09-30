// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package wrap

import (
	"bufio"
	"os"
	"regexp"
	"strings"
)

// Account commands under an env-wrap. The shim injects one vaulted token
// into every call, and nearly every CLI ranks an environment token above
// its own stored logins, so the tool's own account commands stop meaning
// what they say: logins refuse ("unset the variable to log in") or
// succeed and change nothing, logouts revoke the injected token server-side
// (vercel) or report success while the variable keeps working, switches
// warn that the active context "will have no effect", and a --profile
// flag sends the default account's token to another account's host. An
// AccountRule tells the shim which of the tool's commands are account
// commands and how jit answers each; Match picks the rule for a command
// line. Anything unmatched takes the normal wrapped path, so a rule missing
// here costs the old behavior, never a credential-less run of real work.

// AccountAction is how jit answers one account command.
type AccountAction string

const (
	// AccountLogin: the command stores a fresh login. It runs with no
	// token injected (the only way the tool will log in), then jit copies
	// the token it saved into the vault and scrubs the plaintext — the
	// same discovery `jit wrap <tool>` runs.
	AccountLogin AccountAction = "login"
	// AccountLoginExpiring: the command can store a login that expires —
	// an OAuth access token the tool refreshes itself (vercel, railway,
	// wrangler), a leased token (vault), a browser-flow token (hf). It runs
	// with no token injected, like AccountLogin, but nothing is moved into
	// the vault, where it would be frozen until it expired. jit says the
	// wrap keeps its token, and how to store a durable one (Hint).
	AccountLoginExpiring AccountAction = "login-expiring"
	// AccountLogout: the command forgets a login. It runs with no token
	// injected, so it can only ever act on the tool's own stored copy —
	// never revoke or delete the vaulted token — and jit then says the
	// vault's copy is still in use.
	AccountLogout AccountAction = "logout"
	// AccountSwitch: the command picks another stored account or context,
	// which a wrap with one injected token can't honor. jit says so and
	// how to change the account instead, and doesn't run it.
	AccountSwitch AccountAction = "switch"
	// AccountProfile: a flag naming another of the tool's saved profiles.
	// The wrapped token belongs to the default profile, so the call runs
	// with the tool's own saved credentials for that profile instead of
	// sending the wrapped token to another account's host.
	AccountProfile AccountAction = "profile"
)

// AccountRule is one account command: the subcommand words that name it
// (matched against the command line's leading non-flag words) and how jit
// answers it. Hint is the tool-specific way to do what a refused switch
// asked for, when there is one.
type AccountRule struct {
	Command []string
	Action  AccountAction
	Hint    string
}

// AccountMatch is the rule a command line hit.
type AccountMatch struct {
	Rule AccountRule
	// Profile is the profile a ProfileFlags flag named (AccountProfile).
	Profile string
	// Flag is that flag as typed, for the message.
	Flag string
}

// MatchAccount finds the account rule for a wrapped tool's command line.
// Order matters and is deliberate: a refused switch first (it must never
// run); then a profile flag naming a non-default profile (a login or
// logout for another profile is that profile's business, and the wrap's
// token must not be re-vaulted from it); then a login or logout. --help or
// -h anywhere asks for help text, never an account change, and matches
// nothing (gh, where -h is --hostname, has its own parser). home locates
// the tool's config for entries that learn their default profile from it.
func (e CatalogEntry) MatchAccount(home string, args []string) (AccountMatch, bool) {
	if e.Kind != KindShim || (len(e.Accounts) == 0 && len(e.ProfileFlags) == 0) {
		return AccountMatch{}, false
	}
	for _, a := range args {
		if a == "--help" || a == "-h" {
			return AccountMatch{}, false
		}
		if a == "--" {
			break
		}
	}
	words, profile, flag := e.scanArgs(args)

	var hit *AccountRule
	for i := range e.Accounts {
		r := &e.Accounts[i]
		if hasPrefix(words, r.Command) && (hit == nil || len(r.Command) > len(hit.Command)) {
			hit = r
		}
	}
	if hit != nil && hit.Action == AccountSwitch {
		return AccountMatch{Rule: *hit}, true
	}
	if flag != "" && profile != e.defaultProfile(home) {
		return AccountMatch{Rule: AccountRule{Action: AccountProfile}, Profile: profile, Flag: flag}, true
	}
	if hit != nil {
		return AccountMatch{Rule: *hit}, true
	}
	return AccountMatch{}, false
}

// scanArgs splits a command line into its leading subcommand words (every
// non-flag argument, in order, up to "--") and the value of the last
// ProfileFlags flag. A flag's own value is never taken for a subcommand
// word when the flag is a profile flag; other flags' values can be, which
// only ever makes a rule miss (the safe direction: a miss is the normal
// wrapped path) — a rule's words have to match from the first one.
func (e CatalogEntry) scanArgs(args []string) (words []string, profile, flag string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			break
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			words = append(words, a)
			continue
		}
		name, value, hasValue := strings.Cut(a, "=")
		if !contains(e.ProfileFlags, name) {
			continue
		}
		if !hasValue {
			if i+1 >= len(args) {
				continue // the tool reports the missing value itself
			}
			i++
			value = args[i]
		}
		profile, flag = value, name
	}
	return words, profile, flag
}

// defaultProfile is the profile the wrapped token belongs to: fixed for
// tools with a named default, read from the tool's config for tools whose
// wrap vaulted the FIRST profile there (hcloud's first context, snow's
// first connection). "" when it can't be told, which makes every named
// profile another one — the safe direction, since the wrapped token then
// never goes to a profile it may not belong to.
func (e CatalogEntry) defaultProfile(home string) string {
	if e.DefaultProfileFrom != nil {
		return firstProfileName(ExpandHome(home, e.DefaultProfileFrom.Path), e.DefaultProfileFrom.pattern)
	}
	return e.DefaultProfile
}

// ProfileNameSource finds a tool's first profile name in its config: the
// first line of Path matching Pattern, whose first group is the name.
type ProfileNameSource struct {
	Path    string // "~"-rooted
	pattern *regexp.Regexp
}

func firstProfileName(path string, pattern *regexp.Regexp) string {
	f, err := os.Open(path) // #nosec G304 -- a fixed catalog path under the user's home dir
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if m := pattern.FindStringSubmatch(sc.Text()); m != nil {
			return m[1]
		}
	}
	return ""
}

// TokenVars are the environment variables a wrap injects for this tool:
// what an account command runs without.
func (e CatalogEntry) TokenVars() []string { return append([]string{}, e.Order...) }

func hasPrefix(words, prefix []string) bool {
	if len(prefix) == 0 || len(words) < len(prefix) {
		return false
	}
	for i := range prefix {
		if words[i] != prefix[i] {
			return false
		}
	}
	return true
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
