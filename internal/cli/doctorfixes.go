// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// doctorFix is one command from a finding's Action, as data. The prose Action
// stays what a human reads; this is what a program runs. The menu bar app
// used to recover these by splitting on backticks and guessing "destructive"
// from a prefix, which is how an origin_gone row's `jit vault rm` became a
// one-click delete that broke two live profiles
// (design/doctor-repair.md, "The incident").
type doctorFix struct {
	// Command is the exact text between the backticks.
	Command string `json:"command"`
	// Argv is Command split into shell words, with a leading ~ expanded
	// (nothing runs it through a shell to do that). For a jit command it
	// omits the leading "jit", so it can be handed straight to whichever jit
	// binary the caller trusts.
	Argv []string `json:"argv"`
	// External marks a command that is not jit's (brew, sudo, a shell
	// append). Argv then starts with the program, and may hold shell syntax
	// such as a >> redirect: run it in a shell, or show it, never exec it.
	External bool `json:"external,omitempty"`
	// Destructive: running it deletes something or takes a protection away.
	// A command this table does not know is destructive (fail safe).
	Destructive bool `json:"destructive"`
	// Presence: the command asks for a fresh Touch ID or passcode itself,
	// whatever the service session's state.
	Presence bool `json:"presence"`
	// Needs is the placeholder the caller must fill before running it
	// (<file>, <path>, <op://...>), exactly as it appears in Argv. Empty
	// when the command is complete.
	Needs string `json:"needs,omitempty"`
}

// fixClass is what running a command does, per the table below.
type fixClass struct {
	destructive bool
	presence    bool
}

// jitFixClasses classifies every jit command doctor's actions name, keyed by
// cobra command path without the leading "jit" (plus " --prune" where that
// flag turns a listing into a delete). Presence was read from the code, not
// assumed: requireUserPresence (vault rm, orphans/duplicates --prune),
// requireFreshUserPresence (migrate undo/remove, a live unmount), the
// keychain-direct openVaultFreshAuth (vault set/export/import/link) and the
// rekey's own RequireUserPresence.
//
// A command missing here classifies as destructive: an action gaining a new
// command must be classified on purpose before a client may run it freely.
var jitFixClasses = map[string]fixClass{
	"vault set":                {presence: true},
	"vault history":            {},
	"vault list":               {},
	"vault orphans":            {},
	"vault orphans --prune":    {destructive: true, presence: true},
	"vault duplicates":         {},
	"vault duplicates --prune": {destructive: true, presence: true},
	"vault rm":                 {destructive: true, presence: true},
	"vault rekey":              {presence: true},
	"vault export":             {presence: true},
	// Overwrites any secret the file also holds.
	"vault import": {destructive: true, presence: true},
	"vault link":   {presence: true},
	"migrate":      {},
	// Puts the original file back, plaintext and all.
	"migrate undo": {destructive: true, presence: true},
	// Deletes one pointer file jit wrote that nothing uses, and refuses
	// anything else. No secret is read or removed, so no Touch ID.
	"migrate forget": {destructive: true},
	"migrate remove": {destructive: true, presence: true},
	// Rewrites profile records (owner lists) only: no secret is read or
	// deleted. It widens what a later migrate remove of that config takes,
	// which the command says before its own y/N.
	"profile attach": {},
	// Writes one manifest of names, refusing to replace an existing one
	// without --force. Reads the vault's names only, so no Touch ID.
	"profile create": {},
	// Deletes the profile and every secret nothing else uses; Touch ID
	// whenever a secret goes.
	"profile rm": {destructive: true, presence: true},
	// A live mount: unmount writes the secret values back to disk in
	// plaintext. A stale one (its profile is gone) is reclassified in
	// classifyFix: it only clears a registry entry.
	"unmount":         {destructive: true, presence: true},
	"service restart": {},
	"service log":     {},
}

// externalFixClasses is the same table for the commands that are not jit's,
// keyed by their first two words (or the first alone).
var externalFixClasses = map[string]fixClass{
	"brew install":   {},
	"brew reinstall": {},
	"brew uninstall": {destructive: true},
	"sudo rm":        {destructive: true},
	"chmod":          {},
	"echo":           {}, // appends a line to a shell rc
	// An SSO login through the capture wrap: it deletes nothing, and it
	// asks for the IdP password and MFA itself, then stores the minted
	// session in the vault. Needs a terminal for those prompts.
	"clisso get": {presence: true},
}

// fixPlaceholder matches an argument the caller has to supply: <file>,
// <path>, <op://...>. Not "<(", which is shell process substitution.
var fixPlaceholder = regexp.MustCompile(`<[A-Za-z][^<>\s]*>`)

// withFixes fills Fixes on every finding that has none, from its Action.
// Applied to JSON output only: the text report shows the prose.
func withFixes(findings []checkFinding) []checkFinding {
	for i := range findings {
		if findings[i].Fixes == nil {
			findings[i].Fixes = fixesFor(findings[i].Kind, findings[i].Action)
		}
	}
	return findings
}

// fixesFor turns each backticked span in action into a doctorFix, in order.
func fixesFor(kind checkKind, action string) []doctorFix {
	var fixes []doctorFix
	for _, cmd := range backtickSpans(action) {
		words := shellWords(cmd)
		if len(words) == 0 {
			continue
		}
		fix := doctorFix{Command: cmd}
		if words[0] == "jit" {
			words = words[1:]
		} else {
			fix.External = true
		}
		fix.Argv = expandTildes(words)
		if m := fixPlaceholder.FindString(cmd); m != "" {
			fix.Needs = m
		}
		c := classifyFix(kind, words, fix.External)
		fix.Destructive, fix.Presence = c.destructive, c.presence
		fixes = append(fixes, fix)
	}
	return fixes
}

// classifyFix looks a command up in the tables above. words is the
// command's argv without any leading "jit".
func classifyFix(kind checkKind, words []string, external bool) fixClass {
	unknown := fixClass{destructive: true}
	if len(words) == 0 {
		return unknown
	}
	if external {
		if len(words) > 1 {
			if c, ok := externalFixClasses[words[0]+" "+words[1]]; ok {
				return c
			}
		}
		if c, ok := externalFixClasses[words[0]]; ok {
			return c
		}
		return unknown
	}
	key, ok := jitCommandPath(words)
	if !ok {
		return unknown
	}
	for _, w := range words {
		if w == "--prune" {
			key += " --prune"
			break
		}
	}
	if key == "unmount" && kind == kindMountStale {
		// The mount's profile is gone, so there is nothing to write back:
		// unmount only clears the registration, with no auth (unmount.go).
		return fixClass{}
	}
	c, ok := jitFixClasses[key]
	if !ok {
		return unknown
	}
	return c
}

// jitCommandPath resolves argv to the jit command it runs, through the real
// command tree rather than a guess about which words are subcommands: to
// cobra, "migrate ~/x/.mcp.json" is `migrate` with an argument, while
// "migrate remove x" is `migrate remove`.
func jitCommandPath(words []string) (string, bool) {
	cmd, _, err := rootCmd.Find(words)
	if err != nil || cmd == nil || cmd == rootCmd {
		return "", false
	}
	path := strings.TrimPrefix(cmd.CommandPath(), rootCmd.Name()+" ")
	return path, path != ""
}

// backtickSpans returns the `backtick`-delimited spans of s, the same
// delimiting hlCmds renders in cyan.
func backtickSpans(s string) []string {
	var spans []string
	for {
		i := strings.IndexByte(s, '`')
		if i < 0 {
			return spans
		}
		j := strings.IndexByte(s[i+1:], '`')
		if j < 0 {
			return spans
		}
		if span := strings.TrimSpace(s[i+1 : i+1+j]); span != "" {
			spans = append(spans, span)
		}
		s = s[i+1+j+1:]
	}
}

// shellWords splits a command into words the way a POSIX shell would for
// the simple commands doctor prints: whitespace-separated, with single and
// double quotes grouping (and removed). No escapes, globbing or expansion.
func shellWords(s string) []string {
	var words []string
	var cur strings.Builder
	inWord := false
	var quote rune
	for _, r := range s {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
		case r == '\'' || r == '"':
			quote = r
			inWord = true
		case r == ' ' || r == '\t' || r == '\n':
			if inWord {
				words = append(words, cur.String())
				cur.Reset()
				inWord = false
			}
		default:
			cur.WriteRune(r)
			inWord = true
		}
	}
	if inWord {
		words = append(words, cur.String())
	}
	return words
}

// expandTildes expands a leading "~" or "~/" in each word: argv is run
// without a shell, and doctor shortens paths to ~ for the reader.
func expandTildes(words []string) []string {
	home, err := os.UserHomeDir()
	out := make([]string, len(words))
	for i, w := range words {
		switch {
		case err != nil:
			out[i] = w
		case w == "~":
			out[i] = home
		case strings.HasPrefix(w, "~/"):
			out[i] = filepath.Join(home, w[2:])
		default:
			out[i] = w
		}
	}
	return out
}
