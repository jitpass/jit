// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

// Package guard installs jit's prevention hooks: shell integration that
// keeps credentials from being RECORDED, where scan/migrate deal with ones
// that already were. The first (and so far only) guard is the zsh history
// guard, a zshaddhistory hook that stops a credential-carrying command from
// ever reaching the history file.
//
// The hook's design mirrors the two-stage shape of the history scanner
// (internal/audit/shellhistory.go), because the cost constraints are the
// same but sharper — this runs on EVERY command the user enters, at the
// interactive prompt:
//
//   - A pure-zsh admit test, the same four conditions as audit's
//     historyLineMayHoldToken ("-----BEGIN", "@", "eyJ", or a 10+ run of
//     token-body characters), decides in-process whether a line could
//     possibly hold a credential. It costs ~15µs and no fork at all.
//     One of those four is currently inert: a "-----BEGIN" line is admitted
//     and forked for, but `jit guard check` never matches private-key
//     material, because audit cedes those patterns to a file scanner that
//     never sees history. See historyLineMayHoldToken's KNOWN GAP note. The
//     guard therefore does NOT stop a pasted private key from reaching the
//     history file, and this package should not claim otherwise.
//   - Only an admitted line forks `jit guard check`, which runs the real
//     knownTokenPatterns over it. The command line travels via STDIN, never
//     argv: an argv would put the credential into `ps` output for every
//     same-user process to read, which is exactly the class of exposure jit
//     exists to prevent. The binary is resolved with `command -v jit` and
//     there is deliberately NO env-var override — one would be a single
//     variable that both disables the guard and redirects every admitted
//     command line into an attacker's binary, set from the same rc file the
//     hook is sourced from.
//
// Measured on a real 592-line history (2026-08-04): 14% of command lines are
// admitted, each costing ~33ms — not the ~5% an earlier revision of audit's
// prefilter comment estimated. "@" admits every `ssh user@host` and email
// address, and the 10-character run admits ordinary words like "kubectl".
// Both numbers are stated plainly here and in `jit guard history --help`
// rather than rounded into "free", because a claim about latency at someone's
// prompt should be one they can check.
//
// On a confirmed credential the hook returns 2: zsh keeps the command on
// the SESSION's internal history list (up-arrow still works, the user's
// flow is not broken) but never writes it to $HISTFILE. A notice on stderr
// says so, naming the vendor. On any failure — jit missing, check erroring
// — the hook returns 0 and the line saves normally: a history guard must
// fail open, because silently eating commands from history is worse than
// missing one.
//
// zsh-only by decision, like the platform itself: zsh is macOS's default
// shell and the only one of the three with a pre-write hook this clean
// (bash has no equivalent seam; fish grew fish_should_add_to_history only
// recently). The install therefore always targets ~/.zshrc, not
// wrap.RcFile's $SHELL dispatch — the hook is zsh syntax and belongs
// nowhere else.
package guard

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// HookRelPath is the hook's path relative to home, kept next to wrap's
// shims under the one directory jit owns.
const hookRelPath = ".jit/guard.zsh"

// HookPath returns where the zsh hook file lives under home.
func HookPath(home string) string {
	return filepath.Join(home, filepath.FromSlash(hookRelPath))
}

// The one rc-file pair the guard owns, comment included so a human skimming
// their .zshrc knows why the line is there — the same courtesy wrap's PATH
// line and migrate's shell rewrite pay.
const (
	rcComment = "# jit guard: keep typed credentials out of the shell history file"
	rcLine    = `[ -f "$HOME/.jit/guard.zsh" ] && source "$HOME/.jit/guard.zsh"`
)

// RcLine returns the source line Install writes, for callers that print it
// (the CLI tells the user exactly what was added and how to activate it in
// the current shell without restarting).
func RcLine() string {
	return rcLine
}

// RcPath returns the rc file Install writes into, so the CLI names the file it
// actually touched rather than assuming ~/.zshrc (see zshrcPath on ZDOTDIR).
func RcPath(home string) string {
	return zshrcPath(home)
}

// hookScript is the zshaddhistory hook Install writes. Fixed content,
// rewritten on every Install, so upgrading jit and re-running
// `jit guard history` refreshes the hook.
//
// CORRECTNESS OBLIGATION: the admit test here must never reject a line
// `jit guard check` would match — it is the same obligation
// historyLineMayHoldToken carries against knownTokenPatterns, transplanted
// to zsh. TestHookAdmitTestNeverDropsAMatch drives this exact file through
// a real zsh against the same guarding samples.
const hookScript = `# jit history guard — keeps typed credentials out of your history file.
# Installed by 'jit guard history'; remove with 'jit guard history --remove'.
# A command jit recognizes as carrying a credential stays on THIS session's
# history list (up-arrow works) but is never written to $HISTFILE.

_jit_history_guard() {
  emulate -L zsh
  local line=${1%$'\n'}
  # Cheap admit test, mirroring jit scan's own prefilter: only a line that
  # could possibly hold a credential pays for the precise check below.
  #
  # The run test uses =~ (an ERE) rather than zsh's own (#c10,) glob repeat.
  # That glob needs extended_glob AT PARSE TIME, which is when this file is
  # sourced — so a user with sh_glob or emulate sh set before the source line
  # got "parse error near (", the function never defined, and a guard that
  # silently protected nothing. emulate -L zsh above only fixes the runtime.
  if [[ $line != *-----BEGIN* && $line != *@* && $line != *eyJ* ]] &&
     ! [[ $line =~ "[A-Za-z0-9_-]{10,}" ]]; then
    return 0
  fi
  local jit_bin vendors out rc
  jit_bin=$(command -v jit) || return 0

  # Run the precise check with a deadline, because a hung check would hang the
  # PROMPT. The realistic cause is not a jit bug: jit ships a bare Mach-O that
  # cannot be stapled, so Gatekeeper fetches the notarization ticket online the
  # first time a newly upgraded binary runs, and on a slow or captive network
  # that first exec can take seconds. Failing open after the deadline costs one
  # unguarded history line; blocking would cost the user their shell.
  #
  # zselect (zsh/zselect) is the timer: it waits in hundredths of a second
  # without forking, where a sleep-based poll would fork per tick on the hot
  # path. (No backticks anywhere in this script: it is a Go raw string.)
  # If the module is unavailable the check simply runs synchronously — the
  # pre-existing behavior, still correct, just without the deadline.
  # The deadline path needs a writable temp file for the check's OUTPUT (the
  # format names — never the command line, which travels by pipe). Probe it
  # rather than assume: an unwritable, read-only or nonexistent TMPDIR made
  # both redirects fail, which printed raw zsh errors at the user's prompt on
  # every admitted line and then failed open anyway. If the probe fails, run
  # synchronously instead — no deadline, but silent and correct.
  # zsh/files provides BUILTIN rm, so cleanup does not depend on an external
  # rm being resolvable: under an unusual or restricted PATH the external one
  # is not found, the temp file is never deleted, and every admitted command
  # leaves one behind. Falls back to whatever rm is on PATH if the module is
  # unavailable, and is silenced either way.
  zmodload -F zsh/files b:rm 2>/dev/null
  out=${TMPDIR:-/tmp}/.jit-guard.$$.$RANDOM
  if zmodload -F zsh/zselect b:zselect 2>/dev/null && : >| "$out" 2>/dev/null; then
    # no_monitor/no_notify keep job-control chatter ("[1] 12345", "done")
    # off the user's terminal; local_options confines both to this function.
    setopt local_options no_monitor no_notify
    print -r -- "$line" | "$jit_bin" guard check >| "$out" 2>/dev/null &
    local pid=$!
    local waited=0
    while (( waited < 200 )); do        # 200 x 10ms = 2s ceiling
      kill -0 $pid 2>/dev/null || break
      zselect -t 1                      # 1 = one hundredth of a second
      (( waited++ ))
    done
    if kill -0 $pid 2>/dev/null; then
      kill -9 $pid 2>/dev/null
      wait $pid 2>/dev/null
      rm -f "$out" 2>/dev/null
      return 0                          # deadline hit: fail open
    fi
    wait $pid 2>/dev/null
    rc=$?
    vendors=$(<"$out")
    rm -f "$out" 2>/dev/null
  else
    # Stdin, never argv: an argv puts the credential into ps(1) output.
    vendors=$(print -r -- "$line" | "$jit_bin" guard check 2>/dev/null)
    rc=$?
  fi

  if (( rc == 0 )); then
    print -ru2 -- "jit: ${vendors:-a credential} detected, kept in this session's history only and not written to ${HISTFILE:-the history file} (jit guard history --remove turns this off)"
    return 2
  fi
  return 0
}

autoload -Uz add-zsh-hook
add-zsh-hook zshaddhistory _jit_history_guard
`

// HookScript returns the hook's content, for tests that drive it through a
// real zsh.
func HookScript() string {
	return hookScript
}

// Install writes the hook file and makes sure ~/.zshrc sources it.
// Idempotent; reports whether anything changed (a fresh install or a
// content refresh — re-running on an up-to-date install reports false).
func Install(home string) (changed bool, err error) {
	hookPath := HookPath(home)
	if err := os.MkdirAll(filepath.Dir(hookPath), 0o700); err != nil {
		return false, fmt.Errorf("creating %s: %w", filepath.Dir(hookPath), err)
	}
	existing, readErr := os.ReadFile(hookPath) // #nosec G304 -- fixed path under the user's own home
	if readErr != nil && !os.IsNotExist(readErr) {
		return false, fmt.Errorf("reading %s: %w", hookPath, readErr)
	}
	if string(existing) != hookScript {
		if err := os.WriteFile(hookPath, []byte(hookScript), 0o600); err != nil {
			return false, fmt.Errorf("writing %s: %w", hookPath, err)
		}
		changed = true
	}

	rcPath := zshrcPath(home)
	data, err := os.ReadFile(rcPath) // #nosec G304 -- fixed path under the user's own home
	if err != nil && !os.IsNotExist(err) {
		return changed, fmt.Errorf("reading %s: %w", rcPath, err)
	}
	if rcSourcesHook(string(data)) {
		return changed, nil
	}
	block := rcComment + "\n" + rcLine + "\n"
	if len(data) > 0 && !strings.HasSuffix(string(data), "\n") {
		block = "\n" + block
	}
	f, err := os.OpenFile(rcPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644) // #nosec G302 G304 -- a shell rc file's conventional mode; path as above
	if err != nil {
		return changed, fmt.Errorf("opening %s: %w", rcPath, err)
	}
	defer f.Close()
	if _, err := f.WriteString(block); err != nil {
		return changed, fmt.Errorf("appending to %s: %w", rcPath, err)
	}
	return true, nil
}

// Remove deletes the hook file and removes exactly the comment+source pair
// Install writes, leaving every other byte of the rc file alone. A missing
// file or an rc without the pair reports false without error, so removal is
// safe to attempt unconditionally.
//
// rcEdited reports whether the rc file itself was changed, separately from
// changed (which covers the hook file too). The caller needs the distinction
// to describe what happened truthfully: a user who hand-wrote their own
// source line — which Install would have left alone, since it only checks
// whether the path is mentioned at all — gets the hook file deleted but
// their line kept, and saying "the source line was taken out of ~/.zshrc"
// there would be a lie about their config. It also matters because a
// hand-written line without the `[ -f ]` guard errors on every new shell
// once the hook file is gone, which is exactly what the caller must warn
// about.
func Remove(home string) (changed, rcEdited bool, err error) {
	if err := os.Remove(HookPath(home)); err == nil {
		changed = true
	} else if !os.IsNotExist(err) {
		return false, false, fmt.Errorf("removing %s: %w", HookPath(home), err)
	}

	rcPath := zshrcPath(home)
	data, err := os.ReadFile(rcPath) // #nosec G304 -- fixed path under the user's own home
	if err != nil {
		if os.IsNotExist(err) {
			return changed, false, nil
		}
		return changed, false, fmt.Errorf("reading %s: %w", rcPath, err)
	}
	lines := strings.Split(string(data), "\n")
	kept := lines[:0]
	removed := false
	for _, l := range lines {
		// Trimmed comparison, matching wrap's RemovePathLine: an editor or a
		// dotfile formatter that re-indented the block must not strand it.
		trimmed := strings.TrimSpace(l)
		if trimmed == rcComment || trimmed == rcLine {
			removed = true
			continue
		}
		kept = append(kept, l)
	}
	if !removed {
		return changed, false, nil
	}
	mode := os.FileMode(0o644)
	if info, statErr := os.Stat(rcPath); statErr == nil {
		mode = info.Mode()
	}
	if err := os.WriteFile(rcPath, []byte(strings.Join(kept, "\n")), mode); err != nil { // #nosec G703 G306 -- rcPath is the user's own shell rc file; removing the guard's source line is the point of --remove
		return changed, false, fmt.Errorf("writing %s: %w", rcPath, err)
	}
	return true, true, nil
}

// Installed reports whether the guard is fully in place: the hook file
// exists and the rc file actually sources it.
func Installed(home string) bool {
	if _, err := os.Stat(HookPath(home)); err != nil {
		return false
	}
	data, err := os.ReadFile(zshrcPath(home)) // #nosec G304 -- fixed path under the user's own home
	if err != nil {
		return false
	}
	return rcSourcesHook(string(data))
}

// rcSourcesHook reports whether rc content contains a LIVE line sourcing the
// hook — one zsh will actually execute.
//
// A plain strings.Contains over the whole file is what this replaces, and it
// was wrong in the way that matters most: it counted a COMMENTED-OUT line.
// Someone who disables the guard by putting a # in front of jit's line (the
// obvious way to turn it off temporarily) then got "history guard installed,
// ~/.zshrc now sources it" from a run that had changed nothing, a subsequent
// "already installed. Nothing to do.", and a hook zsh never loads. A security
// feature reporting success while protecting nothing is the one outcome this
// package must never produce, so the test is what the shell would do: a line
// whose first non-blank character is # does not count.
func rcSourcesHook(content string) bool {
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.Contains(trimmed, hookRelPath) {
			return true
		}
	}
	return false
}

// zshrcPath is the .zshrc zsh will actually read: $ZDOTDIR/.zshrc when that
// is set, otherwise $HOME/.zshrc.
//
// Honoring ZDOTDIR is not a nicety. A user who sets it (~/.config/zsh is the
// common tidy-home layout) would otherwise get a success message, a hook file
// on disk, an Installed() that reports true — and a hook zsh never sources.
// A security feature that silently does nothing while confirming that it does
// is the worst possible shape, so the one line that prevents it is worth more
// than the config knob it supports.
func zshrcPath(home string) string {
	if zdotdir := os.Getenv("ZDOTDIR"); zdotdir != "" {
		return filepath.Join(zdotdir, ".zshrc")
	}
	return filepath.Join(home, ".zshrc")
}
