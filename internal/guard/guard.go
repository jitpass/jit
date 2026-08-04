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
//     possibly hold a credential. ~95% of real command lines fail it and
//     pay nothing — no fork, no jit involvement at all.
//   - Only an admitted line forks `jit guard check`, which runs the real
//     knownTokenPatterns over it. The command line travels via STDIN,
//     never argv: an argv would put the credential into `ps` output for
//     every same-user process to read, which is exactly the class of
//     exposure jit exists to prevent.
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
  setopt extended_glob
  local line=${1%$'\n'}
  # Cheap admit test, mirroring jit scan's own prefilter: only a line that
  # could possibly hold a credential pays for the precise check below.
  if [[ $line != *-----BEGIN* && $line != *@* && $line != *eyJ* && \
        $line != *[A-Za-z0-9_-](#c10,)* ]]; then
    return 0
  fi
  local jit_bin vendors
  jit_bin=${JIT_GUARD_BIN:-$(command -v jit)} || return 0
  # Stdin, never argv: an argv puts the credential into ps(1) output.
  vendors=$(print -r -- "$line" | "$jit_bin" guard check 2>/dev/null)
  if (( $? == 0 )); then
    print -ru2 -- "jit: ${vendors:-a credential} detected — command kept in this session's history only, not written to ${HISTFILE:-the history file} (jit guard history --remove to turn this off)"
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
	if strings.Contains(string(data), hookRelPath) {
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
// Install writes, leaving every other byte of ~/.zshrc alone. A missing
// file or an rc without the pair reports false without error, so removal
// is safe to attempt unconditionally.
func Remove(home string) (changed bool, err error) {
	if err := os.Remove(HookPath(home)); err == nil {
		changed = true
	} else if !os.IsNotExist(err) {
		return false, fmt.Errorf("removing %s: %w", HookPath(home), err)
	}

	rcPath := zshrcPath(home)
	data, err := os.ReadFile(rcPath) // #nosec G304 -- fixed path under the user's own home
	if err != nil {
		if os.IsNotExist(err) {
			return changed, nil
		}
		return changed, fmt.Errorf("reading %s: %w", rcPath, err)
	}
	lines := strings.Split(string(data), "\n")
	kept := lines[:0]
	removed := false
	for _, l := range lines {
		if l == rcComment || l == rcLine {
			removed = true
			continue
		}
		kept = append(kept, l)
	}
	if !removed {
		return changed, nil
	}
	mode := os.FileMode(0o644)
	if info, statErr := os.Stat(rcPath); statErr == nil {
		mode = info.Mode()
	}
	if err := os.WriteFile(rcPath, []byte(strings.Join(kept, "\n")), mode); err != nil { // #nosec G703 G306 -- rcPath is the user's own shell rc file; removing the guard's source line is the point of --remove
		return changed, fmt.Errorf("writing %s: %w", rcPath, err)
	}
	return true, nil
}

// Installed reports whether the guard is fully in place: the hook file
// exists and ~/.zshrc sources it.
func Installed(home string) bool {
	if _, err := os.Stat(HookPath(home)); err != nil {
		return false
	}
	data, err := os.ReadFile(zshrcPath(home)) // #nosec G304 -- fixed path under the user's own home
	if err != nil {
		return false
	}
	return strings.Contains(string(data), hookRelPath)
}

func zshrcPath(home string) string {
	return filepath.Join(home, ".zshrc")
}
