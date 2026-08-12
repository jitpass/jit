// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"os"
	"path/filepath"
	"strings"
)

// completionShellRC names the shell rc file a source line would live in, and
// the shell it belongs to. zsh only: it is macOS's default shell, it is the
// one `jit guard history` supports, and a bash/fish user who set their own
// shell up deliberately does not need jit guessing at their rc file.
func completionShellRC() (path, shell string) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", ""
	}
	if zdotdir := os.Getenv("ZDOTDIR"); zdotdir != "" {
		return filepath.Join(zdotdir, ".zshrc"), "zsh"
	}
	return filepath.Join(home, ".zshrc"), "zsh"
}

// completionFindings reports that jit's tab completion is not installed.
//
// It is the check that makes every other completion in this CLI reachable. A
// Homebrew CASK installs the binary and nothing else — casks have no
// completion mechanism the way formulas do — so before .goreleaser.yml
// started carrying generated completions in the archive, every `brew install
// jitpass/tap/jitpass` produced a machine where `jit <TAB>` listed the current
// directory and nothing jit knows about (vault paths, grant ids, profile
// names, `--kind` values) could be completed at all. The tarball install still
// produces exactly that. The one remedy is a line in a shell rc that README.md
// labels "Recommended", i.e. optional, i.e. invisible to the people who most
// need it.
//
// Deliberately quiet in two cases that are not defects: a completion file
// installed by Homebrew's own site-functions directory (what the cask does
// now), and a shell rc that already sources jit's completion. Deliberately
// silent, too, when jit cannot tell — a non-interactive run, an unreadable rc
// — because a diagnostic that guesses is worse than one that skips.
func completionFindings() []checkFinding {
	rc, shell := completionShellRC()
	if rc == "" {
		return nil
	}
	if completionInstalled(rc) {
		return nil
	}
	return []checkFinding{{
		Kind: kindCompletion,
		Path: rc,
		Detail: "jit's tab completion is not set up for " + shell +
			", so vault paths, profile names, grant ids and flag values do not complete",
		Action: "`echo 'source <(jit completion " + shell + ")' >> " + shortPath(rc) + "` then restart your shell",
	}}
}

// completionInstalled reports whether this machine already has jit's
// completion available, by either of the two routes that work: a completion
// file in one of the directories the shell loads on its own (where the
// Homebrew cask installs `_jit`), or a source line in the user's rc.
func completionInstalled(rc string) bool {
	for _, dir := range completionSearchDirs() {
		if _, err := os.Stat(filepath.Join(dir, "_jit")); err == nil {
			return true
		}
	}
	data, err := os.ReadFile(rc) // #nosec G304 -- the user's own shell rc, resolved from $HOME/$ZDOTDIR
	if err != nil {
		// An unreadable rc is not evidence either way, and a doctor line that
		// might be wrong about the user's own shell setup is worse than none.
		return true
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		// Both shapes the docs give, plus a hand-rolled compdef: the point is
		// whether jit's completion reaches the shell, not how.
		if strings.Contains(line, "jit completion") || strings.Contains(line, "_jit") {
			return true
		}
	}
	return false
}

// completionSearchDirs lists the completion directories jit checks for an
// installed `_jit`. Homebrew's own site-functions comes first because that is
// where the cask puts it; the two system paths cover a manual install.
func completionSearchDirs() []string {
	dirs := []string{
		"/opt/homebrew/share/zsh/site-functions",
		"/usr/local/share/zsh/site-functions",
		"/usr/share/zsh/site-functions",
	}
	// $fpath is not readable from here (it is a shell variable, not an env
	// var), so a completion installed somewhere exotic is missed and the
	// finding's rc check is what saves it from a false positive.
	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, filepath.Join(home, ".zsh", "completions"))
	}
	return dirs
}
