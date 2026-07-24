// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package wrap

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// The one shell-config line wrap owns: putting the shim dir first on PATH.
// Written once, comment included, so a human skimming their rc file knows
// why the line is there — the same courtesy migrate's shell rewrite pays.
const (
	pathLineComment = "# jit wrap: keep the shim directory first on PATH so wrapped CLIs resolve to jit"
	pathLine        = `export PATH="$HOME/.jit/shims:$PATH"`
)

// PathLine returns the export line EnsurePathLine writes, for callers that
// print it (the CLI tells the user exactly what was added and how to apply
// it to the current shell without restarting).
func PathLine() string {
	return pathLine
}

// RcFile picks which shell config file the PATH line belongs in, from the
// user's login shell ($SHELL). Defaults to .zshrc — macOS's default shell
// — when the shell is unknown or unset; a shell we don't recognize gets
// .profile, the POSIX common ground.
func RcFile(home, shell string) string {
	switch filepath.Base(shell) {
	case "bash":
		return filepath.Join(home, ".bashrc")
	case "zsh", ".": // "." is filepath.Base of an unset $SHELL, assume macOS's default shell
		return filepath.Join(home, ".zshrc")
	default:
		return filepath.Join(home, ".profile")
	}
}

// EnsurePathLine makes sure rcPath puts the shim dir on PATH, appending the
// comment+export pair if no line mentions the shim dir yet. Creates rcPath
// when missing. Idempotent: reports whether the file was changed.
func EnsurePathLine(rcPath string) (changed bool, err error) {
	data, err := os.ReadFile(rcPath) // #nosec G304 -- rcPath is derived from the user's own home dir and $SHELL, never external input
	if err != nil && !os.IsNotExist(err) {
		return false, fmt.Errorf("reading %s: %w", rcPath, err)
	}
	if strings.Contains(string(data), ".jit/shims") {
		return false, nil
	}
	block := pathLineComment + "\n" + pathLine + "\n"
	if len(data) > 0 && !strings.HasSuffix(string(data), "\n") {
		block = "\n" + block
	}
	f, err := os.OpenFile(rcPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644) // #nosec G302 G304 -- a shell rc file's conventional mode; path as above
	if err != nil {
		return false, fmt.Errorf("opening %s: %w", rcPath, err)
	}
	defer f.Close()
	if _, err := f.WriteString(block); err != nil {
		return false, fmt.Errorf("appending to %s: %w", rcPath, err)
	}
	return true, nil
}

// RemovePathLine removes exactly the comment+export pair EnsurePathLine
// writes, leaving every other byte of rcPath alone. A missing file or a
// file without the pair reports false without error, so undo of the last
// wrapped tool is safe to attempt unconditionally.
func RemovePathLine(rcPath string) (changed bool, err error) {
	data, err := os.ReadFile(rcPath) // #nosec G304 -- same provenance as EnsurePathLine's rcPath
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("reading %s: %w", rcPath, err)
	}
	lines := strings.Split(string(data), "\n")
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == pathLineComment || trimmed == pathLine {
			changed = true
			continue
		}
		kept = append(kept, line)
	}
	if !changed {
		return false, nil
	}
	mode := os.FileMode(0o644)
	if info, statErr := os.Stat(rcPath); statErr == nil {
		mode = info.Mode()
	}
	if err := os.WriteFile(rcPath, []byte(strings.Join(kept, "\n")), mode); err != nil { // #nosec G703 -- rcPath is the user's own shell rc file; removing the stale wrap PATH line is the point of undo
		return false, fmt.Errorf("rewriting %s: %w", rcPath, err)
	}
	return true, nil
}
