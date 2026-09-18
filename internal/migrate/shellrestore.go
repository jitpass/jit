// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jitpass/jit/internal/inject"
	"github.com/jitpass/jit/internal/profile"
	"github.com/jitpass/jit/internal/vault"
)

// ErrShellConfigNotWired is RestoreShellConfig's answer for a shell config
// that no longer carries jit's eval line: the user took it out themselves,
// so there is nothing of jit's left in the file to reverse.
var ErrShellConfigNotWired = errors.New("no jit export line in this file")

// RestoreShellConfig reverses ApplyShellConfig at the level it worked at:
// lines. jit's comment and its `eval "$(jit export --profile <name>)"` are
// replaced, where they stand, by one `export KEY='value'` per variable the
// profile holds, from the CURRENT vault values. Every other byte of the
// file stays.
//
// The alternative, `jit migrate undo`, writes back the whole file as it was
// on the day of migration. For a shell config that is the wrong tool: it is
// the most hand-edited file a developer owns, and jit itself appends to it
// afterwards (the history guard's source line, wrap's PATH line), so a
// whole-file restore silently deletes everything added since.
//
// Returns the variable names written, sorted. The file keeps its mode; the
// write is atomic, because a half-written rc file breaks every new shell.
func RestoreShellConfig(v *vault.Vault, path string) ([]string, error) {
	profileName := shellProfileName(path)
	// A dotfiles setup keeps ~/.zshrc as a link into a repo. The atomic
	// write below renames over its target, so write to the real file, or
	// the link would be replaced by a copy the repo no longer tracks.
	if resolved, rerr := filepath.EvalSymlinks(path); rerr == nil {
		path = resolved
	}
	lines, err := readLines(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	if !hasJitExportLine(lines, profileName) {
		return nil, ErrShellConfigNotWired
	}

	home, err := profile.GlobalRoot()
	if err != nil {
		return nil, fmt.Errorf("resolving global profile root: %w", err)
	}
	profilePath, err := profile.Path(home, profileName)
	if err != nil {
		return nil, err
	}
	p, err := profile.LoadFile(profilePath)
	if err != nil {
		return nil, fmt.Errorf("loading profile %s: %w", profilePath, err)
	}
	values, err := inject.Resolve(v, p)
	if err != nil {
		return nil, fmt.Errorf("resolving secrets: %w", err)
	}
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)

	marker := "jit export --profile " + profileName
	out := make([]string, 0, len(lines)+len(names))
	written := false
	for _, line := range lines {
		if strings.TrimSpace(line) == jitShellComment {
			continue
		}
		if !strings.Contains(line, marker) {
			out = append(out, line)
			continue
		}
		// A second eval for the same profile (a hand-made copy) is dropped
		// too: the exports above it already cover it.
		if written {
			continue
		}
		written = true
		for _, name := range names {
			out = append(out, "export "+name+"="+posixSingleQuote(values[name]))
		}
	}

	mode := os.FileMode(0o600)
	if info, statErr := os.Stat(path); statErr == nil {
		mode = info.Mode().Perm()
	}
	if err := vault.AtomicWriteFile(path, []byte(strings.Join(out, "\n"))); err != nil {
		return nil, fmt.Errorf("writing %s: %w", path, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		return nil, fmt.Errorf("restoring permissions on %s: %w", path, err)
	}
	return names, nil
}

// posixSingleQuote quotes s for sh, bash and zsh. Single quotes because the
// value is a secret of unknown shape: nothing inside them expands.
func posixSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// ShellConfigWired reports whether path still carries the eval line
// ApplyShellConfig wrote: the read-only half of RestoreShellConfig, for a
// plan that must not cost a prompt.
func ShellConfigWired(path string) bool {
	lines, err := readLines(path)
	if err != nil {
		return false
	}
	return hasJitExportLine(lines, shellProfileName(path))
}

// ShellProfileName is the global profile a shell config's secrets live in.
func ShellProfileName(path string) string { return shellProfileName(path) }

// IsEnvFileName reports a .env-family file name (.env, .env.local, ...).
// Migrating one always leaves a live mount or a pointer file, so a plain
// file under that name has already been put back.
func IsEnvFileName(name string) bool { return envFileNamePattern.MatchString(name) }
