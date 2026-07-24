// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/jitpass/jit/internal/profile"
)

// pointerFileHeaderPrefix is the start of a jit pointer file's first line
// (the full line, written below, also names why it's safe). Both the file
// WritePointerFile/ReplaceWithPointerFile write and the content-based
// detection LooksLikePointerContent uses derive from this one constant, so
// they can never drift.
const pointerFileHeaderPrefix = "# jit pointer file"

// PointerFilePath returns the git-safe, human-readable companion file
// jit migrate writes alongside a live-mounted .env/.npmrc at mountPath
// (GAPS.md #26) — never a FIFO, so an editor/IDE or a plain `cat` can
// open it instantly, with none of the stat/mmap/hang behavior a live
// mount itself has (GAPS.md #6). Safe to commit to git for the same
// reason a profile manifest is: it holds vault paths, never values.
func PointerFilePath(mountPath string) string {
	return mountPath + ".pointers"
}

// WritePointerFile writes a plain, regular file at PointerFilePath(mountPath)
// listing each variable in vars as a jit://vault/<path> pointer instead
// of its real value. The live mount (while revealed) or `jit export`/`jit
// vault get` are the only ways to actually get the real value — this
// file is deliberately never resolved or parsed by jit itself, purely a
// human-readable map of "what's here and where it actually lives."
// order carries the source file's variable order (issue #4) — same
// contract as mount.FormatDotenv: listed names first, leftovers sorted,
// nil for fully sorted.
func WritePointerFile(mountPath string, vars profile.Profile, order []string) error {
	dest := PointerFilePath(mountPath)
	if err := os.WriteFile(dest, pointerFileContent(vars, order), 0o644); err != nil { // #nosec G306 -- deliberately world-readable: this file never contains a secret value, only vault paths, and is meant to be committed to git and opened casually
		return fmt.Errorf("writing pointer file %s: %w", dest, err)
	}
	return nil
}

// ReplaceWithPointerFile overwrites path itself (no ".pointers" suffix
// added, unlike WritePointerFile) with the same pointer content. Used
// for an .env-family file that's never going to be a live mount at all
// — a backup-suffixed one (.bak/.old/.orig/.backup, GAPS.md #34) is
// never read live by anything, so converting it into a FIFO gains
// nothing and just creates a dead pipe; replacing it in place with a
// safe, readable pointer file (the same format every other .env/npmrc
// live mount gets alongside it) still moves the real values into the
// vault and leaves an honest trail of where they went, without ever
// creating an unservable pipe in the first place.
func ReplaceWithPointerFile(path string, vars profile.Profile, order []string) error {
	if err := os.WriteFile(path, pointerFileContent(vars, order), 0o644); err != nil { // #nosec G306 -- same rationale as WritePointerFile
		return fmt.Errorf("replacing %s with a pointer file: %w", path, err)
	}
	return nil
}

// LooksLikePointerContent reports whether path is one of jit's own pointer
// files identified by CONTENT rather than name. The case that matters:
// ReplaceWithPointerFile overwrites a backup-suffixed .env file (.env.bak
// etc.) IN PLACE, keeping its original name (GAPS.md #34), so
// isJitGeneratedEnvArtifact's name-based check (.pointers suffix /
// .jit-bak- marker) can't catch it — a second `jit migrate` would otherwise
// re-discover it and migrate its `KEY=jit://vault/...` pointer strings as if
// they were real secrets (GAPS.md #66). Reads only the first line. Callers
// must ensure path is a regular file (not a live-mount FIFO) before calling
// — DiscoverEnvFiles checks this after its ModeNamedPipe guard; opening a
// FIFO with no writer would block. A nil/unreadable file is not a pointer.
func LooksLikePointerContent(path string) bool {
	f, err := os.Open(path) // #nosec G304 -- discovered .env-family path, already confirmed a regular file by the caller
	if err != nil {
		return false
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	if !scanner.Scan() {
		return false
	}
	return strings.HasPrefix(scanner.Text(), pointerFileHeaderPrefix)
}

// pointerFileContent renders vars as WritePointerFile/ReplaceWithPointerFile's
// shared "no secret values here, only vault paths" format — in order
// (source-file variable order, issue #4) first, remaining names sorted.
func pointerFileContent(vars profile.Profile, order []string) []byte {
	names := make([]string, 0, len(vars))
	seen := make(map[string]bool, len(vars))
	for _, name := range order {
		if _, ok := vars[name]; ok && !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	rest := make([]string, 0, len(vars)-len(names))
	for name := range vars {
		if !seen[name] {
			rest = append(rest, name)
		}
	}
	sort.Strings(rest)
	names = append(names, rest...)

	var b strings.Builder
	b.WriteString(pointerFileHeaderPrefix + ", no secret values here, only vault paths.\n")
	b.WriteString("# Real values reach a tool through `jit run` (the live mount serves them\n")
	b.WriteString("# to that run), or `jit export`/`jit vault get`, never from this file. Safe to commit.\n")
	for _, name := range names {
		fmt.Fprintf(&b, "%s=jit://vault/%s\n", name, vars[name])
	}
	return []byte(b.String())
}
