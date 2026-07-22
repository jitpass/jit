// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package audit

import (
	"io/fs"
	"os"
	"path/filepath"
)

// noiseDirs are directory names never descended into during a home-directory
// walk: build artifacts and dependency caches that are large and never
// contain files a category scanner cares about. "Library" is macOS-specific
// (app support/caches, not a place developers put project files).
var noiseDirs = map[string]bool{
	"node_modules": true,
	".git":         true,
	"vendor":       true,
	"dist":         true,
	"build":        true,
	".venv":        true,
	"venv":         true,
	"__pycache__":  true,
	".next":        true,
	".nuxt":        true,
	"target":       true,
	".cache":       true,
	".terraform":   true,
	".tox":         true,
	".cargo":       true,
	"Library":      true,
}

// noiseRelativePaths are paths, relative to the walk root, skipped wholesale
// even though a bare-name match (noiseDirs) would be too broad. Real-world
// dogfooding (2026-07-06) found both of these producing pure false
// positives: the Go module cache (third-party package source/testdata —
// including, ironically, this project's own gosec dependency) and installed
// VS Code extensions (bundled example/snippet files, not the user's own
// content). ".vscode/extensions" specifically — not ".vscode" itself — since
// a project-local .vscode directory legitimately holds files this tool needs
// to find (a project's own .vscode/mcp.json, per the MCP config scanner).
var noiseRelativePaths = []string{
	filepath.Join("go", "pkg", "mod"),
	filepath.Join(".vscode", "extensions"),
	filepath.Join(".cursor", "extensions"),
}

// SkipNoiseDir reports whether a discovery walk under root should skip the
// directory at path (bare name name) entirely: the always-irrelevant
// noiseDirs plus the root-relative noiseRelativePaths. Exported for
// internal/migrate, whose Discover* walks must skip exactly the same
// directories this package's walk does — the two lists once drifted apart,
// which let `jit migrate home` discover (and offer to rewrite) fixture
// files audit deliberately excludes: bundled .env files under
// .vscode/extensions, .venv site-packages, everything under ~/Library.
func SkipNoiseDir(root, path, name string) bool {
	if noiseDirs[name] {
		return true
	}
	if rel, err := filepath.Rel(root, path); err == nil {
		for _, noise := range noiseRelativePaths {
			if rel == noise {
				return true
			}
		}
	}
	return false
}

// walkHomeDir walks root, calling fn for every regular file found. This is
// the shared "broad, bounded" discovery mechanism multiple category
// scanners use: real-world review (2026-07-06, see ROADMAP.md) showed most
// exposure lives outside a project's cwd — old repo clones, .Trash,
// timestamped backup directories — so a home-directory-wide walk is the
// deliberate choice over a narrow cwd-only scan, "bounded" by skipping
// noiseDirs/noiseRelativePaths (huge or third-party, never relevant) and
// never following symlinks (avoids loops and avoids silently expanding scope
// outside the intended root). A per-file or per-directory error (permissions,
// a race with something deleting a file mid-walk) is skipped rather than
// aborting the whole scan — one unreadable file shouldn't take down the
// entire audit.
func walkHomeDir(root string, fn func(path string, d fs.DirEntry) error) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if path == root {
				return nil
			}
			if SkipNoiseDir(root, path, d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		// Only regular files are passed to scanners: a symlink is skipped to
		// avoid loops and silent scope expansion, and anything else
		// non-regular (a named pipe, socket, device) has no at-rest content
		// for an exposure scanner to report. The named-pipe case is the one
		// that bit for real: a live jit mount's FIFO, opened for read, either
		// blocks the whole scan forever (no agent running, so no writer) or
		// returns the agent-served DECOY content — which the .env scanner
		// then reported as a real plaintext secret, flagging exactly the
		// files jit already protects. Scan reports registered live mounts as
		// a separate protected count so this skip is visible, never silent.
		if !d.Type().IsRegular() {
			return nil
		}
		return fn(path, d)
	})
}

// openFile opens a file for reading. Every category scanner funnels through
// this instead of calling os.Open directly, so there is exactly one place
// to justify gosec's G304 ("potential file inclusion via variable"): every
// path jit scan ever reads is either a fixed, hardcoded filename (shell
// config names, credential file names) or discovered by our own directory
// walk under a known root — never attacker- or network-controlled input,
// which is what G304 actually guards against. Centralizing this also means
// a future scanner that DOES need to accept a less-trusted path (e.g. an
// arbitrary user-supplied project directory) has one obvious place to add
// real containment (os.Root, Go 1.24+) instead of copy-pasting a suppression.
func openFile(path string) (*os.File, error) {
	return os.Open(path) // #nosec G304 -- see package-level justification above
}
