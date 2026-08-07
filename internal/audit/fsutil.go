// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// noiseDirs are directory names never descended into during a home-directory
// walk: build artifacts and dependency caches that are large and never
// contain files a category scanner cares about. "Library" is macOS-specific
// (app support/caches, not a place developers put project files).
//
// The test for adding one is whether the tree can hold a secret that is the
// USER's to fix. Vendored third-party source, language runtimes a version
// manager installed, and download caches all fail it: whatever is in there
// arrived from a registry, jit has nothing to offer for it, and the next
// install would undo any rewrite anyway. On a real machine these dominate —
// .rbenv alone was 44% of every file walked, for zero findings, and the
// runtime/cache group below accounted for well over half the walk.
//
// Note what is deliberately NOT here, because the directory name looks like
// a cache but the tool keeps a credential in it: ~/.gem (RubyGems API key in
// .gem/credentials), ~/.m2 (server passwords in settings.xml), ~/.gradle
// (gradle.properties), ~/.sbt (.credentials). Only their pure-cache
// subdirectories are skipped, via noiseRelativePaths.
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
	".cargo":       true, // registry cache of vendored crate source; its credentials file is checked by fixed path, see scanCargoCredentials
	"Library":      true,

	// Language runtimes installed by a version manager: thousands of
	// vendor-shipped files per installed version, none of them the user's.
	".rbenv":  true,
	".pyenv":  true,
	".nvm":    true,
	".rustup": true,
	".asdf":   true,
	".jenv":   true,
	".goenv":  true,

	// Package caches and vendored dependency trees.
	"site-packages": true, // Python packages, incl. conda/system installs .venv misses
	"Pods":          true, // CocoaPods
	"_cacache":      true, // npm's content-addressed cache
	".pnpm-store":   true,
	"miniconda3":    true,
	"anaconda3":     true,
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
// The same reasoning covers the cache subdirectory of a tool whose top-level
// directory DOES hold a credential (see noiseDirs): ~/.m2/repository is
// vendored jars, but ~/.m2/settings.xml right next to it can hold a server
// password, so only the former is skipped.
var noiseRelativePaths = []string{
	filepath.Join("go", "pkg", "mod"),
	filepath.Join(".vscode", "extensions"),
	filepath.Join(".cursor", "extensions"),
	filepath.Join(".m2", "repository"),
	filepath.Join(".gradle", "caches"),
	filepath.Join(".local", "share", "uv"),          // uv-managed Python installs
	filepath.Join(".local", "share", "virtualenvs"), // pipenv
	filepath.Join(".ollama", "models"),              // model blobs
	// AI agent trees that are vendored, binary, or both. The rest of
	// ~/.claude is deliberately NOT skipped — file-history/, paste-cache/,
	// shell-snapshots/ and projects/ are where an agent keeps copies of the
	// user's own credentials, which is the whole subject of agentcache.go.
	// These three are a marketplace checkout, a bundled browser, and decoded
	// screenshots: large, third-party or binary, and never the user's to fix.
	filepath.Join(".claude", "plugins"),
	filepath.Join(".claude", "chrome"),
	filepath.Join(".claude", "image-cache"),
}

// SkipNoiseDir reports whether a discovery walk under root should skip the
// directory at path (bare name name) entirely: the always-irrelevant
// noiseDirs plus the root-relative noiseRelativePaths. Exported for
// internal/migrate, whose Discover* walks must skip exactly the same
// directories this package's walk does — the two lists once drifted apart,
// which let `jit migrate ~` discover (and offer to rewrite) fixture
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
	// O_NOFOLLOW | O_NONBLOCK + a regular-file check on the OPEN DESCRIPTOR.
	// walkHomeDir already applies the equivalent rule to everything it hands a
	// scanner, but the fixed-path scanners (~/.aws/credentials, ~/.kube/config,
	// ~/.zshrc, …) are checked outside that walk, and several reached this
	// function with no guard of their own:
	//
	//   - A FIFO at one of those paths hung `jit scan` in open(2) forever, with
	//     no output and nothing to indicate why. jit's own migrate creates FIFOs
	//     for a living, so this is jit's shape of file. O_NONBLOCK makes the
	//     open return instead of waiting for a writer; the IsRegular check then
	//     rejects it. (O_NONBLOCK is inert for reads on a regular file.)
	//   - A symlink pointing outside the scanned tree was followed and its
	//     target read, then REPORTED AT THE LINK'S PATH — a finding naming a
	//     file whose content lives somewhere else entirely, and a silent
	//     widening of the scan's scope past $HOME.
	//
	// Checked through the descriptor rather than an Lstat beforehand, so the
	// answer describes the file actually opened rather than one that may have
	// been swapped in between the two calls.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) // #nosec G304 -- see package-level justification above
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	return f, nil
}

// maxReadFileSize bounds readFile, matching the ceiling content.go's own sweep
// already applies (maxContentScanSize). A credential lives in a text config
// file, never in a multi-megabyte blob.
const maxReadFileSize = maxContentScanSize

// readFile is openFile's whole-file counterpart: same regular-file and
// no-symlink guarantees, plus a size cap.
//
// The direct os.ReadFile calls it replaces had neither. That is how the
// private-key scanner came to follow a symlink out of ~/Downloads and report
// someone else's key file under the link's name, and how a scanner pointed at
// a FIFO would hang.
func readFile(path string) ([]byte, error) {
	f, err := openFile(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(io.LimitReader(f, maxReadFileSize))
}

// maxStructuredParseSize bounds the input handed to a YAML/JSON decoder.
//
// Unlike a line scanner, a structured decoder allocates a representation of
// whatever it is fed, so an oversized document is a memory amplifier rather
// than merely slow work: a 32 MB secrets.yaml drove 188 MB of resident memory
// and was still parsing minutes later, against a scan budget measured in
// milliseconds — and discoverByWalk runs classifiers on 2xNumCPU goroutines,
// so it multiplies. Deliberately the same ceiling as maxContentScanSize: a
// config file holding a credential is a text file someone wrote by hand.
const maxStructuredParseSize = maxContentScanSize
