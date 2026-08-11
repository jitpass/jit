// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

// Package selfpath answers one question, for every part of jit that needs it:
// which path should a DURABLE reference to the jit binary record?
//
// A durable reference is one jit writes into something that outlives the
// process writing it and that nothing revalidates afterwards — the launchd
// plist relaunched at every login, a wrap shim's symlink target, and every
// artifact `jit migrate` rewrites to call back into jit (an MCP server's
// command, a kubeconfig exec, an AWS credential_process, the docker and git
// credential helpers, a terraform wrapper). All of them hard-code an absolute
// path, because a GUI-launched host's PATH often doesn't match an interactive
// shell's and a bare "jit" would fail to launch. That is the right call, and
// it is also the trap: whatever binary happened to run the command is named
// in a config file permanently, and the failure when it disappears is silent
// on both ends — the host reports only "server failed", and the file is one
// the user has no reason to re-read.
//
// So the question is not "where is jit right now", it is "which name for jit
// will still resolve next month". Two different things can make the answer
// wrong, and both are represented here:
//
//   - Resolving too FAR. Full EvalSymlinks on a Homebrew install lands in a
//     version-numbered directory (/opt/homebrew/Caskroom/jitpass/0.84.0/jit)
//     that the very next `brew upgrade` deletes. Stable stops short of that.
//   - Not resolving at all, from a location that was never permanent. A jit
//     run out of a build directory, a mounted disk image, or the un-installed
//     download in ~/Downloads names a path that is about to vanish. Volatile
//     recognizes those, and Durable refuses rather than record one.
//
// This package sits below both internal/cli and internal/migrate because both
// need the same answer and cli imports migrate, so the shared logic cannot
// live in either. It was written after the two halves disagreed in the field:
// cli's launchd plist correctly recorded /opt/homebrew/bin/jit while migrate,
// on the same machine and the same day, wrote the version-pinned Caskroom
// path into a kubeconfig — a copy that stops existing at the next upgrade.
package selfpath

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Stable resolves exePath to the path a durable reference should record. For
// almost everyone that is plain EvalSymlinks — resolve the install symlink or
// shim to the real file, so the reference survives the name in front of it
// being rearranged.
//
// The exception is a Homebrew-managed jit, where full resolution lands in a
// versioned directory `brew upgrade` deletes. The durable name in a brew
// install is the one brew relinks on every upgrade: the prefix's bin symlink
// (/opt/homebrew/bin/jit). So when resolution ends inside a Caskroom or
// Cellar, this recovers that bin path from the layout — prefix/bin/<name>,
// the prefix being whatever sits above Caskroom — and returns it only after
// proving it currently resolves back to the very same file.
//
// Recovering from the layout rather than walking the symlinks in hand means a
// DIRECT invocation of the Caskroom copy (launchd re-running an old plist, a
// shim that resolved all the way through) heals onto the stable name too,
// instead of re-recording the versioned one.
//
// Anything unexpected — no bin symlink, or one pointing at a different build
// — falls back to the fully resolved path. That fallback is deliberately not
// an error here: Stable is also used where recording a versioned path beats
// recording nothing. Callers writing a reference that must outlive an upgrade
// should go through Durable, which refuses it.
func Stable(exePath string) (string, error) {
	resolved, err := filepath.EvalSymlinks(exePath)
	if err != nil {
		return "", err
	}
	prefix, name, ok := brewVersionedParts(resolved)
	if !ok {
		return resolved, nil
	}
	candidate := filepath.Join(prefix, "bin", name)
	if r, cerr := filepath.EvalSymlinks(candidate); cerr == nil && r == resolved {
		return candidate, nil
	}
	return resolved, nil
}

// Durable is Stable for THIS process's own binary, with the volatile-location
// refusal applied: the answer to "what should I write into a config file that
// will still work after the next upgrade".
//
// A volatile path is never returned. When the running binary is durable it is
// used as-is; when it is not, this refuses and names the path, rather than
// handing back a reference guaranteed to break. Refusing is one clear message
// and one reinstall; the alternative is a wrong path wired silently into a
// file nobody reads again.
//
// It deliberately does NOT fall back to exec.LookPath("jit"). An installed
// jit on PATH looks like "what the shell means by jit", but LookPath cannot
// confirm the binary it finds is even the same VERSION as the one that just
// wrote these profiles, so it could silently point a host at an older jit
// that cannot read them. Substituting a binary the user did not invoke is a
// worse failure than refusing — the person running a temporary jit can re-run
// the installed one directly.
//
// Order matters: Stable runs BEFORE the volatility test, so a brew install is
// judged on the bin symlink it heals onto rather than on the Caskroom copy
// underneath it.
func Durable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	stable, err := Stable(exe)
	if err != nil {
		return "", err
	}
	if Volatile(stable) {
		return "", fmt.Errorf("this jit is running from a temporary or removable location (%s); "+
			"a migrated config records jit's absolute path, so migrating now would point it at a binary that is about to disappear — "+
			"install jit to a permanent location (Homebrew, or move the release binary onto your PATH) and re-run from there", stable)
	}
	// Stable could not heal this back onto brew's bin symlink, so the only
	// name available is the version-numbered one `brew upgrade` deletes.
	// Recording it is the exact defect this package exists to prevent, and it
	// is worth refusing for the same reason a /tmp path is: the reference
	// would be written already broken, just on a delay.
	if VersionedBrew(stable) {
		return "", fmt.Errorf("this jit is running from a version-numbered Homebrew directory (%s) "+
			"that the next `brew upgrade` deletes, and it could not be matched back to a stable bin symlink; "+
			"run `brew link --overwrite jitpass` (or invoke jit through its bin symlink) and re-run from there", stable)
	}
	return stable, nil
}

// VersionedBrew reports whether p sits inside a Homebrew Caskroom or Cellar,
// i.e. under a directory named for the version installed at the time. Such a
// path works right now and stops existing at the next upgrade, which makes it
// the one shape that is safe to execute and unsafe to RECORD.
//
// Exported because `jit doctor` needs the same test against paths it did not
// produce: a reference already written into a config by an older jit is
// fragile today and reports as merely "missing" only after the upgrade that
// breaks it, which is too late to be a warning.
func VersionedBrew(p string) bool {
	_, _, ok := brewVersionedParts(p)
	return ok
}

// brewVersionedParts splits a resolved brew path into the prefix above the
// Caskroom/Cellar segment and the binary's own name. ok is false for any path
// that is not inside one, and for a Caskroom at the filesystem root, which
// has no prefix to hang a bin directory off.
func brewVersionedParts(p string) (prefix, name string, ok bool) {
	sep := string(filepath.Separator)
	segs := strings.Split(p, sep)
	idx := -1
	for i, seg := range segs {
		if seg == "Caskroom" || seg == "Cellar" {
			idx = i
			break
		}
	}
	if idx <= 0 {
		return "", "", false
	}
	// A leading-separator path splits to an empty first segment, so a
	// Caskroom directly at the root leaves nothing above it. There is no
	// prefix to hang a bin directory off, so there is nothing to heal onto.
	if prefix = strings.Join(segs[:idx], sep); prefix == "" {
		return "", "", false
	}
	return prefix, filepath.Base(p), true
}

// Volatile reports whether p sits in a directory tree whose contents are not
// expected to survive: the per-user and system temp directories (a `go
// build`/`go run` output lands under TempDir), mounted volumes (the "ran it
// straight out of the downloaded disk image" case), and ~/Downloads (the
// un-installed release tarball, run in place before the install step moves it
// onto PATH — the literal shape of jit's own download).
//
// Deliberately a location test rather than a writability or ownership test.
// The question is not whether the file can be modified, it is whether the
// path will still resolve to a jit binary next week, and only the location
// answers that.
//
// A Homebrew Caskroom path is NOT volatile by this test, and that is correct:
// it disappears on upgrade rather than on reboot, and Stable heals it onto
// the bin symlink before this ever sees it. VersionedBrew is the test for
// that separate failure.
func Volatile(p string) bool {
	for _, root := range volatileRoots() {
		root = filepath.Clean(root)
		if root == "" || root == "." || root == string(filepath.Separator) {
			continue
		}
		if p == root || strings.HasPrefix(p, root+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// volatileRoots is the tree list Volatile tests against.
//
// ~/Downloads is joined onto the real home rather than matched as a bare
// "Downloads" segment, so a project directory literally named Downloads
// elsewhere is not swept in. A jit truly installed onto a secondary /Volumes
// disk is the one legitimate case this refuses; that is rare, the refusal
// explains itself, and it is the correct side to err on against the far
// commoner run-from-DMG.
func volatileRoots() []string {
	roots := []string{os.TempDir(), "/tmp", "/private/tmp", "/var/folders", "/private/var/folders", "/Volumes"}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		roots = append(roots, filepath.Join(home, "Downloads"))
	}
	return roots
}
