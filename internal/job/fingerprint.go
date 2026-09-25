// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package job

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Fingerprint is what a job's folder looked like when the human approved it.
// Hashes, never copies: jit can name which file changed, not show what it
// was before.
type Fingerprint struct {
	// Root is one hash over every entry and the executable, for a cheap
	// equality check.
	Root string `json:"root"`
	// Files maps a slash-separated path relative to the job folder to its
	// entry: "sha256:<hex>" for a regular file, "link:<target>" for a symlink.
	Files map[string]string `json:"files"`
	// Exe is the entry for the resolved executable, which usually lives
	// outside the folder (a venv's python links to uv's interpreter).
	Exe string `json:"exe"`
}

// Limits bound a fingerprint. Guesses sized well above the one folder
// measured (notion: 236 files, 3.8 MB, 0.28 s), to confirm as more are.
const (
	MaxFiles = 20000
	MaxBytes = 500 << 20
)

// ErrTooLarge means the folder is past Limits. The fix is a narrower folder.
var ErrTooLarge = errors.New("too large to fingerprint")

// skipDirs are directory NAMES never walked. .git holds nothing a job runs;
// the other two are rewritten by the runtime on every run, and the runner
// keeps Python from reading or writing __pycache__ in the tree at all
// (PYTHONPYCACHEPREFIX), so skipping it hides nothing that executes.
var skipDirs = map[string]bool{".git": true, "__pycache__": true}

// skipPaths are relative paths never walked, for caches whose parent name is
// too common to skip whole.
var skipPaths = map[string]bool{"node_modules/.cache": true}

// Compute fingerprints dir and the executable exe. outputs are absolute
// folders the job writes into; anything under them is skipped. FIFOs and
// sockets are skipped (a jit mount's .env is a FIFO; opening it would block).
func Compute(dir, exe string, outputs []string) (Fingerprint, error) {
	fp := Fingerprint{Files: map[string]string{}}
	var files int
	var bytes int64
	skipAbs := make([]string, 0, len(outputs))
	for _, o := range outputs {
		skipAbs = append(skipAbs, filepath.Clean(o))
	}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(dir, path)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}
		for _, o := range skipAbs {
			if path == o || strings.HasPrefix(path, o+string(filepath.Separator)) {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
		}
		if d.IsDir() {
			if skipDirs[d.Name()] || skipPaths[rel] {
				return filepath.SkipDir
			}
			return nil
		}
		switch {
		case d.Type()&fs.ModeSymlink != 0:
			target, lerr := os.Readlink(path)
			if lerr != nil {
				return lerr
			}
			fp.Files[rel] = "link:" + target
		case d.Type().IsRegular():
			files++
			if files > MaxFiles {
				return fmt.Errorf("%s: more than %d files: %w", dir, MaxFiles, ErrTooLarge)
			}
			sum, n, herr := hashFile(path)
			if herr != nil {
				return herr
			}
			bytes += n
			if bytes > MaxBytes {
				return fmt.Errorf("%s: more than %d MB: %w", dir, MaxBytes>>20, ErrTooLarge)
			}
			fp.Files[rel] = "sha256:" + sum
		default:
			// FIFO, socket, device: nothing a job executes, and a FIFO would
			// block the read.
		}
		return nil
	})
	if err != nil {
		return Fingerprint{}, err
	}
	resolved, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return Fingerprint{}, fmt.Errorf("resolving %s: %w", exe, err)
	}
	sum, _, err := hashFile(resolved)
	if err != nil {
		return Fingerprint{}, err
	}
	fp.Exe = "sha256:" + sum
	fp.Root = fp.rootHash()
	return fp, nil
}

func hashFile(path string) (string, int64, error) {
	f, err := os.Open(path) // #nosec G304 -- a file inside the job folder the human approved
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func (fp Fingerprint) rootHash() string {
	keys := make([]string, 0, len(fp.Files))
	for k := range fp.Files {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h := sha256.New()
	for _, k := range keys {
		fmt.Fprintf(h, "%s\x00%s\n", k, fp.Files[k])
	}
	fmt.Fprintf(h, "\x00exe\x00%s\n", fp.Exe)
	return hex.EncodeToString(h.Sum(nil))
}

// ChangeKind says how one path differs from the approved fingerprint.
type ChangeKind string

const (
	Changed ChangeKind = "changed"
	Added   ChangeKind = "added"
	Removed ChangeKind = "removed"
)

// Change is one difference, for the sentence that names it.
type Change struct {
	Path string     `json:"path"`
	Kind ChangeKind `json:"kind"`
}

// ExePath is the Change.Path used for the executable, which has no path
// inside the folder.
const ExePath = "(the program itself)"

// Diff lists what now differs from approved, sorted by path, executable
// first. Empty means the job may run.
func Diff(approved, now Fingerprint) []Change {
	var out []Change
	if approved.Exe != now.Exe {
		out = append(out, Change{Path: ExePath, Kind: Changed})
	}
	var rest []Change
	for p, a := range approved.Files {
		n, ok := now.Files[p]
		switch {
		case !ok:
			rest = append(rest, Change{Path: p, Kind: Removed})
		case n != a:
			rest = append(rest, Change{Path: p, Kind: Changed})
		}
	}
	for p := range now.Files {
		if _, ok := approved.Files[p]; !ok {
			rest = append(rest, Change{Path: p, Kind: Added})
		}
	}
	sort.Slice(rest, func(a, b int) bool { return rest[a].Path < rest[b].Path })
	return append(out, rest...)
}
