// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package job

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

// Fingerprint is what a job's folder looked like when the human approved it.
// Hashes, never copies: jit can name which file changed, not show what it
// was before.
type Fingerprint struct {
	// Root is one hash over every entry, the executable and the libraries,
	// for a cheap equality check.
	Root string `json:"root"`
	// Files maps a slash-separated path relative to the job folder to its
	// entry: "sha256:<hex>" for a regular file, "link:<target>" for a symlink.
	Files map[string]string `json:"files"`
	// Exe is the entry for the resolved executable, which usually lives
	// outside the folder (a venv's python links to uv's interpreter).
	Exe string `json:"exe"`
	// Stamps holds each hashed file's change-time, keyed like Files. Only
	// the kernel sets a change-time, and on APFS it moves on every write and
	// on a rename away and back (measured 2026-09-25), even when the content
	// ends up identical and the modification time is reset. So a file
	// swapped for a moment and put back, which a content hash cannot see,
	// still shows here. A fingerprint from before stamps existed has none,
	// and is compared by content alone.
	Stamps map[string]string `json:"stamps,omitempty"`
	// Libs is what the job's program loads from outside the folder (libs.go,
	// interp.go): its interpreter's installation, a venv outside the folder,
	// folders a .pth file adds, the native libraries every fingerprinted
	// Mach-O links, and places the interpreter looks that held nothing
	// (AbsentEntry). Keyed by absolute path, valued like Files; a value ending
	// " @ <path>" also says where a named path resolved. Stamps holds their
	// change-times under the same keys.
	Libs map[string]string `json:"libs,omitempty"`
	// LibsV is 1 on a fingerprint that took Libs, even an empty one. A
	// fingerprint from a jit before it (0) cannot say what the program loaded,
	// so a job approved then stops once its program loads anything from
	// outside the folder (Unchecked).
	LibsV int `json:"libs_v,omitempty"`
}

// Limits bound a fingerprint. Guesses sized well above the one folder
// measured (notion: 236 files, 3.8 MB, 0.28 s), to confirm as more are.
const (
	MaxFiles = 20000
	MaxBytes = 500 << 20
)

// OutsidePrefix marks a fingerprint entry for a file outside the job folder.
const OutsidePrefix = "outside:"

// ExternalFiles lists the files the command names that live outside dir:
// `python ../run.py`, `--config=/elsewhere/c.yaml`, or a path inside dir that
// is a symlink out of it. The folder walk never sees them, so without this an
// agent that proposed the path could edit the script after approval and the
// job would keep running. Paths are resolved through symlinks before they are
// judged inside or out, and recorded resolved. An argument that is not an
// existing regular file is not a file the job reads by name and is left alone,
// with one exception: the PROGRAM an interpreter is given (`python ../tool`,
// `node ../pkg`) may be a folder, whose code no fingerprint covers, so that is
// refused. dir must already be resolved (the service resolves it).
func ExternalFiles(argv []string, dir string, outputs []string) ([]string, error) {
	dir = ResolvePath(dir)
	outs := resolveAll(outputs)
	sc := scanArgs(argv)
	code := map[string]bool{}
	if sc.program != "" {
		code[sc.program] = true
	}
	for _, c := range sc.code {
		code[c] = true
	}
	seen := map[string]bool{}
	var out []string
	for i, a := range argv {
		if i == 0 {
			continue // the executable, hashed on its own
		}
		cands := []string{a}
		if j := strings.IndexByte(a, '='); j > 0 {
			cands = append(cands, a[j+1:])
		}
		// A value glued to a short code flag (`-rhook.js`, `-I../lib`) is
		// still code: scanArgs reports it bare.
		for c := range code {
			if c != a && strings.HasSuffix(a, c) {
				cands = append(cands, c)
			}
		}
		for _, c := range cands {
			if c == "" {
				continue
			}
			p := c
			if !filepath.IsAbs(p) {
				p = filepath.Join(dir, p)
			}
			resolved, err := filepath.EvalSymlinks(p)
			if err != nil {
				continue
			}
			// Inside the folder and walked: the fingerprint has it already.
			// Inside but in a part the walk skips (.git, an output folder):
			// covered here, or it would be covered nowhere.
			if inside(resolved, dir) && !skippedPath(resolved, dir, outs) {
				continue
			}
			info, err := os.Stat(resolved)
			if err != nil {
				continue
			}
			if info.IsDir() {
				if code[c] && !inside(resolved, dir) {
					return nil, fmt.Errorf("%s loads code from the folder %s, which is outside the job's folder, so no edit to it could stop the job: approve the job from a folder that contains it", a, resolved)
				}
				continue
			}
			if !info.Mode().IsRegular() || seen[resolved] {
				continue
			}
			seen[resolved] = true
			out = append(out, resolved)
		}
	}
	sort.Strings(out)
	return out, nil
}

func resolveAll(paths []string) []string {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		out = append(out, ResolvePath(p))
	}
	return out
}

// skippedPath reports whether p, inside dir, lies in a part the folder walk
// does not visit: a skipped directory name, a skipped path, or an output.
func skippedPath(p, dir string, outs []string) bool {
	for _, o := range outs {
		if inside(p, o) {
			return true
		}
	}
	rel, err := filepath.Rel(dir, p)
	if err != nil {
		return false
	}
	rel = filepath.ToSlash(rel)
	for sp := range skipPaths {
		if rel == sp || strings.HasPrefix(rel, sp+"/") {
			return true
		}
	}
	for _, part := range strings.Split(rel, "/") {
		if skipDirs[part] {
			return true
		}
	}
	return false
}

// ResolvePath resolves p through symlinks as far as it exists, keeping the
// rest as written: an output folder a job has not created yet still has to
// compare equal to the walk's resolved paths (/var → /private/var) once it
// does.
func ResolvePath(p string) string {
	p = filepath.Clean(p)
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	parent := filepath.Dir(p)
	if parent == p {
		return p
	}
	return filepath.Join(ResolvePath(parent), filepath.Base(p))
}

func inside(p, dir string) bool {
	return p == dir || strings.HasPrefix(p, dir+string(filepath.Separator))
}

// OutputCoversDir reports whether an output folder is dir or contains it.
// Such an output would skip every file in the walk and leave an empty
// fingerprint, so a job could never be stopped by an edit.
func OutputCoversDir(output, dir string) bool {
	output, dir = ResolvePath(output), ResolvePath(dir)
	return output == dir || strings.HasPrefix(dir, output+string(filepath.Separator))
}

// ErrLinkOutside means a symlink in the folder points at a folder outside it.
var ErrLinkOutside = errors.New("links outside the job's folder")

// LinkTargetSuffix marks the entry holding the content a symlink points at
// when that content lives outside the folder.
const LinkTargetSuffix = " (its target)"

// ErrTooLarge means the folder is past Limits. The fix is a narrower folder.
var ErrTooLarge = errors.New("too large to fingerprint")

// skipDirs are directory NAMES never walked. .git holds nothing a job runs.
//
// __pycache__ is deliberately NOT skipped, though it once was. The runner
// sends a job's own bytecode elsewhere (a fresh PYTHONPYCACHEPREFIX per run),
// so a jit run never writes into the tree; but `python -I` and a child
// started with a cleaned environment ignore that variable and load whatever
// .pyc sits in the folder, and a planted .pyc whose header matches its
// source's mtime and size runs in place of that source. Fingerprinted, a
// planted or rewritten .pyc stops the job like any other edit.
var skipDirs = map[string]bool{".git": true}

// skipPaths are relative paths never walked, for caches whose parent name is
// too common to skip whole.
var skipPaths = map[string]bool{"node_modules/.cache": true}

// Compute fingerprints dir, the program p starts (its executable, and in Libs
// what it loads from outside dir: libs.go), and extra: files the command
// names that live outside dir (ExternalFiles), recorded under their absolute
// path with an "outside:" prefix. outputs are absolute folders the job writes
// into; anything under them is skipped. FIFOs and sockets are skipped (a jit
// mount's .env is a FIFO; opening it would block).
//
// dir is resolved through symlinks first: WalkDir does not descend into a
// symlinked root, and walking one used to produce an empty fingerprint that
// no edit could ever change. A symlink INSIDE the folder is recorded by its
// target text and, when it resolves outside the folder, by the content it
// points at (a file) or refused (a folder, whose code nothing would cover).
func Compute(dir string, p Program, outputs, extra []string) (Fingerprint, error) {
	fp := Fingerprint{Files: map[string]string{}, Stamps: map[string]string{}}
	realDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return Fingerprint{}, err
	}
	b := &budget{dir: dir}
	// The Mach-O files hashed here: what each links is fingerprinted with
	// the libraries (a venv's compiled module can link Homebrew's libpq).
	var machos []string
	skipAbs := make([]string, 0, len(outputs))
	for _, o := range outputs {
		skipAbs = append(skipAbs, ResolvePath(o))
	}
	err = filepath.WalkDir(realDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(realDir, path)
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
			if li, lerr := os.Lstat(path); lerr == nil {
				if st, ok := li.Sys().(*syscall.Stat_t); ok {
					fp.Stamps[rel] = fmt.Sprintf("%d.%09d", st.Ctimespec.Sec, st.Ctimespec.Nsec)
				}
			}
			resolved, rerr := filepath.EvalSymlinks(path)
			if rerr != nil {
				return nil // dangling
			}
			if inside(resolved, realDir) && !skippedPath(resolved, realDir, skipAbs) {
				return nil // its target is walked in place
			}
			info, serr := os.Stat(resolved)
			if serr != nil {
				return nil
			}
			if info.IsDir() {
				where := "outside the job's folder"
				if inside(resolved, realDir) {
					where = "in a part of the folder jit does not fingerprint (.git, an output folder)"
				}
				return fmt.Errorf("%s links to the folder %s, %s, so no edit to it could stop the job: %w", rel, resolved, where, ErrLinkOutside)
			}
			if info.Mode().IsRegular() {
				h, herr := hashFileStamp(resolved)
				if herr != nil {
					return herr
				}
				b.bytes += h.n
				fp.Files[rel+LinkTargetSuffix] = "sha256:" + h.sum
				fp.Stamps[rel+LinkTargetSuffix] = h.stamp
				if h.macho {
					machos = append(machos, resolved)
				}
			}
		case d.Type().IsRegular():
			b.files++
			if b.files > limitFiles {
				return fmt.Errorf("%s: more than %d files: %w", dir, limitFiles, ErrTooLarge)
			}
			h, herr := hashFileStamp(path)
			if herr != nil {
				return herr
			}
			b.bytes += h.n
			if b.bytes > limitBytes {
				return fmt.Errorf("%s: more than %d MB: %w", dir, limitBytes>>20, ErrTooLarge)
			}
			fp.Files[rel] = "sha256:" + h.sum
			fp.Stamps[rel] = h.stamp
			if h.macho {
				machos = append(machos, path)
			}
		default:
			// FIFO, socket, device: nothing a job executes, and a FIFO would
			// block the read.
		}
		return nil
	})
	if err != nil {
		return Fingerprint{}, err
	}
	for _, e := range extra {
		h, herr := hashFileStamp(e)
		if herr != nil {
			return Fingerprint{}, herr
		}
		fp.Files[OutsidePrefix+e] = "sha256:" + h.sum
		fp.Stamps[OutsidePrefix+e] = h.stamp
		if h.macho {
			machos = append(machos, e)
		}
	}
	resolved, err := filepath.EvalSymlinks(p.Exe)
	if err != nil {
		return Fingerprint{}, fmt.Errorf("resolving %s: %w", p.Exe, err)
	}
	h, err := hashFileStamp(resolved)
	if err != nil {
		return Fingerprint{}, err
	}
	fp.Exe = "sha256:" + h.sum
	fp.Stamps[ExePath] = h.stamp
	libs, stamps, err := collectLibs(realDir, skipAbs, p, classify(realDir, p), machos, b)
	if err != nil {
		return Fingerprint{}, err
	}
	fp.Libs, fp.LibsV = libs, 1
	for k, v := range stamps {
		fp.Stamps[k] = v
	}
	fp.Root = fp.rootHash()
	return fp, nil
}

// hashFileStamp hashes one regular file and reads its change-time from the
// same open file. It opens without blocking and refuses anything that is not
// a regular file once open: a path swapped for a named pipe (by whoever can
// write the folder, or a file named outside it) would otherwise block the
// open forever, hanging every list and run behind it.
func hashFileStamp(path string) (fileHash, error) {
	f, err := openRegular(path)
	if err != nil {
		return fileHash{}, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return fileHash{}, err
	}
	sum, n, isMachO, err := hashReader(f)
	if err != nil {
		return fileHash{}, err
	}
	return fileHash{sum: sum, n: n, stamp: ctimeStamp(info), macho: isMachO}, nil
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
	libs := make([]string, 0, len(fp.Libs))
	for k := range fp.Libs {
		libs = append(libs, k)
	}
	sort.Strings(libs)
	for _, k := range libs {
		fmt.Fprintf(h, "\x00lib\x00%s\x00%s\n", k, fp.Libs[k])
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ChangeKind says how one path differs from the approved fingerprint.
type ChangeKind string

const (
	Changed ChangeKind = "changed"
	Added   ChangeKind = "added"
	Removed ChangeKind = "removed"
	// Rewritten: the content matches approval, but the file was written to
	// or replaced and put back since (its change-time moved). The swap a
	// content hash cannot see.
	Rewritten ChangeKind = "rewritten"
	// Unchecked: the approval predates Libs, so nothing says what the program
	// loaded from outside the folder then. Only approving again can.
	Unchecked ChangeKind = "not fingerprinted when you approved it"
)

// Change is one difference, for the sentence that names it.
type Change struct {
	Path string     `json:"path"`
	Kind ChangeKind `json:"kind"`
}

// ExePath is the Change.Path used for the executable, which has no path
// inside the folder.
const ExePath = "(the program itself)"

// LibsPath is the Change.Path of an Unchecked change: everything Libs holds.
const LibsPath = "(what the program loads from outside the folder)"

// stampMoved reports a change-time that moved. A fingerprint with no stamp
// for the key (taken before stamps existed) compares by content alone.
func stampMoved(approved, now Fingerprint, key string) bool {
	a, ok := approved.Stamps[key]
	if !ok || a == "" {
		return false
	}
	return now.Stamps[key] != a
}

// Sentence says what happened to one path, in the words a stop reports:
// "list_guest_users.py changed since you approved it".
func (c Change) Sentence() string {
	switch c.Kind {
	case Rewritten:
		return c.Path + " was written to since you approved it: its content matches, but something rewrote it or swapped it and put it back"
	case Unchecked:
		return "this job was approved by an older jit, which did not fingerprint what its program loads from outside the folder (the interpreter's own libraries); approve it again"
	default:
		return fmt.Sprintf("%s %s since you approved it", c.Path, c.Kind)
	}
}

// StopHint explains a stop whose changes are all Python bytecode: running the
// script outside jit writes it into the folder (review finding 9, kept
// fingerprinted by decision), and running that Python outside jit writes it
// into the interpreter's own library the first time a module is imported.
// Empty for any other stop.
func StopHint(changes []Change) string {
	if len(changes) == 0 {
		return ""
	}
	library := false
	for _, c := range changes {
		if !strings.HasSuffix(c.Path, ".pyc") || !(strings.HasPrefix(c.Path, "__pycache__/") || strings.Contains(c.Path, "/__pycache__/")) {
			return ""
		}
		library = library || filepath.IsAbs(c.Path)
	}
	if library {
		return "Python writes .pyc files into its own library the first time it imports a module outside jit. If you ran this Python yourself, approve the job again"
	}
	return "Python writes these .pyc files when the script runs outside jit. Run it with `jit job run` instead, or approve the job again"
}

// Diff lists what now differs from approved, sorted by path, executable
// first. Empty means the job may run.
func Diff(approved, now Fingerprint) []Change {
	var out []Change
	if approved.Exe != now.Exe {
		out = append(out, Change{Path: ExePath, Kind: Changed})
	}
	if approved.Exe == now.Exe && stampMoved(approved, now, ExePath) {
		out = append(out, Change{Path: ExePath, Kind: Rewritten})
	}
	rest := diffEntries(approved, now, approved.Files, now.Files)
	if approved.LibsV == 0 && len(now.Libs) > 0 {
		rest = append(rest, Change{Path: LibsPath, Kind: Unchecked})
	} else {
		rest = append(rest, diffEntries(approved, now, approved.Libs, now.Libs)...)
	}
	sort.Slice(rest, func(a, b int) bool { return rest[a].Path < rest[b].Path })
	return append(out, rest...)
}

// diffEntries compares one map of entries. An AbsentEntry is compared as a
// missing one: a place that held nothing and now holds a file is Added.
func diffEntries(approved, now Fingerprint, a, n map[string]string) []Change {
	var out []Change
	present := func(m map[string]string, k string) (string, bool) {
		v, ok := m[k]
		return v, ok && v != AbsentEntry
	}
	for p := range a {
		av, aok := present(a, p)
		nv, nok := present(n, p)
		switch {
		case !aok && nok:
			out = append(out, Change{Path: p, Kind: Added})
		case !aok:
		case !nok:
			out = append(out, Change{Path: p, Kind: Removed})
		case nv != av:
			out = append(out, Change{Path: p, Kind: Changed})
		case stampMoved(approved, now, p):
			out = append(out, Change{Path: p, Kind: Rewritten})
		}
	}
	for p := range n {
		if _, ok := a[p]; ok {
			continue
		}
		if _, nok := present(n, p); nok {
			out = append(out, Change{Path: p, Kind: Added})
		}
	}
	return out
}
