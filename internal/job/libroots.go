// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package job

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/jitpass/jit/internal/atomicfile"
)

// This file is how a fingerprint stores what the program loads from outside
// its folder (libs.go collects it). A Python job's interpreter is about two
// thousand files; one entry per file in jobs.json was about 700 KB per job,
// rewritten after every run. So jobs.json holds one entry per library ROOT:
//
//   - a folder walked whole (an installation prefix, a venv outside the
//     folder, a folder a .pth file adds, a folder a symlink points at):
//     one hash over the listing of every entry under it, sorted by path,
//     each entry its path relative to the root, its mode, its size and its
//     content hash (or link target, or "absent", or "unreadable"); and one
//     hash over the same paths' change-times, the Stamps rule.
//   - a place recorded on its own (a dylib, a pyvenv.cfg that is not there,
//     where a symlink resolves): the same two hashes over its one entry.
//
// Whether a job may run is decided from those hashes alone: the approved
// ones in jobs.json against the ones just computed from disk. To NAME the
// file that changed, the per-file listing of each walked folder is kept in
// a manifest outside jobs.json (LibManifests), keyed by the root's hashes.
// A manifest is used only when its own listing hashes to the approved root
// hash, so it cannot make a changed library look unchanged, nor blame the
// wrong file; a missing or damaged one only costs the name, and the stop
// then names the folder.

// libsVersion is a fingerprint's LibsV since libraries are stored per root.
const libsVersion = 2

// LibRoot is one library root of a fingerprint, as jobs.json holds it.
type LibRoot struct {
	// Sum is one hash over the root's listing: each entry's path relative
	// to the root (empty for a root that is one place), its mode, its size
	// and its value as Libs holds it, sorted by path.
	Sum string `json:"sum"`
	// Stamps is one hash over each entry's path and change-time: a file
	// rewritten and put back moves it while Sum stays (Rewritten).
	Stamps string `json:"stamps,omitempty"`
	// Files counts the regular files hashed under it.
	Files int `json:"files,omitempty"`
	// Dir is set for a folder walked whole, whose listing a manifest keeps.
	Dir bool `json:"dir,omitempty"`
}

// libMeta is a library entry's mode and size, for its root's listing.
type libMeta struct {
	mode fs.FileMode
	size int64
}

// libLine is one entry of a root's listing, as a manifest stores it.
type libLine struct {
	Rel   string `json:"p"`
	Mode  uint32 `json:"m,omitempty"`
	Size  int64  `json:"s,omitempty"`
	Val   string `json:"v"`
	Stamp string `json:"t,omitempty"`
}

// libSet is what collectLibs gathered: every entry by absolute path, and
// the folders it walked.
type libSet struct {
	entries map[string]string
	stamps  map[string]string
	meta    map[string]libMeta
	walked  []string
}

// group sorts the entries into roots: an entry under a walked folder
// belongs to the deepest one, and any other entry is a root of its own.
func (s libSet) group() (map[string]LibRoot, map[string][]libLine) {
	walked := append([]string(nil), s.walked...)
	sort.Slice(walked, func(a, b int) bool { return len(walked[a]) > len(walked[b]) })
	lines := make(map[string][]libLine, len(walked))
	dirs := make(map[string]bool, len(walked))
	for _, w := range walked {
		lines[w] = []libLine{} // walked, even if it held nothing
		dirs[w] = true
	}
	for k, v := range s.entries {
		root, rel := k, ""
		for _, w := range walked {
			if inside(k, w) {
				root = w
				rel = strings.TrimPrefix(strings.TrimPrefix(k, w), string(filepath.Separator))
				break
			}
		}
		m := s.meta[k]
		lines[root] = append(lines[root], libLine{Rel: rel, Mode: uint32(m.mode), Size: m.size, Val: v, Stamp: s.stamps[k]})
	}
	roots := make(map[string]LibRoot, len(lines))
	for r, ls := range lines {
		sortLines(ls)
		roots[r] = rootOf(ls, dirs[r])
	}
	return roots, lines
}

func sortLines(ls []libLine) {
	sort.Slice(ls, func(a, b int) bool { return ls[a].Rel < ls[b].Rel })
}

// rootOf is the LibRoot of a sorted listing.
func rootOf(ls []libLine, dir bool) LibRoot {
	sum, stamps := sha256.New(), sha256.New()
	files := 0
	for _, l := range ls {
		field(sum, l.Rel)
		field(sum, strconv.FormatUint(uint64(l.Mode), 8))
		field(sum, strconv.FormatInt(l.Size, 10))
		field(sum, l.Val)
		field(stamps, l.Rel)
		field(stamps, l.Stamp)
		if strings.HasPrefix(l.Val, "sha256:") {
			files++
		}
	}
	return LibRoot{Sum: hex.EncodeToString(sum.Sum(nil)), Stamps: hex.EncodeToString(stamps.Sum(nil)), Files: files, Dir: dir}
}

// field writes s length-prefixed: a path or a link target may hold any byte
// but NUL, a newline included, so no separator alone keeps two different
// listings from writing the same bytes.
func field(h hash.Hash, s string) {
	_, _ = fmt.Fprintf(h, "%d:%s;", len(s), s)
}

// LibraryFiles counts the files fp holds from outside the folder: the
// regular files hashed under its library roots.
func (fp Fingerprint) LibraryFiles() int {
	n := 0
	for _, r := range fp.LibRoots {
		n += r.Files
	}
	return n
}

// Compact is fp as jobs.json holds it: without the per-file lists Compute
// kept (Libs), which LibManifests.Save keeps outside jobs.json.
func (fp Fingerprint) Compact() Fingerprint {
	fp.Libs, fp.libLines = nil, nil
	return fp
}

// LibManifests is the folder of library manifests: for each walked library
// root, the listing its hash was taken over, so a stop can name the file
// that changed. A cache, never a decision: see this file's head. Empty
// means none.
type LibManifests string

// LibManifestDir is where the service keeps them: jit's own directory,
// beside jobs.json, which no sandbox is given.
func LibManifestDir(root string) string {
	return filepath.Join(root, "job-libraries")
}

// manifestVersion is the manifest file's shape.
const manifestVersion = 1

// maxManifest bounds a manifest read: MaxFiles entries of a few hundred
// bytes each, with room to spare.
const maxManifest = 64 << 20

type libManifest struct {
	Version int       `json:"version"`
	Files   []libLine `json:"files"`
}

// manifestName is the file a root's manifest is kept in: named by both of
// its hashes, so jobs whose program loads the same unchanged installation
// share one.
func (r LibRoot) manifestName() string {
	h := sha256.Sum256([]byte(r.Sum + ":" + r.Stamps))
	return hex.EncodeToString(h[:]) + ".json"
}

func isManifestName(name string) bool {
	if len(name) != 64+len(".json") || !strings.HasSuffix(name, ".json") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimSuffix(name, ".json"))
	return err == nil
}

// Save keeps a manifest for every walked root of fp, a fingerprint Compute
// returned, that has none yet. Each is written atomically, mode 0600. A
// failure costs only the file's name in a later stop.
func (m LibManifests) Save(fp Fingerprint) error {
	if m == "" {
		return nil
	}
	var errs []error
	for r, root := range fp.LibRoots {
		ls, ok := fp.libLines[r]
		if !root.Dir || !ok {
			continue
		}
		if _, ok := m.load(root); ok {
			continue
		}
		data, err := json.Marshal(libManifest{Version: manifestVersion, Files: ls})
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if err := atomicfile.WriteFile(filepath.Join(string(m), root.manifestName()), data); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Keep deletes every manifest that none of fps names.
func (m LibManifests) Keep(fps []Fingerprint) error {
	if m == "" {
		return nil
	}
	want := map[string]bool{}
	for _, fp := range fps {
		for _, r := range fp.LibRoots {
			if r.Dir {
				want[r.manifestName()] = true
			}
		}
	}
	entries, err := os.ReadDir(string(m))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var errs []error
	for _, e := range entries {
		if !isManifestName(e.Name()) || want[e.Name()] {
			continue
		}
		if err := os.Remove(filepath.Join(string(m), e.Name())); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// load reads root's manifest, and returns its listing only when that
// listing hashes to root's own hashes: anything else (missing, damaged,
// planted, a FIFO in its place) is no manifest.
func (m LibManifests) load(root LibRoot) ([]libLine, bool) {
	if m == "" {
		return nil, false
	}
	f, err := openRegular(filepath.Join(string(m), root.manifestName()))
	if err != nil {
		return nil, false
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxManifest+1))
	if err != nil || len(data) > maxManifest {
		return nil, false
	}
	var mf libManifest
	if json.Unmarshal(data, &mf) != nil || mf.Version != manifestVersion {
		return nil, false
	}
	sortLines(mf.Files)
	if rootOf(mf.Files, root.Dir) != root {
		return nil, false
	}
	return mf.Files, true
}

// absentLine is the listing of a place recorded on its own that held
// nothing.
var absentLine = []libLine{{Val: AbsentEntry}}

// approvedLines is root r's listing at approval, when something trusted
// says it: approved's own lists (a fingerprint Compute returned), a single
// place's listing when that place held nothing, or a manifest. Each is
// checked against approved's hashes for r first.
func (m LibManifests) approvedLines(approved Fingerprint, r string, root LibRoot) ([]libLine, bool) {
	if ls, ok := approved.libLines[r]; ok && rootOf(ls, root.Dir) == root {
		return ls, true
	}
	if !root.Dir && rootOf(absentLine, false) == root {
		return absentLine, true
	}
	if root.Dir {
		return m.load(root)
	}
	return nil, false
}

// diffLibs compares approved's library roots with now's. A root whose
// hashes match is unchanged. One that does not is named file by file when
// its approved listing is known; otherwise, or when the listings name
// nothing, the change is the root itself, so a mismatch stops the job
// unless the root held nothing then and holds nothing now.
func (m LibManifests) diffLibs(approved, now Fingerprint) []Change {
	keys := make([]string, 0, len(approved.LibRoots)+len(now.LibRoots))
	for r := range approved.LibRoots {
		keys = append(keys, r)
	}
	for r := range now.LibRoots {
		if _, ok := approved.LibRoots[r]; !ok {
			keys = append(keys, r)
		}
	}
	sort.Strings(keys)
	var out []Change
	for _, r := range keys {
		a, aok := approved.LibRoots[r]
		n, nok := now.LibRoots[r]
		if aok && nok && a == n {
			continue
		}
		nowLines, nowKnown := now.libLines[r]
		if !nok {
			nowLines, nowKnown = nil, true
		}
		var aLines []libLine
		aKnown := true
		if aok {
			aLines, aKnown = m.approvedLines(approved, r, a)
		}
		if aKnown && nowKnown {
			// Both listings are known and hash as recorded, so they differ
			// exactly where the hashes do.
			if cs := diffLines(r, aLines, nowLines); len(cs) > 0 {
				out = append(out, cs...)
				continue
			}
			// Nothing to name: fine only when neither side held anything
			// (a place still empty, or no longer looked at). Otherwise the
			// hashes differ and the job stops on the root, whatever the
			// listings say.
			if !holdsAnything(aLines) && !holdsAnything(nowLines) {
				continue
			}
		}
		out = append(out, rootChange(r, a, aok, n, nok, nowLines))
	}
	return out
}

// holdsAnything reports whether a listing has an entry that is not a place
// recorded empty.
func holdsAnything(ls []libLine) bool {
	for _, l := range ls {
		if l.Val != AbsentEntry {
			return true
		}
	}
	return false
}

// diffLines names each difference between two listings of root. A place
// that held nothing compares as a missing one, as diffEntries does.
func diffLines(root string, a, n []libLine) []Change {
	present := func(ls []libLine) map[string]libLine {
		out := make(map[string]libLine, len(ls))
		for _, l := range ls {
			if l.Val != AbsentEntry {
				out[l.Rel] = l
			}
		}
		return out
	}
	am, nm := present(a), present(n)
	path := func(rel string) string {
		if rel == "" {
			return root
		}
		return root + string(filepath.Separator) + rel
	}
	var out []Change
	for rel, al := range am {
		nl, ok := nm[rel]
		switch {
		case !ok:
			out = append(out, Change{Path: path(rel), Kind: Removed})
		case nl.Val != al.Val || nl.Mode != al.Mode || nl.Size != al.Size:
			out = append(out, Change{Path: path(rel), Kind: Changed})
		case al.Stamp != "" && nl.Stamp != al.Stamp:
			out = append(out, Change{Path: path(rel), Kind: Rewritten})
		}
	}
	for rel := range nm {
		if _, ok := am[rel]; !ok {
			out = append(out, Change{Path: path(rel), Kind: Added})
		}
	}
	return out
}

// rootChange is the one change a root whose approved listing is not known
// reports: the root is named, never passed over.
func rootChange(r string, a LibRoot, aok bool, n LibRoot, nok bool, nowLines []libLine) Change {
	switch {
	case !aok:
		return Change{Path: r, Kind: Added}
	case !nok:
		return Change{Path: r, Kind: Removed}
	case a.Dir && n.Dir && a.Sum == n.Sum:
		return Change{Path: r, Kind: FolderRewritten}
	case a.Dir:
		return Change{Path: r, Kind: FolderChanged}
	case len(nowLines) == 0 || len(nowLines) == 1 && nowLines[0].Val == AbsentEntry:
		return Change{Path: r, Kind: Removed}
	case a.Sum == n.Sum:
		return Change{Path: r, Kind: Rewritten}
	}
	return Change{Path: r, Kind: Changed}
}
