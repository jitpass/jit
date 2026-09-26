// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package job

import (
	"bufio"
	"crypto/sha256"
	"debug/macho"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

// This file fingerprints what a job's program loads from outside its folder
// (interp.go says what that is and why it is read from files):
//
//   - every file under each installation root, whole: the stdlib, its
//     lib-dynload, its site-packages, its bin folder (where a ._pth file or a
//     stdlib zip would appear), __pycache__ included. A run redirects its own
//     bytecode, but a child started with -I or a cleaned environment reads
//     the library's .pyc files, and a planted one whose header matches its
//     source runs instead of it: the folder's rule (fingerprint.go, skipDirs).
//   - a venv outside the job folder, the folders a site-packages .pth file
//     adds to sys.path (a path line, as editable installs by uv and pip
//     write), and a folder a symlink in any of these points at.
//   - the places the interpreter looks and finds nothing (a pyvenv.cfg beside
//     the executable, a ._pth file, Node's global folders), recorded as
//     absent, so one appearing stops the job.
//   - the native libraries every fingerprinted Mach-O links, through @rpath,
//     @loader_path and absolute paths, recursively: Homebrew's Python and
//     Node load dozens from /opt/homebrew, which the user can write. Every
//     place dyld would try is recorded, found or not. /usr/lib and /System
//     are left out: System Integrity Protection keeps them.

// AbsentEntry marks a place the program looks for code that held nothing at
// approval. One appearing there stops the job.
const AbsentEntry = "absent"

// unreadableEntry marks a library file or folder the user cannot read: the
// job, running as the user, cannot load it either.
const unreadableEntry = "unreadable"

// limitFiles and limitBytes are MaxFiles and MaxBytes, variables so a test
// can reach them without writing 20,000 files.
var (
	limitFiles       = MaxFiles
	limitBytes int64 = MaxBytes
)

// budget counts files and bytes across the folder and its libraries: the
// limits are per job.
type budget struct {
	dir   string
	files int
	bytes int64
}

func (b *budget) add(n int64) error {
	b.files++
	b.bytes += n
	if b.files > limitFiles {
		return fmt.Errorf("%s: with what its program loads from outside it, more than %d files: %w", b.dir, limitFiles, ErrTooLarge)
	}
	if b.bytes > limitBytes {
		return fmt.Errorf("%s: with what its program loads from outside it, more than %d MB: %w", b.dir, limitBytes>>20, ErrTooLarge)
	}
	return nil
}

// machoItem is a Mach-O file whose dependencies are still to be read, with
// the rpaths dyld would search for it: its loaders', resolved.
type machoItem struct {
	path   string
	rpaths []string
}

// libCollector gathers a Fingerprint's Libs.
type libCollector struct {
	realDir string
	outs    []string
	b       *budget
	entries map[string]string
	stamps  map[string]string
	// walked are the roots walked so far, resolved.
	walked []string
	// execDir is the folder of the process's main executable, for
	// @executable_path; mainRpaths are its rpaths, which dyld also searches
	// for everything the process loads.
	execDir    string
	mainRpaths []string
	machos     []machoItem
	machoSeen  map[string]map[string]bool
}

// collectLibs fingerprints what the program described by rt loads from
// outside realDir. folderMachOs are the Mach-O files the folder walk hashed.
func collectLibs(realDir string, outs []string, p Program, rt runtimeInfo, folderMachOs []string, b *budget) (map[string]string, map[string]string, error) {
	c := &libCollector{
		realDir: realDir, outs: outs, b: b,
		entries: map[string]string{}, stamps: map[string]string{},
		machoSeen: map[string]map[string]bool{},
	}
	mainExe, err := filepath.EvalSymlinks(rt.interp)
	if err != nil {
		mainExe, _ = filepath.EvalSymlinks(p.Exe)
	}
	if mainExe != "" {
		c.execDir = filepath.Dir(mainExe)
		if m, merr := readMachO(mainExe); merr == nil {
			c.mainRpaths = expandRpaths(m.rpaths, c.execDir, c.execDir)
		}
		c.queueMachO(mainExe, nil)
	}
	if realExe, rerr := filepath.EvalSymlinks(p.Exe); rerr == nil && realExe != mainExe {
		c.queueMachO(realExe, nil) // a #! script is no Mach-O; checked anyway
	}
	for _, f := range folderMachOs {
		c.queueMachO(f, nil)
	}

	// Named files and places: recorded after the walks, unless a walk has
	// them already. First the executable as started: outside the folder,
	// where it resolves is a fact of its own (re-pointing
	// /opt/homebrew/opt/python@3.13 moves the whole installation, even to an
	// identical binary).
	named := []string{p.Exe}
	var roots []string
	if rt.fromShebang {
		named = append(named, rt.interp)
	}
	// Places the program looks for code: recorded, and walked like a root
	// when they are a folder (Node's ~/.node_modules).
	var searched []string
	switch rt.kind {
	case kindPython:
		roots = append(roots, rt.python.roots...)
		if rt.python.venv != "" {
			if r, rerr := filepath.EvalSymlinks(rt.python.venv); rerr == nil {
				roots = append(roots, r)
			}
		}
		named = append(named, rt.python.probes...)
		named = append(named, rt.python.homes...)
		searched = append(searched, rt.python.sites...)
		var sites []string
		for _, pre := range append(append([]string(nil), rt.python.roots...), rt.python.venv) {
			if pre != "" {
				m, _ := filepath.Glob(filepath.Join(pre, "lib", "python3*", "site-packages"))
				sites = append(sites, m...)
			}
		}
		roots = append(roots, pthFolders(append(sites, rt.python.sites...))...)
	case kindNode:
		searched = append(searched, nodeProbes(realDir, mainExe, p.Home)...)
	}
	for _, n := range searched {
		if info, serr := os.Stat(n); serr == nil && info.IsDir() {
			if r, rerr := filepath.EvalSymlinks(n); rerr == nil {
				roots = append(roots, r)
			}
		}
	}
	named = append(named, searched...)

	for len(roots) > 0 {
		r := roots[0]
		roots = roots[1:]
		more, werr := c.walkRoot(r)
		if werr != nil {
			return nil, nil, werr
		}
		roots = append(roots, more...)
	}
	sort.Strings(named)
	for _, n := range named {
		if c.covered(n) {
			continue
		}
		if err := c.recordPath(n, nil); err != nil {
			return nil, nil, err
		}
	}
	if err := c.closure(); err != nil {
		return nil, nil, err
	}
	return c.entries, c.stamps, nil
}

// covered reports whether p is fingerprinted by the folder walk or a walk
// of a library root, so recording it again would only duplicate it.
func (c *libCollector) covered(p string) bool {
	if sipProtected(p) {
		return true
	}
	if inside(p, c.realDir) && !skippedPath(p, c.realDir, c.outs) {
		return true
	}
	for _, w := range c.walked {
		if inside(p, w) {
			return true
		}
	}
	return false
}

// walkRoot hashes every file under root, which is resolved. It returns the
// folders outside root that symlinks in it point at, to walk next.
func (c *libCollector) walkRoot(root string) ([]string, error) {
	if c.covered(root) {
		return nil, nil
	}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return nil, nil // gone: the entries it had are "removed" in a diff
	}
	c.walked = append(c.walked, root)
	var more []string
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrPermission) && path != root {
				// The job, running as the same user, cannot read it either.
				// Recorded, so it becoming readable is a change.
				c.entries[path] = unreadableEntry
				if d != nil && d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			return err
		}
		if d.IsDir() {
			if path == root {
				return nil
			}
			if path == c.realDir || c.isOtherRoot(path, root) {
				return filepath.SkipDir // fingerprinted by its own walk
			}
			return nil
		}
		switch {
		case d.Type()&fs.ModeSymlink != 0:
			target, lerr := os.Readlink(path)
			if lerr != nil {
				return lerr
			}
			c.entries[path] = "link:" + target
			if li, lerr := os.Lstat(path); lerr == nil {
				c.stamps[path] = ctimeStamp(li)
			}
			resolved, rerr := filepath.EvalSymlinks(path)
			if rerr != nil || inside(resolved, root) || c.covered(resolved) {
				return nil
			}
			ti, serr := os.Stat(resolved)
			switch {
			case serr != nil:
			case ti.IsDir():
				more = append(more, resolved)
			case ti.Mode().IsRegular():
				return c.hashInto(path+LinkTargetSuffix, resolved, nil)
			}
		case d.Type().IsRegular():
			// The walk's own lstat answers the cache without opening the
			// file: a hit costs one stat.
			if info, ierr := d.Info(); ierr == nil {
				if h, ok := cachedLibHash(path, info); ok {
					return c.take(path, path, h, nil)
				}
			}
			return c.hashInto(path, path, nil)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("fingerprinting %s: %w", root, err)
	}
	return more, nil
}

// isOtherRoot reports whether dir, met inside the walk of current, is the
// root of another walk.
func (c *libCollector) isOtherRoot(dir, current string) bool {
	for _, w := range c.walked {
		if w == dir && w != current {
			return true
		}
	}
	return false
}

// hashInto hashes file under key, counts it, and queues it when it is a
// Mach-O.
func (c *libCollector) hashInto(key, file string, rpaths []string) error {
	h, err := hashLibFile(file)
	if errors.Is(err, fs.ErrPermission) {
		c.entries[key] = unreadableEntry
		return nil
	}
	if err != nil {
		return err
	}
	return c.take(key, file, h, rpaths)
}

// take records a hashed file under key, counts it, and queues it when it is
// a Mach-O.
func (c *libCollector) take(key, file string, h fileHash, rpaths []string) error {
	if err := c.b.add(h.n); err != nil {
		return err
	}
	c.entries[key] = "sha256:" + h.sum
	c.stamps[key] = h.stamp
	if h.macho {
		c.queueMachO(file, rpaths)
	}
	return nil
}

// recordPath records one named place: absent, a folder, or a file's hash,
// with where it resolves when that differs from p (re-pointing a symlink on
// the way moves everything the interpreter finds from it).
func (c *libCollector) recordPath(p string, rpaths []string) error {
	resolved, err := filepath.EvalSymlinks(p)
	if err != nil {
		if _, lerr := os.Lstat(p); lerr == nil {
			// A dangling link: where it points is the fact.
			target, _ := os.Readlink(p)
			c.entries[p] = "link:" + target
			return nil
		}
		c.entries[p] = AbsentEntry
		return nil
	}
	via := ""
	if resolved != p {
		via = " @ " + resolved
	}
	info, err := os.Stat(resolved)
	if err != nil {
		c.entries[p] = AbsentEntry
		return nil
	}
	if !info.Mode().IsRegular() {
		kind := "other"
		if info.IsDir() {
			kind = "dir"
		}
		c.entries[p] = kind + via
		return nil
	}
	if err := c.hashInto(p, resolved, rpaths); err != nil {
		return err
	}
	c.entries[p] += via
	return nil
}

func (c *libCollector) queueMachO(path string, rpaths []string) {
	seen := c.machoSeen[path]
	if seen == nil {
		seen = map[string]bool{}
		c.machoSeen[path] = seen
	} else {
		fresh := false
		for _, r := range rpaths {
			if !seen[r] {
				fresh = true
			}
		}
		if !fresh {
			return
		}
	}
	for _, r := range rpaths {
		seen[r] = true
	}
	c.machos = append(c.machos, machoItem{path: path, rpaths: rpaths})
}

// closure records every library each queued Mach-O links, and theirs, at
// every place dyld would try.
func (c *libCollector) closure() error {
	for len(c.machos) > 0 {
		item := c.machos[0]
		c.machos = c.machos[1:]
		m, err := readMachO(item.path)
		if errors.Is(err, errNotMachO) {
			continue
		}
		if err != nil {
			return fmt.Errorf("%s: a native library jit cannot read, so what it loads cannot be fingerprinted: %w", item.path, err)
		}
		dir := filepath.Dir(item.path)
		// dyld searches the image's own rpaths, then its loaders', then the
		// main executable's.
		rpaths := uniq(append(append(expandRpaths(m.rpaths, dir, c.execDir), item.rpaths...), c.mainRpaths...))
		for _, dep := range m.deps {
			for _, cand := range dylibCandidates(dep, dir, c.execDir, rpaths) {
				if c.covered(cand) {
					// Hashed by a walk, which queued it with the main
					// executable's rpaths; its loaders' may add more.
					if r, rerr := filepath.EvalSymlinks(cand); rerr == nil {
						c.queueMachO(r, rpaths)
					}
					continue
				}
				if _, done := c.entries[cand]; done {
					if r, rerr := filepath.EvalSymlinks(cand); rerr == nil {
						c.queueMachO(r, rpaths)
					}
					continue
				}
				if err := c.recordPath(cand, rpaths); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// uniq drops repeats, keeping the first of each: dyld's search order.
func uniq(list []string) []string {
	seen := make(map[string]bool, len(list))
	out := list[:0]
	for _, s := range list {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// pthFolders reads the .pth files of the given site-packages folders and
// returns the folders their path lines add to sys.path, resolved. Lines that
// import are code, and the .pth holding them is fingerprinted with its
// folder; what they import is found on sys.path like any module.
func pthFolders(sites []string) []string {
	var out []string
	{
		for _, site := range sites {
			pths, _ := filepath.Glob(filepath.Join(site, "*.pth"))
			sort.Strings(pths)
			for _, pth := range pths {
				f, err := openRegular(pth)
				if err != nil {
					continue
				}
				sc := bufio.NewScanner(f)
				for sc.Scan() {
					line := strings.TrimRight(sc.Text(), " \t\r")
					if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "import ") || strings.HasPrefix(line, "import\t") {
						continue
					}
					p := line
					if !filepath.IsAbs(p) {
						p = filepath.Join(site, p)
					}
					if info, serr := os.Stat(p); serr == nil && info.IsDir() {
						if r, rerr := filepath.EvalSymlinks(p); rerr == nil {
							out = append(out, r)
						}
					}
				}
				_ = f.Close()
			}
		}
	}
	return out
}

// nodeProbes are the places Node looks for a package outside the folder: a
// node_modules and a package.json in every folder above it, and its global
// folders ($HOME/.node_modules, $HOME/.node_libraries, <prefix>/lib/node).
func nodeProbes(realDir, realNode, home string) []string {
	var out []string
	for d := filepath.Dir(realDir); ; d = filepath.Dir(d) {
		out = append(out, filepath.Join(d, "node_modules"), filepath.Join(d, "package.json"))
		if filepath.Dir(d) == d {
			break
		}
	}
	if home != "" {
		out = append(out, filepath.Join(home, ".node_modules"), filepath.Join(home, ".node_libraries"))
	}
	if realNode != "" {
		out = append(out, filepath.Join(filepath.Dir(filepath.Dir(realNode)), "lib", "node"))
	}
	return out
}

// sipProtected reports whether System Integrity Protection keeps p: not even
// root can change it while SIP is on, so it is left out (and on current
// macOS the system's dylibs are not on disk at all). /usr/local is not SIP's,
// nor is /System/Volumes, where the Data volume (and so every home folder)
// is reachable. Compared without case, as APFS compares names: a mixed-case
// spelling of an exception must not pass for protected.
func sipProtected(p string) bool {
	lp := strings.ToLower(filepath.Clean(p))
	for _, ex := range []string{"/usr/local", "/system/volumes"} {
		if lp == ex || strings.HasPrefix(lp, ex+"/") {
			return false
		}
	}
	for _, pre := range []string{"/system/", "/bin/", "/sbin/", "/usr/"} {
		if strings.HasPrefix(lp, pre) {
			return true
		}
	}
	return false
}

var errNotMachO = errors.New("not a Mach-O file")

// machoInfo is what a Mach-O file says it loads: the dylib paths of its load
// commands, as written, and its LC_RPATH entries, as written.
type machoInfo struct {
	deps   []string
	rpaths []string
}

// Load commands that name a dylib to load, and LC_RPATH. debug/macho decodes
// only LC_LOAD_DYLIB, so all of them are read from their raw bytes, the same
// way.
const (
	lcLoadDylib     = 0xc
	lcLoadWeakDylib = 0x18 | 0x80000000
	lcRpath         = 0x1c | 0x80000000
	lcReexportDylib = 0x1f | 0x80000000
	lcLazyLoadDylib = 0x20
	lcLoadUpward    = 0x23 | 0x80000000
)

// readMachO reads path's load commands, from every architecture of a
// universal file. errNotMachO for anything else, including a Java class file
// (which shares the universal magic).
func readMachO(path string) (machoInfo, error) {
	f, err := openRegular(path)
	if err != nil {
		return machoInfo{}, err
	}
	defer f.Close()
	// debug/macho reads the symbol table too, which for Homebrew Node's 160
	// dylibs is most of a check's time: the load commands are cached under
	// the library cache's rule.
	info, err := f.Stat()
	if err != nil {
		return machoInfo{}, err
	}
	key, keyed := statKeyOf(info)
	if keyed {
		libCacheMu.Lock()
		hit, ok := machoCache[path]
		libCacheMu.Unlock()
		if ok && hit.key == key {
			return hit.info, hit.err
		}
	}
	start := time.Now()
	m, err := parseMachO(f)
	if keyed && (err == nil || errors.Is(err, errNotMachO)) {
		if after, aerr := f.Stat(); aerr == nil {
			if k2, ok := statKeyOf(after); ok && k2 == key && key.ctime < start.Add(-racyWindow).UnixNano() {
				libCacheMu.Lock()
				if len(machoCache) >= libCacheLimit {
					machoCache = map[string]cachedMachO{}
				}
				machoCache[path] = cachedMachO{key: key, info: m, err: err}
				libCacheMu.Unlock()
			}
		}
	}
	return m, err
}

type cachedMachO struct {
	key  statKey
	info machoInfo
	err  error
}

var machoCache = map[string]cachedMachO{}

func parseMachO(f *os.File) (machoInfo, error) {
	var magic [4]byte
	if _, err := io.ReadFull(f, magic[:]); err != nil {
		return machoInfo{}, errNotMachO
	}
	var files []*macho.File
	switch binary.BigEndian.Uint32(magic[:]) {
	case 0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe:
		mf, err := macho.NewFile(f)
		if err != nil {
			return machoInfo{}, err
		}
		files = append(files, mf)
	case 0xcafebabe, 0xcafebabf, 0xbebafeca:
		ff, err := macho.NewFatFile(f)
		if err != nil {
			return machoInfo{}, errNotMachO
		}
		for _, a := range ff.Arches {
			files = append(files, a.File)
		}
	default:
		return machoInfo{}, errNotMachO
	}
	var out machoInfo
	seen := map[string]bool{}
	for _, mf := range files {
		for _, l := range mf.Loads {
			raw := l.Raw()
			if len(raw) < 12 {
				continue
			}
			cmd := mf.ByteOrder.Uint32(raw[0:4])
			off := mf.ByteOrder.Uint32(raw[8:12])
			if int(off) >= len(raw) {
				continue
			}
			s := raw[off:]
			if i := strings.IndexByte(string(s), 0); i >= 0 {
				s = s[:i]
			}
			name := string(s)
			switch cmd {
			case lcLoadDylib, lcLoadWeakDylib, lcReexportDylib, lcLazyLoadDylib, lcLoadUpward:
				if !seen["d"+name] {
					seen["d"+name] = true
					out.deps = append(out.deps, name)
				}
			case lcRpath:
				if !seen["r"+name] {
					seen["r"+name] = true
					out.rpaths = append(out.rpaths, name)
				}
			}
		}
	}
	return out, nil
}

// expandRpaths makes LC_RPATH entries absolute: @loader_path is the folder
// of the image that declared them, @executable_path the main executable's.
func expandRpaths(raw []string, loaderDir, execDir string) []string {
	out := make([]string, 0, len(raw))
	for _, r := range raw {
		switch {
		case strings.HasPrefix(r, "@loader_path"):
			r = filepath.Join(loaderDir, strings.TrimPrefix(r, "@loader_path"))
		case strings.HasPrefix(r, "@executable_path"):
			r = filepath.Join(execDir, strings.TrimPrefix(r, "@executable_path"))
		case !filepath.IsAbs(r):
			continue // relative to the process's working folder: dyld refuses those now
		}
		out = append(out, filepath.Clean(r))
	}
	return out
}

// dylibCandidates lists every file dyld may try for dep, in its order. A
// system library (/usr/lib, /System) gives none.
func dylibCandidates(dep, loaderDir, execDir string, rpaths []string) []string {
	var out []string
	switch {
	case strings.HasPrefix(dep, "@rpath/"):
		rest := strings.TrimPrefix(dep, "@rpath/")
		for _, r := range rpaths {
			out = append(out, filepath.Join(r, rest))
		}
	case strings.HasPrefix(dep, "@loader_path/"):
		out = append(out, filepath.Join(loaderDir, strings.TrimPrefix(dep, "@loader_path/")))
	case strings.HasPrefix(dep, "@executable_path/"):
		out = append(out, filepath.Join(execDir, strings.TrimPrefix(dep, "@executable_path/")))
	case filepath.IsAbs(dep):
		out = append(out, filepath.Clean(dep))
	}
	kept := out[:0]
	for _, p := range out {
		if !sipProtected(p) {
			kept = append(kept, p)
		}
	}
	return kept
}

// fileHash is one hashed file.
type fileHash struct {
	sum   string
	n     int64
	stamp string
	macho bool
}

// hashReader hashes f from its start and says whether it begins with a
// Mach-O magic.
func hashReader(f *os.File) (sum string, n int64, isMachO bool, err error) {
	h := sha256.New()
	var head [4]byte
	k, err := io.ReadFull(f, head[:])
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return "", 0, false, err
	}
	h.Write(head[:k])
	if k == 4 {
		switch binary.BigEndian.Uint32(head[:]) {
		case 0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe, 0xcafebabe, 0xcafebabf, 0xbebafeca:
			isMachO = true
		}
	}
	rest, err := io.Copy(h, f)
	if err != nil {
		return "", 0, false, err
	}
	return hex.EncodeToString(h.Sum(nil)), int64(k) + rest, isMachO, nil
}

func ctimeStamp(info os.FileInfo) string {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return fmt.Sprintf("%d.%09d", st.Ctimespec.Sec, st.Ctimespec.Nsec)
	}
	return ""
}

// The library cache. An interpreter's installation is thousands of files,
// and a run checks the fingerprint three times, so a library file whose
// stat is unchanged is not read again. The key is what a same-user process
// cannot forge: the inode and device, the size, the modification time and
// the CHANGE time. Only the kernel sets a change-time, to the current time,
// on every write, rename and metadata change; a file rewritten and put back,
// with its modification time reset, still has a new one (the Stamps rule).
// And a file is cached only when its change-time is older than racyWindow
// before the read began, so a write landing during the read (which could
// share the change-time's clock tick) always gives a different key. Only
// library files are cached; the folder's own walk reads every file.
type statKey struct {
	dev, ino     uint64
	size         int64
	mtime, ctime int64
}

type cachedHash struct {
	key   statKey
	sum   string
	macho bool
}

var (
	libCache      = map[string]cachedHash{}
	libCacheMu    sync.Mutex
	racyWindow    = 2 * time.Second
	libCacheLimit = 200000
)

// cachedLibHash answers from the cache when path's stat, info, is the one
// the cached hash was taken at.
func cachedLibHash(path string, info os.FileInfo) (fileHash, bool) {
	key, ok := statKeyOf(info)
	if !ok || !info.Mode().IsRegular() {
		return fileHash{}, false
	}
	libCacheMu.Lock()
	hit, ok := libCache[path]
	libCacheMu.Unlock()
	if !ok || hit.key != key {
		return fileHash{}, false
	}
	return fileHash{sum: hit.sum, n: key.size, stamp: ctimeStamp(info), macho: hit.macho}, true
}

func statKeyOf(info os.FileInfo) (statKey, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return statKey{}, false
	}
	return statKey{
		dev: uint64(st.Dev), ino: st.Ino, size: st.Size, // #nosec G115 -- a device number, compared for equality only
		mtime: st.Mtimespec.Nano(), ctime: st.Ctimespec.Nano(),
	}, true
}

// hashLibFile hashes one library file (following symlinks), from the cache
// when its stat is unchanged.
func hashLibFile(path string) (fileHash, error) {
	f, err := openRegular(path)
	if err != nil {
		return fileHash{}, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return fileHash{}, err
	}
	if h, ok := cachedLibHash(path, info); ok {
		return h, nil
	}
	stamp := ctimeStamp(info)
	key, keyed := statKeyOf(info)
	start := time.Now()
	sum, n, isMachO, err := hashReader(f)
	if err != nil {
		return fileHash{}, err
	}
	if keyed {
		if after, aerr := f.Stat(); aerr == nil {
			if k2, ok := statKeyOf(after); ok && k2 == key && key.ctime < start.Add(-racyWindow).UnixNano() {
				libCacheMu.Lock()
				if len(libCache) >= libCacheLimit {
					libCache = map[string]cachedHash{}
				}
				libCache[path] = cachedHash{key: key, sum: sum, macho: isMachO}
				libCacheMu.Unlock()
			}
		}
	}
	return fileHash{sum: sum, n: n, stamp: stamp, macho: isMachO}, nil
}
