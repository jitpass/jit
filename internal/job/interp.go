// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package job

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// This file decides WHAT a job's program loads from outside its folder, so
// libs.go can fingerprint it. The job folder and the executable were always
// fingerprinted; the interpreter's own standard library and site-packages
// were not, although the interpreter runs them with the secrets in its
// environment, and they usually sit somewhere the user (and so any agent
// running as the user) can write: uv's and pyenv's Pythons under the home
// folder, Homebrew's under /opt/homebrew.
//
// Nothing here runs the program. Asking the interpreter (`python -I -S -c
// "import sys; print(sys.path)"`) would be exact, but it executes code from
// the very tree being checked (Python imports its encodings package before
// any -c runs), and it would do so before the Touch ID: approval checks run
// for any process that reaches the socket, and a preview must never start a
// program the human has not approved as the service's own child. So the
// layout is read from files, the way the interpreter itself finds it
// (pyvenv.cfg, the stdlib landmark, the Mach-O load commands), and every
// file that reading depends on is fingerprinted too. The reading only has to
// be right on the day of approval: after that, anything that could change
// its answer is a fingerprinted file, and changing it stops the job.

// Program is what a job starts: the executable its argv resolved to
// (ResolveExe), the argv, and the approving shell's PATH and HOME, which
// decide where an interpreter looks for code.
type Program struct {
	Exe     string
	Argv    []string
	PathEnv string
	Home    string
}

type runtimeKind int

const (
	// kindProgram is anything jit does not know as an interpreter: its
	// executable and the native libraries it links are fingerprinted, and
	// what it chooses to read when it runs is its own business, like any
	// program on PATH.
	kindProgram runtimeKind = iota
	kindPython
	kindNode
	kindShell
)

// runtimeInfo is what classify found.
type runtimeInfo struct {
	kind runtimeKind
	// interp is the interpreter as it is started, NOT resolved through
	// symlinks: a venv's bin/python finds its venv from that path. For a
	// script with a #! line it is the line's interpreter; else the exe.
	interp string
	// fromShebang is set when interp came from the exe's #! line, and so is
	// a file outside the fingerprinted executable.
	fromShebang bool
	// python is the installation found for kindPython.
	python pythonLayout
	// gap, when set, is why jit cannot fingerprint everything the program
	// loads from outside the folder. A job with a gap may not run unasked.
	gap string
}

// launchers pick the interpreter, or build the code, when they run: what
// they start is decided then, from places outside the folder, so the
// approval cannot have fingerprinted it. Each says what it picks.
var launchers = func() map[string]string {
	m := map[string]string{}
	for what, names := range map[string][]string{
		"picks the Python it runs":      {"uv", "uvx", "poetry", "pipenv", "pdm", "hatch", "rye", "pixi", "conda", "mamba", "micromamba", "pyenv", "pipx"},
		"picks the packages it runs":    {"npx", "npm", "pnpm", "pnpx", "yarn", "bunx", "corepack"},
		"picks the Node it runs":        {"volta", "nodenv"},
		"picks the interpreter it runs": {"asdf", "mise", "rtx"},
		"picks the Ruby code it runs":   {"rbenv", "bundle", "bundler", "rake", "gem"},
		"builds the code it runs":       {"go", "cargo"},
	} {
		for _, n := range names {
			m[n] = what
		}
	}
	return m
}()

// Unfingerprinted says why jit cannot fingerprint everything the program
// loads from outside dir, or "" when it can: the folder, the executable, the
// native libraries it links, and for Python, Node and the shells the places
// they load code from. A job with a reason may not run unasked, and the
// approval says so.
func Unfingerprinted(dir string, p Program) string {
	return classify(ResolvePath(dir), p).gap
}

// classify reads what p is. realDir is the resolved job folder.
func classify(realDir string, p Program) runtimeInfo {
	info := runtimeInfo{kind: kindProgram, interp: p.Exe}
	real, err := filepath.EvalSymlinks(p.Exe)
	if err != nil {
		// Compute fails on the executable anyway; nothing to add here.
		return info
	}
	script := ""
	if line, ok := readShebang(real); ok {
		if f := family(p.Exe); f == "python" || f == "node" {
			// Named like the interpreter but a script: a version manager's
			// shim (pyenv, asdf, volta), which picks the real one when it
			// runs. Following its #! would find only the shell it runs in.
			info.gap = fmt.Sprintf("%s is a script that picks the interpreter when it runs (a version manager's shim?), so jit can't fingerprint the one it picks", p.Exe)
			return info
		}
		ip, serr := shebangInterpreter(line, realDir, p.PathEnv)
		if serr != nil {
			info.gap = fmt.Sprintf("%s starts %s, and jit can't tell which program that is", filepath.Base(p.Exe), serr)
			return info
		}
		info.interp, info.fromShebang, script = ip, true, real
	}
	name := filepath.Base(info.interp)
	if what, ok := launchers[strings.ToLower(name)]; ok {
		info.gap = fmt.Sprintf("%s %s when the job starts, so jit can't fingerprint what that loads", name, what)
		return info
	}
	fam := family(info.interp)
	if _, known := inlineFlags[fam]; !known && fam != "python" {
		// A name jit does not know (python3.14 is known by prefix): try the
		// file it resolves to, so a link named after nothing still counts.
		if r, rerr := filepath.EvalSymlinks(info.interp); rerr == nil {
			if f := family(r); f == "python" || f == "node" || f == "sh" {
				fam = f
			}
		}
	}
	switch fam {
	case "python", "node", "sh":
	default:
		if _, known := inlineFlags[fam]; known {
			info.gap = fmt.Sprintf("%s loads libraries from outside the job's folder that jit does not fingerprint", name)
		}
		return info
	}

	realInterp, err := filepath.EvalSymlinks(info.interp)
	if err != nil {
		info.gap = fmt.Sprintf("%s is not there, so jit can't fingerprint the program that runs the job", info.interp)
		return info
	}
	if _, ok := readShebang(realInterp); ok {
		// A version manager's shim (pyenv, asdf, volta): a script that picks
		// the real interpreter when it runs.
		info.gap = fmt.Sprintf("%s is a script that picks the interpreter when it runs (a version manager's shim?), so jit can't fingerprint the one it picks", info.interp)
		return info
	}
	if fam == "sh" {
		info.kind = kindShell
		return info
	}
	lang := map[string]string{"python": "Python", "node": "Node"}[fam]
	if script == "" && !info.fromShebang {
		if prog := scanArgs(p.Argv).program; prog != "" {
			if !filepath.IsAbs(prog) {
				prog = filepath.Join(realDir, prog)
			}
			if r, rerr := filepath.EvalSymlinks(prog); rerr == nil {
				script = r
			}
		}
	}
	if script != "" && !inside(script, realDir) {
		// Python puts the script's own folder first on sys.path, and Node
		// resolves a relative require from it: that folder is code too.
		info.gap = fmt.Sprintf("%s is outside the job's folder, and %s loads modules from the script's own folder, which jit does not fingerprint", script, lang)
		return info
	}
	if fam == "node" {
		info.kind = kindNode
		return info
	}
	info.kind = kindPython
	info.python = findPython(info.interp, realInterp)
	if len(info.python.roots) == 0 {
		info.gap = fmt.Sprintf("jit can't find the Python installation %s starts (a launcher that picks one when it runs?), so it can't fingerprint that Python's libraries", info.interp)
	}
	return info
}

// readShebang returns the #! line of path, if it has one. It opens without
// blocking and reads only a regular file, hashFileStamp's rule.
func readShebang(path string) (string, bool) {
	f, err := openRegular(path)
	if err != nil {
		return "", false
	}
	defer f.Close()
	line, err := bufio.NewReaderSize(f, 512).ReadSlice('\n')
	if err != nil && len(line) == 0 {
		return "", false
	}
	if !strings.HasPrefix(string(line), "#!") {
		return "", false
	}
	return strings.TrimSpace(strings.TrimPrefix(string(line), "#!")), true
}

// shebangInterpreter names the program a #! line starts: its path, or for
// `/usr/bin/env NAME` the NAME found on the job's PATH, as env would find it.
// The error completes "<script> starts ___".
func shebangInterpreter(line, dir, pathEnv string) (string, error) {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return "", fmt.Errorf("an empty #! line")
	}
	ip := fields[0]
	if filepath.Base(ip) != "env" {
		if !filepath.IsAbs(ip) {
			ip = filepath.Join(dir, ip)
		}
		return ip, nil
	}
	for _, f := range fields[1:] {
		switch {
		case f == "-S":
			continue
		case strings.HasPrefix(f, "-"), strings.Contains(f, "="):
			// env's other options change what it runs or where it looks.
			return "", fmt.Errorf("env with %s", f)
		}
		return ResolveExe(f, dir, pathEnv)
	}
	return "", fmt.Errorf("env with no program")
}

// pythonLayout is a Python installation found from files, the way the
// interpreter finds its own (CPython's getpath).
type pythonLayout struct {
	// roots are the installation prefixes: each holds lib/python3.X/os.py,
	// the landmark CPython searches for, and is fingerprinted whole.
	roots []string
	// venv is the virtual environment's own folder, when the interpreter is
	// started from one (its pyvenv.cfg).
	venv string
	// probes are files the interpreter looks for at start and that may not
	// exist: a pyvenv.cfg beside the executable, a ._pth file. Recorded
	// either way, so one appearing later stops the job.
	probes []string
	// homes are pyvenv.cfg `home` values as written, whose resolution is
	// recorded: re-pointing a symlink in one moves the whole installation.
	// Recorded, never walked: a home is where the interpreter is, and Xcode's
	// venvs name Developer/usr/bin, which holds every Xcode tool.
	homes []string
	// sites are site-packages folders a distribution's own site.py adds
	// outside the prefix (Apple's builds: /Library/Python/X.Y/site-packages
	// and the AppleInternal ones). Walked when they exist, recorded as
	// absent when not.
	sites []string
}

// findPython finds the installation interp starts. interp is the path as
// started (a venv's bin/python), real its symlink-resolved file.
func findPython(interp, real string) pythonLayout {
	var l pythonLayout
	// CPython looks for pyvenv.cfg beside the executable and one folder up,
	// from the path it was STARTED as, not the resolved one.
	for _, d := range []string{filepath.Dir(interp), filepath.Dir(filepath.Dir(interp))} {
		cfg := filepath.Join(d, "pyvenv.cfg")
		l.probes = append(l.probes, cfg)
		home, ok := readVenvHome(cfg)
		if !ok {
			continue
		}
		if l.venv == "" {
			l.venv = d
		}
		if home != "" {
			l.homes = append(l.homes, home)
		}
	}
	// A ._pth file beside the executable (as started, or resolved) replaces
	// sys.path entirely, on every platform since 3.11.
	l.probes = append(l.probes, interp+"._pth", real+"._pth")

	// Where CPython starts its search for the stdlib landmark: the resolved
	// executable's folder, each venv home, and the folder of a libpython or
	// framework it links (a framework build finds its prefix from there).
	starts := []string{filepath.Dir(real)}
	for _, h := range l.homes {
		if r, err := filepath.EvalSymlinks(h); err == nil {
			starts = append(starts, r)
		}
	}
	if m, err := readMachO(real); err == nil {
		dir := filepath.Dir(real)
		rpaths := expandRpaths(m.rpaths, dir, dir)
		for _, dep := range m.deps {
			for _, c := range dylibCandidates(dep, dir, dir, rpaths) {
				if r, err := filepath.EvalSymlinks(c); err == nil {
					starts = append(starts, filepath.Dir(r))
					break
				}
			}
		}
	}
	seen := map[string]bool{}
	for _, s := range starts {
		if root := stdlibPrefix(s); root != "" && !seen[root] {
			seen[root] = true
			l.roots = append(l.roots, root)
		}
	}
	for _, root := range l.roots {
		l.sites = append(l.sites, appleSites(root)...)
	}
	return l
}

// appleSites are the site-packages folders Apple's patched site.py adds for
// its own Python builds (Xcode's, the Command Line Tools'), which live
// outside the prefix: /Library/Python/X.Y/site-packages, two under
// /AppleInternal, and one under Xcode's Developer folder. Found with the
// cross-check against a real Xcode Python (TestRealInterpreters). Asked of
// every installation: they are absent almost everywhere, and a place absent
// at approval that appears later stops the job.
func appleSites(root string) []string {
	var out []string
	libs, _ := filepath.Glob(filepath.Join(root, "lib", "python3*", "os.py"))
	for _, l := range libs {
		ver := strings.TrimPrefix(filepath.Base(filepath.Dir(l)), "python")
		for _, base := range []string{"/Library/Python", "/AppleInternal/Library/Python", "/AppleInternal/Tests/Python"} {
			out = append(out, filepath.Join(base, ver, "site-packages"))
		}
		const dev = "/Contents/Developer/Library/Frameworks/"
		if i := strings.Index(root, dev); i >= 0 {
			developer := root[:i+len("/Contents/Developer")]
			out = append(out, filepath.Join(developer, "AppleInternal/Library/Python", ver, "site-packages"))
		}
	}
	return out
}

// stdlibPrefix walks up from start to the first folder holding
// lib/python3*/os.py, CPython's landmark, and returns it resolved. The
// folders it passes on the way are inside the one it finds, so a landmark
// planted lower down (which CPython would find first) is a file added to the
// fingerprinted tree.
func stdlibPrefix(start string) string {
	for d := start; ; {
		if m, _ := filepath.Glob(filepath.Join(d, "lib", "python3*", "os.py")); len(m) > 0 {
			if r, err := filepath.EvalSymlinks(d); err == nil {
				return r
			}
			return d
		}
		parent := filepath.Dir(d)
		if parent == d {
			return ""
		}
		d = parent
	}
}

// readVenvHome reads pyvenv.cfg's `home`. ok is false when there is no
// pyvenv.cfg (or it is not a regular file).
func readVenvHome(cfg string) (home string, ok bool) {
	f, err := openRegular(cfg)
	if err != nil {
		return "", false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, found := strings.Cut(sc.Text(), "=")
		if found && strings.TrimSpace(k) == "home" {
			home = strings.TrimSpace(v)
		}
	}
	return home, true
}

// openRegular opens path for reading without blocking and refuses anything
// that is not a regular file once open: a path swapped for a named pipe must
// not hang the check.
func openRegular(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0) // #nosec G304 -- a file a job's fingerprint covers
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	return f, nil
}
