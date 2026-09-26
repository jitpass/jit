// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package job

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestRealInterpreters checks the file-based reading of an installation
// (interp.go) against real interpreters on this Mac, and measures what
// fingerprinting them costs. Gated: it reads whatever is installed and runs
// each Python once to ask where it loads from, which a correctness test must
// not depend on.
//
//	JIT_REAL_INTERPRETERS=1 go test -run TestRealInterpreters -v ./internal/job/
//
// It writes only under its own temp folders: every Python it runs gets -B or
// a PYTHONPYCACHEPREFIX of its own, so no bytecode lands in an installation.
func TestRealInterpreters(t *testing.T) {
	if os.Getenv("JIT_REAL_INTERPRETERS") != "1" {
		t.Skip("set JIT_REAL_INTERPRETERS=1 to measure the interpreters installed on this Mac")
	}
	home, _ := os.UserHomeDir()
	var pythons []string
	for _, p := range []string{"/opt/homebrew/bin/python3", "/usr/local/bin/python3", "/Applications/Xcode.app/Contents/Developer/usr/bin/python3"} {
		if _, err := os.Stat(p); err == nil {
			pythons = append(pythons, p)
		}
	}
	uv, _ := filepath.Glob(filepath.Join(home, ".local/share/uv/python/cpython-*/bin/python3"))
	pyenv, _ := filepath.Glob(filepath.Join(home, ".pyenv/versions/*/bin/python3"))
	pythons = append(pythons, uv...)
	pythons = append(pythons, pyenv...)
	if len(pythons) == 0 {
		t.Skip("no Python installed here")
	}
	if _, err := os.Stat("/opt/homebrew/bin/python3"); err != nil {
		t.Log("no Homebrew python3 on this Mac; measuring the Pythons it has")
	}

	for _, py := range pythons {
		t.Run(strings.TrimPrefix(py, home), func(t *testing.T) {
			dir := resolved(t, t.TempDir())
			write(t, filepath.Join(dir, "job.py"), "import json, email, http.client, ssl, sqlite3\n")
			p := Program{Exe: py, Argv: []string{py, "job.py"}, PathEnv: "/usr/bin:/bin", Home: home}
			if gap := Unfingerprinted(dir, p); gap != "" {
				t.Fatalf("gap for a real Python: %s", gap)
			}
			fp := measure(t, dir, p)
			crossCheck(t, py, dir, fp)
			stable(t, py, dir, p, fp)

			// The same interpreter through a venv, made here.
			venvDir := resolved(t, t.TempDir())
			if out, err := exec.Command(py, "-B", "-m", "venv", "--without-pip", filepath.Join(venvDir, ".venv")).CombinedOutput(); err != nil { // #nosec G204 -- a test's own interpreter list
				t.Fatalf("making a venv: %v\n%s", err, out)
			}
			write(t, filepath.Join(venvDir, "job.py"), "import json\n")
			vpy := filepath.Join(venvDir, ".venv/bin/python")
			vp := Program{Exe: vpy, Argv: []string{".venv/bin/python", "job.py"}, PathEnv: "/usr/bin:/bin", Home: home}
			vfp := measure(t, venvDir, vp)
			crossCheck(t, vpy, venvDir, vfp)
			stable(t, vpy, venvDir, vp, vfp)
		})
	}

	// Apple's /usr/bin/python3 is a stub that picks a Python when it runs:
	// jit must say it cannot fingerprint it, not silently cover nothing.
	if _, err := os.Stat("/usr/bin/python3"); err == nil {
		gap := Unfingerprinted(t.TempDir(), Program{Exe: "/usr/bin/python3", Argv: []string{"python3", "x.py"}})
		t.Logf("/usr/bin/python3: %s", gap)
		if gap == "" {
			t.Error("Apple's python3 stub has no gap")
		}
	}

	// A real job's folder, read only: JIT_REAL_JOB_DIR=~/code/scripts/notion
	// measures that folder with its own .venv/bin/python.
	if d := os.Getenv("JIT_REAL_JOB_DIR"); d != "" {
		t.Run("the job folder "+filepath.Base(d), func(t *testing.T) {
			py := filepath.Join(d, ".venv/bin/python")
			p := Program{Exe: py, Argv: []string{".venv/bin/python", "x.py"}, PathEnv: "/usr/bin:/bin", Home: home}
			if gap := Unfingerprinted(d, p); gap != "" {
				t.Fatalf("gap: %s", gap)
			}
			fp := measure(t, d, p)
			t.Logf("its own folder: %d entries", len(fp.Files))
			crossCheck(t, py, resolveOrSelf(d), fp)
		})
	}

	if node, err := filepath.EvalSymlinks("/opt/homebrew/bin/node"); err == nil {
		t.Run("homebrew node", func(t *testing.T) {
			dir := resolved(t, t.TempDir())
			write(t, filepath.Join(dir, "index.js"), "console.log(1)\n")
			measure(t, dir, Program{Exe: node, Argv: []string{"node", "index.js"}, Home: home})
		})
	}
}

// measure fingerprints dir twice, the first time with an empty library
// cache, and logs what it covered and what it cost.
func measure(t *testing.T, dir string, p Program) Fingerprint {
	t.Helper()
	libCacheMu.Lock()
	libCache, machoCache = map[string]cachedHash{}, map[string]cachedMachO{}
	libCacheMu.Unlock()
	start := time.Now()
	fp, err := Compute(dir, p, nil, nil)
	cold := time.Since(start)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	start = time.Now()
	again, err := Compute(dir, p, nil, nil)
	warm := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	if d := Diff(fp, again); len(d) != 0 {
		t.Fatalf("two fingerprints in a row differ: %v", d)
	}
	var files, absent, native int
	var size int64
	for k, v := range fp.Libs {
		switch {
		case strings.HasPrefix(v, "sha256:"):
			files++
			if info, err := os.Stat(k); err == nil {
				size += info.Size()
			}
			if strings.HasSuffix(k, ".dylib") || strings.HasSuffix(k, ".so") {
				native++
			}
		case v == AbsentEntry:
			absent++
		}
	}
	stored, _ := json.MarshalIndent(fp, "", "  ")
	m := LibManifests(filepath.Join(t.TempDir(), "job-libraries"))
	if err := m.Save(fp); err != nil {
		t.Fatal(err)
	}
	var kept int64
	if entries, err := os.ReadDir(string(m)); err == nil {
		for _, e := range entries {
			if info, err := e.Info(); err == nil {
				kept += info.Size()
			}
		}
	}
	t.Logf("%s: %d library files (%d native), %.1f MB, %d places recorded empty; first %v, cached %v; %.1f KB in jobs.json (%d library roots), %d KB of manifests beside it",
		p.Exe, files, native, float64(size)/1e6, absent, cold.Round(time.Millisecond), warm.Round(time.Millisecond), float64(len(stored))/1024, len(fp.LibRoots), kept>>10)
	if files+len(fp.Files) > MaxFiles || size > MaxBytes {
		t.Errorf("past the per-job limits: %d files, %d bytes", files+len(fp.Files), size)
	}
	return fp
}

// crossCheck asks the interpreter where it loads from (isolated, no site,
// no bytecode written) and requires every place it names to be covered.
func crossCheck(t *testing.T, py, dir string, fp Fingerprint) {
	t.Helper()
	const snippet = `import sys, sysconfig, json
paths = sysconfig.get_paths()
print(json.dumps({"path": sys.path, "prefix": sys.prefix, "base_prefix": sys.base_prefix,
  "stdlib": paths["stdlib"], "platstdlib": paths["platstdlib"], "purelib": paths["purelib"], "platlib": paths["platlib"]}))`
	out, err := exec.Command(py, "-I", "-S", "-B", "-c", snippet).Output() // #nosec G204 -- a test's own interpreter list
	if err != nil {
		t.Fatalf("asking %s: %v", py, err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(out, &raw); err != nil {
		t.Fatal(err)
	}
	var places []string
	if err := json.Unmarshal(raw["path"], &places); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"prefix", "base_prefix", "stdlib", "platstdlib", "purelib", "platlib"} {
		var s string
		if err := json.Unmarshal(raw[k], &s); err != nil {
			t.Fatal(err)
		}
		places = append(places, s)
	}
	siteOut, err := exec.Command(py, "-I", "-B", "-c", "import site, json; print(json.dumps(site.getsitepackages()))").Output() // #nosec G204 -- as above
	if err == nil {
		var sites []string
		if json.Unmarshal(siteOut, &sites) == nil {
			places = append(places, sites...)
		}
	}
	for _, place := range places {
		if place == "" {
			continue
		}
		r, err := filepath.EvalSymlinks(place)
		if err != nil {
			// Not there (python3XX.zip): its folder must be covered, so it
			// appearing is a file added to a walked tree.
			r = filepath.Join(resolveOrSelf(filepath.Dir(place)), filepath.Base(place))
		}
		if inside(r, dir) || coveredBy(fp, r) {
			continue
		}
		t.Errorf("%s loads from %s, which the fingerprint does not cover", py, place)
	}
}

func resolveOrSelf(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return p
}

// coveredBy reports whether p is recorded itself (a place recorded empty
// counts: one appearing there stops the job), or some fingerprinted library
// file lies in p's folder or below it.
func coveredBy(fp Fingerprint, p string) bool {
	if _, ok := fp.Libs[p]; ok {
		return true
	}
	parent := filepath.Dir(p)
	for k, v := range fp.Libs {
		if !strings.HasPrefix(v, "sha256:") && !strings.HasPrefix(v, "link:") {
			continue
		}
		if inside(k, p) || filepath.Dir(k) == parent || inside(k, parent) {
			return true
		}
	}
	return false
}

// stable runs the interpreter the way a job runs (a fresh bytecode cache,
// no user site) and requires the fingerprint not to move.
func stable(t *testing.T, py, dir string, p Program, before Fingerprint) {
	t.Helper()
	cmd := exec.Command(py, "job.py") // #nosec G204 -- as above
	cmd.Dir = dir
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + p.Home, "PYTHONPYCACHEPREFIX=" + t.TempDir(), "PYTHONNOUSERSITE=1"}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("running %s: %v\n%s", py, err, out)
	}
	after, err := Compute(dir, p, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if d := Diff(before, after); len(d) != 0 {
		t.Fatalf("a run as jit runs it moved the fingerprint: %v", d)
	}
}
