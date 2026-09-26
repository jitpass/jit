// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/job"
)

// The interpreter's libraries, end to end through the service: a job whose
// Python's stdlib changes stops like one whose script changes, a job whose
// program jit cannot fingerprint may not run unasked, and a job approved
// before libraries were fingerprinted stops until approved again. The
// installation is a fake one in temp folders (internal/job's tests say why).

func writeAll(t *testing.T, path, body string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
}

// pythonSpec gives the rig's folder a venv whose interpreter lives in a fake
// installation outside it, and returns the spec that runs the script with
// it and the installation's stdlib encodings/__init__.py.
func (r *jobRig) pythonSpec(t *testing.T) (JobSpec, string) {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	writeAll(t, filepath.Join(base, "bin/python3.14"), "interpreter", 0o700)
	writeAll(t, filepath.Join(base, "lib/python3.14/os.py"), "# landmark\n", 0o600)
	enc := filepath.Join(base, "lib/python3.14/encodings/__init__.py")
	writeAll(t, enc, "# decodes\n", 0o600)
	writeAll(t, filepath.Join(r.dir, ".venv/pyvenv.cfg"), "home = "+filepath.Join(base, "bin")+"\n", 0o600)
	if err := os.MkdirAll(filepath.Join(r.dir, ".venv/bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(base, "bin/python3.14"), filepath.Join(r.dir, ".venv/bin/python")); err != nil {
		t.Fatal(err)
	}
	spec := r.spec()
	spec.Argv = []string{".venv/bin/python", "list_guest_users.py"}
	return spec, enc
}

func TestNeverJobStopsWhenItsInterpretersStdlibChanges(t *testing.T) {
	r := newJobRig(t)
	spec, enc := r.pythonSpec(t)
	spec.Ask = string(job.AskNever)
	st, err := r.c.JobAllow("notion-guests", spec)
	if err != nil {
		t.Fatalf("JobAllow: %v", err)
	}
	if st.Libraries == 0 {
		t.Fatalf("approval fingerprinted no library files: %+v", st)
	}
	if _, err := r.c.JobRun("notion-guests"); err != nil {
		t.Fatalf("an unchanged run: %v", err)
	}
	writeAll(t, enc, "import os; os.system('send $NOTION_API_KEY')\n", 0o600)
	_, err = r.c.JobRun("notion-guests")
	if err == nil || !strings.Contains(err.Error(), enc) {
		t.Fatalf("a run after the stdlib changed: %v, want a stop naming %s", err, enc)
	}
	if r.runs() != 1 {
		t.Fatalf("the runner ran %d times, want only the unchanged run", r.runs())
	}
}

func TestNeverJobRefusedWhenJitCannotFingerprintWhatItRuns(t *testing.T) {
	r := newJobRig(t)
	bin := t.TempDir()
	writeAll(t, filepath.Join(bin, "uv"), "a launcher", 0o700)
	spec := r.spec()
	spec.Argv = []string{"uv", "run", "list_guest_users.py"}
	spec.PathEnv = bin + ":/usr/bin:/bin"

	never := spec
	never.Ask = string(job.AskNever)
	if _, err := r.c.JobAllow("notion-guests", never); err == nil || !strings.Contains(err.Error(), "uv picks the Python") {
		t.Fatalf("a never job through uv: %v, want refused", err)
	}
	if r.prompts() != 0 {
		t.Fatalf("the refusal cost %d prompts; it must come before the Touch ID", r.prompts())
	}
	p, err := r.c.JobPreview("notion-guests", never)
	if err != nil || !strings.Contains(p.Refusal, "uv picks the Python") {
		t.Fatalf("preview of the never job: %v %+v, want the same refusal", err, p)
	}

	// Each-time is allowed, and the sheet is told what is not covered.
	p, err = r.c.JobPreview("notion-guests", spec)
	if err != nil || p.Refusal != "" || !strings.Contains(p.Unfingerprinted, "uv picks the Python") {
		t.Fatalf("preview of the each-time job: %v %+v", err, p)
	}
	if _, err := r.c.JobAllow("notion-guests", spec); err != nil {
		t.Fatalf("each-time through uv: %v", err)
	}
}

func TestJobApprovedBeforeLibrariesStopsUntilApprovedAgain(t *testing.T) {
	r := newJobRig(t)
	spec, _ := r.pythonSpec(t)
	if _, err := r.c.JobAllow("notion-guests", spec); err != nil {
		t.Fatal(err)
	}
	// Rewrite jobs.json as a jit from before Libs would have left it.
	data, err := os.ReadFile(r.storeAt)
	if err != nil {
		t.Fatal(err)
	}
	var file map[string]any
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	for _, j := range file["jobs"].([]any) {
		fp := j.(map[string]any)["fingerprint"].(map[string]any)
		if fp["lib_roots"] == nil {
			t.Fatal("jobs.json holds no library roots; the test would prove nothing")
		}
		delete(fp, "lib_roots")
		delete(fp, "libs_v")
	}
	data, err = json.Marshal(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(r.storeAt, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := r.s.SetJobStore(r.storeAt); err != nil {
		t.Fatal(err)
	}
	if _, err := r.c.JobRun("notion-guests"); err == nil || !strings.Contains(err.Error(), "approved by an older jit") {
		t.Fatalf("a pre-libraries approval ran: %v", err)
	}
	spec.Replace = true
	if _, err := r.c.JobAllow("notion-guests", spec); err != nil {
		t.Fatal(err)
	}
	if _, err := r.c.JobRun("notion-guests"); err != nil {
		t.Fatalf("approved again, it should run: %v", err)
	}
}

// libDir is the rig's library manifests' folder, beside its jobs.json.
func (r *jobRig) libDir() string {
	return job.LibManifestDir(filepath.Dir(r.storeAt))
}

// installationOf is the installation folder pythonSpec made, from its
// stdlib file.
func installationOf(enc string) string {
	return filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(enc))))
}

// After a restart the job comes back from jobs.json, which holds one hash
// per library root: the stop still names the file, from the manifest.
func TestLibraryStopNamesTheFileAfterARestart(t *testing.T) {
	r := newJobRig(t)
	spec, enc := r.pythonSpec(t)
	spec.Ask = string(job.AskNever)
	if _, err := r.c.JobAllow("notion-guests", spec); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(r.storeAt)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"libs"`) || strings.Contains(string(data), enc) {
		t.Fatalf("jobs.json holds the per-file list:\n%s", data)
	}
	if info, err := os.Stat(r.libDir()); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("no private manifests folder: %v", err)
	}
	if _, err := r.s.SetJobStore(r.storeAt); err != nil { // the service restarts
		t.Fatal(err)
	}
	writeAll(t, enc, "import os; os.system('send $NOTION_API_KEY')\n", 0o600)
	_, err = r.c.JobRun("notion-guests")
	if err == nil || !strings.Contains(err.Error(), enc+" changed") {
		t.Fatalf("a run after the stdlib changed: %v, want a stop naming %s", err, enc)
	}
	if r.runs() != 0 {
		t.Fatalf("the runner ran %d times", r.runs())
	}
}

// With the manifests gone, the job stops all the same and names the folder.
func TestLibraryStopNamesTheFolderWhenItsListIsGone(t *testing.T) {
	r := newJobRig(t)
	spec, enc := r.pythonSpec(t)
	spec.Ask = string(job.AskNever)
	if _, err := r.c.JobAllow("notion-guests", spec); err != nil {
		t.Fatal(err)
	}
	if _, err := r.c.JobRun("notion-guests"); err != nil {
		t.Fatalf("an unchanged run: %v", err)
	}
	if err := os.RemoveAll(r.libDir()); err != nil {
		t.Fatal(err)
	}
	writeAll(t, enc, "import os; os.system('send $NOTION_API_KEY')\n", 0o600)
	_, err := r.c.JobRun("notion-guests")
	base := installationOf(enc)
	if err == nil || !strings.Contains(err.Error(), "a file in "+base+" changed") || !strings.Contains(err.Error(), "can't say which") {
		t.Fatalf("a run after the stdlib changed with no manifest: %v, want a stop naming %s", err, base)
	}
	if r.runs() != 1 {
		t.Fatalf("the runner ran %d times, want only the unchanged run", r.runs())
	}
}

// A job approved by the build that stored every library file (libs_v 1)
// stops with the older-jit sentence until approved again.
func TestJobApprovedWithPerFileLibrariesStopsUntilApprovedAgain(t *testing.T) {
	r := newJobRig(t)
	spec, enc := r.pythonSpec(t)
	if _, err := r.c.JobAllow("notion-guests", spec); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(r.storeAt)
	if err != nil {
		t.Fatal(err)
	}
	var file map[string]any
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	for _, j := range file["jobs"].([]any) {
		fp := j.(map[string]any)["fingerprint"].(map[string]any)
		delete(fp, "lib_roots")
		fp["libs"] = map[string]string{enc: "sha256:" + strings.Repeat("0", 64)}
		fp["libs_v"] = 1
	}
	if data, err = json.Marshal(file); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(r.storeAt, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := r.s.SetJobStore(r.storeAt); err != nil {
		t.Fatal(err)
	}
	if _, err := r.c.JobRun("notion-guests"); err == nil || !strings.Contains(err.Error(), "approved by an older jit") {
		t.Fatalf("a per-file approval ran: %v", err)
	}
	spec.Replace = true
	if _, err := r.c.JobAllow("notion-guests", spec); err != nil {
		t.Fatal(err)
	}
	if _, err := r.c.JobRun("notion-guests"); err != nil {
		t.Fatalf("approved again, it should run: %v", err)
	}
}

// Jobs on one Python share its manifest; it goes with the last of them.
func TestLibraryManifestsGoWithTheirJobs(t *testing.T) {
	r := newJobRig(t)
	spec, _ := r.pythonSpec(t)
	for _, name := range []string{"notion-guests", "notion-pages"} {
		if _, err := r.c.JobAllow(name, spec); err != nil {
			t.Fatal(err)
		}
	}
	manifests := func() int {
		entries, _ := os.ReadDir(r.libDir())
		return len(entries)
	}
	n := manifests()
	if n == 0 {
		t.Fatal("approval kept no manifest")
	}
	if _, err := r.c.JobRemove("notion-guests"); err != nil {
		t.Fatal(err)
	}
	if manifests() != n {
		t.Fatalf("removing one job of two took %d manifests of %d", n-manifests(), n)
	}
	if _, err := r.c.JobRemove("notion-pages"); err != nil {
		t.Fatal(err)
	}
	if got := manifests(); got != 0 {
		t.Fatalf("%d manifests outlived every job", got)
	}
}
