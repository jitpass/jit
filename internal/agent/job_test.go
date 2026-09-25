// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package agent

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jitpass/jit/internal/job"
)

// jobRig is a running test server wired for jobs: a vault of wrapped DEKs
// the test controls (OnWrappedDEK), a resolver returning a fixed profile
// (OnResolveJob), and a runner that records what it was handed instead of
// starting anything (OnRunJob).
type jobRig struct {
	s       *Server
	c       *Client
	calls   *int32
	dir     string
	storeAt string

	mu      sync.Mutex
	vault   map[string][]byte // path → wrapped bytes as the vault holds them now
	sources []JobSecretSource
	ran     []job.Job
	gotDEKs []map[string][]byte
}

var jobDEK = bytes.Repeat([]byte{0x07}, 32)

func newJobRig(t *testing.T) *jobRig {
	t.Helper()
	var calls int32
	r := &jobRig{calls: &calls, vault: map[string][]byte{}}
	r.dir = t.TempDir()
	if err := os.WriteFile(filepath.Join(r.dir, "list_guest_users.py"), []byte("print('hi')\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	wrapped, err := seal(grantTestMEK, jobDEK, []byte("mcp"))
	if err != nil {
		t.Fatal(err)
	}
	r.vault["notion/NOTION_API_KEY"] = wrapped
	r.sources = []JobSecretSource{{Var: "NOTION_API_KEY", Path: "notion/NOTION_API_KEY", Wrapped: wrapped, Class: "mcp"}}
	r.storeAt = filepath.Join(t.TempDir(), "jobs.json")

	s, socketPath, cleanup := startTestServerWith(t, time.Minute, &calls, func(s *Server) {
		if _, err := s.SetJobStore(r.storeAt); err != nil {
			t.Fatal(err)
		}
		s.OnResolveJob = func(GrantProfile) ([]JobSecretSource, error) {
			r.mu.Lock()
			defer r.mu.Unlock()
			return append([]JobSecretSource(nil), r.sources...), nil
		}
		s.OnWrappedDEK = func(path string) ([]byte, string, error) {
			r.mu.Lock()
			defer r.mu.Unlock()
			w, ok := r.vault[path]
			if !ok {
				return nil, "", errors.New("not found")
			}
			return w, "mcp", nil
		}
		s.OnRunJob = func(j job.Job, deks map[string][]byte) (JobResult, error) {
			r.mu.Lock()
			defer r.mu.Unlock()
			cp := map[string][]byte{}
			for k, v := range deks {
				cp[k] = append([]byte(nil), v...)
			}
			r.ran = append(r.ran, j)
			r.gotDEKs = append(r.gotDEKs, cp)
			return JobResult{Exit: 0, Stdout: "Total users seen: 264\n"}, nil
		}
		s.discloseBackoff = nil
	})
	t.Cleanup(cleanup)
	r.s, r.c = s, NewClient(socketPath)
	return r
}

func (r *jobRig) spec() JobSpec {
	return JobSpec{
		Dir: r.dir, Argv: []string{"/bin/sh", "list_guest_users.py"},
		Profile: &GrantProfile{Name: "notion", Root: r.dir},
		PathEnv: "/usr/bin:/bin", Home: "/Users/x",
	}
}

func (r *jobRig) prompts() int32 { return atomic.LoadInt32(r.calls) }

func (r *jobRig) runs() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.ran)
}

func TestJobAllowThenRunHandsTheRunnerOnlyApprovedKeys(t *testing.T) {
	r := newJobRig(t)
	st, err := r.c.JobAllow("notion-guests", r.spec())
	if err != nil {
		t.Fatalf("JobAllow: %v", err)
	}
	if r.prompts() != 1 {
		t.Fatalf("approval prompted %d times, want 1", r.prompts())
	}
	if st.State != JobReady || len(st.Secrets) != 1 || st.Secrets[0].Var != "NOTION_API_KEY" || st.Exe != "/bin/sh" {
		t.Fatalf("status = %+v", st)
	}
	if unlocked, _ := r.s.status(); unlocked {
		t.Fatal("approving a job opened a session; a disclosed challenge must not")
	}

	res, err := r.c.JobRun("notion-guests")
	if err != nil {
		t.Fatalf("JobRun: %v", err)
	}
	if r.prompts() != 2 {
		t.Fatalf("an each-time run prompted %d times in total, want 2 (approve + run)", r.prompts())
	}
	if res.Stdout != "Total users seen: 264\n" {
		t.Fatalf("result = %+v", res)
	}
	r.mu.Lock()
	got := r.gotDEKs[0][wrappedDigest(r.sources[0].Wrapped)]
	n := len(r.gotDEKs[0])
	r.mu.Unlock()
	if n != 1 || !bytes.Equal(got, jobDEK) {
		t.Fatalf("runner got %d keys, key match %v; want exactly the one approved", n, bytes.Equal(got, jobDEK))
	}

	// Kept across a restart: a fresh load of the file has it.
	back, err := job.Load(r.storeAt)
	if err != nil || back["notion-guests"] == nil || back["notion-guests"].Runs != 1 {
		t.Fatalf("jobs.json after a run: %v %+v", err, back["notion-guests"])
	}
}

func TestJobRunRefusesAChangedFileWithoutPrompting(t *testing.T) {
	r := newJobRig(t)
	if _, err := r.c.JobAllow("notion-guests", r.spec()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(r.dir, "list_guest_users.py"), []byte("import os; print(os.environ)\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := r.prompts()
	_, err := r.c.JobRun("notion-guests")
	if err == nil || !strings.Contains(err.Error(), "list_guest_users.py changed since you approved it") {
		t.Fatalf("JobRun on a changed script: %v", err)
	}
	if r.prompts() != before || r.runs() != 0 {
		t.Fatalf("a refused run prompted (%d) or ran (%d)", r.prompts()-before, r.runs())
	}
	jobs, err := r.c.JobList()
	if err != nil || len(jobs) != 1 || jobs[0].State != JobChanged || jobs[0].Changes[0].Path != "list_guest_users.py" {
		t.Fatalf("list after the change: %v %+v", err, jobs)
	}
	if !strings.Contains(jobs[0].LastRefusal, "list_guest_users.py") {
		t.Fatalf("LastRefusal = %q, want it to name the file", jobs[0].LastRefusal)
	}
}

func TestJobRunRefusesARotatedSecret(t *testing.T) {
	r := newJobRig(t)
	if _, err := r.c.JobAllow("notion-guests", r.spec()); err != nil {
		t.Fatal(err)
	}
	rotated, _ := seal(grantTestMEK, bytes.Repeat([]byte{0x09}, 32), []byte("mcp"))
	r.mu.Lock()
	r.vault["notion/NOTION_API_KEY"] = rotated
	r.mu.Unlock()
	before := r.prompts()
	_, err := r.c.JobRun("notion-guests")
	if err == nil || !strings.Contains(err.Error(), "NOTION_API_KEY was rotated") {
		t.Fatalf("JobRun after rotation: %v", err)
	}
	if r.prompts() != before || r.runs() != 0 {
		t.Fatal("a rotated secret still prompted or ran")
	}
}

// A profile is a file in a folder an agent can write. Remapping it after
// approval must not change what the job injects: the job carries the paths
// it was approved with, and the resolver is never consulted at run time.
func TestJobRunIgnoresAProfileRemappedAfterApproval(t *testing.T) {
	r := newJobRig(t)
	if _, err := r.c.JobAllow("notion-guests", r.spec()); err != nil {
		t.Fatal(err)
	}
	other, _ := seal(grantTestMEK, bytes.Repeat([]byte{0x0a}, 32), []byte("mcp"))
	r.mu.Lock()
	r.vault["jamf/JAMF_CLIENT_SECRET"] = other
	r.sources = []JobSecretSource{{Var: "NOTION_API_KEY", Path: "jamf/JAMF_CLIENT_SECRET", Wrapped: other, Class: "mcp"}}
	r.mu.Unlock()
	if _, err := r.c.JobRun("notion-guests"); err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ran[0].Secrets[0].Path != "notion/NOTION_API_KEY" {
		t.Fatalf("the run used %s, want the approved notion/NOTION_API_KEY", r.ran[0].Secrets[0].Path)
	}
	if _, ok := r.gotDEKs[0][wrappedDigest(other)]; ok {
		t.Fatal("the remapped secret's key reached the runner")
	}
}

func TestJobAllowRefusesBeforeThePrompt(t *testing.T) {
	r := newJobRig(t)
	cases := map[string]func(*JobSpec) (name string){
		"inline program": func(s *JobSpec) string { s.Argv = []string{"/bin/sh", "-c", "env"}; return "a" },
		"printer":        func(s *JobSpec) string { s.Argv = []string{"/usr/bin/env"}; return "b" },
		"bad name":       func(*JobSpec) string { return "Bad Name" },
		"never asks":     func(s *JobSpec) string { s.Ask = string(job.AskNever); return "c" },
		"show unknown":   func(s *JobSpec) string { s.Shown = []string{"NOPE"}; return "d" },
		"relative dir":   func(s *JobSpec) string { s.Dir = "notion"; return "e" },
		"missing exe":    func(s *JobSpec) string { s.Argv = []string{"no-such-tool-xyz"}; return "f" },
	}
	for label, mut := range cases {
		spec := r.spec()
		name := mut(&spec)
		if _, err := r.c.JobAllow(name, spec); err == nil {
			t.Errorf("%s: approved", label)
		}
	}
	if r.prompts() != 0 {
		t.Fatalf("refusals prompted %d times; every one must fail before Touch ID", r.prompts())
	}
}

func TestJobAllowRefusesAnExistingNameUnlessReplaced(t *testing.T) {
	r := newJobRig(t)
	if _, err := r.c.JobAllow("notion-guests", r.spec()); err != nil {
		t.Fatal(err)
	}
	if _, err := r.c.JobAllow("notion-guests", r.spec()); err == nil || !strings.Contains(err.Error(), "--replace") {
		t.Fatalf("second approval without replace: %v", err)
	}
	// Approving again after a change is the one way back to Ready.
	if err := os.WriteFile(filepath.Join(r.dir, "list_guest_users.py"), []byte("print('v2')\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	spec := r.spec()
	spec.Replace = true
	st, err := r.c.JobAllow("notion-guests", spec)
	if err != nil || st.State != JobReady {
		t.Fatalf("replace: %v %+v", err, st)
	}
}

func TestJobRunDeclinedTouchIDRunsNothing(t *testing.T) {
	r := newJobRig(t)
	if _, err := r.c.JobAllow("notion-guests", r.spec()); err != nil {
		t.Fatal(err)
	}
	r.s.newFetcher = func() MEKFetcher { return &fakeFetcher{err: errors.New("declined")} }
	if _, err := r.c.JobRun("notion-guests"); err == nil {
		t.Fatal("a declined run succeeded")
	}
	if r.runs() != 0 {
		t.Fatal("a declined run reached the runner")
	}
}

func TestJobRemoveIsFreeAndFinal(t *testing.T) {
	r := newJobRig(t)
	if _, err := r.c.JobAllow("notion-guests", r.spec()); err != nil {
		t.Fatal(err)
	}
	before := r.prompts()
	if err := r.c.JobRemove("notion-guests"); err != nil {
		t.Fatal(err)
	}
	if r.prompts() != before {
		t.Fatal("remove prompted")
	}
	if _, err := r.c.JobRun("notion-guests"); err == nil || !strings.Contains(err.Error(), "no job named") {
		t.Fatalf("run after remove: %v", err)
	}
	back, _ := job.Load(r.storeAt)
	if len(back) != 0 {
		t.Fatalf("jobs.json still holds %d jobs", len(back))
	}
}

func TestJobReasonsFitThePrompt(t *testing.T) {
	long := strings.Repeat("x", 40)
	for _, s := range []string{
		jobAllowReason(long, 14),
		jobRunReason("Claude Helper (Renderer)", long, 14),
	} {
		if len([]rune(s)) > maxReasonLen {
			t.Errorf("%d runes > %d: %q", len([]rune(s)), maxReasonLen, s)
		}
		if !strings.Contains(s, "never the values") {
			t.Errorf("the promise was truncated off: %q", s)
		}
	}
}

// The human approves the folder as it was when asked. An edit landing while
// the dialog is up (an agent rewriting the script the moment it sees the
// prompt) must fail the approval, not be absorbed into it.
func TestJobAllowRefusesAFolderChangedDuringThePrompt(t *testing.T) {
	r := newJobRig(t)
	script := filepath.Join(r.dir, "list_guest_users.py")
	r.s.newFetcher = func() MEKFetcher {
		return fnFetcher{fn: func(string) ([]byte, error) {
			if err := os.WriteFile(script, []byte("import os; print(os.environ)\n"), 0o600); err != nil {
				return nil, err
			}
			return append([]byte(nil), grantTestMEK...), nil
		}}
	}
	_, err := r.c.JobAllow("notion-guests", r.spec())
	if err == nil || !strings.Contains(err.Error(), "changed while the prompt was up") {
		t.Fatalf("JobAllow with an edit during the prompt: %v", err)
	}
	if jobs, _ := r.c.JobList(); len(jobs) != 0 {
		t.Fatalf("a job was stored: %+v", jobs)
	}
}
