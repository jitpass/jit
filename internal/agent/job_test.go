// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package agent

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jitpass/jit/internal/job"
	"github.com/jitpass/jit/internal/lineage"
)

// jobRig is a running test server wired for jobs: a vault of wrapped DEKs
// the test controls (OnWrappedDEK), a resolver returning a fixed profile
// (OnResolveJob), and a runner that records what it was handed instead of
// starting anything (OnRunJob).
type jobRig struct {
	s       *Server
	c       *Client
	calls   *int32
	keys    *memGrantKeys
	dir     string
	storeAt string

	mu      sync.Mutex
	vault   map[string][]byte // path → wrapped bytes as the vault holds them now
	sources []JobSecretSource
	// settings is what OnResolveJobSettings returns; none by default.
	settings []JobSettingSource
	ran      []job.Job
	gotDEKs  []map[string][]byte
	// moved is what OnMovedSetting reports: a vault path's plain setting
	// after a move out. plain is what OnReadVaultValue decrypts, and only
	// with the DEK the entry was sealed with (jobcarry_test.go).
	moved map[string]MovedSetting
	plain map[string]plainValue
}

// plainValue is one vault value as the fake vault decrypts it.
type plainValue struct {
	dek, value []byte
}

var jobDEK = bytes.Repeat([]byte{0x07}, 32)

func newJobRig(t *testing.T) *jobRig {
	t.Helper()
	var calls int32
	r := &jobRig{calls: &calls, vault: map[string][]byte{}, keys: &memGrantKeys{}, moved: map[string]MovedSetting{}, plain: map[string]plainValue{}}
	r.dir = t.TempDir()
	if err := os.WriteFile(filepath.Join(r.dir, "list_guest_users.py"), []byte("print('hi')\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	wrapped, err := seal(grantTestMEK, jobDEK, []byte("mcp"))
	if err != nil {
		t.Fatal(err)
	}
	r.vault["notion/NOTION_API_KEY"] = wrapped
	r.plain["notion/NOTION_API_KEY"] = plainValue{dek: jobDEK, value: []byte("secret_notion_value")}
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
		s.OnResolveJobSettings = func(GrantProfile) ([]JobSettingSource, error) {
			r.mu.Lock()
			defer r.mu.Unlock()
			return append([]JobSettingSource(nil), r.settings...), nil
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
		s.OnMovedSetting = func(path string) (MovedSetting, bool) {
			r.mu.Lock()
			defer r.mu.Unlock()
			m, ok := r.moved[path]
			return m, ok
		}
		s.OnReadVaultValue = func(path string, dek []byte) ([]byte, error) {
			r.mu.Lock()
			defer r.mu.Unlock()
			pv, ok := r.plain[path]
			if !ok || r.vault[path] == nil {
				return nil, errors.New("not found")
			}
			if !bytes.Equal(pv.dek, dek) {
				return nil, errors.New("wrong key")
			}
			return append([]byte(nil), pv.value...), nil
		}
		s.discloseBackoff = nil
		s.GrantKeys = r.keys
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

// A plain setting sits outside the vault, so nothing but the fingerprint
// stands between an approved job and a BILLING_URL pointed somewhere else
// (design/secrets-only-vault.md, D8). The setting is recorded on the job, and
// a change to its file refuses the run without a prompt, like a changed
// script.
func TestJobRunRefusesAChangedSetting(t *testing.T) {
	r := newJobRig(t)
	file := filepath.Join(t.TempDir(), "settings", "billing", "BILLING_BASE_URL")
	if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("https://api.example.com"), 0o600); err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	r.settings = []JobSettingSource{{Var: "BILLING_BASE_URL", Path: "jit://setting/billing/BILLING_BASE_URL", File: file}}
	r.mu.Unlock()

	st, err := r.c.JobAllow("billing-report", r.spec())
	if err != nil {
		t.Fatalf("JobAllow: %v", err)
	}
	if len(st.Secrets) != 1 {
		t.Fatalf("a setting was counted as a secret: %+v", st.Secrets)
	}
	stored, err := job.Load(r.storeAt)
	if err != nil {
		t.Fatal(err)
	}
	if got := stored["billing-report"].Settings; len(got) != 1 || got[0].Var != "BILLING_BASE_URL" {
		t.Fatalf("stored settings = %+v, want BILLING_BASE_URL", got)
	}

	if err := os.WriteFile(file, []byte("https://attacker.example.net"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := r.prompts()
	if _, err := r.c.JobRun("billing-report"); err == nil || !strings.Contains(err.Error(), "BILLING_BASE_URL") {
		t.Fatalf("JobRun after the setting changed: %v, want a refusal naming it", err)
	}
	if r.prompts() != before || r.runs() != 0 {
		t.Fatalf("a changed setting still prompted (%d) or ran (%d)", r.prompts()-before, r.runs())
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
	if _, err := r.c.JobRemove("notion-guests"); err != nil {
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
	long := strings.Repeat("x", 40) + "/" + strings.Repeat("y", 40) + ".py"
	for _, r := range []string{
		jobAllowReason(long, 14, 3, job.AskEachTime),
		jobAllowReason(long, 14, 3, job.AskNever),
		jobRunReason("Claude Helper (Renderer)", long, 14),
	} {
		if len([]rune(r)) > maxReasonLen {
			t.Errorf("%d runes > %d: %q", len([]rune(r)), maxReasonLen, r)
		}
	}
	// The facts that change the decision survive a long label: how many
	// secrets, how many shown, and that it never asks again.
	r := jobAllowReason(long, 14, 3, job.AskNever)
	for _, want := range []string{"with 14 secrets", "3 shown", ", without asking"} {
		if !strings.Contains(r, want) {
			t.Errorf("%q lost %q", r, want)
		}
	}
	if r := jobRunReason("claude", long, 14); !strings.HasSuffix(r, " for claude with 14 secrets") {
		t.Errorf("who asked and with how many secrets was truncated off: %q", r)
	}
	if got, want := jobRunReason("claude", "reports/weekly.py", 2), "run reports/weekly.py for claude with 2 secrets"; got != want {
		t.Errorf("jobRunReason = %q, want %q", got, want)
	}
	if got, want := jobAllowReason("reports/weekly.py", 2, 0, job.AskNever), "let AI run reports/weekly.py with 2 secrets, without asking"; got != want {
		t.Errorf("jobAllowReason = %q, want %q", got, want)
	}
	if got, want := jobAllowReason("reports/weekly.py", 0, 0, job.AskEachTime), "let AI run reports/weekly.py with no secrets"; got != want {
		t.Errorf("jobAllowReason with no secrets = %q, want %q", got, want)
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

func (r *jobRig) neverSpec() JobSpec {
	spec := r.spec()
	spec.Ask = string(job.AskNever)
	return spec
}

func (r *jobRig) stored(t *testing.T) *job.Job {
	t.Helper()
	jobs, err := job.Load(r.storeAt)
	if err != nil || jobs["notion-guests"] == nil {
		t.Fatalf("jobs.json: %v %v", err, jobs)
	}
	return jobs["notion-guests"]
}

// The feature: approved once, then it runs with no prompt, including with
// the vault locked, and its key dies with it.
func TestNeverJobRunsUnaskedAndItsKeyDiesWithIt(t *testing.T) {
	r := newJobRig(t)
	if _, err := r.c.JobAllow("notion-guests", r.neverSpec()); err != nil {
		t.Fatalf("JobAllow: %v", err)
	}
	keyID := r.stored(t).KeyID
	if keyID == "" || !r.keys.has(keyID) {
		t.Fatalf("no key made (id %q)", keyID)
	}
	if err := r.c.Lock(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := r.c.JobRun("notion-guests"); err != nil {
			t.Fatalf("run %d: %v", i+1, err)
		}
	}
	if r.prompts() != 1 {
		t.Fatalf("prompted %d times in total, want only the approval's 1", r.prompts())
	}
	r.mu.Lock()
	got := r.gotDEKs[1][wrappedDigest(r.sources[0].Wrapped)]
	r.mu.Unlock()
	if !bytes.Equal(got, jobDEK) {
		t.Fatal("an unasked run got the wrong key")
	}
	if _, err := r.c.JobRemove("notion-guests"); err != nil {
		t.Fatal(err)
	}
	if r.keys.has(keyID) {
		t.Fatal("removing the job left its key in the keychain")
	}
}

// jobs.json sits beside grants.json: wrapped material, never a plaintext key.
func TestNeverJobStoresNoPlaintextKey(t *testing.T) {
	r := newJobRig(t)
	if _, err := r.c.JobAllow("notion-guests", r.neverSpec()); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(r.storeAt)
	if err != nil {
		t.Fatal(err)
	}
	for _, form := range []string{hex.EncodeToString(jobDEK), base64.StdEncoding.EncodeToString(jobDEK)} {
		if bytes.Contains(raw, []byte(form)) {
			t.Fatal("jobs.json holds the plaintext DEK")
		}
	}
	if sec := r.stored(t).Secrets[0]; sec.KeyWrapped == "" || sec.Wrap != standingWrapAEAD {
		t.Fatalf("secret not sealed under the job key: %+v", sec)
	}
}

// Approving again replaces the key. Going back to each-time must leave no
// key that still opens the secrets.
func TestReplacingANeverJobDropsItsOldKey(t *testing.T) {
	r := newJobRig(t)
	if _, err := r.c.JobAllow("notion-guests", r.neverSpec()); err != nil {
		t.Fatal(err)
	}
	old := r.stored(t).KeyID
	spec := r.spec()
	spec.Replace = true
	if _, err := r.c.JobAllow("notion-guests", spec); err != nil {
		t.Fatal(err)
	}
	if r.keys.has(old) {
		t.Fatal("the replaced job's key survived")
	}
	if j := r.stored(t); j.KeyID != "" || j.Secrets[0].KeyWrapped != "" {
		t.Fatalf("an each-time job kept key material: %+v", j)
	}
	before := r.prompts()
	if _, err := r.c.JobRun("notion-guests"); err != nil {
		t.Fatal(err)
	}
	if r.prompts() != before+1 {
		t.Fatal("the each-time replacement ran without asking")
	}
}

// A key deleted out of band refuses the run. It must not fall back to a
// prompt: a job set to run while the human is away would otherwise sit on a
// dialog nobody is there to answer.
func TestNeverJobWithItsKeyGoneRefusesWithoutPrompting(t *testing.T) {
	r := newJobRig(t)
	if _, err := r.c.JobAllow("notion-guests", r.neverSpec()); err != nil {
		t.Fatal(err)
	}
	_ = r.keys.Delete(r.stored(t).KeyID)
	before := r.prompts()
	_, err := r.c.JobRun("notion-guests")
	if err == nil || !strings.Contains(err.Error(), "key is gone") {
		t.Fatalf("run with the key gone: %v", err)
	}
	if r.prompts() != before || r.runs() != 0 {
		t.Fatal("a keyless run prompted or ran")
	}
}

// A key gone is a stop that stands until the job is approved again: the
// second run is refused as stopped, still without a prompt.
func TestNeverJobWithItsKeyGoneStaysStopped(t *testing.T) {
	r := newJobRig(t)
	if _, err := r.c.JobAllow("notion-guests", r.neverSpec()); err != nil {
		t.Fatal(err)
	}
	_ = r.keys.Delete(r.stored(t).KeyID)
	if _, err := r.c.JobRun("notion-guests"); err == nil {
		t.Fatal("ran with its key gone")
	}
	if got := r.stored(t).Stopped; got != "the job's key is gone" {
		t.Fatalf("stopped = %q, want the key-gone stop", got)
	}
	before := r.prompts()
	_, err := r.c.JobRun("notion-guests")
	if err == nil || !strings.Contains(err.Error(), "stopped because the job's key is gone") {
		t.Fatalf("second run: %v", err)
	}
	if r.prompts() != before || r.runs() != 0 {
		t.Fatal("a stopped job prompted or ran")
	}
}

// notNow marks cause as the stores mark a key that can't be used right now
// (cli's markLoad and markedKey).
func notNow(cause string) error { return fmt.Errorf("%w: %s", ErrGrantKeyNotNow, cause) }

// A key that is there but can't be used right now (an enclave this copy of
// jit can't reach: ErrGrantKeyNotNow) proves nothing about the key. The run
// is refused, naming the real cause, without a prompt, and the job is NOT
// stopped: once the key loads again, the next run runs with no new
// approval. It used to be stopped for good as "the job's key is gone".
func TestNeverJobWhoseKeyWontLoadIsNotStopped(t *testing.T) {
	r := newJobRig(t)
	if _, err := r.c.JobAllow("notion-guests", r.neverSpec()); err != nil {
		t.Fatal(err)
	}
	cause := notNow("grant key: this copy of jit can't use the Secure Enclave; use the jit inside JitPass.app")
	r.keys.mu.Lock()
	r.keys.loadErr = cause
	r.keys.mu.Unlock()
	before := r.prompts()
	_, err := r.c.JobRun("notion-guests")
	if err == nil {
		t.Fatal("ran with a key that couldn't be loaded")
	}
	const want = "agent: job_run: notion-guests: the job's key couldn't be loaded (the key can't be used right now: grant key: this copy of jit can't use the Secure Enclave; use the jit inside JitPass.app). The job wasn't stopped; the next run tries again"
	if err.Error() != want {
		t.Fatalf("refusal:\n got %q\nwant %q", err, want)
	}
	if strings.Contains(err.Error(), "gone") || strings.Contains(err.Error(), "approve it again") {
		t.Fatalf("a key that wouldn't load was called gone, or a stop: %v", err)
	}
	if r.prompts() != before || r.runs() != 0 {
		t.Fatal("a run whose key wouldn't load prompted or ran")
	}
	j := r.stored(t)
	if j.Stopped != "" {
		t.Fatalf("stopped = %q; a key that wouldn't load must not stop the job", j.Stopped)
	}
	if !strings.Contains(j.LastRefusal, "couldn't be loaded") {
		t.Errorf("last refusal = %q, want the real cause recorded", j.LastRefusal)
	}
	r.keys.mu.Lock()
	r.keys.loadErr = nil
	r.keys.mu.Unlock()
	if _, err := r.c.JobRun("notion-guests"); err != nil {
		t.Fatalf("the next run, with the key loading again: %v", err)
	}
	if r.runs() != 1 || r.prompts() != before {
		t.Fatalf("runs %d, prompts %d: want one unasked run", r.runs(), r.prompts()-before)
	}
}

// A non-sticky refusal must not read as a stop. The app notifies "<job>
// stopped running" for any job_run error whose cause contains "refused"
// (jit-app noteJobStop), so its event says "didn't run" instead, and still
// names the cause.
func TestNeverJobRunRefusalIsNotAnnouncedAsAStop(t *testing.T) {
	r := newJobRig(t)
	if _, err := r.c.JobAllow("notion-guests", r.neverSpec()); err != nil {
		t.Fatal(err)
	}
	r.keys.mu.Lock()
	r.keys.loadErr = notNow("grant key: the Mac is locked")
	r.keys.mu.Unlock()
	if _, err := r.c.JobRun("notion-guests"); err == nil {
		t.Fatal("ran with a key that couldn't be loaded")
	}
	const want = "notion-guests: didn't run, the job's key couldn't be loaded (the key can't be used right now: grant key: the Mac is locked)"
	if c := lastCause(t, r.s); c != want {
		t.Fatalf("event cause:\n got %q\nwant %q", c, want)
	}
	if strings.Contains(lastCause(t, r.s), "refused") {
		t.Fatal("the app would announce this as a stop")
	}
}

// A key that loads but can't be used right now (a locked keychain answers
// Open's read with errSecInteractionNotAllowed) proves nothing about the
// job's copies: the run is refused naming the cause, and the job is NOT
// stopped. It used to be stopped for good as "does not open under the
// job's key".
func TestNeverJobWhoseKeyWontOpenNowIsNotStopped(t *testing.T) {
	r := newJobRig(t)
	if _, err := r.c.JobAllow("notion-guests", r.neverSpec()); err != nil {
		t.Fatal(err)
	}
	r.keys.mu.Lock()
	r.keys.openErr = notNow("grant key: reading the key in the keychain without asking failed, OSStatus=-25308")
	r.keys.mu.Unlock()
	before := r.prompts()
	_, err := r.c.JobRun("notion-guests")
	if err == nil {
		t.Fatal("ran with a key that couldn't open")
	}
	const want = "agent: job_run: notion-guests: the job's key couldn't open NOTION_API_KEY (the key can't be used right now: grant key: reading the key in the keychain without asking failed, OSStatus=-25308). The job wasn't stopped; the next run tries again"
	if err.Error() != want {
		t.Fatalf("refusal:\n got %q\nwant %q", err, want)
	}
	if j := r.stored(t); j.Stopped != "" {
		t.Fatalf("stopped = %q; a key that can't be used right now must not stop the job", j.Stopped)
	}
	if r.prompts() != before || r.runs() != 0 {
		t.Fatal("prompted or ran")
	}
	r.keys.mu.Lock()
	r.keys.openErr = nil
	r.keys.mu.Unlock()
	if _, err := r.c.JobRun("notion-guests"); err != nil || r.runs() != 1 {
		t.Fatalf("the next run, with the key opening again: %v (runs %d)", err, r.runs())
	}
}

// A copy that doesn't open under the key (ErrGrantKeyWrongKey: tampered,
// sealed for another key or class) is the sticky stop, as before.
func TestNeverJobWhoseCopyDoesntOpenStaysStopped(t *testing.T) {
	for _, tc := range []struct {
		name    string
		openErr error
	}{
		{"marked by the store", fmt.Errorf("%w: cipher: message authentication failed", ErrGrantKeyWrongKey)},
		{"a real tag mismatch", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newJobRig(t)
			if _, err := r.c.JobAllow("notion-guests", r.neverSpec()); err != nil {
				t.Fatal(err)
			}
			if tc.openErr != nil {
				r.keys.mu.Lock()
				r.keys.openErr = tc.openErr
				r.keys.mu.Unlock()
			} else {
				// Another key under the job's id: its copies fail GCM.
				id := r.stored(t).KeyID
				_ = r.keys.Delete(id)
				if _, err := r.keys.Create(id); err != nil {
					t.Fatal(err)
				}
			}
			_, err := r.c.JobRun("notion-guests")
			if err == nil || !strings.Contains(err.Error(), "NOTION_API_KEY does not open under the job's key. It won't run until you approve it again") {
				t.Fatalf("run: %v", err)
			}
			if got := r.stored(t).Stopped; got != "NOTION_API_KEY does not open under the job's key" {
				t.Fatalf("stopped = %q", got)
			}
			if c := lastCause(t, r.s); !strings.HasPrefix(c, "notion-guests: refused, ") {
				t.Fatalf("a stop's event must still read as one: %q", c)
			}
		})
	}
}

// The default is a stop. Any Load or Open failure a store did not mark as
// "can't be used right now" is an answer about the key or the copy (a
// malformed item, errSecAuthFailed, CryptoTokenKit's -3 for a damaged
// ephemeral key, a lookup's -50), and stops the job for good, the real
// cause in the reason, with no prompt: as it did before a skip existed.
func TestNeverJobWhoseKeyFailsUnmarkedStops(t *testing.T) {
	for _, tc := range []struct {
		name, cause string
		load        bool
		stopped     string
	}{
		{"Load, a lookup's -50", "grant key: checking for the Secure Enclave key failed (OSStatus=-50)", true,
			"the job's key couldn't be loaded (grant key: checking for the Secure Enclave key failed (OSStatus=-50))"},
		{"Open, errSecAuthFailed", "grant key: reading the key in the keychain without asking failed, OSStatus=-25293", false,
			"the job's key couldn't open NOTION_API_KEY (grant key: reading the key in the keychain without asking failed, OSStatus=-25293)"},
		{"Open, a damaged ephemeral key", "opening with the Secure Enclave key: The operation couldn't be completed. (CryptoTokenKit error -3.)", false,
			"the job's key couldn't open NOTION_API_KEY (opening with the Secure Enclave key: The operation couldn't be completed. (CryptoTokenKit error -3.))"},
		{"Open, a malformed item", `grant key: the keychain item "x" is not a master key: 7 bytes, want 32`, false,
			`the job's key couldn't open NOTION_API_KEY (grant key: the keychain item "x" is not a master key: 7 bytes, want 32)`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newJobRig(t)
			if _, err := r.c.JobAllow("notion-guests", r.neverSpec()); err != nil {
				t.Fatal(err)
			}
			r.keys.mu.Lock()
			if tc.load {
				r.keys.loadErr = errors.New(tc.cause)
			} else {
				r.keys.openErr = errors.New(tc.cause)
			}
			r.keys.mu.Unlock()
			before := r.prompts()
			_, err := r.c.JobRun("notion-guests")
			if want := "agent: job_run: notion-guests: " + tc.stopped + ". It won't run until you approve it again"; err == nil || err.Error() != want {
				t.Fatalf("run:\n got %v\nwant %s", err, want)
			}
			if got := r.stored(t).Stopped; got != tc.stopped {
				t.Fatalf("stopped = %q, want %q", got, tc.stopped)
			}
			if c := lastCause(t, r.s); c != "notion-guests: refused, "+tc.stopped {
				t.Fatalf("a stop's event must read as one: %q", c)
			}
			if r.prompts() != before || r.runs() != 0 {
				t.Fatal("prompted or ran")
			}
			// Sticky: the key working again changes nothing.
			r.keys.mu.Lock()
			r.keys.loadErr, r.keys.openErr = nil, nil
			r.keys.mu.Unlock()
			if _, err := r.c.JobRun("notion-guests"); err == nil || r.runs() != 0 {
				t.Fatalf("a stopped job ran again without approval: %v", err)
			}
		})
	}
}

// A job that could not be saved must not leave its key behind.
func TestNeverJobThatCannotBeSavedLeavesNoKey(t *testing.T) {
	r := newJobRig(t)
	blocker := filepath.Join(t.TempDir(), "a-file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	r.s.jobMu.Lock()
	r.s.jobsPath = filepath.Join(blocker, "jobs.json") // a directory that cannot exist
	r.s.jobMu.Unlock()
	if _, err := r.c.JobAllow("notion-guests", r.neverSpec()); err == nil {
		t.Fatal("approval reported success with an unwritable job list")
	}
	r.keys.mu.Lock()
	n := len(r.keys.keys)
	r.keys.mu.Unlock()
	if n != 0 {
		t.Fatalf("%d key(s) orphaned in the keychain", n)
	}
}

func TestNeverJobRefusedWithoutAKeyStore(t *testing.T) {
	r := newJobRig(t)
	r.s.GrantKeys = nil
	if _, err := r.c.JobAllow("notion-guests", r.neverSpec()); err == nil {
		t.Fatal("a never-asking job was approved with nowhere to keep its key")
	}
	if r.prompts() != 0 {
		t.Fatal("the refusal prompted")
	}
}

// Review finding 1: the run re-checks the folder AFTER the prompt. An edit
// made while the human reads the dialog must not run with the secrets.
func TestJobRunRefusesAScriptEditedDuringThePrompt(t *testing.T) {
	r := newJobRig(t)
	if _, err := r.c.JobAllow("notion-guests", r.spec()); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(r.dir, "list_guest_users.py")
	r.s.newFetcher = func() MEKFetcher {
		return fnFetcher{fn: func(string) ([]byte, error) {
			if err := os.WriteFile(script, []byte("import os; print(os.environ)\n"), 0o600); err != nil {
				return nil, err
			}
			return append([]byte(nil), grantTestMEK...), nil
		}}
	}
	_, err := r.c.JobRun("notion-guests")
	if err == nil || !strings.Contains(err.Error(), "while the prompt was up") {
		t.Fatalf("run with an edit during the prompt: %v", err)
	}
	if r.runs() != 0 {
		t.Fatal("the edited script reached the runner")
	}
}

// Review finding 2, at the service: --output . is refused before the prompt.
func TestJobAllowRefusesAnOutputHoldingTheFolder(t *testing.T) {
	r := newJobRig(t)
	for _, o := range []string{".", r.dir, filepath.Dir(r.dir)} {
		spec := r.spec()
		spec.Outputs = []string{o}
		if _, err := r.c.JobAllow("notion-guests", spec); err == nil {
			t.Errorf("--output %s approved", o)
		}
	}
	if r.prompts() != 0 {
		t.Fatal("the refusal prompted")
	}
}

// Review finding 3: a job with no secrets still asks when approved to ask,
// and a never-asking one with no secrets needs no key.
func TestJobWithNoSecretsStillAsks(t *testing.T) {
	r := newJobRig(t)
	spec := r.spec()
	spec.Profile = nil
	if _, err := r.c.JobAllow("notion-guests", spec); err != nil {
		t.Fatal(err)
	}
	before := r.prompts()
	if _, err := r.c.JobRun("notion-guests"); err != nil {
		t.Fatal(err)
	}
	if r.prompts() != before+1 {
		t.Fatal("an each-time job with no secrets ran without asking")
	}
	spec.Ask, spec.Replace = string(job.AskNever), true
	if _, err := r.c.JobAllow("notion-guests", spec); err != nil {
		t.Fatal(err)
	}
	if r.stored(t).KeyID != "" {
		t.Fatal("a job with no secrets got a key")
	}
	before = r.prompts()
	if _, err := r.c.JobRun("notion-guests"); err != nil {
		t.Fatalf("never-asking job with no secrets: %v", err)
	}
	if r.prompts() != before {
		t.Fatal("a never-asking job prompted")
	}
}

// Review finding 7: the names-only list does no fingerprinting, so it
// cannot report a change; the full list does.
func TestJobNamesSkipsTheChecks(t *testing.T) {
	r := newJobRig(t)
	if _, err := r.c.JobAllow("notion-guests", r.spec()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(r.dir, "list_guest_users.py"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	names, err := r.c.JobNames()
	if err != nil || len(names) != 1 || names[0].Name != "notion-guests" || names[0].State != "" {
		t.Fatalf("JobNames = %v %+v", err, names)
	}
	full, _ := r.c.JobList()
	if full[0].State != JobChanged {
		t.Fatalf("full list state = %q", full[0].State)
	}
}

// Found in the live test: a never-asking job printed "Touch ID required" on
// every run, because the notice fires on any call slower than a moment and a
// run lasts as long as its script. Only an each-time job may show it.
func TestJobRunWaitNoticeOnlyWhenAPromptIsPossible(t *testing.T) {
	r := newJobRig(t)
	slow := r.s.OnRunJob
	r.s.OnRunJob = func(j job.Job, deks map[string][]byte) (JobResult, error) {
		time.Sleep(2 * waitNotifyDelay)
		return slow(j, deks)
	}
	var notices int32
	c := r.c.WithWaitNotifier(func() { atomic.AddInt32(&notices, 1) })

	if _, err := r.c.JobAllow("notion-guests", r.neverSpec()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.JobRun("notion-guests"); err != nil {
		t.Fatal(err)
	}
	if n := atomic.LoadInt32(&notices); n != 0 {
		t.Fatalf("a never-asking run showed the Touch ID notice %d time(s)", n)
	}

	spec := r.spec()
	spec.Replace = true
	if _, err := r.c.JobAllow("notion-guests", spec); err != nil {
		t.Fatal(err)
	}
	if _, err := c.JobRun("notion-guests"); err != nil {
		t.Fatal(err)
	}
	if n := atomic.LoadInt32(&notices); n != 1 {
		t.Fatalf("an each-time run showed the notice %d time(s), want 1", n)
	}
}

// captureReasons swaps in a fetcher that approves and records each prompt.
func (r *jobRig) captureReasons() *[]string {
	var mu sync.Mutex
	reasons := &[]string{}
	r.s.newFetcher = func() MEKFetcher {
		return fnFetcher{fn: func(reason string) ([]byte, error) {
			mu.Lock()
			*reasons = append(*reasons, reason)
			mu.Unlock()
			return append([]byte(nil), grantTestMEK...), nil
		}}
	}
	return reasons
}

// Second review, findings 2 and 7: the approval prompt names what the
// service resolved (folder/script, vault group, shown count) and never the
// caller-chosen job name.
func TestJobAllowPromptNamesResolvedFacts(t *testing.T) {
	r := newJobRig(t)
	reasons := r.captureReasons()
	spec := r.spec()
	spec.Shown = []string{"NOTION_API_KEY"}
	if _, err := r.c.JobAllow("trusted-name", spec); err != nil {
		t.Fatal(err)
	}
	got := (*reasons)[0]
	script := r.spec().Argv[1]
	for _, want := range []string{filepath.Base(r.dir) + "/" + script, "with 1 secret", "1 shown"} {
		if !strings.Contains(got, want) {
			t.Errorf("prompt %q lacks %q", got, want)
		}
	}
	if strings.Contains(got, "trusted-name") {
		t.Errorf("prompt shows the caller-chosen name: %q", got)
	}
}

// Second review, finding 1: a job approved through a symlinked path is kept
// under the real folder, with its files.
func TestJobAllowResolvesASymlinkedFolder(t *testing.T) {
	r := newJobRig(t)
	link := filepath.Join(t.TempDir(), "linked")
	if err := os.Symlink(r.dir, link); err != nil {
		t.Fatal(err)
	}
	spec := r.spec()
	spec.Dir = link
	st, err := r.c.JobAllow("notion-guests", spec)
	if err != nil {
		t.Fatal(err)
	}
	real, _ := filepath.EvalSymlinks(r.dir)
	if st.Dir != real || st.Files == 0 {
		t.Fatalf("Dir %q (want %q), %d files", st.Dir, real, st.Files)
	}
	if err := os.WriteFile(filepath.Join(r.dir, "list_guest_users.py"), []byte("changed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := r.c.JobRun("notion-guests"); err == nil {
		t.Fatal("an edit under a symlinked job folder did not stop the job")
	}
}

// Second review, finding 5: a stop is sticky. Putting the file back does
// not make the job runnable, so a swap cannot be retried for free.
func TestJobStopIsStickyUntilApprovedAgain(t *testing.T) {
	r := newJobRig(t)
	if _, err := r.c.JobAllow("notion-guests", r.spec()); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(r.dir, "list_guest_users.py")
	orig, _ := os.ReadFile(script)
	if err := os.WriteFile(script, []byte("import os; print(os.environ)\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := r.c.JobRun("notion-guests"); err == nil {
		t.Fatal("the swapped script ran")
	}
	if err := os.WriteFile(script, orig, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := r.c.JobRun("notion-guests"); err == nil || !strings.Contains(err.Error(), "stopped because") {
		t.Fatalf("after putting the file back: %v, want still stopped", err)
	}
	if jobs, _ := r.c.JobList(); jobs[0].State != JobChanged {
		t.Fatalf("list state = %q, want stopped", jobs[0].State)
	}
	spec := r.spec()
	spec.Replace = true
	if _, err := r.c.JobAllow("notion-guests", spec); err != nil {
		t.Fatal(err)
	}
	if _, err := r.c.JobRun("notion-guests"); err != nil {
		t.Fatalf("after approving again: %v", err)
	}
}

// Second review, finding 5: a change that lands during the run withholds
// the output and stops the job.
func TestJobOutputWithheldWhenTheFolderChangesDuringTheRun(t *testing.T) {
	r := newJobRig(t)
	if _, err := r.c.JobAllow("notion-guests", r.spec()); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(r.dir, "list_guest_users.py")
	inner := r.s.OnRunJob
	r.s.OnRunJob = func(j job.Job, deks map[string][]byte) (JobResult, error) {
		res, err := inner(j, deks)
		_ = os.WriteFile(script, []byte("swapped mid-run\n"), 0o600)
		res.Stdout = "shaped by the swapped code"
		return res, err
	}
	res, err := r.c.JobRun("notion-guests")
	if err == nil || !strings.Contains(err.Error(), "while the job ran, so its output was withheld") {
		t.Fatalf("run = %+v, %v", res, err)
	}
	if strings.Contains(err.Error(), "shaped by") {
		t.Fatal("the output reached the caller")
	}
}

// Second review, finding 1: nothing to fingerprint means nothing could ever
// stop the job.
func TestJobAllowRefusesAFolderWithNothingToFingerprint(t *testing.T) {
	r := newJobRig(t)
	empty := t.TempDir()
	spec := r.spec()
	spec.Dir, spec.Argv, spec.Profile = empty, []string{"/bin/sh", "/dev/null"}, nil
	if _, err := r.c.JobAllow("empty", spec); err == nil || !strings.Contains(err.Error(), "no files") {
		t.Fatalf("empty folder: %v", err)
	}
}

// The live Cowork test's prompt said "for jit-dev" and the app said
// "launched by disclaimer". The requester is the app behind jit, whatever
// jit's own file is called.
func TestJobRequesterNamesTheAppBehindJit(t *testing.T) {
	behind := []lineage.Process{
		{PID: 27067, ExecPath: "/Applications/Claude.app/Contents/Helpers/disclaimer"},
		{PID: 27002, ExecPath: "/Applications/Claude.app/Contents/MacOS/Claude"},
	}
	for name, self := range map[string]lineage.Process{
		"this binary, renamed": {PID: 27071, ExecPath: currentExecutablePath()},
		"a jit elsewhere":      {PID: 27071, ExecPath: "/opt/homebrew/bin/jit"},
	} {
		if got := jobRequester(&caller{pid: 27071, self: self, ancestors: behind}); got != "Claude" {
			t.Errorf("%s: requester = %q, want Claude", name, got)
		}
	}
	other := &caller{pid: 5, self: lineage.Process{PID: 5, ExecPath: "/usr/local/bin/claude"}}
	if got := jobRequester(other); got != "claude" {
		t.Errorf("a direct caller: requester = %q, want claude", got)
	}
}

// Third review, findings 1 and 7: the prompt names the program that runs,
// even when an argument names another file and the folder name is long.
func TestJobAllowPromptNamesTheProgramThatRuns(t *testing.T) {
	r := newJobRig(t)
	reasons := r.captureReasons()
	long := filepath.Join(t.TempDir(), "notion-weekly-guest-report-list_guest_users.py-runner-v2-final")
	if err := os.MkdirAll(long, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"exfil.sh", "list_guest_users.py"} {
		if err := os.WriteFile(filepath.Join(long, f), []byte("#!/bin/sh\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	spec := r.spec()
	spec.Dir, spec.Argv = long, []string{"./exfil.sh", "list_guest_users.py"}
	if _, err := r.c.JobAllow("x", spec); err != nil {
		t.Fatal(err)
	}
	got := (*reasons)[0]
	if !strings.Contains(got, "exfil.sh") || strings.Contains(got, "list_guest_users.py with") {
		t.Fatalf("prompt %q must name exfil.sh, the program that runs", got)
	}
}

// Third review, finding 2: one run of a job at a time.
func TestJobRunsOneAtATime(t *testing.T) {
	r := newJobRig(t)
	if _, err := r.c.JobAllow("notion-guests", r.spec()); err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	inner := r.s.OnRunJob
	r.s.OnRunJob = func(j job.Job, deks map[string][]byte) (JobResult, error) {
		started <- struct{}{}
		<-release
		return inner(j, deks)
	}
	first := make(chan error, 1)
	go func() { _, err := r.c.JobRun("notion-guests"); first <- err }()
	<-started
	if _, err := r.c.JobRun("notion-guests"); err == nil || !strings.Contains(err.Error(), "already running") {
		t.Fatalf("a second concurrent run: %v", err)
	}
	close(release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
}

// Third review, finding 2: a job stopped while a run waited on its prompt
// does not run.
func TestJobRunRechecksTheStoredJobAfterThePrompt(t *testing.T) {
	r := newJobRig(t)
	if _, err := r.c.JobAllow("notion-guests", r.spec()); err != nil {
		t.Fatal(err)
	}
	r.s.newFetcher = func() MEKFetcher {
		return fnFetcher{fn: func(string) ([]byte, error) {
			r.s.jobMu.Lock()
			r.s.jobs["notion-guests"].Stopped = "a file changed during another run"
			r.s.jobMu.Unlock()
			return append([]byte(nil), grantTestMEK...), nil
		}}
	}
	if _, err := r.c.JobRun("notion-guests"); err == nil || !strings.Contains(err.Error(), "while this run waited") {
		t.Fatalf("run after a stop during its prompt: %v", err)
	}
	if r.runs() != 0 {
		t.Fatal("it ran")
	}
}

// Third review, finding 5: a swap made during the run and put back before
// it ends leaves the content identical, and is still caught after the run.
func TestJobRunWithholdsOutputAfterASwapPutBack(t *testing.T) {
	r := newJobRig(t)
	if _, err := r.c.JobAllow("notion-guests", r.spec()); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(r.dir, "list_guest_users.py")
	inner := r.s.OnRunJob
	r.s.OnRunJob = func(j job.Job, deks map[string][]byte) (JobResult, error) {
		time.Sleep(20 * time.Millisecond)
		aside := script + ".aside"
		_ = os.Rename(script, aside)
		_ = os.WriteFile(script, []byte("import os; print(os.environ)\n"), 0o600)
		_ = os.Rename(aside, script) // put back: identical content
		res, err := inner(j, deks)
		res.Stdout = "shaped by the swapped code"
		return res, err
	}
	_, err := r.c.JobRun("notion-guests")
	if err == nil || !strings.Contains(err.Error(), "list_guest_users.py was written to") || strings.Contains(err.Error(), "shaped by") {
		t.Fatalf("run with a swap put back: %v", err)
	}
	if jobs, _ := r.c.JobList(); jobs[0].State != JobChanged {
		t.Fatal("the job was not stopped")
	}
}

func TestJobStopForBytecodeExplainsItself(t *testing.T) {
	r := newJobRig(t)
	if _, err := r.c.JobAllow("notion-guests", r.spec()); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(r.dir, "__pycache__"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(r.dir, "__pycache__", "list_guest_users.cpython-314.pyc"), []byte("bytecode"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := r.c.JobRun("notion-guests"); err == nil || !strings.Contains(err.Error(), "runs outside jit") {
		t.Fatalf("bytecode-only stop: %v", err)
	}
}

// Step 4b: a proposal needs the app, creates nothing, can never ask to run
// unasked, and is cleared by approving or dismissing it.
func TestJobProposalsGoToTheAppAndCreateNothing(t *testing.T) {
	r := newJobRig(t)
	spec := r.spec()
	spec.Ask = string(job.AskNever) // the agent asks for unattended; it must not get it

	if _, err := r.c.JobRequest("guest-report", spec, "access review"); err == nil || !strings.Contains(err.Error(), ErrNoProposalViewer.Error()) {
		t.Fatalf("with no app: %v", err)
	}

	events := make(chan SessionEvent, 4)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = r.c.SubscribeShowingProposals(ctx, func(e SessionEvent) {
			if e.Kind == KindJobProposal {
				events <- e
			}
		})
	}()
	defer func() { cancel(); <-done }()
	waitFor(t, "the app's stream", func() bool { return r.s.proposalViewers() == 1 })

	p, err := r.c.JobRequest("guest-report", spec, "access review")
	if err != nil {
		t.Fatal(err)
	}
	select {
	case e := <-events:
		if e.ConsentID != p.ID || e.Job != "guest-report" || e.Cause != "access review" {
			t.Fatalf("app was shown %+v", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the app was never shown the proposal")
	}
	if p.Spec.Ask != string(job.AskEachTime) {
		t.Fatalf("a proposal kept ask=%q; the agent cannot choose unattended", p.Spec.Ask)
	}
	if jobs, _ := r.c.JobList(); len(jobs) != 0 || r.prompts() != 0 {
		t.Fatal("a proposal created a job or prompted")
	}
	if list, _ := r.c.JobProposals(); len(list) != 1 {
		t.Fatalf("proposals = %v", list)
	}

	// Approving it is the ordinary approval, and it stops waiting.
	if _, err := r.c.JobAllowProposal("guest-report", p.Spec, p.ID); err != nil {
		t.Fatal(err)
	}
	if r.prompts() != 1 {
		t.Fatalf("approving a proposal prompted %d times, want the one Touch ID", r.prompts())
	}
	if list, _ := r.c.JobProposals(); len(list) != 0 {
		t.Fatal("an approved proposal still waits")
	}

	// Dismissing drops one without a prompt.
	q, _ := r.c.JobRequest("other", spec, "")
	<-events
	if err := r.c.JobDismiss(q.ID); err != nil {
		t.Fatal(err)
	}
	if list, _ := r.c.JobProposals(); len(list) != 0 {
		t.Fatal("a dismissed proposal still waits")
	}

	// Refused before anything is kept.
	bad := spec
	bad.Argv = []string{"python3", "-c", "print(1)"}
	if _, err := r.c.JobRequest("bad", bad, ""); err == nil {
		t.Fatal("python -c was kept as a proposal")
	}
	for i := 0; i < maxJobProposals; i++ {
		if _, err := r.c.JobRequest(fmt.Sprintf("p%d", i), spec, ""); err != nil {
			t.Fatal(err)
		}
		<-events
	}
	if _, err := r.c.JobRequest("one-too-many", spec, ""); err == nil {
		t.Fatal("the proposal list is not capped")
	}
}

// job_preview is approval's own checks with no prompt: what it reports is
// what approval then does, its Prompt is the sentence the Touch ID shows,
// and a refusal is approval's refusal word for word.
func TestJobPreviewIsApprovalWithoutThePrompt(t *testing.T) {
	r := newJobRig(t)
	reasons := r.captureReasons()
	spec := r.spec()
	spec.Shown = []string{"NOTION_API_KEY"}

	p, err := r.c.JobPreview("notion-guests", spec)
	if err != nil || p.Refusal != "" {
		t.Fatalf("preview: %v %q", err, p.Refusal)
	}
	if len(*reasons) != 0 {
		t.Fatal("a preview prompted")
	}
	if p.Program != "list_guest_users.py" || p.Files == 0 || len(p.Secrets) != 1 || !p.Secrets[0].Shown || p.Exists {
		t.Fatalf("preview = %+v", p)
	}
	if jobs, _ := r.c.JobList(); len(jobs) != 0 {
		t.Fatal("a preview kept a job")
	}
	if _, err := r.c.JobAllow("notion-guests", spec); err != nil {
		t.Fatal(err)
	}
	if (*reasons)[0] != p.Prompt {
		t.Fatalf("preview promised %q, the Touch ID said %q", p.Prompt, (*reasons)[0])
	}
	if again, _ := r.c.JobPreview("notion-guests", spec); !again.Exists {
		t.Fatal("a preview over an existing job does not say it would replace it")
	}

	bad := r.spec()
	bad.Argv = []string{"/bin/sh", "-c", "env"}
	pv, _ := r.c.JobPreview("x", bad)
	_, allowErr := r.c.JobAllow("x", bad)
	if pv.Refusal == "" || allowErr == nil || !strings.Contains(allowErr.Error(), pv.Refusal) {
		t.Fatalf("preview refusal %q, approval said %v", pv.Refusal, allowErr)
	}
}

// A client approving a job again must send the profile it was made from:
// the status says whether that profile is global, which the folder alone
// cannot, so an edit never turns a ~/.jit/profiles job into a folder one.
func TestJobStatusSaysWhenItsProfileIsGlobal(t *testing.T) {
	r := newJobRig(t)
	st, err := r.c.JobAllow("notion-guests", r.spec())
	if err != nil || st.ProfileGlobal || st.ProfileRoot != r.dir {
		t.Fatalf("a folder profile: %v, global %v, root %q", err, st.ProfileGlobal, st.ProfileRoot)
	}
	spec := r.spec()
	spec.Profile = &GrantProfile{Name: "notion"}
	spec.Replace = true
	st, err = r.c.JobAllow("notion-guests", spec)
	if err != nil || !st.ProfileGlobal {
		t.Fatalf("a global profile: %v, global %v", err, st.ProfileGlobal)
	}
}

// The live Cursor run's prompt read "run notion/…t_guest_users.py": the
// folder kept, the script cut. The script is what the prompt is for.
func TestFitLabelDropsTheFolderBeforeCuttingTheProgram(t *testing.T) {
	if got := fitLabel("notion/list_guest_users.py", 24); got != "list_guest_users.py" {
		t.Fatalf("fitLabel = %q, want the whole script", got)
	}
	if got := fitLabel("jamf/x.py", 24); got != "jamf/x.py" {
		t.Fatalf("a label that fits is kept whole: %q", got)
	}
	if got := fitLabel("n/a_script_name_far_too_long_to_fit.py", 20); len([]rune(got)) != 20 || !strings.HasSuffix(got, ".py") {
		t.Fatalf("a program too long alone keeps both ends: %q", got)
	}
	if got := jobRunReason("Cursor", "notion/list_guest_users.py", 3); !strings.Contains(got, "run list_guest_users.py for Cursor") {
		t.Fatalf("run reason = %q", got)
	}
}

// removeDuringLoad is a key store that removes a job while the job's key is
// being loaded for a run, once, and records whether the key it handed out
// was closed.
type removeDuringLoad struct {
	*memGrantKeys
	once   sync.Once
	remove func()
	handed []*closeRecorded
	mu     sync.Mutex
}

func (r *removeDuringLoad) Load(id string) (GrantKey, error) {
	k, err := r.memGrantKeys.Load(id)
	if err != nil {
		return nil, err
	}
	r.once.Do(r.remove)
	ck := &closeRecorded{GrantKey: k}
	r.mu.Lock()
	r.handed = append(r.handed, ck)
	r.mu.Unlock()
	return ck, nil
}

// Third review of #168, the job half of the revoke race: a never-ask job
// removed while its run is opening its key does not run. A job's key is
// never cached (each run loads it and closes it), so nothing is left
// behind; the stored-job check after the open is what refuses the run.
func TestANeverJobRemovedWhileItsKeyOpensDoesNotRun(t *testing.T) {
	r := newJobRig(t)
	if _, err := r.c.JobAllow("notion-guests", r.neverSpec()); err != nil {
		t.Fatalf("JobAllow: %v", err)
	}
	store := &removeDuringLoad{memGrantKeys: r.keys}
	store.remove = func() {
		if resp := r.s.removeJob("notion-guests", nil); !resp.OK {
			t.Errorf("remove: %s", resp.Error)
		}
	}
	r.s.GrantKeys = store
	if _, err := r.c.JobRun("notion-guests"); err == nil || !strings.Contains(err.Error(), "while this run waited") {
		t.Fatalf("run of a job removed while its key opened: %v", err)
	}
	if r.runs() != 0 {
		t.Fatal("it ran")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.handed) != 1 || !store.handed[0].closed.Load() {
		t.Fatalf("the job's key was not closed after the refused run (%d handed out)", len(store.handed))
	}
}

// A secret removed from the vault after approval leaves the job with less
// than was approved, never more: the job runs without it and stays ready.
// It used to stop the job until approved again (reported 2026-09-28: a value
// moved out of the vault blocked every AI job that named it).
func TestJobRunLeavesOutASecretGoneFromTheVault(t *testing.T) {
	r := newJobRig(t)
	second, _ := seal(grantTestMEK, bytes.Repeat([]byte{0x0b}, 32), []byte("mcp"))
	r.vault["reports/REPORT_WORKSPACE_ID"] = second
	r.sources = append(r.sources, JobSecretSource{Var: "REPORT_WORKSPACE_ID", Path: "reports/REPORT_WORKSPACE_ID", Wrapped: second, Class: "mcp"})
	if _, err := r.c.JobAllow("guest-report", r.spec()); err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	delete(r.vault, "reports/REPORT_WORKSPACE_ID")
	r.mu.Unlock()

	jobs, err := r.c.JobList()
	if err != nil || len(jobs) != 1 {
		t.Fatalf("JobList: %v %v", jobs, err)
	}
	if jobs[0].State != JobReady || jobs[0].Stopped {
		t.Fatalf("state %q stopped %v: a gone secret must not stop the job", jobs[0].State, jobs[0].Stopped)
	}
	var gone []string
	for _, sec := range jobs[0].Secrets {
		if sec.Gone {
			gone = append(gone, sec.Var)
		}
	}
	if len(gone) != 1 || gone[0] != "REPORT_WORKSPACE_ID" {
		t.Fatalf("gone = %v, want [REPORT_WORKSPACE_ID]", gone)
	}

	if _, err := r.c.JobRun("guest-report"); err != nil {
		t.Fatalf("JobRun without the removed secret: %v", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	kept := r.sources[0].Var // the rig's own secret, still in the vault
	if len(r.ran) != 1 || len(r.ran[0].Secrets) != 1 || r.ran[0].Secrets[0].Var != kept {
		t.Fatalf("the run carried %+v, want only %s", r.ran, kept)
	}
}

// A profile manifest in the job's folder is never read by a run, and jit
// rewrites it itself (vault move-out): editing one must not stop the job,
// while an edit to anything the job does run still does.
func TestJobRunIgnoresProfileManifestEdits(t *testing.T) {
	r := newJobRig(t)
	manifests := filepath.Join(r.dir, ".jit", "profiles")
	if err := os.MkdirAll(manifests, 0o700); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(manifests, "other.yaml")
	if err := os.WriteFile(other, []byte("a: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := r.c.JobAllow("guest-report", r.spec()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(other, []byte("a: 2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(manifests, "new.yaml"), []byte("b: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := r.c.JobRun("guest-report"); err != nil {
		t.Fatalf("a profile manifest edit stopped the job: %v", err)
	}
	script := r.spec().Argv[1] // the rig's own script
	if err := os.WriteFile(filepath.Join(r.dir, script), []byte("print('changed')\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := r.c.JobRun("guest-report"); err == nil {
		t.Fatal("an edit to the job's own script no longer stops it")
	}
}

// An app that shows proposals (JitPass) is shown a proposal, and nothing
// else reaches its stream but the trail: the job's own approval goes
// straight to the Touch ID, once.
func TestJobProposalsReachTheApp(t *testing.T) {
	r := newJobRig(t)
	events := make(chan SessionEvent, 16)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = r.c.SubscribeShowingProposals(ctx, func(e SessionEvent) { events <- e })
	}()
	defer func() { cancel(); <-done }()
	waitFor(t, "the app's stream", func() bool { return r.s.proposalViewers() == 1 })

	p, err := r.c.JobRequest("guest-report", r.spec(), "access review")
	if err != nil {
		t.Fatalf("JobRequest with an app showing proposals: %v", err)
	}
	select {
	case e := <-events:
		if e.Kind != KindJobProposal || e.ConsentID != p.ID {
			t.Fatalf("the app was shown %+v, want the proposal %s", e, p.ID)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the app was never shown the proposal")
	}

	if _, err := r.c.JobAllow("guest-report", r.spec()); err != nil {
		t.Fatalf("JobAllow: %v", err)
	}
	if r.prompts() != 1 {
		t.Errorf("prompts = %d, want the one Touch ID", r.prompts())
	}
	// Everything the stream carried after the proposal is in the trail:
	// no request was sent to the app for it to answer or show beside the
	// dialog.
	history, err := r.c.History()
	if err != nil {
		t.Fatal(err)
	}
	recorded := map[string]bool{}
	for _, e := range history {
		recorded[e.Kind+" "+e.Op+" "+e.Cause] = true
	}
	for quiet := false; !quiet; {
		select {
		case e := <-events:
			if !recorded[e.Kind+" "+e.Op+" "+e.Cause] || e.ConsentID != "" {
				t.Errorf("the app was sent %+v, which is not in the trail", e)
			}
		case <-time.After(200 * time.Millisecond):
			quiet = true
		}
	}
}

// A JitPass older than shows_proposals subscribes with the deprecated
// broker flag, and is still shown proposals.
func TestJobProposalsReachAnAppThatSaysBroker(t *testing.T) {
	r := newJobRig(t)
	events := make(chan SessionEvent, 4)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = r.c.subscribe(ctx, Request{Broker: true}, func(e SessionEvent) {
			if e.Kind == KindJobProposal {
				events <- e
			}
		})
	}()
	defer func() { cancel(); <-done }()
	waitFor(t, "the app's stream", func() bool { return r.s.subscriberCount() == 1 })

	p, err := r.c.JobRequest("guest-report", r.spec(), "access review")
	if err != nil {
		t.Fatalf("JobRequest with an app that says broker: %v", err)
	}
	select {
	case e := <-events:
		if e.ConsentID != p.ID || e.Job != "guest-report" {
			t.Fatalf("the app was shown %+v, want the proposal %s", e, p.ID)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the app was never shown the proposal")
	}
}

// The consent ops an older JitPass still sends are gone: each is refused as
// any unknown op is, and the service goes on answering.
func TestRemovedConsentOpsAreUnknown(t *testing.T) {
	r := newJobRig(t)
	for _, op := range []string{"consent_list", "consent_answer", "consent_shown"} {
		_, err := r.c.call(Request{Op: op})
		if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("unknown op %q", op)) {
			t.Errorf("%s: %v, want the unknown-op error", op, err)
		}
	}
	if _, err := r.c.History(); err != nil {
		t.Fatalf("the service stopped answering: %v", err)
	}
}
