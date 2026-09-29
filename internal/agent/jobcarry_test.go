// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package agent

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jitpass/jit/internal/job"
)

// The moved value in these tests: a second secret of the rig's job, a URL a
// user would move out of the vault into a plain setting.
const (
	reportPath  = "reports/REPORT_URL"
	reportVar   = "REPORT_URL"
	reportValue = "https://reports.example.test/v2"
)

var reportDEK = bytes.Repeat([]byte{0x0c}, 32)

// withReportURL adds the second secret to the rig's profile and vault, before
// the job is approved.
func (r *jobRig) withReportURL(t *testing.T) {
	t.Helper()
	wrapped, err := seal(grantTestMEK, reportDEK, []byte("mcp"))
	if err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.vault[reportPath] = wrapped
	r.plain[reportPath] = plainValue{dek: reportDEK, value: []byte(reportValue)}
	r.sources = append(r.sources, JobSecretSource{Var: reportVar, Path: reportPath, Wrapped: wrapped, Class: "mcp"})
}

// writeSetting is the first half of a move out: the value written to its
// setting file, with the vault copy still there. It returns the file.
func (r *jobRig) writeSetting(t *testing.T, value string) string {
	t.Helper()
	file := filepath.Join(t.TempDir(), "settings", "reports", reportVar)
	if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	r.moved[reportPath] = MovedSetting{Pointer: "jit://setting/" + reportPath, File: file}
	r.mu.Unlock()
	return file
}

// removeVaultCopy is the move's last step.
func (r *jobRig) removeVaultCopy() {
	r.mu.Lock()
	delete(r.vault, reportPath)
	r.mu.Unlock()
}

// storedJob is the carried job as jobs.json holds it.
func (r *jobRig) storedJob(t *testing.T) *job.Job {
	t.Helper()
	jobs, err := job.Load(r.storeAt)
	if err != nil || jobs["report-export"] == nil {
		t.Fatalf("jobs.json: %v %v", err, jobs)
	}
	return jobs["report-export"]
}

func (r *jobRig) onlyJob(t *testing.T) JobStatus {
	t.Helper()
	jobs, err := r.c.JobList()
	if err != nil || len(jobs) != 1 {
		t.Fatalf("JobList: %v %v", jobs, err)
	}
	return jobs[0]
}

// The reported case (2026-09-29): a value moved out of the vault left the
// job still "ready", running without it. Carried along, a job that never
// asks reads it from the setting, with the vault locked and no prompt, and
// the setting's file is fingerprinted like any other setting's.
func TestMoveOutCarriesANeverJobToTheSetting(t *testing.T) {
	r := newJobRig(t)
	r.withReportURL(t)
	if _, err := r.c.JobAllow("report-export", r.neverSpec()); err != nil {
		t.Fatal(err)
	}
	if err := r.c.Lock(); err != nil {
		t.Fatal(err)
	}
	prompts := r.prompts()
	file := r.writeSetting(t, reportValue)

	carried, err := r.c.JobCarry(reportPath)
	if err != nil {
		t.Fatalf("JobCarry: %v", err)
	}
	if len(carried) != 1 || !carried[0].Carried || carried[0].Job != "report-export" || carried[0].Var != reportVar {
		t.Fatalf("carried = %+v, want report-export's %s carried", carried, reportVar)
	}
	if r.prompts() != prompts {
		t.Fatal("carrying the job prompted")
	}
	r.removeVaultCopy()

	st := r.onlyJob(t)
	if st.State != JobReady || st.Stopped {
		t.Fatalf("state %q stopped %v (%s): a carried job must stay ready", st.State, st.Stopped, st.LastRefusal)
	}
	for _, sec := range st.Secrets {
		if sec.Var == reportVar {
			t.Fatalf("%s is still one of the job's secrets: %+v", reportVar, st.Secrets)
		}
	}
	stored := job.Job{}
	if js, err := job.Load(r.storeAt); err == nil && js["report-export"] != nil {
		stored = *js["report-export"]
	}
	wantSetting := job.Setting{Var: reportVar, Path: "jit://setting/" + reportPath}
	if len(stored.Settings) != 1 || stored.Settings[0] != wantSetting {
		t.Fatalf("settings = %+v, want [%+v]", stored.Settings, wantSetting)
	}
	if !containsString(stored.Extra, file) {
		t.Fatalf("extra = %v, want the setting's file %s", stored.Extra, file)
	}

	if _, err := r.c.JobRun("report-export"); err != nil {
		t.Fatalf("JobRun after the carry: %v", err)
	}
	r.mu.Lock()
	ran := r.ran[len(r.ran)-1]
	r.mu.Unlock()
	if len(ran.Settings) != 1 || ran.Settings[0].Var != reportVar {
		t.Fatalf("the run got settings %+v, want %s", ran.Settings, reportVar)
	}

	// The setting is now what protects the job: a changed value stops it.
	if err := os.WriteFile(file, []byte("https://elsewhere.example.test"), 0o600); err != nil {
		t.Fatal(err)
	}
	if st := r.onlyJob(t); st.State != JobChanged || !st.Stopped {
		t.Fatalf("state %q after the setting changed, want %q", st.State, JobChanged)
	}
}

// Nothing the caller says is trusted: a setting that doesn't hold the
// approved value carries nothing, and stops the job at once. A move copies
// the value exactly, so only someone else's setting mismatches, and a job
// that kept answering would let them test guesses at its secret: one guess
// per approval, and the second call learns nothing.
func TestJobCarryToADifferentValueStopsTheJob(t *testing.T) {
	r := newJobRig(t)
	r.withReportURL(t)
	if _, err := r.c.JobAllow("report-export", r.neverSpec()); err != nil {
		t.Fatal(err)
	}
	if err := r.c.Lock(); err != nil {
		t.Fatal(err)
	}
	file := r.writeSetting(t, "https://attacker.example.test")

	carried, err := r.c.JobCarry(reportPath)
	if err != nil {
		t.Fatalf("JobCarry: %v", err)
	}
	if len(carried) != 1 || carried[0].Carried || !strings.Contains(carried[0].Why, "doesn't hold the value you approved") {
		t.Fatalf("carried = %+v, want not carried for a different value", carried)
	}
	stored := r.storedJob(t)
	if len(stored.Settings) != 0 || stored.Stopped == "" {
		t.Fatalf("settings %+v stopped %q: want the job unchanged and stopped", stored.Settings, stored.Stopped)
	}

	// The right value now gets no answer: the job is stopped.
	if err := os.WriteFile(file, []byte(reportValue), 0o600); err != nil {
		t.Fatal(err)
	}
	carried, err = r.c.JobCarry(reportPath)
	if err != nil {
		t.Fatalf("JobCarry: %v", err)
	}
	if len(carried) != 1 || carried[0].Carried || carried[0].Why != "it is stopped already" {
		t.Fatalf("second carry = %+v, want no answer for a stopped job", carried)
	}
	runs := r.runs()
	if _, err := r.c.JobRun("report-export"); err == nil {
		t.Fatal("a job stopped by a mismatched setting ran")
	}
	if r.runs() != runs {
		t.Fatal("the stopped job ran")
	}
}

// A job the move could not carry along (here: asks each time, vault locked)
// stops once the vault copy is gone, naming the move, instead of running
// without the value as it would for a value simply deleted.
func TestAJobNotCarriedStopsOnceTheVaultCopyIsGone(t *testing.T) {
	r := newJobRig(t)
	r.withReportURL(t)
	if _, err := r.c.JobAllow("report-export", r.spec()); err != nil {
		t.Fatal(err)
	}
	r.writeSetting(t, reportValue)
	if err := r.c.Lock(); err != nil {
		t.Fatal(err)
	}
	if carried, err := r.c.JobCarry(reportPath); err != nil || len(carried) != 1 || carried[0].Carried {
		t.Fatalf("JobCarry while locked = %+v, %v; want not carried", carried, err)
	}
	r.removeVaultCopy()

	st := r.onlyJob(t)
	if st.State != JobChanged || !st.Stopped || !strings.Contains(st.LastRefusal, reportVar+" was moved out of the vault") {
		t.Fatalf("state %q stopped %v refusal %q, want stopped for the move", st.State, st.Stopped, st.LastRefusal)
	}
	for _, sec := range st.Secrets {
		if sec.Var == reportVar && (!sec.Moved || sec.Gone) {
			t.Fatalf("%s status %+v, want moved and not gone", reportVar, sec)
		}
	}
	runs := r.runs()
	if _, err := r.c.JobRun("report-export"); err == nil || !strings.Contains(err.Error(), "moved out of the vault") {
		t.Fatalf("JobRun of a job whose value moved: %v", err)
	}
	if r.runs() != runs {
		t.Fatal("the job ran without its moved value")
	}
}

// A job that asks each time has no key of its own: the service can check
// the vault copy only with the session already open, and never prompts for
// it (the move took its own Touch ID).
func TestMoveOutCarriesAnEachTimeJobOnlyWhileUnlocked(t *testing.T) {
	r := newJobRig(t)
	r.withReportURL(t)
	if _, err := r.c.JobAllow("report-export", r.spec()); err != nil {
		t.Fatal(err)
	}
	r.writeSetting(t, reportValue)
	if err := r.c.Lock(); err != nil {
		t.Fatal(err)
	}
	prompts := r.prompts()
	carried, err := r.c.JobCarry(reportPath)
	if err != nil {
		t.Fatalf("JobCarry: %v", err)
	}
	if len(carried) != 1 || carried[0].Carried || carried[0].Why != "the vault is locked" {
		t.Fatalf("carried while locked = %+v, want not carried, the vault is locked", carried)
	}
	if r.prompts() != prompts {
		t.Fatal("carrying the job prompted")
	}

	if _, _, err := r.c.Unlock(); err != nil {
		t.Fatal(err)
	}
	carried, err = r.c.JobCarry(reportPath)
	if err != nil {
		t.Fatalf("JobCarry: %v", err)
	}
	if len(carried) != 1 || !carried[0].Carried {
		t.Fatalf("carried while unlocked = %+v, want carried", carried)
	}
}

// Carrying adds the setting's file to the fingerprint and nothing else: a
// job whose folder changed since approval is not approved again on the way.
func TestMoveOutDoesNotCarryAJobWhoseFilesChanged(t *testing.T) {
	r := newJobRig(t)
	r.withReportURL(t)
	if _, err := r.c.JobAllow("report-export", r.neverSpec()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(r.dir, r.spec().Argv[1]), []byte("print('changed')\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r.writeSetting(t, reportValue)
	carried, err := r.c.JobCarry(reportPath)
	if err != nil {
		t.Fatalf("JobCarry: %v", err)
	}
	if len(carried) != 1 || carried[0].Carried || !strings.Contains(carried[0].Why, "files changed") {
		t.Fatalf("carried = %+v, want not carried for a changed folder", carried)
	}
}

// A job that doesn't get the value is not touched, and a value no job gets
// answers an empty list.
func TestJobCarryLeavesOtherJobsAlone(t *testing.T) {
	r := newJobRig(t)
	if _, err := r.c.JobAllow("report-export", r.neverSpec()); err != nil {
		t.Fatal(err)
	}
	before := r.storedJob(t).Fingerprint.Root
	r.writeSetting(t, reportValue)
	carried, err := r.c.JobCarry(reportPath)
	if err != nil || len(carried) != 0 {
		t.Fatalf("JobCarry = %+v, %v; want none", carried, err)
	}
	if r.storedJob(t).Fingerprint.Root != before {
		t.Fatal("a job that doesn't get the value was changed")
	}
}

// The file the carried job fingerprints must be the bytes compared: a
// setting rewritten after the comparison (an honest move hijacked in the
// window) is not approved on the way through.
func TestJobCarryRefusesASettingSwappedAfterTheComparison(t *testing.T) {
	r := newJobRig(t)
	r.withReportURL(t)
	if _, err := r.c.JobAllow("report-export", r.neverSpec()); err != nil {
		t.Fatal(err)
	}
	file := r.writeSetting(t, reportValue)
	r.s.carryCompared = func() {
		if err := os.WriteFile(file, []byte("https://attacker.example.test"), 0o600); err != nil {
			t.Error(err)
		}
	}
	carried, err := r.c.JobCarry(reportPath)
	if err != nil {
		t.Fatalf("JobCarry: %v", err)
	}
	if len(carried) != 1 || carried[0].Carried || carried[0].Why != "the setting changed while it was checked" {
		t.Fatalf("carried = %+v, want refused for a swapped setting", carried)
	}
	if st := r.storedJob(t); len(st.Settings) != 0 {
		t.Fatalf("the job was carried to the swapped setting: %+v", st.Settings)
	}
}

// A job changed between the checks and the store (approved again, or its
// fingerprint otherwise replaced) is not overwritten with the carried copy
// of the old one.
func TestJobCarryDoesNotStoreOverAChangedJob(t *testing.T) {
	r := newJobRig(t)
	r.withReportURL(t)
	if _, err := r.c.JobAllow("report-export", r.neverSpec()); err != nil {
		t.Fatal(err)
	}
	r.writeSetting(t, reportValue)
	r.s.carryBeforeStore = func() {
		r.s.jobMu.Lock()
		r.s.jobs["report-export"].Fingerprint.Root = "replaced"
		r.s.jobMu.Unlock()
	}
	carried, err := r.c.JobCarry(reportPath)
	if err != nil {
		t.Fatalf("JobCarry: %v", err)
	}
	if len(carried) != 1 || carried[0].Carried || carried[0].Why != "the job changed while it was checked" {
		t.Fatalf("carried = %+v, want refused for a changed job", carried)
	}
}

// One carry at a time: a second call waits for the first, so concurrent
// calls can't each get their own answer before the first mismatch stops
// the job.
func TestJobCarriesRunOneAtATime(t *testing.T) {
	r := newJobRig(t)
	r.withReportURL(t)
	if _, err := r.c.JobAllow("report-export", r.neverSpec()); err != nil {
		t.Fatal(err)
	}
	r.writeSetting(t, reportValue)
	entered, release := make(chan struct{}, 2), make(chan struct{})
	// Only the first call waits (a sync.Once would make the second wait on
	// it too, and hide a missing lock).
	var calls int32
	r.s.carryBeforeStore = func() {
		entered <- struct{}{}
		if atomic.AddInt32(&calls, 1) == 1 {
			<-release
		}
	}
	first := make(chan struct{})
	go func() { _, _ = r.c.JobCarry(reportPath); close(first) }()
	<-entered
	second := make(chan struct{})
	go func() { _, _ = r.c.JobCarry(reportPath); close(second) }()
	select {
	case <-second:
		t.Fatal("a second carry ran while the first was still checking")
	case <-time.After(300 * time.Millisecond):
	}
	close(release)
	<-first
	<-second
}

// One mismatch stops every job that gets the value, without comparing again
// for the others, and the stop is recorded as the event the app announces.
func TestJobCarryMismatchStopsEveryJobThatGetsTheValue(t *testing.T) {
	r := newJobRig(t)
	r.withReportURL(t)
	for _, name := range []string{"report-export", "report-digest"} {
		if _, err := r.c.JobAllow(name, r.neverSpec()); err != nil {
			t.Fatal(err)
		}
	}
	r.writeSetting(t, "https://attacker.example.test")
	carried, err := r.c.JobCarry(reportPath)
	if err != nil {
		t.Fatalf("JobCarry: %v", err)
	}
	if len(carried) != 2 || carried[0].Carried || carried[1].Carried || carried[1].Why != mismatchAnswer {
		t.Fatalf("carried = %+v, want both stopped", carried)
	}
	jobs, err := r.c.JobList()
	if err != nil {
		t.Fatal(err)
	}
	for _, j := range jobs {
		if !j.Stopped {
			t.Fatalf("%s not stopped by the mismatch", j.Name)
		}
	}
	announced := 0
	for _, e := range r.s.history() {
		if e.Kind == KindError && e.Op == OpJobRun && e.JobOutcome == JobOutcomeStop {
			announced++
		}
	}
	if announced != 2 {
		t.Fatalf("%d stop events the app announces, want 2", announced)
	}
}

// A secret rotated since approval is a different value: not carried, and
// not a reason to stop here (the rotation stops the job on its own).
func TestJobCarrySkipsARotatedSecretWithoutStopping(t *testing.T) {
	r := newJobRig(t)
	r.withReportURL(t)
	if _, err := r.c.JobAllow("report-export", r.neverSpec()); err != nil {
		t.Fatal(err)
	}
	rotated, _ := seal(grantTestMEK, bytes.Repeat([]byte{0x0d}, 32), []byte("mcp"))
	r.mu.Lock()
	r.vault[reportPath] = rotated
	r.mu.Unlock()
	r.writeSetting(t, reportValue)
	carried, err := r.c.JobCarry(reportPath)
	if err != nil {
		t.Fatalf("JobCarry: %v", err)
	}
	if len(carried) != 1 || carried[0].Carried || !strings.Contains(carried[0].Why, "changed since you approved") {
		t.Fatalf("carried = %+v, want not carried for a rotated secret", carried)
	}
	if st := r.storedJob(t); st.Stopped != "" {
		t.Fatalf("stopped %q by a carry of a rotated secret", st.Stopped)
	}
}
