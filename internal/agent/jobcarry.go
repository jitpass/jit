// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package agent

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"syscall"

	"github.com/jitpass/jit/internal/job"
)

// Carrying a job along when `jit vault move-out` moves a value it gets into a
// plain setting (design/agent-jobs.md, "Decided 2026-09-29"). A job keeps the
// vault paths it was approved with, so a moved value used to leave every job
// that read it running without it: still "ready", failing at its first use
// of the value.
//
// The move asks here while both copies exist: it writes the setting and
// points the profiles at it first, and removes the vault copy last. For each
// job that gets the value, the service opens the vault copy ITSELF, with the
// job's own key or the open session, and compares it with the setting file.
// Only an exact match moves the job over: the secret becomes a setting and
// the setting's file joins the job's fingerprint, as approval would have
// done. Nothing the caller says about either copy is trusted, because the
// caller is any program running as the user, and one that could point a job
// at a setting of its own choosing would pick where the job sends its other
// secrets (job.Setting). For the same reason a setting that doesn't match
// stops the job: an honest move never offers one, and answering would let
// that program test guesses at the secret. A job that can't be checked is
// left as it was, and stops once the vault copy is gone (movedSecrets).

// MovedSetting is where a value moved out of the vault is kept now.
type MovedSetting struct {
	// Pointer is the manifest's jit://setting/ pointer to it.
	Pointer string
	// File is the file holding it, which a carried job fingerprints.
	File string
}

// maxCarriedSetting bounds the setting file read for the comparison. A
// setting is a URL or an id; a vault value is capped far below this.
const maxCarriedSetting = 1 << 20

// carryMovedValue is job_carry: every job whose secrets include path,
// carried along to its setting or not, with why not. One carry at a time
// (carryMu), and the setting is read once per call: concurrent calls, or one
// call walking several jobs while the file is rewritten between them, would
// otherwise each get their own answer to "is this the value?", and the
// first mismatch is meant to be the only one (carryJob).
func (s *Server) carryMovedValue(path string, c *caller) []JobCarry {
	s.carryMu.Lock()
	defer s.carryMu.Unlock()
	s.jobMu.Lock()
	var cands []job.Job
	for _, j := range s.jobs {
		if len(secretsAt(j, path)) > 0 {
			cands = append(cands, *j)
		}
	}
	s.jobMu.Unlock()
	sort.Slice(cands, func(a, b int) bool { return cands[a].Name < cands[b].Name })

	out := []JobCarry{}
	answer := func(j *job.Job, why string) {
		for _, sec := range secretsAt(j, path) {
			out = append(out, JobCarry{Job: j.Name, Var: sec.Var, Carried: why == "", Why: why})
		}
	}
	all := func(why string) []JobCarry {
		for i := range cands {
			answer(&cands[i], why)
		}
		return out
	}
	if len(cands) == 0 {
		return out
	}
	if s.OnMovedSetting == nil || s.OnReadVaultValue == nil || s.OnWrappedDEK == nil {
		return all("this jit service can't check it")
	}
	moved, ok := s.OnMovedSetting(path)
	if !ok {
		return all("the setting isn't there")
	}
	setting, err := readSettingFile(moved.File)
	if err != nil {
		return all("the setting couldn't be read")
	}
	defer wipe(setting)

	mismatched := false
	for i := range cands {
		j := &cands[i]
		if mismatched {
			// Someone else's setting: every job that gets the value stops,
			// without another comparison to answer.
			s.stopCarried(j, c, mismatchReason(secretsAt(j, path)[0].Var))
			answer(j, mismatchAnswer)
			continue
		}
		why, mismatch := s.carryJob(j, path, moved, setting, c)
		mismatched = mismatch
		answer(j, why)
	}
	return out
}

// mismatchAnswer is job_carry's answer for a job a mismatched setting stopped.
const mismatchAnswer = "the setting doesn't hold the value you approved, so the job stopped"

func mismatchReason(v string) string {
	return fmt.Sprintf("a setting offered for %s didn't hold the value you approved", v)
}

// secretsAt is every secret of j read from path: usually one, but a profile
// may set two variables from the same entry.
func secretsAt(j *job.Job, path string) []job.Secret {
	var out []job.Secret
	for _, sec := range j.Secrets {
		if sec.Path == path {
			out = append(out, sec)
		}
	}
	return out
}

// carryJob moves j's secrets at path over to the setting, whose bytes the
// caller read once, when it holds the same value; or says in a few words why
// it did not, and whether that was a mismatch (which stopped the job). j is
// a copy of the job.
func (s *Server) carryJob(j *job.Job, path string, moved MovedSetting, setting []byte, c *caller) (string, bool) {
	secs := secretsAt(j, path)
	sec := secs[0]
	wrapped, _, err := s.OnWrappedDEK(path)
	if err != nil {
		return "it isn't in the vault", false
	}
	if wrappedDigest(wrapped) != sec.DeviceDigest {
		return "it was changed since you approved the job", false
	}
	// The stored job, checked right before its value is opened: a job a
	// run stopped since the list was taken answers nothing more. A job
	// that never asks refuses a secret sealed in a way this build can't
	// read in openJobKeys, as its runs do.
	if why := s.stillCarriable(j); why != "" {
		return why, false
	}
	dek, why := s.carryDEK(j, sec, wrapped)
	if why != "" {
		return why, false
	}
	defer wipe(dek)
	value, err := s.OnReadVaultValue(path, dek)
	if err != nil {
		return "its vault copy couldn't be read", false
	}
	defer wipe(value)
	// Compared as hashes, so the comparison's time says nothing of either
	// length (ConstantTimeCompare returns early on a length mismatch).
	vh, sh := sha256.Sum256(value), sha256.Sum256(setting)
	if subtle.ConstantTimeCompare(vh[:], sh[:]) != 1 {
		// A move copies the value exactly, so a mismatch is someone else's
		// setting, and without this every call would answer "is this the
		// value?" for free: a guessing oracle on the job's secret, with no
		// prompt, the vault locked for a job that never asks. The job stops
		// instead, so each approval allows one guess.
		s.stopCarried(j, c, mismatchReason(sec.Var))
		return mismatchAnswer, true
	}
	if s.carryCompared != nil {
		s.carryCompared()
	}

	// The setting's file joins the fingerprint, and nothing else may: a job
	// whose folder changed since approval stops for that, and is not
	// approved again on the way through here.
	key := job.OutsidePrefix + moved.File
	extra := append([]string(nil), j.Extra...)
	if !containsString(extra, moved.File) {
		extra = append(extra, moved.File)
	}
	now, err := job.Compute(j.Dir, jobProgram(j), j.Outputs, extra)
	if err != nil {
		return "its folder couldn't be read", false
	}
	for _, ch := range withoutProfileManifests(s.libManifests().Diff(j.Fingerprint, now)) {
		if ch.Path != key || ch.Kind != job.Added {
			return "its files changed since you approved it", false
		}
	}
	// The file fingerprinted must be the bytes compared: one rewritten in
	// between would have the job approve whatever was swapped in.
	if now.Files[key] != "sha256:"+hex.EncodeToString(sh[:]) {
		return "the setting changed while it was checked", false
	}
	if s.carryBeforeStore != nil {
		s.carryBeforeStore()
	}

	if why := s.storeCarried(j, path, secs, moved, extra, key, now); why != "" {
		return why, false
	}
	vars := make([]string, 0, len(secs))
	for _, sc := range secs {
		vars = append(vars, sc.Var)
	}
	s.recordJobEvent(KindUse, OpJobCarry, c, j,
		fmt.Sprintf("%s: %s read from its setting now, moved out of the vault", j.Name, strings.Join(vars, ", ")), "")
	return "", false
}

// stillCarriable says why the stored job can no longer be carried, or "":
// removed, approved again, or stopped since j was copied.
func (s *Server) stillCarriable(j *job.Job) string {
	s.jobMu.Lock()
	defer s.jobMu.Unlock()
	cur, ok := s.jobs[j.Name]
	switch {
	case !ok || cur.ApprovedUnix != j.ApprovedUnix:
		return "the job changed while it was checked"
	case cur.Stopped != "":
		return "it is stopped already"
	}
	return ""
}

// stopCarried stops the stored job, if it is still the approval that was
// checked, as a refused run does (refuseJob): sticky until approved again.
func (s *Server) stopCarried(j *job.Job, c *caller, why string) {
	s.jobMu.Lock()
	if cur, ok := s.jobs[j.Name]; ok && cur.ApprovedUnix == j.ApprovedUnix && cur.Stopped == "" {
		cur.Stopped = why
		cur.LastRefusal = why
		endSkipStreak(cur)
		_ = s.saveJobsLocked()
	}
	s.jobMu.Unlock()
	// Recorded as a run's stop (OpJobRun, JobOutcomeStop), which is the event
	// the app announces: this stop is the one sign that something offered a
	// setting that isn't the value, and it must not wait for the list.
	s.recordJobEvent(KindError, OpJobRun, c, j, j.Name+": stopped, "+why, JobOutcomeStop)
}

// storeCarried replaces the stored job with its carried form, if it is still
// the job that was checked: the same approval, not stopped, the same
// fingerprint. A setting is never hidden in output, like any other.
func (s *Server) storeCarried(j *job.Job, path string, secs []job.Secret, moved MovedSetting, extra []string, key string, now job.Fingerprint) string {
	s.jobMu.Lock()
	defer s.jobMu.Unlock()
	cur, ok := s.jobs[j.Name]
	if !ok || cur.ApprovedUnix != j.ApprovedUnix || cur.Stopped != "" || cur.Fingerprint.Root != j.Fingerprint.Root {
		return "the job changed while it was checked"
	}
	carried := *cur
	carried.Secrets = nil
	for _, sc := range cur.Secrets {
		if sc.Path != path {
			carried.Secrets = append(carried.Secrets, sc)
		}
	}
	carried.Settings = append([]job.Setting(nil), cur.Settings...)
	for _, sc := range secs {
		carried.Settings = append(carried.Settings, job.Setting{Var: sc.Var, Path: moved.Pointer})
	}
	carried.Extra = extra
	carried.Fingerprint = cur.Fingerprint.WithEntry(key, now)
	s.jobs[j.Name] = &carried
	if err := s.saveJobsLocked(); err != nil {
		s.jobs[j.Name] = cur
		return "the job list couldn't be saved"
	}
	return ""
}

// carryDEK opens sec's DEK the way a run of j would, without a prompt: with
// the job's own key for a job that never asks, or the session already open
// for one that asks each time. A locked vault is an answer, not a reason to
// ask: the move already took its own Touch ID.
func (s *Server) carryDEK(j *job.Job, sec job.Secret, wrapped []byte) ([]byte, string) {
	if j.Ask == job.AskNever {
		one := *j
		one.Secrets = []job.Secret{sec}
		deks := map[string][]byte{}
		if err := s.openJobKeys(&one, deks); err != nil {
			for _, d := range deks {
				wipe(d)
			}
			return nil, "the job's key couldn't open it"
		}
		return deks[sec.DeviceDigest], ""
	}
	mek := s.peekSession()
	if mek == nil {
		return nil, "the vault is locked"
	}
	defer wipe(mek)
	// The approved class is the AAD, as in a run.
	dek, err := open(mek, wrapped, []byte(sec.Class))
	if err != nil {
		return nil, "its vault copy couldn't be opened"
	}
	return dek, ""
}

// readSettingFile reads a setting's file for the comparison. It opens
// without blocking and refuses anything but a regular file, as the
// fingerprint does: a FIFO swapped in would otherwise hang the service.
func readSettingFile(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0) // #nosec G304 -- the settings store's own file, named by the service's wiring
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxCarriedSetting+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxCarriedSetting {
		wipe(data)
		return nil, fmt.Errorf("%s is larger than a setting", path)
	}
	return data, nil
}

// movedSecrets maps each of the gone secret paths that now has a plain
// setting to true: moved, not deleted. The job's profile still sets such a value, so
// running without it would only fail, and the job stops instead.
func (s *Server) movedSecrets(gone map[string]bool) map[string]bool {
	moved := map[string]bool{}
	if s.OnMovedSetting == nil {
		return moved
	}
	for p := range gone {
		if _, ok := s.OnMovedSetting(p); ok {
			moved[p] = true
		}
	}
	return moved
}

// movedReason is the stop's sentence for the variables of moved secrets.
func movedReason(vars []string) string {
	sort.Strings(vars)
	verb := "was"
	if len(vars) > 1 {
		verb = "were"
	}
	return fmt.Sprintf("%s %s moved out of the vault into settings since you approved it", strings.Join(vars, ", "), verb)
}
