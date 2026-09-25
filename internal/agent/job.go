// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package agent

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jitpass/jit/internal/job"
)

// This file is AI Jobs' service half (design/agent-jobs.md): approving a job,
// listing and removing them, and running one for a caller that never holds a
// key. What a job IS, its fingerprint, the command check and the output
// masker live in internal/job, which decrypts nothing; decrypting values and
// starting the process happen in the CLI's wiring (OnRunJob), for the reason
// OnResolveGrant's comment gives: Server never imports internal/vault.
//
// The ordering of every handler follows createGrant's: everything that can
// fail without the human fails BEFORE the prompt, so a Touch ID is never spent
// on a request that was going to be refused anyway, and the human approves
// exactly what will be stored.

// JobSecretSource is one secret a job's profile resolves to, as the CLI's
// wiring reads it from the profile and the vault envelope: the variable, the
// vault path, the wrapped DEK bytes and their AAD-bound class. No value.
type JobSecretSource struct {
	Var     string
	Path    string
	Wrapped []byte
	Class   string
}

// maxJobChanges caps the changes a status carries. The first few name the
// problem; a whole reinstalled venv would otherwise ship thousands of paths.
const maxJobChanges = 20

// SetJobStore names jobs.json and loads it. Called once at service start. A
// file that fails to load leaves the service with no jobs and never writes
// over that file, grants.json's rule.
func (s *Server) SetJobStore(path string) (int, error) {
	jobs, err := job.Load(path)
	s.jobMu.Lock()
	defer s.jobMu.Unlock()
	if err != nil {
		s.jobs, s.jobsPath = map[string]*job.Job{}, ""
		return 0, err
	}
	s.jobs, s.jobsPath = jobs, path
	return len(jobs), nil
}

// saveJobsLocked writes the list. Caller holds jobMu.
func (s *Server) saveJobsLocked() error {
	if s.jobsPath == "" {
		return fmt.Errorf("this service has no usable job list (see the service log for why it was not loaded)")
	}
	return job.Save(s.jobsPath, s.jobs)
}

func (s *Server) allowJob(req Request, c *caller) Response {
	if c == nil {
		return Response{OK: false, Error: "job_allow: caller could not be identified"}
	}
	spec := req.JobSpec
	if spec == nil {
		return Response{OK: false, Error: "job_allow: missing job_spec"}
	}
	if err := job.ValidateName(req.JobName); err != nil {
		return Response{OK: false, Error: "job_allow: " + err.Error()}
	}
	ask := job.Ask(spec.Ask)
	if ask == "" {
		ask = job.AskEachTime
	}
	if !ask.Valid() {
		return Response{OK: false, Error: fmt.Sprintf("job_allow: ask must be %s or %s", job.AskEachTime, job.AskNever)}
	}
	if ask == job.AskNever && s.GrantKeys == nil {
		// A job that never asks runs on a key of its own, in the same store
		// standing grants use. Without one it could only ever prompt, which is
		// not what the human would be approving.
		return Response{OK: false, Error: "job_allow: this service has no key store wired, so it cannot keep a job that never asks - approve it as each-time"}
	}
	if err := job.CheckArgv(spec.Argv); err != nil {
		return Response{OK: false, Error: "job_allow: " + err.Error()}
	}
	if !filepath.IsAbs(spec.Dir) {
		return Response{OK: false, Error: "job_allow: the job folder must be an absolute path"}
	}
	dir := filepath.Clean(spec.Dir)
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		return Response{OK: false, Error: fmt.Sprintf("job_allow: %s is not a folder", dir)}
	}
	exe, err := job.ResolveExe(spec.Argv[0], dir, spec.PathEnv)
	if err != nil {
		return Response{OK: false, Error: "job_allow: " + err.Error()}
	}
	outputs := make([]string, 0, len(spec.Outputs))
	for _, o := range spec.Outputs {
		if !filepath.IsAbs(o) {
			o = filepath.Join(dir, o)
		}
		o = filepath.Clean(o)
		if job.OutputCoversDir(o, dir) {
			// Everything under an output is skipped by the fingerprint, so an
			// output that holds the whole folder would leave nothing to stop
			// the job on. Refused rather than fingerprinted empty.
			return Response{OK: false, Error: fmt.Sprintf("job_allow: --output %s holds the job's own folder, so no edit could ever stop the job - name the folder it writes into, inside or beside this one", o)}
		}
		outputs = append(outputs, o)
	}
	extra := job.ExternalFiles(spec.Argv[1:], dir)

	s.jobMu.Lock()
	_, exists := s.jobs[req.JobName]
	ready := s.jobsPath != ""
	s.jobMu.Unlock()
	if exists && !spec.Replace {
		return Response{OK: false, Error: fmt.Sprintf("job_allow: a job named %s exists - remove it first, or approve it again with --replace", req.JobName)}
	}
	if !ready {
		return Response{OK: false, Error: "job_allow: this service has no usable job list, so the job could not be kept (see the service log)"}
	}

	var sources []JobSecretSource
	profileName, profileRoot := "", ""
	if spec.Profile != nil {
		if s.OnResolveJob == nil {
			return Response{OK: false, Error: "job_allow: this service has no profile resolver wired"}
		}
		sources, err = s.OnResolveJob(*spec.Profile)
		if err != nil {
			return Response{OK: false, Error: "job_allow: " + err.Error()}
		}
		profileName, profileRoot = spec.Profile.Name, spec.Profile.Root
	}
	shown := map[string]bool{}
	for _, v := range spec.Shown {
		shown[v] = true
	}
	for _, src := range sources {
		delete(shown, src.Var)
	}
	if len(shown) > 0 {
		names := make([]string, 0, len(shown))
		for v := range shown {
			names = append(names, v)
		}
		sort.Strings(names)
		return Response{OK: false, Error: fmt.Sprintf("job_allow: --show names %s, which the profile does not set", strings.Join(names, ", "))}
	}

	before, err := job.Compute(dir, exe, outputs, extra)
	if err != nil {
		return Response{OK: false, Error: "job_allow: fingerprinting the folder: " + err.Error()}
	}

	reason := jobAllowReason(req.JobName, len(sources), ask)
	event, mek, err := s.discloseChallengeOp(reason, OpJobAllow, c)
	if event != nil && s.OnSessionEvent != nil {
		s.OnSessionEvent(*event)
	}
	if err != nil {
		return Response{OK: false, Error: err.Error()}
	}
	// Every secret must open under its class, as a grant's must: the human
	// approved a count, and a job that could not inject one of them would be
	// a prompt that lied by omission.
	deks := make([][]byte, len(sources))
	defer func() {
		for _, d := range deks {
			wipe(d)
		}
	}()
	for i, src := range sources {
		dek, oerr := open(mek, src.Wrapped, []byte(src.Class))
		if oerr != nil {
			wipe(mek)
			return Response{OK: false, Error: fmt.Sprintf("job_allow: %s cannot be unwrapped (%s), no job created", src.Path, oerr)}
		}
		deks[i] = dek
	}
	wipe(mek)

	// The folder the human approved is the folder as it was when they were
	// asked. A change while the prompt was up is refused, not absorbed.
	after, err := job.Compute(dir, exe, outputs, extra)
	if err != nil {
		return Response{OK: false, Error: "job_allow: fingerprinting the folder: " + err.Error()}
	}
	if d := job.Diff(before, after); len(d) > 0 {
		return Response{OK: false, Error: fmt.Sprintf("job_allow: %s changed while the prompt was up, no job created", d[0].Path)}
	}

	j := &job.Job{
		Name: req.JobName, Dir: dir, Argv: append([]string(nil), spec.Argv...), Exe: exe,
		Profile: profileName, ProfileRoot: profileRoot, Ask: ask, Outputs: outputs, Extra: extra,
		PathEnv: spec.PathEnv, Home: spec.Home, Fingerprint: after,
		Description: spec.Description, ApprovedUnix: time.Now().Unix(),
	}
	for _, src := range sources {
		j.Secrets = append(j.Secrets, job.Secret{
			Var: src.Var, Path: src.Path, Class: src.Class,
			DeviceDigest: wrappedDigest(src.Wrapped), Shown: containsString(spec.Shown, src.Var),
		})
	}

	// A job that never asks gets a key of its own, made now, under the
	// approval just given: the DEKs are sealed under it and the key goes to
	// the keychain, exactly as a standing grant's does. Everything that can
	// fail without a key has already failed; from here, every failure
	// deletes the key, so a refused approval never leaves one behind.
	dropKey := func() {}
	if ask == job.AskNever && len(j.Secrets) > 0 {
		keyID, kerr := newJobKeyID()
		if kerr != nil {
			return Response{OK: false, Error: "job_allow: " + kerr.Error()}
		}
		key, kerr := s.GrantKeys.Create(keyID)
		if kerr != nil {
			return Response{OK: false, Error: "job_allow: making the job's key: " + kerr.Error()}
		}
		dropKey = func() { _ = s.GrantKeys.Delete(keyID) }
		for i := range j.Secrets {
			sealed, serr := key.Seal(deks[i], j.Secrets[i].Class)
			if serr != nil {
				key.Close()
				dropKey()
				return Response{OK: false, Error: fmt.Sprintf("job_allow: %s cannot be sealed under the job's key (%s), no job created", j.Secrets[i].Path, serr)}
			}
			j.Secrets[i].KeyWrapped = hex.EncodeToString(sealed)
			j.Secrets[i].Wrap = standingWrapAEAD
		}
		key.Close()
		j.KeyID = keyID
	}
	sort.Slice(j.Secrets, func(a, b int) bool { return j.Secrets[a].Var < j.Secrets[b].Var })

	s.jobMu.Lock()
	prev := s.jobs[j.Name]
	s.jobs[j.Name] = j
	err = s.saveJobsLocked()
	if err != nil {
		if prev != nil {
			s.jobs[j.Name] = prev
		} else {
			delete(s.jobs, j.Name)
		}
	}
	s.jobMu.Unlock()
	if err != nil {
		dropKey()
		return Response{OK: false, Error: "job_allow: saving the job: " + err.Error()}
	}
	// Approving again replaces the job, and with it the old key: a job that
	// was never-asking and is now each-time must not keep a key that opens
	// its secrets.
	if prev != nil && prev.KeyID != "" && prev.KeyID != j.KeyID {
		_ = s.GrantKeys.Delete(prev.KeyID)
	}
	return Response{OK: true, Jobs: []JobStatus{s.jobStatus(j)}}
}

// newJobKeyID mints a job key's keychain name: "j-" and random hex, never the
// job's name, so a key outliving its record (a crash between the keychain
// write and the file write) can never be mistaken for a later job's.
func newJobKeyID() (string, error) {
	id, err := newGrantID()
	if err != nil {
		return "", err
	}
	return "j-" + strings.TrimPrefix(id, "g-"), nil
}

// jobAllowReason completes macOS's "jit is trying to ___." Everything in it
// is the human's own name for the job plus a count the agent resolved; the
// command itself is too long for the dialog, so the CLI prints it in full
// before asking, and the app's sheet shows it verbatim.
func jobAllowReason(name string, secrets int, ask job.Ask) string {
	if ask == job.AskNever {
		// The scope clause changes the decision, so it is the half that must
		// survive: 17 + 18 + 13 + 41 = 89 runes at 14 secrets.
		return truncate(fmt.Sprintf("let AI tools run %s (%s) unasked, until removed; never the values",
			truncate(name, 18), countNoun(secrets, "secret")), maxReasonLen)
	}
	// Budgets: 17 + 22 + 47 runes at 14 secrets = 86, under maxReasonLen,
	// so the promise at the end is never what a long name pushes off.
	return truncate(fmt.Sprintf("let AI tools run %s (%s); they see output, never the values",
		truncate(name, 22), countNoun(secrets, "secret")), maxReasonLen)
}

// jobRunReason is the per-run prompt of an each-time job: who asked, which
// job, and the promise.
func jobRunReason(requester, name string, secrets int) string {
	// Budgets: 4 + 20 + 18 + 12 + 34 = 88 at 14 secrets.
	return truncate(fmt.Sprintf("run %s (%s) for %s; it sees output, never the values",
		truncate(name, 20), countNoun(secrets, "secret"), truncate(requester, 12)), maxReasonLen)
}

func countNoun(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

// jobRequester names who is asking in the words a person recognises: the
// program that launched the caller (claude, Claude) when the caller is jit
// itself relaying the request, else the caller.
func jobRequester(c *caller) string {
	if c == nil {
		return "a program"
	}
	if name := c.self.Name(); name != "" && name != "jit" {
		return name
	}
	if l := c.launchedBy(); l != "" {
		return l
	}
	return requesterName(c)
}

func (s *Server) removeJob(name string, c *caller) Response {
	s.jobMu.Lock()
	j, ok := s.jobs[name]
	if !ok {
		s.jobMu.Unlock()
		return Response{OK: false, Error: fmt.Sprintf("job_remove: no job named %s", name)}
	}
	delete(s.jobs, name)
	err := s.saveJobsLocked()
	if err != nil {
		s.jobs[name] = j
	}
	s.jobMu.Unlock()
	if err != nil {
		return Response{OK: false, Error: "job_remove: " + err.Error()}
	}
	cause := "removed"
	if j.KeyID != "" && s.GrantKeys != nil {
		// Removing is what ends a job that never asks, so the key goes with
		// it. A delete that fails is said in the trail: the record is already
		// gone, so nothing can use the key, but it is not destroyed either.
		if err := s.GrantKeys.Delete(j.KeyID); err != nil {
			cause = fmt.Sprintf("removed, but its key %s could not be deleted: %s", j.KeyID, err)
		} else {
			cause = "removed, its key deleted"
		}
	}
	s.recordJobEvent(KindUse, OpJobRemove, c, j, cause)
	return Response{OK: true}
}

func (s *Server) listJobs(namesOnly bool) []JobStatus {
	s.jobMu.Lock()
	jobs := make([]*job.Job, 0, len(s.jobs))
	for _, j := range s.jobs {
		cp := *j
		jobs = append(jobs, &cp)
	}
	s.jobMu.Unlock()
	sort.Slice(jobs, func(a, b int) bool { return jobs[a].Name < jobs[b].Name })
	out := make([]JobStatus, 0, len(jobs))
	for _, j := range jobs {
		if namesOnly {
			out = append(out, JobStatus{Name: j.Name, Dir: j.Dir, Argv: j.Argv, Ask: string(j.Ask), Description: j.Description})
			continue
		}
		out = append(out, s.jobStatus(j))
	}
	return out
}

// jobStatus snapshots j with its CURRENT state: the fingerprint and every
// secret's wrapped bytes are re-read, so a list says "changed" the moment it
// is true rather than only after a run is refused.
func (s *Server) jobStatus(j *job.Job) JobStatus {
	st := JobStatus{
		Name: j.Name, Dir: j.Dir, Argv: append([]string(nil), j.Argv...), Exe: j.Exe,
		Profile: j.Profile, Ask: string(j.Ask), Outputs: j.Outputs, Description: j.Description,
		Files: len(j.Fingerprint.Files), State: JobReady, ApprovedUnix: j.ApprovedUnix,
		Runs: j.Runs, LastRunUnix: j.LastRunUnix, LastExit: j.LastExit, LastCaller: j.LastCaller,
		LastRefusal: j.LastRefusal, LastHidden: j.LastHiddenSum,
	}
	rotated := s.rotatedSecrets(j)
	for _, sec := range j.Secrets {
		st.Secrets = append(st.Secrets, JobSecretStatus{Var: sec.Var, Path: sec.Path, Shown: sec.Shown, Rotated: rotated[sec.Path]})
	}
	if len(rotated) > 0 {
		st.State = JobRotated
	}
	if changes := jobChanges(j); len(changes) > 0 {
		st.State = JobChanged
		if len(changes) > maxJobChanges {
			changes = changes[:maxJobChanges]
		}
		st.Changes = changes
	}
	return st
}

// jobChanges re-fingerprints j's folder. A folder that cannot be read at all
// is reported as one change on the folder itself, which stops the job the
// same way.
func jobChanges(j *job.Job) []job.Change {
	now, err := job.Compute(j.Dir, j.Exe, j.Outputs, j.Extra)
	if err != nil {
		return []job.Change{{Path: j.Dir, Kind: job.Removed}}
	}
	return job.Diff(j.Fingerprint, now)
}

// rotatedSecrets maps each secret path whose wrapped bytes no longer match
// approval, or that is gone, to true. Without OnWrappedDEK nothing can be
// checked, and a run then fails at unwrap instead: closed either way.
func (s *Server) rotatedSecrets(j *job.Job) map[string]bool {
	out := map[string]bool{}
	if s.OnWrappedDEK == nil {
		return out
	}
	for _, sec := range j.Secrets {
		wrapped, _, err := s.OnWrappedDEK(sec.Path)
		if err != nil || wrappedDigest(wrapped) != sec.DeviceDigest {
			out[sec.Path] = true
		}
	}
	return out
}

func (s *Server) runJob(name string, c *caller) Response {
	s.jobMu.Lock()
	stored, ok := s.jobs[name]
	var j job.Job
	if ok {
		j = *stored
	}
	s.jobMu.Unlock()
	if !ok {
		return Response{OK: false, Error: fmt.Sprintf("job_run: no job named %s - `jit job list` shows the approved ones", name)}
	}
	if s.OnRunJob == nil {
		return Response{OK: false, Error: "job_run: this service has no job runner wired"}
	}
	requester := jobRequester(c)

	if changes := jobChanges(&j); len(changes) > 0 {
		msg := fmt.Sprintf("%s %s since you approved it", changes[0].Path, changes[0].Kind)
		if len(changes) > 1 {
			msg += fmt.Sprintf(" (and %d more)", len(changes)-1)
		}
		return s.refuseJob(&j, c, requester, msg+". It won't run until you approve it again")
	}
	if s.OnWrappedDEK == nil {
		return Response{OK: false, Error: "job_run: this service cannot read the vault's wrapped keys"}
	}
	current := make([][]byte, len(j.Secrets))
	for i, sec := range j.Secrets {
		wrapped, _, err := s.OnWrappedDEK(sec.Path)
		if err != nil {
			return s.refuseJob(&j, c, requester, fmt.Sprintf("%s is no longer in the vault. It won't run until you approve it again", sec.Var))
		}
		if wrappedDigest(wrapped) != sec.DeviceDigest {
			return s.refuseJob(&j, c, requester, fmt.Sprintf("%s was rotated since you approved it. It won't run until you approve it again", sec.Var))
		}
		current[i] = wrapped
	}

	deks := map[string][]byte{}
	defer func() {
		for _, d := range deks {
			wipe(d)
		}
	}()
	// A job with no secrets still asks when it was approved to: the prompt
	// is consent to run a command, not only to hand out a key, and approval
	// told the human "asks each time".
	switch {
	case j.Ask == job.AskNever && len(j.Secrets) == 0:
	case j.Ask == job.AskNever:
		// No prompt: the human approved this job to run unasked, and the
		// job's own key is that decision (the standing grant's model). A key
		// that is gone, or a wrap it cannot open, refuses the run. It never
		// falls back to prompting, which would turn a job the human set to
		// run while away into one that silently waits on a dialog.
		if err := s.openJobKeys(&j, deks); err != nil {
			return s.refuseJob(&j, c, requester, err.Error()+". Approve it again to make a new key")
		}
	default:
		reason := jobRunReason(requester, j.Name, len(j.Secrets))
		event, mek, err := s.discloseChallengeOp(reason, OpJobRun, c)
		if event != nil && s.OnSessionEvent != nil {
			s.OnSessionEvent(*event)
		}
		if err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		for i, sec := range j.Secrets {
			dek, oerr := open(mek, current[i], []byte(sec.Class))
			if oerr != nil {
				wipe(mek)
				return Response{OK: false, Error: fmt.Sprintf("job_run: %s cannot be unwrapped (%s)", sec.Path, oerr)}
			}
			deks[sec.DeviceDigest] = dek
		}
		wipe(mek)
	}

	// Checked again now, after the prompt: the caller is the party the job
	// keeps values from, and it can write the folder. An edit landing while
	// the human reads the dialog must not run with the secrets it unlocked.
	if changes := jobChanges(&j); len(changes) > 0 {
		return s.refuseJob(&j, c, requester, fmt.Sprintf("%s %s while the prompt was up. It won't run until you approve it again", changes[0].Path, changes[0].Kind))
	}
	result, err := s.OnRunJob(j, deks)
	if err != nil {
		return Response{OK: false, Error: "job_run: " + err.Error()}
	}
	hidden := 0
	for _, n := range result.Hidden {
		hidden += n
	}
	s.jobMu.Lock()
	if cur, ok := s.jobs[j.Name]; ok && cur.ApprovedUnix == j.ApprovedUnix {
		cur.Runs++
		cur.LastRunUnix = time.Now().Unix()
		cur.LastExit = result.Exit
		cur.LastCaller = requester
		cur.LastRefusal = ""
		cur.LastHiddenSum = hidden
		_ = s.saveJobsLocked() // bookkeeping only; the run already happened
	}
	s.jobMu.Unlock()
	how := "asked"
	if j.Ask == job.AskNever {
		how = "unasked"
	}
	s.recordJobEvent(KindUse, OpJobRun, c, &j, fmt.Sprintf("%s for %s (%s), exit %d, %d hidden", j.Name, requester, how, result.Exit, hidden))
	return Response{OK: true, JobResult: &result}
}

// openJobKeys fills deks from a never-asking job's own key: each secret's
// KeyWrapped opened under it with the secret's class as AAD, filed by the
// device digest the runner looks keys up by.
func (s *Server) openJobKeys(j *job.Job, deks map[string][]byte) error {
	if s.GrantKeys == nil || j.KeyID == "" {
		return fmt.Errorf("this job has no key of its own")
	}
	key, err := s.GrantKeys.Load(j.KeyID)
	if err != nil {
		return fmt.Errorf("the job's key is gone from the keychain")
	}
	defer key.Close()
	for _, sec := range j.Secrets {
		if sec.Wrap != standingWrapAEAD {
			return fmt.Errorf("%s is sealed in a way this jit cannot open", sec.Var)
		}
		sealed, herr := hex.DecodeString(sec.KeyWrapped)
		if herr != nil {
			return fmt.Errorf("%s's sealed key is damaged", sec.Var)
		}
		dek, oerr := key.Open(sealed, sec.Class)
		if oerr != nil {
			return fmt.Errorf("%s does not open under the job's key", sec.Var)
		}
		deks[sec.DeviceDigest] = dek
	}
	return nil
}

// refuseJob records why a run did not happen, on the job (for the list and
// the app's Changed card) and in the trail, and answers the caller.
func (s *Server) refuseJob(j *job.Job, c *caller, requester, why string) Response {
	s.jobMu.Lock()
	if cur, ok := s.jobs[j.Name]; ok {
		cur.LastRefusal = why
		cur.LastCaller = requester
		_ = s.saveJobsLocked()
	}
	s.jobMu.Unlock()
	s.recordJobEvent(KindError, OpJobRun, c, j, j.Name+": refused, "+why)
	return Response{OK: false, Error: fmt.Sprintf("job_run: %s: %s", j.Name, why)}
}

// recordJobEvent writes one job event to the ring and the durable trail,
// never collapsed: a run is a discrete fact, and two runs a minute apart are
// two runs. Labels are the job's vault paths, like a grant's.
func (s *Server) recordJobEvent(kind, op string, c *caller, j *job.Job, cause string) {
	e := unlockEvent(op, c)
	e.Kind = kind
	e.Cause = cause
	e.UnixTime = time.Now().Unix()
	for _, sec := range j.Secrets {
		if len(e.Labels) < maxUseLabels {
			e.Labels = append(e.Labels, sec.Path)
		}
	}
	s.mu.Lock()
	s.recordEvent(*e)
	s.mu.Unlock()
	s.notifySessionEvents([]SessionEvent{*e})
}

// WrappedDigest is the key a job's DEK map uses: sha256 of the envelope's
// wrapped bytes, hex. Exported for the CLI's runner, which receives the map
// and must look keys up the same way the agent filed them.
func WrappedDigest(wrapped []byte) string { return wrappedDigest(wrapped) }
