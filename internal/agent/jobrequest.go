// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package agent

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"time"

	"github.com/jitpass/jit/internal/job"
)

// This file is how an agent PROPOSES a job (design/agent-jobs.md, step 4b):
// MCP's request_job, when JitPass is running. The proposal is kept here for
// the app to show as a pre-filled New AI Job sheet, and it creates nothing.
// Approving it is the human's own job_allow, from that sheet, which resolves,
// fingerprints and asks for Touch ID exactly as a job typed at a terminal
// does. A proposal is therefore inert: the worst a flood of them can do is
// fill a list, which is why the list is capped and entries expire.

// ErrNoJobBroker is job_request's answer when no app is there to show the
// proposal. The proposer falls back to the `jit job allow` line.
var ErrNoJobBroker = errors.New("JitPass is not running to show the proposal")

const (
	maxJobProposals  = 8
	jobProposalTTL   = time.Hour
	maxProposalWhy   = 300
	maxProposalArgs  = 32
	maxProposalArgSz = 1024
)

func (s *Server) requestJob(req Request, c *caller) Response {
	spec := req.JobSpec
	if spec == nil {
		return Response{OK: false, Error: "job_request: missing job_spec"}
	}
	if err := job.ValidateName(req.JobName); err != nil {
		return Response{OK: false, Error: "job_request: " + err.Error()}
	}
	if len(spec.Argv) > maxProposalArgs {
		return Response{OK: false, Error: "job_request: too many arguments"}
	}
	for _, a := range spec.Argv {
		if len(a) > maxProposalArgSz {
			return Response{OK: false, Error: "job_request: an argument is too long"}
		}
	}
	if err := job.CheckArgv(spec.Argv); err != nil {
		return Response{OK: false, Error: "job_request: jit would refuse this job: " + err.Error()}
	}
	if !filepath.IsAbs(spec.Dir) {
		return Response{OK: false, Error: "job_request: the folder must be an absolute path"}
	}
	if s.brokerCount() == 0 {
		return Response{OK: false, Error: "job_request: " + ErrNoJobBroker.Error()}
	}
	why := req.Why
	if r := []rune(why); len(r) > maxProposalWhy {
		why = string(r[:maxProposalWhy-1]) + "…"
	}
	id, err := newConsentID()
	if err != nil {
		return Response{OK: false, Error: "job_request: " + err.Error()}
	}
	// What the proposer asked for is kept, except the one thing a proposal
	// may never carry: a job that runs without asking. The human can choose
	// that on the sheet; the agent cannot choose it for them.
	kept := *spec
	kept.Ask = string(job.AskEachTime)
	kept.Replace = false
	p := JobProposal{
		ID: id, Name: req.JobName, Spec: kept, Why: why,
		By: c.command(), LaunchedBy: jobRequester(c), UnixTime: time.Now().Unix(),
	}

	s.jobMu.Lock()
	s.pruneProposalsLocked(time.Now())
	if len(s.jobProposals) >= maxJobProposals {
		s.jobMu.Unlock()
		return Response{OK: false, Error: fmt.Sprintf("job_request: %d proposals are already waiting for the user", maxJobProposals)}
	}
	if s.jobProposals == nil {
		s.jobProposals = map[string]JobProposal{}
	}
	s.jobProposals[id] = p
	s.jobMu.Unlock()

	e := unlockEvent(OpJobRequest, c)
	e.Kind = KindJobProposal
	e.ConsentID = id
	e.Job = p.Name
	e.Cause = why
	e.UnixTime = p.UnixTime
	s.publishBrokers(*e)
	s.recordJobEvent(KindUse, OpJobRequest, c, &job.Job{Name: p.Name}, fmt.Sprintf("proposed %s (%s) to the user", p.Name, jobLabel(spec.Dir, spec.Argv)), "")
	return Response{OK: true, Proposals: []JobProposal{p}}
}

func (s *Server) listProposals() []JobProposal {
	s.jobMu.Lock()
	defer s.jobMu.Unlock()
	s.pruneProposalsLocked(time.Now())
	out := make([]JobProposal, 0, len(s.jobProposals))
	for _, p := range s.jobProposals {
		out = append(out, p)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].UnixTime < out[b].UnixTime })
	return out
}

// dropProposal removes a proposal: dismissed, or approved with job_allow.
// Unknown ids are not an error: the answer may have raced an expiry.
func (s *Server) dropProposal(id string) {
	s.jobMu.Lock()
	delete(s.jobProposals, id)
	s.jobMu.Unlock()
}

func (s *Server) pruneProposalsLocked(now time.Time) {
	for id, p := range s.jobProposals {
		if now.Sub(time.Unix(p.UnixTime, 0)) > jobProposalTTL {
			delete(s.jobProposals, id)
		}
	}
}
