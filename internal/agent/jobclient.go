// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package agent

import (
	"fmt"

	"github.com/jitpass/jit/internal/job"
)

// JobAllow proposes a job and waits on the disclosed Touch ID that approves
// it. The agent resolves and fingerprints everything itself; spec is the
// proposal, and the status returned is what was actually stored.
func (c *Client) JobAllow(name string, spec JobSpec) (JobStatus, error) {
	return c.JobAllowProposal(name, spec, "")
}

// JobAllowProposal is JobAllow for a job an agent proposed: the same
// approval, plus the proposal's id, so it stops waiting once approved.
func (c *Client) JobAllowProposal(name string, spec JobSpec, proposalID string) (JobStatus, error) {
	resp, err := c.call(Request{Op: OpJobAllow, JobName: name, JobSpec: &spec, ProposalID: proposalID})
	if err != nil {
		return JobStatus{}, err
	}
	if len(resp.Jobs) != 1 {
		return JobStatus{}, fmt.Errorf("agent: job approved but not reported back")
	}
	return resp.Jobs[0], nil
}

// JobList reads every approved job with its current state. No prompt.
func (c *Client) JobList() ([]JobStatus, error) {
	resp, err := c.call(Request{Op: OpJobList})
	if err != nil {
		return nil, err
	}
	return resp.Jobs, nil
}

// JobNames lists the jobs without checking their state: names and settings
// only, cheap enough for shell completion. State is empty.
func (c *Client) JobNames() ([]JobStatus, error) {
	resp, err := c.call(Request{Op: OpJobList, JobNamesOnly: true})
	if err != nil {
		return nil, err
	}
	return resp.Jobs, nil
}

// JobRemove deletes a job now. No prompt: reducing access is always free.
func (c *Client) JobRemove(name string) error {
	_, err := c.call(Request{Op: OpJobRemove, JobName: name})
	return err
}

// JobRun asks the service to run a job and waits for it to finish. The
// deadline covers a Touch ID (for an each-time job) plus the run itself, so
// it is the default response window plus job.RunTimeout, never shorter
// than what the service may legitimately take.
//
// The "waiting for Touch ID" notice is for a prompt, and only an each-time
// job has one. A job that never asks takes as long as its script, so the
// notice would fire on every run and say something false; it is switched
// off for those, looked up with one cheap names-only list first.
func (c *Client) JobRun(name string) (JobResult, error) {
	run := *c
	run.respTimeout = c.respTimeout + job.RunTimeout
	if run.waitNotify != nil {
		if jobs, err := c.JobNames(); err == nil {
			for _, j := range jobs {
				if j.Name == name && j.Ask == string(job.AskNever) {
					run.waitNotify = nil
				}
			}
		}
	}
	resp, err := run.call(Request{Op: OpJobRun, JobName: name})
	if err != nil {
		return JobResult{}, err
	}
	if resp.JobResult == nil {
		return JobResult{}, fmt.Errorf("agent: job ran but no result came back")
	}
	return *resp.JobResult, nil
}

// JobRequest proposes a job for the human to approve in JitPass. It
// creates nothing. ErrNoJobBroker's text in the error means no app is
// running; the caller then prints the `jit job allow` line instead.
func (c *Client) JobRequest(name string, spec JobSpec, why string) (JobProposal, error) {
	resp, err := c.call(Request{Op: OpJobRequest, JobName: name, JobSpec: &spec, Why: why})
	if err != nil {
		return JobProposal{}, err
	}
	if len(resp.Proposals) != 1 {
		return JobProposal{}, fmt.Errorf("agent: proposal kept but not reported back")
	}
	return resp.Proposals[0], nil
}

// JobProposals lists the proposals waiting for the human. No prompt.
func (c *Client) JobProposals() ([]JobProposal, error) {
	resp, err := c.call(Request{Op: OpJobProposals})
	if err != nil {
		return nil, err
	}
	return resp.Proposals, nil
}

// JobDismiss drops a proposal. No prompt.
func (c *Client) JobDismiss(id string) error {
	_, err := c.call(Request{Op: OpJobDismiss, ProposalID: id})
	return err
}
