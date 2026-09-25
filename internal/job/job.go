// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package job

import (
	"fmt"
	"regexp"
)

// Ask is when a job asks the human before it runs.
type Ask string

const (
	// AskEachTime puts a disclosed Touch ID in front of every run, naming the
	// caller and the job. The default, and what every agent-proposed job
	// starts as whatever the agent asked for.
	AskEachTime Ask = "each-time"
	// AskNever runs with the job's own key and no prompt, until the job is
	// removed. It is the standing grant's model applied to one command.
	AskNever Ask = "never"
)

// Valid reports whether a is one of the two defined modes.
func (a Ask) Valid() bool { return a == AskEachTime || a == AskNever }

// Secret is one value a job injects, frozen at approval.
type Secret struct {
	// Var is the environment variable the command sees it as.
	Var string `json:"var"`
	// Path is the vault path, resolved from the profile at approval. A later
	// edit to the profile file changes the fingerprint, never this.
	Path  string `json:"path"`
	Class string `json:"class,omitempty"`
	// DeviceDigest is sha256 of the envelope's wrapped DEK bytes at approval.
	// A run compares it with the current bytes, so a rotated secret refuses
	// the run and says so instead of injecting a value nobody approved.
	DeviceDigest string `json:"device_wrapped_sha256"`
	// Shown lets the value appear in the output. Hidden is the default; the
	// human flips it for values that are configuration rather than
	// credentials (the notion job's INTERNAL_DOMAINS is in every email the
	// script prints).
	Shown bool `json:"shown,omitempty"`
	// KeyWrapped is the secret's DEK sealed under the job's own key (hex),
	// set only on a job that never asks. The key itself is in the keychain,
	// never here: this is the standing-grant ledger's trust tier, wrapped
	// material on disk with its key elsewhere.
	KeyWrapped string `json:"key_wrapped,omitempty"`
	// Wrap names how KeyWrapped was sealed, so a later scheme (the Secure
	// Enclave move) can coexist with this one, as the grant ledger's does.
	Wrap string `json:"wrap,omitempty"`

	// raw is the object this secret was read from, if it was: its fields
	// this build does not know are written back with it (store.go).
	raw []byte
}

// Job is one approved command and the secrets it gets.
type Job struct {
	Name string `json:"name"`
	// Dir is the absolute working directory, and the folder fingerprinted.
	Dir string `json:"dir"`
	// Argv is exact. Argv[0] is as the human typed it; Exe is what it
	// resolved to at approval, and what actually runs.
	Argv []string `json:"argv"`
	Exe  string   `json:"exe"`
	// Profile and ProfileRoot say where Secrets came from, for display.
	Profile     string   `json:"profile,omitempty"`
	ProfileRoot string   `json:"profile_root,omitempty"`
	Secrets     []Secret `json:"secrets"`
	Ask         Ask      `json:"ask"`
	// KeyID names the job's own key in the keychain, for a job that never
	// asks. Minted fresh at every approval, so approving again replaces the
	// key rather than reusing it.
	KeyID string `json:"key_id,omitempty"`
	// Outputs are folders the job writes into. New or changed files there are
	// reported to the caller by path; they are skipped by the fingerprint.
	Outputs []string `json:"outputs,omitempty"`
	// Extra are files the command names outside Dir (ExternalFiles), found
	// at approval and fingerprinted with the folder.
	Extra []string `json:"extra,omitempty"`
	// PathEnv and Home are captured from the approving shell, because the
	// service's own environment is launchd's minimal one and the command must
	// run the way it ran when the human read it.
	PathEnv     string      `json:"path_env"`
	Home        string      `json:"home"`
	Fingerprint Fingerprint `json:"fingerprint"`
	// Description is the human's own one-liner for list_jobs; optional.
	Description  string `json:"description,omitempty"`
	ApprovedUnix int64  `json:"approved_unix"`

	// Stopped, when set, says why the job stopped: a file changed, a secret
	// was rotated, its key is gone. A stop is STICKY. Only approving the job
	// again clears it, because a stop that lifted itself when the file was
	// put back would let a caller retry a swap for free until one landed
	// between the check and the start.
	Stopped string `json:"stopped,omitempty"`

	Runs          int64  `json:"runs,omitempty"`
	LastRunUnix   int64  `json:"last_run_unix,omitempty"`
	LastExit      int    `json:"last_exit,omitempty"`
	LastCaller    string `json:"last_caller,omitempty"`
	LastRefusal   string `json:"last_refusal,omitempty"`
	LastHiddenSum int    `json:"last_hidden,omitempty"`

	// raw is the object this job was read from, if it was: its fields this
	// build does not know are written back with it (store.go). A job
	// approved again is a new Job, and starts without one.
	raw []byte
}

var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)

// ValidateName accepts what an agent can say and a human can type: lowercase
// letters, digits and dashes, starting with a letter or digit, at most 40.
func ValidateName(name string) error {
	if !nameRE.MatchString(name) {
		return fmt.Errorf("job name %q: use lowercase letters, digits and dashes, up to 40, e.g. notion-guests", name)
	}
	return nil
}

// HiddenVars lists the variables whose values the masker must hide.
func (j *Job) HiddenVars() []string {
	var out []string
	for _, s := range j.Secrets {
		if !s.Shown {
			out = append(out, s.Var)
		}
	}
	return out
}
