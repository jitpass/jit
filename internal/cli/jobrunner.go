// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/jitpass/jit/internal/agent"
	"github.com/jitpass/jit/internal/inject"
	"github.com/jitpass/jit/internal/job"
	"github.com/jitpass/jit/internal/onepassword"
	"github.com/jitpass/jit/internal/profile"
	"github.com/jitpass/jit/internal/vault"
)

// This file is the half of AI Jobs that runs INSIDE the service and holds
// plaintext (design/agent-jobs.md): the agent has already checked the
// fingerprint and rotation and taken the approval, and hands over the DEKs it
// unwrapped for this one run. Here they decrypt the job's values, the command
// starts with them in a scratch environment, and its output passes through
// the masker before anything is returned.

// resolveJobSecrets is the service's OnResolveJob: a profile's variables to
// vault paths and wrapped DEK bytes, read without decrypting (so resolution
// can never prompt), from the profile's own folder shadowing the global store
// exactly as a grant resolves.
func resolveJobSecrets(root string) func(p agent.GrantProfile) ([]agent.JobSecretSource, error) {
	return func(gp agent.GrantProfile) ([]agent.JobSecretSource, error) {
		deviceID, err := vault.EnsureDeviceID(root)
		if err != nil {
			return nil, fmt.Errorf("determining device recipient ID: %w", err)
		}
		v := &vault.Vault{Root: root, RecipientID: deviceID}
		loadRoot := gp.Root
		if loadRoot == "" {
			if home, herr := profile.GlobalRoot(); herr == nil {
				loadRoot = home
			}
		}
		p, err := profile.Load(loadRoot, gp.Name)
		if err != nil {
			return nil, err
		}
		vars := make([]string, 0, len(p))
		for k := range p {
			vars = append(vars, k)
		}
		sort.Strings(vars)
		out := make([]agent.JobSecretSource, 0, len(vars))
		for _, name := range vars {
			wrapped, class, err := v.WrappedDEK(p[name])
			if err != nil {
				return nil, fmt.Errorf("profile %s: %s (%s): %w (the profile names it, the vault does not have it - `jit vault list` shows what is stored)", gp.Name, name, p[name], err)
			}
			out = append(out, agent.JobSecretSource{Var: name, Path: p[name], Wrapped: wrapped, Class: class})
		}
		return out, nil
	}
}

// jobKeys is the KeyWrapper a job's run decrypts through: it answers ONLY
// the DEKs the agent unwrapped for this run, looked up by the wrapped bytes
// the vault envelope carries, and nothing else. It cannot wrap.
type jobKeys map[string][]byte

func (k jobKeys) WrapKey([]byte) ([]byte, error) {
	return nil, errors.New("a job run cannot write to the vault")
}

func (k jobKeys) UnwrapKey(wrapped []byte) ([]byte, error) {
	dek, ok := k[agent.WrappedDigest(wrapped)]
	if !ok {
		return nil, errors.New("not a secret this job was approved to use")
	}
	return append([]byte(nil), dek...), nil
}

// runJobProcess is the service's OnRunJob.
func runJobProcess(root string) func(j job.Job, deks map[string][]byte) (agent.JobResult, error) {
	return func(j job.Job, deks map[string][]byte) (agent.JobResult, error) {
		deviceID, err := vault.EnsureDeviceID(root)
		if err != nil {
			return agent.JobResult{}, fmt.Errorf("determining device recipient ID: %w", err)
		}
		v := &vault.Vault{Root: root, RecipientID: deviceID, KeyWrapper: jobKeys(deks), RefResolver: onepassword.New()}
		p := profile.Profile{}
		for _, sec := range j.Secrets {
			p[sec.Var] = sec.Path
		}
		values, err := inject.Resolve(v, p)
		if err != nil {
			return agent.JobResult{}, err
		}
		hidden := map[string]string{}
		for _, sec := range j.Secrets {
			if !sec.Shown {
				hidden[sec.Var] = values[sec.Var]
			}
		}
		scratch, err := os.MkdirTemp("", "jit-job-")
		if err != nil {
			return agent.JobResult{}, err
		}
		defer os.RemoveAll(scratch)
		return runJobCommand(j, values, hidden, jobEnv(scratch, j), job.RunTimeout)
	}
}

// jobEnv is the environment a job starts from, built from scratch: nothing
// from the service's own environment and nothing from the caller, only what
// the human's shell had at approval (PATH, HOME) and what a program needs to
// behave (locale, temp dir, user). scratch is a folder made for this one run
// and removed after it.
//
// Three variables close doors the fingerprint cannot watch:
//   - PYTHONPYCACHEPREFIX points at a fresh, empty folder under scratch, so
//     a run neither writes bytecode into the fingerprinted tree nor loads a
//     cached .pyc from an earlier run. A per-job cache that persisted was a
//     place to leave poisoned bytecode that matched its source's mtime and
//     size.
//   - PYTHONNOUSERSITE=1 keeps ~/Library/Python/*/site-packages, and any
//     .pth file dropped there, out of a non-venv Python.
//   - ZDOTDIR points at an empty folder, so a `zsh script.sh` job does not
//     source ~/.zshenv. /etc/zshenv still applies; it is root's.
//
// What remains trusted as installed, and is stated in the design rather than
// hidden: the programs on the captured PATH that the job itself calls, and
// their own configuration.
func jobEnv(scratch string, j job.Job) []string {
	user := os.Getenv("USER")
	return []string{
		"PATH=" + j.PathEnv,
		"HOME=" + j.Home,
		"USER=" + user,
		"LOGNAME=" + user,
		"LANG=en_US.UTF-8",
		"TMPDIR=" + os.TempDir(),
		"PYTHONPYCACHEPREFIX=" + filepath.Join(scratch, "pycache"),
		"PYTHONNOUSERSITE=1",
		"ZDOTDIR=" + filepath.Join(scratch, "zdotdir"),
		"JIT_JOB=" + j.Name,
	}
}

// runJobCommand starts j with base plus values, reads stdout and stderr
// through a masker each, and returns the result. Split from runJobProcess so
// a test can run a real process without a vault.
func runJobCommand(j job.Job, values, hidden map[string]string, base []string, timeout time.Duration) (agent.JobResult, error) {
	env := inject.MergeEnv(base, values)
	half := job.OutputCap / 2
	outBuf, errBuf := newTailBuffer(half), newTailBuffer(half)
	outMask, errMask := job.NewMasker(outBuf, hidden), job.NewMasker(errBuf, hidden)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, j.Exe, j.Argv[1:]...) // #nosec G204 -- the exact argv the human approved, fingerprint-checked by the agent before this call
	cmd.Args[0] = j.Argv[0]
	cmd.Dir = j.Dir
	cmd.Env = env
	cmd.Stdout, cmd.Stderr = outMask, errMask
	// Own process group, so a timeout ends the script's children too, not
	// just the script.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM) }
	cmd.WaitDelay = 5 * time.Second

	before := snapshotOutputs(j.Outputs)
	start := time.Now()
	runErr := cmd.Run()
	_ = outMask.Flush()
	_ = errMask.Flush()

	res := agent.JobResult{
		Stdout: outBuf.String(), Stderr: errBuf.String(),
		Truncated:  outBuf.truncated || errBuf.truncated,
		DurationMS: time.Since(start).Milliseconds(),
		Hidden:     map[string]int{},
	}
	for _, m := range []*job.Masker{outMask, errMask} {
		for k, n := range m.Counts() {
			res.Hidden[k] += n
		}
	}
	var exitErr *exec.ExitError
	switch {
	case runErr == nil:
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		res.TimedOut, res.Exit = true, -1
		res.Notes = append(res.Notes, fmt.Sprintf("stopped after %s: the time limit for a job", formatJobDuration(timeout)))
	case errors.As(runErr, &exitErr):
		res.Exit = exitErr.ExitCode()
	default:
		return agent.JobResult{}, fmt.Errorf("starting %s: %w", j.Argv[0], runErr)
	}
	res.NewFiles = changedOutputs(j.Outputs, before)
	for _, name := range job.ShortValues(hidden) {
		res.Notes = append(res.Notes, fmt.Sprintf("%s is under %d characters, too short to hide; it may appear in the output", name, job.MinHiddenRaw))
	}
	if res.Truncated {
		res.Notes = append(res.Notes, fmt.Sprintf("output passed %d KB on stdout or stderr; only the end of it is kept", half>>10))
	}
	return res, nil
}

func formatJobDuration(d time.Duration) string {
	if d%time.Minute == 0 {
		return fmt.Sprintf("%d min", int(d/time.Minute))
	}
	return fmt.Sprintf("%d s", int(d/time.Second))
}

// tailBuffer keeps the last n bytes written: the end of a run (the summary,
// the error) is what the caller needs when output overflows.
type tailBuffer struct {
	mu        sync.Mutex
	n         int
	b         []byte
	truncated bool
}

func newTailBuffer(n int) *tailBuffer { return &tailBuffer{n: n} }

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.b = append(t.b, p...)
	if over := len(t.b) - t.n; over > 0 {
		t.b = append(t.b[:0], t.b[over:]...)
		t.truncated = true
	}
	return len(p), nil
}

func (t *tailBuffer) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return string(t.b)
}

// snapshotOutputs records each file's modification time under the output
// folders, so the run can report what it created or changed.
func snapshotOutputs(dirs []string) map[string]time.Time {
	out := map[string]time.Time{}
	for _, d := range dirs {
		_ = filepath.WalkDir(d, func(p string, e fs.DirEntry, err error) error {
			if err != nil || e.IsDir() {
				return nil
			}
			if info, ierr := e.Info(); ierr == nil && info.Mode().IsRegular() {
				out[p] = info.ModTime()
			}
			return nil
		})
	}
	return out
}

func changedOutputs(dirs []string, before map[string]time.Time) []string {
	var out []string
	for p, mt := range snapshotOutputs(dirs) {
		if prev, ok := before[p]; !ok || !mt.Equal(prev) {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}
