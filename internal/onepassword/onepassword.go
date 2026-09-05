// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

// Package onepassword is the shipped implementation of vault.RefResolver
// (design/1password-adapter.md, issue #60): it resolves op:// secret
// references by exec-ing the 1Password CLI, `op`, which the user installed
// and signed in themselves. jit never holds 1Password credentials — the
// desktop app's own biometric authorization gates release from 1Password,
// while jit's consent/Touch ID gates who gets the resolved value and into
// which process tree. Pure Go, no SDK: the integration is deliberately an
// exec boundary (TECH_STACK.md §2), consistent with jit's supply-chain
// stance.
//
// Before the first exec, the resolved `op` binary must carry a valid
// Developer ID signature from 1Password's (AgileBits') Apple team — the
// same codesign technique and fail-closed stance as jit's own upgrade
// verification (internal/cli/upgrade.go). The threat is a PATH-planted
// fake `op`: it never receives a secret, but it learns which references
// exist and can answer with attacker-chosen values. There is deliberately
// no override flag.
package onepassword

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/jitpass/jit/internal/vault"
)

// opTeamID is 1Password's (AgileBits Inc.'s) Apple Developer Team ID,
// read off the shipping binary (op 2.39.0: "Developer ID Application:
// AgileBits Inc. (2BUA8C4S2C)", TeamIdentifier=2BUA8C4S2C). Unlike jit's
// own upgradeTeamIDs this is not a list: if 1Password ever re-issues
// under a new team, a jit release updates this constant — nothing in the
// field is bricked in the meantime, linked secrets just fail closed with
// a clear error until that release ships.
const opTeamID = "2BUA8C4S2C"

// resolveTimeout bounds one op invocation. Generous on purpose, same
// class of wait as jit's own Touch ID prompt: a read may legitimately
// block on 1Password's unlock dialog, and cutting a user off mid-reach
// for the sensor is worse than a slow failure. Callers on paths where a
// GUI prompt must never appear (the background service's refresh) get
// their bound from this same constant — fail closed, never a hung reader.
const resolveTimeout = 2 * time.Minute

// Resolver implements vault.RefResolver by exec-ing `op read`. Use New()
// for the real thing; tests construct Resolver{path: ..., verify: ...}
// directly with a fake binary and a no-op verifier.
//
// The zero value is not usable — New wires the real lookup and the real
// codesign verification, both deferred to the first resolve so
// constructing a Resolver (which every openVault does) costs nothing and
// cannot fail on machines that never use a linked secret.
type Resolver struct {
	// path locates the op binary; empty means "resolve via $PATH on first
	// use". verify vets it before the first exec.
	path   string
	verify func(path string) error

	once    sync.Once
	binPath string
	initErr error
	timeout time.Duration
}

var _ vault.RefResolver = (*Resolver)(nil)

// New returns a Resolver backed by the real `op` on $PATH and the real
// Developer ID signature check.
func New() *Resolver {
	return &Resolver{verify: verifySignature, timeout: resolveTimeout}
}

// ResolveRef resolves one op:// secret reference to the exact bytes of
// the field it names, via `op read -n` (no trailing newline appended, so
// injection stays byte-exact). A reference pinned to an account
// (account.go) resolves in that account, whatever op's default is today;
// an unpinned one resolves under op's default, and when that fails on a
// machine with several accounts the error says so, because that is the
// likely cause.
func (r *Resolver) ResolveRef(ref string) ([]byte, error) {
	if err := ValidateRef(ref); err != nil {
		return nil, err
	}
	bin, err := r.bin()
	if err != nil {
		return nil, err
	}
	bare, account := SplitAccount(ref)
	args := accountArgs(Account{ID: account}, "read", "-n", bare)

	timeout := r.timeout
	if timeout <= 0 {
		timeout = resolveTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, bin, args...) // #nosec G204 -- bin is signature-verified above; ref is validated op:// syntax, account is op's own id
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	// Without WaitDelay, a child op leaves behind (its cache daemon, a
	// helper) keeps the stdio pipes open past the kill and Run blocks on
	// them long after the timeout has "fired" — the bound must bound.
	cmd.WaitDelay = time.Second
	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("op read timed out after %s (waiting for a 1Password unlock that never came?)", timeout)
		}
		detail := firstLine(stderr.String())
		if detail == "" {
			detail = err.Error()
		}
		if account == "" {
			if accounts, aerr := r.Accounts(); aerr == nil && len(accounts) > 1 {
				return nil, fmt.Errorf("op read failed: %s (op is signed in to %d accounts and this link names none; `jit vault link` it again to pin one)", detail, len(accounts))
			}
		}
		return nil, fmt.Errorf("op read failed: %s", detail)
	}
	return stdout.Bytes(), nil
}

// bin resolves and vets the op binary exactly once: $PATH lookup (unless
// a path was injected), then the Developer ID signature check. Shared by
// every exec-ing entry point (ResolveRef, Inventory) so none can reach
// an unverified binary.
func (r *Resolver) bin() (string, error) {
	r.once.Do(func() {
		path := r.path
		if path == "" {
			var err error
			path, err = exec.LookPath("op")
			if err != nil {
				r.initErr = fmt.Errorf("the 1Password CLI is not installed (`op` not on PATH); install it with `brew install 1password-cli`")
				return
			}
		}
		if err := r.verify(path); err != nil {
			r.initErr = err
			return
		}
		r.binPath = path
	})
	if r.initErr != nil {
		return "", r.initErr
	}
	return r.binPath, nil
}

// Installed reports whether an `op` binary is on $PATH at all — the cheap,
// exec-free probe surfaces use to decide whether 1Password integration is
// even in play (e.g. migrate's plan line). It deliberately does NOT verify
// the signature: verification runs before the first exec, and a plan must
// stay free of side effects and of second-guessing a binary it won't run.
func Installed() bool {
	_, err := exec.LookPath("op")
	return err == nil
}

// InstalledVerified resolves op on $PATH and runs the Developer ID
// signature check on it, returning the vetted path. For `jit doctor`'s
// automatic 1Password section: prompt-free (codesign inspects the binary,
// op itself is never executed) and fail-closed like every other caller of
// the verifier.
func InstalledVerified() (string, error) {
	path, err := exec.LookPath("op")
	if err != nil {
		return "", fmt.Errorf("the 1Password CLI is not installed (`op` not on PATH)")
	}
	if err := verifySignature(path); err != nil {
		return "", err
	}
	return path, nil
}

// Version reports the op binary's own version string ("2.39.0"), or "" if
// it cannot be read. `op --version` needs no session and pops no prompt;
// the short bound is because a health report must never hang on a
// misbehaving binary.
func Version(path string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := runOp(ctx, path, nil, "--version")
	if err != nil {
		return ""
	}
	return firstLine(string(out))
}

// ValidateRef checks that ref is a structurally plausible op:// secret
// reference — scheme op, a vault, and at least item/field path segments.
// It deliberately validates SHAPE only: whether the reference resolves is
// op's business, and 1Password's reference charset/ID rules are theirs to
// evolve. Exported for `jit vault link`, which wants to reject a typo
// before spending a trial resolve on it.
func ValidateRef(ref string) error {
	u, err := url.Parse(ref)
	if err != nil {
		return fmt.Errorf("not a valid secret reference: %v", err)
	}
	if u.Scheme != "op" {
		return fmt.Errorf("unsupported reference scheme %q (only op:// references are supported)", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("reference %q names no 1Password vault (want op://<vault>/<item>/<field>)", ref)
	}
	segs := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(segs) < 2 || segs[0] == "" || segs[len(segs)-1] == "" {
		return fmt.Errorf("reference %q is incomplete (want op://<vault>/<item>/<field>)", ref)
	}
	return nil
}

// firstLine trims s to its first non-empty line — op's stderr can carry
// multi-line advice, and jit's own error surfaces are one clause each.
func firstLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			return line
		}
	}
	return ""
}
