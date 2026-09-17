// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package wrap

import (
	"os"
	"path/filepath"

	"github.com/jitpass/jit/internal/profile"
)

// Shim verdicts a ToolStatus can carry. Three words, not a sentence, so a
// consumer branches on them; Detail carries the sentence.
const (
	ShimOK      = "ok"
	ShimMissing = "missing"
	ShimBroken  = "broken"
)

// ToolStatus is one wrapped tool's health, machine-shaped. Doctor renders it
// into its checks and `jit wrap list --format json` serializes it, so the
// two can never disagree about whether a shim works: there is one function
// that looks.
//
// Shim is about the shim itself: the symlink exists (else ShimMissing) and
// points at an executable (else ShimBroken). ProfileDetail is set when an
// env-wrap's profile manifest cannot be resolved — a separate field because
// Doctor ranks it BELOW a missing real binary (a tool that is not installed
// has no use for a profile) while a listing wants to say "broken" either
// way. InstalledPath is the real binary beyond the shim dir on pathEnv, ""
// when it is not there; that is a fact about this process's PATH, not about
// the installation, which is why Doctor reports it as environmental.
type ToolStatus struct {
	Shim          string
	Detail        string
	ProfileDetail string
	InstalledPath string
}

// Broken reports whether anything about the wrap itself is wrong — the shim
// or, for an env-wrap, its profile. A missing real binary is not "broken":
// see InstalledPath.
func (s ToolStatus) Broken() bool {
	return s.Shim != ShimOK || s.ProfileDetail != ""
}

// CheckTool inspects one manifest entry's installation under home against
// pathEnv. Read-only; it never opens the vault.
func CheckTool(home, pathEnv, tool string, entry Entry) ToolStatus {
	dir := ShimDir(home)
	st := ToolStatus{Shim: ShimOK}

	link := filepath.Join(dir, tool)
	target, err := os.Readlink(link)
	switch {
	case err != nil:
		st.Shim = ShimMissing
		st.Detail = "shim symlink missing, `jit wrap add " + tool + " ...` reinstalls it"
	default:
		if info, statErr := os.Stat(target); statErr != nil || info.Mode()&0o111 == 0 {
			st.Shim = ShimBroken
			st.Detail = "shim points at " + target + ", which isn't an executable, jit moved? re-run `jit wrap add " + tool + " ...`"
		}
	}

	st.InstalledPath = RealBinary(home, pathEnv, tool)

	// Grant, capture and run-grant wraps have no profile: the mount, the
	// per-capture aws-<app> profiles, or the project's own mounts serve
	// them at use time, so their absence before first use is health.
	if entry.IsGrant() || entry.IsCapture() || entry.IsRunGrant() {
		return st
	}
	// profile.Path owns this layout, and every other call site in the repo
	// goes through it (add.go, undo.go, and 18 more). Hand-joining it here
	// meant a change to ProfilesDir or the extension would make doctor
	// report EVERY wrapped tool's profile as missing — a fully red report
	// over a healthy install, which is the worst direction for a
	// diagnostic to fail in.
	profilePath, perr := profile.Path(home, entry.Profile)
	if perr != nil {
		st.ProfileDetail = "profile " + entry.Profile + " has an unusable name: " + perr.Error()
		return st
	}
	if _, statErr := os.Stat(profilePath); statErr != nil {
		st.ProfileDetail = "profile " + entry.Profile + " missing at " + profilePath
	}
	return st
}

// RealBinary returns where tool resolves on pathEnv once the shim dir is
// skipped — the binary the shim will exec — or "" when it is not on this
// PATH at all. Used both for wrapped tools (is the real one still
// installed?) and for catalog tools that are not wrapped yet (is it
// installed here, so wrapping it is even an option?).
func RealBinary(home, pathEnv, tool string) string {
	path, err := lookPathSkipping(pathEnv, tool, ShimDir(home))
	if err != nil {
		return ""
	}
	return path
}

// ShimDirOnPath reports whether pathEnv already carries the shim directory
// — the condition under which a wrapped tool is actually wrapped in the
// shell that handed jit this PATH.
func ShimDirOnPath(home, pathEnv string) bool {
	dir := ShimDir(home)
	for _, p := range filepath.SplitList(pathEnv) {
		if samePath(p, dir) {
			return true
		}
	}
	return false
}

// RcHasPathLine reports whether the rc file for shell carries the shim PATH
// line, i.e. whether FUTURE shells get the shims. Unreadable reads as no.
func RcHasPathLine(home, shell string) bool {
	data, err := os.ReadFile(RcFile(home, shell)) // #nosec G304 -- the user's own rc file
	return err == nil && RcMentionsShimDir(string(data))
}
