// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/jitpass/jit/internal/secureenclave"
)

// thisJitEntitled is secureenclave.Entitled, a var so a test decides what
// this binary's signature says.
var thisJitEntitled = secureenclave.Entitled

// enclaveReach answers, from this binary's signature alone, whether it can
// reach the Secure Enclave: nil when it can, secureenclave.ErrUnavailable
// when it can't (a jit outside JitPass.app), and the reason when the
// signature couldn't be read. No keychain query, so no prompt, and the
// same answer with the screen locked.
func enclaveReach() error {
	ok, err := thisJitEntitled()
	switch {
	case err != nil:
		return err
	case !ok:
		return secureenclave.ErrUnavailable
	}
	return nil
}

// appBundleID is JitPass.app's CFBundleIdentifier (jit-app's Info.plist).
const appBundleID = "com.jitpass.app"

// findAppJit is appJitPath, a var so a test names the app's jit.
var findAppJit = appJitPath

// appJitLookup is one command's search for the app's jit, for a refusal to
// name: made when the refusal is built, run only when its text is
// (needsAppJitError.Error), and at most once. A refusal nobody reads (the
// silent first-use install's, ensureAgentInstalled) never searches, and
// one read twice searches once.
type appJitLookup struct {
	once sync.Once
	path string
}

// jit is the app's jit (findAppJit), "" when none was found or l is nil.
func (l *appJitLookup) jit() string {
	if l == nil {
		return ""
	}
	l.once.Do(func() { l.path = findAppJit() })
	return l.path
}

// appJitPath finds the jit inside JitPass.app, the one copy that can reach
// the Secure Enclave, for a refusal to name. A path is only ever named once
// its signature says it IS that jit (verifyAppJit): a login item's program,
// a folder or Spotlight's index can each point anywhere, and the refusal
// tells the user to run what it names. In order:
//
//  1. the login item's program, when it is inside a JitPass*.app bundle
//     (the jit the service runs);
//  2. /Applications/JitPass.app, then ~/Applications/JitPass.app;
//  3. Spotlight's answer for the app's bundle ID, last, and never a copy
//     on another volume, in a Trash, or in a build folder (DerivedData,
//     .build): those are not the installed app.
//
// "" when none verifies: the refusal then says "the jit inside
// JitPass.app" without a path.
func appJitPath() string {
	tried := map[string]bool{}
	verified := func(jit string) bool {
		if tried[jit] {
			return false
		}
		tried[jit] = true
		return isFile(jit) && verifyAppJit(jit) == nil
	}
	if p, ok := plistProgram(); ok && inJitPassBundle(p) && verified(p) {
		return p
	}
	for _, app := range appBundleDirs() {
		if jit := bundleJit(app); verified(jit) {
			return jit
		}
	}
	for _, app := range appBundlesByID(appBundleID) {
		if notTheInstalledApp(app) {
			continue
		}
		if jit := bundleJit(app); verified(jit) {
			return jit
		}
	}
	return ""
}

// notTheInstalledApp reports whether a bundle Spotlight found is somewhere
// the installed app never is: another volume (a mounted disk image, a
// backup), a Trash, or a build folder.
func notTheInstalledApp(app string) bool {
	if strings.HasPrefix(app, "/Volumes/") {
		return true
	}
	for _, dir := range []string{"/.Trash/", "/.Trashes/", "/DerivedData/", "/.build/"} {
		if strings.Contains(app, dir) {
			return true
		}
	}
	return false
}

// appBundlesByID lists the bundles with a bundle ID, from Spotlight's index
// (the one LaunchServices keeps current); a var so a test lists its own.
// Best-effort: no Spotlight, or no answer within two seconds, is none.
var appBundlesByID = func(id string) []string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	// #nosec G204 -- a fixed program and a query built from a constant bundle ID
	out, err := exec.CommandContext(ctx, "mdfind", "kMDItemCFBundleIdentifier == '"+id+"'").Output()
	if err != nil {
		return nil
	}
	var apps []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line != "" {
			apps = append(apps, line)
		}
	}
	return apps
}

// appBundleDirs is where JitPass.app is installed: /Applications, then
// ~/Applications. A var so a test points it at its own directories.
var appBundleDirs = func() []string {
	dirs := []string{"/Applications/JitPass.app"}
	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, filepath.Join(home, "Applications", "JitPass.app"))
	}
	return dirs
}

// bundleJit is the jit in an app bundle's Contents/MacOS (in JitPass.app, a
// symlink to its helper's main executable).
func bundleJit(app string) string {
	return filepath.Join(app, "Contents", "MacOS", "jit")
}

// isFile reports whether path (symlinks followed) is a regular file.
func isFile(path string) bool {
	st, err := os.Stat(path) // #nosec G703 -- stat-only existence probe of a jit path
	return err == nil && st.Mode().IsRegular()
}

// inJitPassBundle reports whether path is inside a JitPass app bundle:
// JitPass.app's own Contents, or its helper's (JitPassAgent.app).
func inJitPassBundle(path string) bool {
	segs := strings.Split(path, string(filepath.Separator))
	for i, seg := range segs {
		if strings.HasPrefix(seg, "JitPass") && strings.HasSuffix(seg, ".app") && i+1 < len(segs) && segs[i+1] == "Contents" {
			return true
		}
	}
	return false
}

// verifyAppJit is codesignAppJit, a var so a test decides which paths are
// the app's jit.
var verifyAppJit = codesignAppJit

// appJitRequirement is the code requirement only the jit inside JitPass.app
// meets: Apple-anchored and signed by the team, code identifier jit (the
// helper is signed `-i jit`, spike S3f), and carrying the keychain access
// group that lets it reach the Secure Enclave (group). The entitlement
// clause matches an array that contains the group. Measured 2026-09-26
// against /Applications/JitPass.app: its helper passes, and so does the
// Contents/MacOS/jit link to it; /bin/ls (another identifier and team),
// and the helper against another group, fail
// (TestAppJitRequirementOnRealSignatures).
func appJitRequirement(group string) string {
	return fmt.Sprintf("=anchor apple generic and identifier \"jit\" and certificate leaf[subject.OU] = %q and entitlement[\"keychain-access-groups\"] = %q",
		secureenclave.TeamID, group)
}

// codesignAppJit checks path is the jit inside JitPass.app by its
// signature (appJitRequirement): codesign validates the signature against
// the code on disk and the requirement against the signature. No keychain
// query, nothing run.
func codesignAppJit(path string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// #nosec G204 -- a fixed system binary; the path is only ever an argument
	out, err := exec.CommandContext(ctx, "/usr/bin/codesign", "--verify", "--strict", "-R", appJitRequirement(secureenclave.AccessGroup), path).CombinedOutput()
	if err != nil {
		if detail := strings.TrimSpace(string(out)); detail != "" {
			return fmt.Errorf("%s is not the jit inside JitPass.app: %s", path, detail)
		}
		return fmt.Errorf("%s is not the jit inside JitPass.app: %w", path, err)
	}
	return nil
}

// plistProgram is the program the installed login item runs.
func plistProgram() (string, bool) {
	path, err := agentPlistPath()
	if err != nil {
		return "", false
	}
	data, err := os.ReadFile(path) // #nosec G304 -- jit's own launchd plist under the user's LaunchAgents dir
	if err != nil {
		return "", false
	}
	return plistProgramPath(data)
}

// serviceRunsAppJit reports whether the login item already runs the jit
// inside JitPass.app: its program is inside a JitPass bundle AND passes
// that jit's signature check (verifyAppJit), so a plist naming some other
// binary at such a path does not count. Then a `jit upgrade` refused only
// for running outside the app has nothing to put right.
func serviceRunsAppJit() bool {
	program, ok := plistProgram()
	return ok && inJitPassBundle(program) && isFile(program) && verifyAppJit(program) == nil
}
