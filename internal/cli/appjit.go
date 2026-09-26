// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

// appJitPath finds the jit inside JitPass.app, the one copy that can reach
// the Secure Enclave, for a refusal to name. In order: the login item's
// program, when it is inside a JitPass bundle (it is the jit the service
// runs); the app wherever LaunchServices' index knows it (appBundlesByID);
// then /Applications and ~/Applications. "" when none has a jit, and the
// refusal then says "the jit inside JitPass.app" without a path.
func appJitPath() string {
	if p, ok := plistProgram(); ok && inJitPassBundle(p) && isFile(p) {
		return p
	}
	for _, app := range appBundlesByID(appBundleID) {
		if jit := bundleJit(app); jit != "" {
			return jit
		}
	}
	for _, app := range appBundleDirs() {
		if jit := bundleJit(app); jit != "" {
			return jit
		}
	}
	return ""
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
		// A copy in the Trash still has an index entry.
		if line != "" && !strings.Contains(line, "/.Trash/") {
			apps = append(apps, line)
		}
	}
	return apps
}

// appBundleDirs is where JitPass.app is installed when Spotlight doesn't
// say: /Applications, then ~/Applications. A var so a test points it at
// its own directories.
var appBundleDirs = func() []string {
	dirs := []string{"/Applications/JitPass.app"}
	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, filepath.Join(home, "Applications", "JitPass.app"))
	}
	return dirs
}

// bundleJit is the jit in an app bundle's Contents/MacOS (in JitPass.app, a
// symlink to its helper's main executable), "" when there is none.
func bundleJit(app string) string {
	jit := filepath.Join(app, "Contents", "MacOS", "jit")
	if !isFile(jit) {
		return ""
	}
	return jit
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

// serviceRunsAppJit reports whether the login item already runs appJit:
// the plist's program and appJit resolve, symlinks followed on both, to the
// same file. Then a refused `jit upgrade` has nothing to put right.
func serviceRunsAppJit(appJit string) bool {
	if appJit == "" {
		return false
	}
	program, ok := plistProgram()
	if !ok {
		return false
	}
	a, err := filepath.EvalSymlinks(program)
	if err != nil {
		return false
	}
	b, err := filepath.EvalSymlinks(appJit)
	return err == nil && a == b
}
