// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// This file is jit's one way to launchd. Every launchctl jit runs —
// install's bootout/bootstrap/kickstart, the client's self-heal kickstart,
// the service's self-retire kickstart -k, uninstall's bootout, the health
// surfaces' print — goes through launchctlRun, and launchctlRun's real
// implementation is the only code that execs launchctl
// (TestOnlyTheSeamRunsLaunchctl fails on another).
//
// A test binary must never reach the real service. HOME is a temp dir in
// tests, but launchd's domain (gui/<uid>) and jit's label are the
// developer's real, shared ones: during PR #170 a local `go test ./...`
// booted out the owner's running service and bootstrapped a plist from a
// test's temp HOME in its place, a job whose program was the cli.test
// binary. The service stayed down (exit 78) until it was restored by hand.
// So guardLaunchctlInTests, below the seam every test fakes, makes the real
// label unusable from a test binary: it panics before the exec, whatever
// the verb, and whichever way the label is named (a service target, or the
// Label inside a plist bootstrap loads). A test that wants real launchd
// names a TEST-ONLY label (testLaunchdLabelPrefix); everything else a test
// binary asks for is refused without running launchctl.

// launchctlRun runs launchctl with fixed, jit-controlled arguments and
// returns its combined output. A package var so tests can substitute a fake
// and drive install/restart's recovery logic without real launchd.
var launchctlRun = runLaunchctl

// launchctlExec is the exec itself, below the guard. A var only so the
// guard's own test can prove the guard stops a call before it would run.
var launchctlExec = func(args ...string) ([]byte, error) {
	return exec.Command("launchctl", args...).CombinedOutput() // #nosec G204 -- fixed subcommands with jit's own label/domain/plist path, never external input
}

func runLaunchctl(args ...string) ([]byte, error) {
	if testing.Testing() {
		if err := guardLaunchctlInTests(args); err != nil {
			return nil, err
		}
	}
	return launchctlExec(args...)
}

// testLaunchdLabelPrefix is the only launchd label a test binary may run
// launchctl against: jit's label with a TEST-ONLY suffix, never the label
// itself.
const testLaunchdLabelPrefix = agentPlistLabel + ".TEST-ONLY-"

// errLaunchctlInTests is what a test binary gets from launchctl on anything
// but a TEST-ONLY label.
var errLaunchctlInTests = errors.New("launchctl is not run from a test binary except on a " + testLaunchdLabelPrefix + " label")

// guardLaunchctlInTests decides a test binary's launchctl call: panic on
// jit's real label, allow a call whose every label is TEST-ONLY, refuse the
// rest. It panics rather than returning an error on the real label because
// every production caller ignores or tolerates launchctl's errors, so an
// error would let a test that forgot its fake pass quietly.
func guardLaunchctlInTests(args []string) error {
	labels, known := launchctlLabels(args)
	for _, l := range labels {
		if l == agentPlistLabel {
			panic(fmt.Sprintf("a test binary ran `launchctl %s` against the real %s service: fake launchctlRun in this test", strings.Join(args, " "), agentPlistLabel))
		}
	}
	if !known || len(labels) == 0 {
		return errLaunchctlInTests
	}
	for _, l := range labels {
		if !strings.HasPrefix(l, testLaunchdLabelPrefix) || len(l) == len(testLaunchdLabelPrefix) {
			return errLaunchctlInTests
		}
	}
	return nil
}

// launchctlLabels returns the launchd labels a launchctl call names: the
// label in a service target (gui/501/<label>, and a bare label or a
// <label>.plist file name), and the Label inside a plist file bootstrap
// loads — the incident's shape, where the arguments carried only a domain
// and a temp path. known is false when a plist named cannot be read, so its
// label cannot be ruled out.
func launchctlLabels(args []string) (labels []string, known bool) {
	known = true
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		if filepath.IsAbs(a) {
			data, err := os.ReadFile(a) // #nosec G304 -- a plist path jit itself passes to launchctl, read only to check its label
			if err != nil {
				known = false
			} else if l, ok := plistLabel(data); ok {
				labels = append(labels, l)
			} else {
				known = false
			}
			labels = append(labels, strings.TrimSuffix(filepath.Base(a), ".plist"))
			continue
		}
		parts := strings.Split(a, "/")
		switch {
		case len(parts) >= 3: // gui/501/<label>, user/501/<label>
			labels = append(labels, strings.Join(parts[2:], "/"))
		case len(parts) == 2 && parts[0] == "system":
			labels = append(labels, parts[1])
		case len(parts) == 1 && strings.Contains(a, "."): // a bare label
			labels = append(labels, a)
		}
	}
	return labels, known
}

// plistLabel returns the <string> after a plist's Label key.
func plistLabel(data []byte) (string, bool) {
	const key = "<key>Label</key>"
	i := strings.Index(string(data), key)
	if i < 0 {
		return "", false
	}
	values := plistStringValues(data[i+len(key):])
	if len(values) == 0 {
		return "", false
	}
	return xmlUnescape(strings.TrimSpace(values[0])), true
}
