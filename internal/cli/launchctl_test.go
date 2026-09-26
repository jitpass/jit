// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// withFakeLaunchd replaces launchctlRun for one test with a recorder that
// answers every verb the way launchd answers for a job that is not loaded,
// and shortens the start wait so an install gives up quickly. It returns the
// recorded calls. For a test that reaches install, heal or uninstall only on
// the way to what it is testing.
func withFakeLaunchd(t *testing.T) func() [][]string {
	t.Helper()
	var mu sync.Mutex
	var calls [][]string
	origRun, origWait := launchctlRun, agentStartWait
	t.Cleanup(func() { launchctlRun, agentStartWait = origRun, origWait })
	agentStartWait = 50 * time.Millisecond
	launchctlRun = func(args ...string) ([]byte, error) {
		mu.Lock()
		calls = append(calls, append([]string(nil), args...))
		mu.Unlock()
		return []byte(`Could not find service "` + agentPlistLabel + `" in domain for user gui: ` + strconv.Itoa(os.Getuid())), errors.New("exit status 113")
	}
	return func() [][]string {
		mu.Lock()
		defer mu.Unlock()
		return append([][]string(nil), calls...)
	}
}

// recordLaunchctlExec stands in for the exec below the guard, so no test
// here can run launchctl even with the guard removed (the negative
// control), and restores the real seam above it.
func recordLaunchctlExec(t *testing.T) func() [][]string {
	t.Helper()
	var mu sync.Mutex
	var calls [][]string
	origRun, origExec := launchctlRun, launchctlExec
	t.Cleanup(func() { launchctlRun, launchctlExec = origRun, origExec })
	launchctlRun = runLaunchctl
	launchctlExec = func(args ...string) ([]byte, error) {
		mu.Lock()
		calls = append(calls, append([]string(nil), args...))
		mu.Unlock()
		return nil, nil
	}
	return func() [][]string {
		mu.Lock()
		defer mu.Unlock()
		return append([][]string(nil), calls...)
	}
}

// writeLaunchdPlist writes a plist carrying label under dir/name.
func writeLaunchdPlist(t *testing.T, dir, name, label string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	body := fmt.Sprintf(agentPlistTemplate, label, "/nonexistent/cli.test", "5m0s", "", "/dev/null", "/dev/null")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// mustPanicOnRealLabel runs call and fails the test unless it panicked with
// the guard's message.
func mustPanicOnRealLabel(t *testing.T, name string, call func()) {
	t.Helper()
	defer func() {
		t.Helper()
		r := recover()
		if r == nil {
			t.Errorf("%s: a test binary reached launchctl on the real %s service without a panic", name, agentPlistLabel)
			return
		}
		if msg := fmt.Sprint(r); !strings.Contains(msg, "against the real "+agentPlistLabel+" service") {
			t.Errorf("%s: panicked with %q, want the real-label guard", name, msg)
		}
	}()
	call()
}

// Every launchctl verb jit uses, and the ones it could, on the real label:
// a test binary panics before the exec. The bootstrap rows are the
// PR #170 incident's shape — the arguments name only the domain and a
// temp plist, and the real label is inside the file.
func TestLaunchctlOnTheRealLabelPanicsInATestBinary(t *testing.T) {
	execd := recordLaunchctlExec(t)
	dir := t.TempDir()
	target := agentServiceTarget()
	realByName := writeLaunchdPlist(t, dir, agentPlistLabel+".plist", agentPlistLabel)
	realByContent := writeLaunchdPlist(t, dir, "innocent.plist", agentPlistLabel)
	cases := [][]string{
		{"print", target},
		{"kickstart", target},
		{"kickstart", "-k", target},
		{"bootout", target},
		{"bootstrap", agentDomainTarget(), realByName},
		{"bootstrap", agentDomainTarget(), realByContent},
		{"bootstrap", agentDomainTarget(), filepath.Join(dir, agentPlistLabel+".plist.missing"), realByContent},
		{"enable", target},
		{"disable", target},
		{"kill", "SIGTERM", target},
		{"list", agentPlistLabel},
		{"remove", agentPlistLabel},
	}
	for _, args := range cases {
		mustPanicOnRealLabel(t, strings.Join(args, " "), func() { _, _ = launchctlRun(args...) })
	}
	if got := execd(); len(got) != 0 {
		t.Fatalf("launchctl ran on the real label from a test binary: %q", got)
	}
}

// The production callers, through the default seam, from a test whose HOME
// is a temp dir: the incident's install (bootout + bootstrap of the temp
// HOME's plist), the self-heal kickstart, and the health read all stop at
// the guard.
func TestProductionLaunchdCallersCannotReachTheRealServiceFromATest(t *testing.T) {
	shortFixtureHome(t)
	execd := recordLaunchctlExec(t)
	origWait := agentStartWait
	agentStartWait = 10 * time.Millisecond
	t.Cleanup(func() { agentStartWait = origWait; agentHealOnce = sync.Once{} })

	// ensureAgentInstalled first: it installs only while no plist is there,
	// and the install below leaves one behind in the temp HOME.
	mustPanicOnRealLabel(t, "ensureAgentInstalled", func() { _, _ = ensureAgentInstalled() })
	mustPanicOnRealLabel(t, "installAgentService", func() { _, _, _ = installAgentService(time.Minute, true) })
	agentHealOnce = sync.Once{}
	mustPanicOnRealLabel(t, "healDeadService", func() { _ = healDeadService() })
	mustPanicOnRealLabel(t, "queryLaunchdJobState", func() { _, _ = queryLaunchdJobState() })
	if got := execd(); len(got) != 0 {
		t.Fatalf("launchctl ran on the real label from a test binary: %q", got)
	}
}

// A test that wants real launchd opts in with a TEST-ONLY label, and only
// that runs; anything a test binary names that is neither — a bare domain,
// another label, a plist that can't be read — is refused without the exec.
func TestLaunchctlInATestBinaryRunsOnlyTestOnlyLabels(t *testing.T) {
	execd := recordLaunchctlExec(t)
	suffix := make([]byte, 4)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatal(err)
	}
	label := testLaunchdLabelPrefix + hex.EncodeToString(suffix)
	dir := t.TempDir()
	testPlist := writeLaunchdPlist(t, dir, label+".plist", label)
	allowed := [][]string{
		{"print", agentDomainTarget() + "/" + label},
		{"bootstrap", agentDomainTarget(), testPlist},
		{"kickstart", "-k", agentDomainTarget() + "/" + label},
	}
	for _, args := range allowed {
		if _, err := launchctlRun(args...); err != nil {
			t.Errorf("launchctl %q: %v, want it run", args, err)
		}
	}
	refused := [][]string{
		{"print", agentDomainTarget()},
		{"print", agentDomainTarget() + "/com.example.other"},
		{"print", agentDomainTarget() + "/" + testLaunchdLabelPrefix},
		{"bootstrap", agentDomainTarget(), filepath.Join(dir, "missing-"+label+".plist")},
		{"bootstrap", agentDomainTarget(), writeLaunchdPlist(t, dir, label+"-other.plist", "com.example.other")},
		{"print", agentDomainTarget() + "/" + label, agentDomainTarget() + "/com.example.other"},
	}
	for _, args := range refused {
		if _, err := launchctlRun(args...); !errors.Is(err, errLaunchctlInTests) {
			t.Errorf("launchctl %q: %v, want refused", args, err)
		}
	}
	if got := execd(); len(got) != len(allowed) {
		t.Fatalf("ran %q, want only the %d TEST-ONLY calls", got, len(allowed))
	}
}

// runLaunchctl is the only code that execs launchctl: no other file in cmd
// or internal, test or not, names the program. A test that spawned
// launchctl itself would walk around the guard.
func TestOnlyTheSeamRunsLaunchctl(t *testing.T) {
	root := filepath.Join("..", "..")
	seam := filepath.Join(root, "internal", "cli", "launchctl.go")
	self := filepath.Join(root, "internal", "cli", "launchctl_test.go")
	var offenders []string
	for _, top := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, top), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if filepath.Base(path) == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || path == seam || path == self {
				return nil
			}
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return err
			}
			ast.Inspect(f, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				if s, uerr := strconv.Unquote(lit.Value); uerr == nil && (s == "launchctl" || strings.HasSuffix(s, "/launchctl")) {
					offenders = append(offenders, fset.Position(lit.Pos()).String())
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, o := range offenders {
		t.Errorf("%s: names the launchctl program outside internal/cli/launchctl.go; go through launchctlRun", o)
	}
}
