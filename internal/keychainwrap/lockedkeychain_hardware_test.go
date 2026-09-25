// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package keychainwrap

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// errSecUserCanceled is the status only this test decides on.
const errSecUserCanceled int32 = -128

// securityTool runs /usr/bin/security with args and fails the test on error.

func securityTool(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("/usr/bin/security", args...).CombinedOutput() // #nosec G204 -- fixed system tool, the test's own temporary keychain
	if err != nil {
		t.Fatalf("security %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

// searchSecurity runs /usr/bin/security for the search-list guard; a var so
// the guard's own test runs over a fake and never touches the real list.
var searchSecurity = func(args ...string) ([]byte, error) {
	return exec.Command("/usr/bin/security", args...).CombinedOutput() // #nosec G204 -- fixed system tool and subcommands
}

// guardExit ends the process after a signal restored the search list; a var
// so the guard's test sees the exit instead of dying.
var guardExit = os.Exit

// reporter is the part of testing.T the guard reports through.
type reporter interface {
	Helper()
	Logf(format string, args ...any)
	Errorf(format string, args ...any)
}

// quotedPaths parses `security list-keychains` or `default-keychain`
// output: one quoted path per line.
func quotedPaths(out []byte) []string {
	var list []string
	for _, line := range strings.Split(string(out), "\n") {
		if p := strings.Trim(strings.TrimSpace(line), `"`); p != "" {
			list = append(list, p)
		}
	}
	return list
}

// searchListGuard holds the user's keychain search list and default
// keychain as they were BEFORE the test changed anything, and puts them
// back exactly. create-keychain adds the test's keychain to that list, and
// a list left changed would have every program on the Mac searching a
// temporary keychain, or no longer searching one it did. So:
//
//   - the snapshot is taken first, and the command that restores it is
//     logged at once, so even a run killed outright (a -test.timeout panic
//     runs no cleanup) leaves the way back in its output;
//   - restore puts it back whenever asked (right after create-keychain), at
//     t.Cleanup, and on SIGINT, SIGTERM or SIGHUP, which then exit;
//   - at the end the list is read again, and if it differs the test fails
//     loudly with the exact command to run.
type searchListGuard struct {
	list []string
	dflt string
}

// newSearchListGuard snapshots the list and the default keychain, logs the
// restore command, and arranges the restore at cleanup and on a signal.
func newSearchListGuard(t *testing.T) *searchListGuard {
	t.Helper()
	g, err := snapshotSearchList()
	if err != nil {
		t.Fatalf("reading the keychain search list before the test: %v", err)
	}
	t.Logf("if this run dies before its cleanup, restore the keychain search list with:\n  %s", g.restoreCommand())
	sigs := make(chan os.Signal, 1)
	done := make(chan struct{})
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		select {
		case sig := <-sigs:
			err := g.restore()
			fmt.Fprintf(os.Stderr, "keychainwrap test: %v: restored the keychain search list (%v); check it with `security list-keychains -d user`, and if it differs run:\n  %s\n", sig, err, g.restoreCommand())
			guardExit(1)
		case <-done:
		}
	}()
	t.Cleanup(func() {
		signal.Stop(sigs)
		close(done)
		g.finish(t)
	})
	return g
}

func snapshotSearchList() (*searchListGuard, error) {
	list, err := searchSecurity("list-keychains", "-d", "user")
	if err != nil {
		return nil, fmt.Errorf("list-keychains: %w: %s", err, list)
	}
	dflt, err := searchSecurity("default-keychain", "-d", "user")
	if err != nil {
		return nil, fmt.Errorf("default-keychain: %w: %s", err, dflt)
	}
	d := quotedPaths(dflt)
	if len(d) != 1 {
		return nil, fmt.Errorf("default-keychain answered %q", dflt)
	}
	return &searchListGuard{list: quotedPaths(list), dflt: d[0]}, nil
}

// restoreCommand is the shell command that puts the snapshot back.
func (g *searchListGuard) restoreCommand() string {
	quoted := make([]string, len(g.list))
	for i, p := range g.list {
		quoted[i] = strconv.Quote(p)
	}
	return "security list-keychains -d user -s " + strings.Join(quoted, " ") +
		" && security default-keychain -d user -s " + strconv.Quote(g.dflt)
}

// differs reports what, if anything, is not as the snapshot had it.
func (g *searchListGuard) differs() (list []string, dflt string, changed bool, err error) {
	now, err := snapshotSearchList()
	if err != nil {
		return nil, "", false, err
	}
	return now.list, now.dflt, !slices.Equal(now.list, g.list) || now.dflt != g.dflt, nil
}

// restore puts the snapshot back if anything differs from it.
func (g *searchListGuard) restore() error {
	list, dflt, changed, err := g.differs()
	if err != nil || !changed {
		return err
	}
	if !slices.Equal(list, g.list) {
		if out, err := searchSecurity(append([]string{"list-keychains", "-d", "user", "-s"}, g.list...)...); err != nil {
			return fmt.Errorf("list-keychains -s: %w: %s", err, out)
		}
	}
	if dflt != g.dflt {
		if out, err := searchSecurity("default-keychain", "-d", "user", "-s", g.dflt); err != nil {
			return fmt.Errorf("default-keychain -s: %w: %s", err, out)
		}
	}
	return nil
}

// finish restores, then reads the list again and fails loudly, with the
// exact command, if it is still not what it was.
func (g *searchListGuard) finish(t reporter) {
	t.Helper()
	before, beforeDflt, changed, _ := g.differs()
	restoreErr := g.restore()
	list, dflt, still, err := g.differs()
	switch {
	case err != nil:
		t.Errorf("KEYCHAIN SEARCH LIST NOT CHECKED after the test (%v). Check `security list-keychains -d user`; it was %q. To restore it run:\n  %s", err, g.list, g.restoreCommand())
	case still:
		t.Errorf("KEYCHAIN SEARCH LIST CHANGED and not restored (%v): it is %q with default %q, and was %q with default %q. Run:\n  %s", restoreErr, list, dflt, g.list, g.dflt, g.restoreCommand())
	case changed:
		t.Errorf("the test left the keychain search list changed (%q, default %q); it is restored to %q. Check it; if it differs run:\n  %s", before, beforeDflt, g.list, g.restoreCommand())
	}
}

// What a LOCKED file-based keychain asks of the registry's queries, measured
// on a temporary keychain this test creates with a known password and locks
// itself; the item in it is TEST-ONLY and made by this binary. Nothing here
// reads or changes any other keychain, and the user's search list and
// default keychain end exactly as they began. Only `security` subcommands
// that take the password or never prompt are used: show-keychain-info on a
// locked keychain asks to unlock it (it did, once, while this was written).
//
// Measured 2026-09-26 (macOS 27), interaction off: the presence query and
// the delete need no unlock at all (both 0), so on a locked keychain there
// is no dialog for kSecUseAuthenticationUIFail to stop. The data read is
// the one the lock stops, and it fails at once with errSecAuthFailed
// (-25293), not errSecInteractionNotAllowed: a locked keychain cannot make
// these queries answer -25308, so this test pins what they do answer.
//
// Two halves. Unattended (scripts/se-test.sh): everything with interaction
// off (TestMain, and kwWithoutUI around each probe). Attended
// (JIT_SE_INTERACTIVE=1): the quiet read again with the process-wide switch
// ON, so only its own kSecUseAuthenticationUIFail can stop an unlock
// dialog. That half can raise a dialog if the flag is not honoured for a
// file-based keychain (an openclaw fix found it was not for an item's
// access dialog), so it runs only with someone at the keyboard to cancel
// it. It passes only if the read fails at once, without a cancel.
func TestHardwareLockedKeychainNeverAsks(t *testing.T) {
	if os.Getenv("JIT_SE_TEST") != "1" {
		t.Skip("hardware: scripts/se-test.sh")
	}
	DisallowKeychainUITesting()

	// Before anything can change the search list: the snapshot, the
	// restore command in the log, and the restore at cleanup and on a
	// signal (searchListGuard).
	guard := newSearchListGuard(t)
	suffix := make([]byte, 4)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatal(err)
	}
	const password = "jit-TEST-ONLY-password"
	path := filepath.Join(t.TempDir(), "jit-TEST-ONLY-"+hex.EncodeToString(suffix)+".keychain-db")
	service, account := "com.jitpass.locked.TEST-ONLY", "probe-"+hex.EncodeToString(suffix)

	// Cleanups run last-registered first: the temporary keychain goes, then
	// the guard restores and checks the list.
	securityTool(t, "create-keychain", "-p", password, path)
	t.Cleanup(func() {
		_ = exec.Command("/usr/bin/security", "delete-keychain", path).Run() // #nosec G204 -- the test's own temporary keychain
	})
	// create-keychain adds the new keychain to the user's search list; put
	// the list back at once, so nothing else ever searches it.
	if err := guard.restore(); err != nil {
		t.Fatalf("restoring the search list after create-keychain: %v\nRun:\n  %s", err, guard.restoreCommand())
	}
	if _, _, changed, err := guard.differs(); err != nil || changed {
		t.Fatalf("couldn't restore the search list (%v); run:\n  %s", err, guard.restoreCommand())
	}

	if st := addInKeychain(path, service, account); st != errSecSuccess {
		t.Fatalf("adding the TEST-ONLY item: OSStatus=%d", st)
	}
	// A second item for the delete by reference, the fallback the service's
	// grant key delete takes without the process switch (kwDeleteRefsIn).
	byRef := account + "-ref"
	if st := addInKeychain(path, service, byRef); st != errSecSuccess {
		t.Fatalf("adding the second TEST-ONLY item: OSStatus=%d", st)
	}
	securityTool(t, "lock-keychain", path)

	// Interaction off: the lock stops the read, and only the read.
	if st := probeInKeychain(path, service, account, probeQuietRead, true); st != errSecAuthFailed {
		t.Fatalf("locked, interaction off: the quiet read answered %d; measured %d", st, errSecAuthFailed)
	}
	if st := probeInKeychain(path, service, account, probePresence, true); st != errSecSuccess {
		t.Errorf("locked, interaction off: presence answered %d; measured 0 (metadata needs no unlock)", st)
	}

	if os.Getenv("JIT_SE_INTERACTIVE") == "1" {
		// The switch ON: only the query's own flag can stop a dialog now.
		setUIAllowed(true)
		start := time.Now()
		st := probeInKeychain(path, service, account, probeQuietRead, false)
		took := time.Since(start)
		pr := probeInKeychain(path, service, account, probePresence, false)
		setUIAllowed(false)
		if st == errSecSuccess || st == errSecUserCanceled || took > 2*time.Second {
			t.Errorf("locked, interaction ON: the quiet read answered %d after %s; want a failure at once, no dialog (kSecUseAuthenticationUIFail not honoured?)", st, took)
		}
		if pr != errSecSuccess {
			t.Errorf("locked, interaction ON: presence answered %d, want 0", pr)
		}
	} else {
		t.Log("the half with keychain interaction on runs only attended (JIT_SE_INTERACTIVE=1): it may raise a dialog")
	}

	// The delete, still locked and interaction off: it needs no unlock
	// either, and the item is gone after it.
	if st := probeInKeychain(path, service, account, probeDelete, true); st != errSecSuccess {
		t.Errorf("locked, interaction off: the delete answered %d; measured 0", st)
	}
	// The delete by reference (lookup, then SecKeychainItemDelete), locked
	// and interaction off: an unlock it needed would fail it with -25308,
	// so 0 here is that it needs none, which is what lets the service run
	// it without switching interaction off.
	if st := probeInKeychain(path, service, byRef, probeDeleteByRef, true); st != errSecSuccess {
		t.Errorf("locked, interaction off: the delete by reference answered %d, want 0", st)
	}
	securityTool(t, "unlock-keychain", "-p", password, path)
	if st := probeInKeychain(path, service, account, probePresence, true); st != errSecItemNotFound {
		t.Fatalf("after the delete: presence %d, want %d", st, errSecItemNotFound)
	}
	if st := probeInKeychain(path, service, byRef, probePresence, true); st != errSecItemNotFound {
		t.Fatalf("after the delete by reference: presence %d, want %d", st, errSecItemNotFound)
	}
}

// fakeSearchList stands in for /usr/bin/security's search-list commands.
// stuck ignores every -s, the way a restore that doesn't take would.
type fakeSearchList struct {
	mu    sync.Mutex
	list  []string
	dflt  string
	stuck bool
}

func (f *fakeSearchList) run(args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	quote := func(ps ...string) []byte {
		var b strings.Builder
		for _, p := range ps {
			fmt.Fprintf(&b, "    %q\n", p)
		}
		return []byte(b.String())
	}
	switch {
	case len(args) == 3 && args[0] == "list-keychains":
		return quote(f.list...), nil
	case len(args) >= 4 && args[0] == "list-keychains" && args[3] == "-s":
		if !f.stuck {
			f.list = append([]string(nil), args[4:]...)
		}
		return nil, nil
	case len(args) == 3 && args[0] == "default-keychain":
		return quote(f.dflt), nil
	case len(args) == 5 && args[0] == "default-keychain" && args[3] == "-s":
		if !f.stuck {
			f.dflt = args[4]
		}
		return nil, nil
	}
	return nil, fmt.Errorf("unexpected security %q", args)
}

func (f *fakeSearchList) set(list ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.list = list
}

func (f *fakeSearchList) get() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.list...)
}

// recorder is a reporter that keeps what it was told.
type recorder struct{ errs, logs []string }

func (*recorder) Helper()                   {}
func (r *recorder) Logf(f string, a ...any) { r.logs = append(r.logs, fmt.Sprintf(f, a...)) }
func (r *recorder) Errorf(format string, a ...any) {
	r.errs = append(r.errs, fmt.Sprintf(format, a...))
}

// withFakeSearchList puts the guard over a fake security tool.
func withFakeSearchList(t *testing.T) *fakeSearchList {
	t.Helper()
	f := &fakeSearchList{list: []string{"/Users/x/Library/Keychains/login.keychain-db", "/Library/Keychains/System.keychain"}, dflt: "/Users/x/Library/Keychains/login.keychain-db"}
	orig := searchSecurity
	searchSecurity = f.run
	t.Cleanup(func() { searchSecurity = orig })
	return f
}

// The guard TestHardwareLockedKeychainNeverAsks stands on, over a fake
// security tool (the real search list is never touched here): a list the
// test changed is put back; one that can't be put back fails loudly with
// the exact command; and a signal restores it before the process exits.
func TestSearchListGuard(t *testing.T) {
	temp := "/private/var/folders/jit-TEST-ONLY-1.keychain-db"
	t.Run("changed, restored", func(t *testing.T) {
		f := withFakeSearchList(t)
		g, err := snapshotSearchList()
		if err != nil {
			t.Fatal(err)
		}
		start := f.get()
		f.set(append(f.get(), temp)...)
		var r recorder
		g.finish(&r)
		if !slices.Equal(f.get(), start) {
			t.Fatalf("list %q, want it restored to %q", f.get(), start)
		}
		if len(r.errs) != 1 || !strings.Contains(r.errs[0], "left the keychain search list changed") {
			t.Fatalf("errors %q, want one saying the test changed it", r.errs)
		}
	})
	t.Run("won't restore: loud, with the exact command", func(t *testing.T) {
		f := withFakeSearchList(t)
		g, err := snapshotSearchList()
		if err != nil {
			t.Fatal(err)
		}
		f.set(append(f.get(), temp)...)
		f.stuck = true
		var r recorder
		g.finish(&r)
		want := `security list-keychains -d user -s "/Users/x/Library/Keychains/login.keychain-db" "/Library/Keychains/System.keychain" && security default-keychain -d user -s "/Users/x/Library/Keychains/login.keychain-db"`
		if len(r.errs) != 1 || !strings.Contains(r.errs[0], "KEYCHAIN SEARCH LIST CHANGED") || !strings.Contains(r.errs[0], want) {
			t.Fatalf("errors %q, want one naming %q", r.errs, want)
		}
	})
	t.Run("unchanged: quiet", func(t *testing.T) {
		withFakeSearchList(t)
		g, err := snapshotSearchList()
		if err != nil {
			t.Fatal(err)
		}
		var r recorder
		g.finish(&r)
		if len(r.errs) != 0 {
			t.Fatalf("errors %q, want none", r.errs)
		}
	})
	t.Run("a signal restores, then exits", func(t *testing.T) {
		f := withFakeSearchList(t)
		exited := make(chan int, 1)
		orig := guardExit
		guardExit = func(code int) { exited <- code }
		t.Cleanup(func() { guardExit = orig })
		start := f.get()
		newSearchListGuard(t)
		f.set(append(f.get(), temp)...)
		if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
			t.Fatal(err)
		}
		select {
		case code := <-exited:
			if code == 0 {
				t.Error("exited 0 after a signal")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("no exit after SIGHUP")
		}
		if !slices.Equal(f.get(), start) {
			t.Fatalf("after SIGHUP the list is %q, want %q", f.get(), start)
		}
	})
}
