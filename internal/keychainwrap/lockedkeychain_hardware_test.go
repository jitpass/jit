// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package keychainwrap

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// securityTool runs /usr/bin/security with args and fails the test on error.
// The statuses only this test decides on.
const (
	errSecAuthFailed   int32 = -25293
	errSecUserCanceled int32 = -128
)

func securityTool(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("/usr/bin/security", args...).CombinedOutput() // #nosec G204 -- fixed system tool, the test's own temporary keychain
	if err != nil {
		t.Fatalf("security %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

// userSearchList is `security list-keychains -d user`, one path per entry.
func userSearchList(t *testing.T) []string {
	t.Helper()
	var list []string
	for _, line := range strings.Split(securityTool(t, "list-keychains", "-d", "user"), "\n") {
		if p := strings.Trim(strings.TrimSpace(line), `"`); p != "" {
			list = append(list, p)
		}
	}
	return list
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

	startList := userSearchList(t)
	startDefault := securityTool(t, "default-keychain", "-d", "user")
	suffix := make([]byte, 4)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatal(err)
	}
	const password = "jit-TEST-ONLY-password"
	path := filepath.Join(t.TempDir(), "jit-TEST-ONLY-"+hex.EncodeToString(suffix)+".keychain-db")
	service, account := "com.jitpass.locked.TEST-ONLY", "probe-"+hex.EncodeToString(suffix)

	securityTool(t, "create-keychain", "-p", password, path)
	t.Cleanup(func() {
		_ = exec.Command("/usr/bin/security", "delete-keychain", path).Run() // #nosec G204 -- the test's own temporary keychain
		if got := userSearchList(t); !slices.Equal(got, startList) {
			securityTool(t, append([]string{"list-keychains", "-d", "user", "-s"}, startList...)...)
			t.Errorf("the search list was %q after the test, restored to %q", got, startList)
		}
		if got := securityTool(t, "default-keychain", "-d", "user"); got != startDefault {
			t.Errorf("the default keychain changed: %q, was %q", got, startDefault)
		}
	})
	// create-keychain adds the new keychain to the user's search list; put
	// the list back at once, so nothing else ever searches it.
	if got := userSearchList(t); !slices.Equal(got, startList) {
		securityTool(t, append([]string{"list-keychains", "-d", "user", "-s"}, startList...)...)
	}
	if got := userSearchList(t); !slices.Equal(got, startList) {
		t.Fatalf("couldn't restore the search list: %q, want %q", got, startList)
	}

	if st := addInKeychain(path, service, account); st != errSecSuccess {
		t.Fatalf("adding the TEST-ONLY item: OSStatus=%d", st)
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
	securityTool(t, "unlock-keychain", "-p", password, path)
	if st := probeInKeychain(path, service, account, probePresence, true); st != errSecItemNotFound {
		t.Fatalf("after the delete: presence %d, want %d", st, errSecItemNotFound)
	}
}
