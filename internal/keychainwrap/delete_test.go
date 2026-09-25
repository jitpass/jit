// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package keychainwrap

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// fakeOps answers deleteItem's three calls and counts the last two.
type fakeOps struct {
	del, ref   int32
	after      MEKPresence
	refs, pres int
}

func (f *fakeOps) secItemDelete() int32 { return f.del }
func (f *fakeOps) deleteByRef() int32   { f.refs++; return f.ref }
func (f *fakeOps) presence() MEKPresence {
	f.pres++
	return f.after
}

// deleteItem's decisions. The one this was written for: SecItemDelete saw
// an item and refused it (errSecInvalidOwnerEdit), and the fallback's
// lookup, which searches only the login keychain, found nothing. That item
// is somewhere and still there; it used to be reported deleted.
func TestDeleteItemDecisions(t *testing.T) {
	for _, tc := range []struct {
		name     string
		ops      fakeOps
		fallback bool
		wantErr  string // "" for success
		wantRefs int
		wantPres int
	}{
		{"deleted", fakeOps{del: errSecSuccess}, true, "", 0, 0},
		{"not there", fakeOps{del: errSecItemNotFound}, true, "", 0, 0},
		{"another error", fakeOps{del: -25293}, true, "OSStatus=-25293", 0, 0},
		{"owner edit, no fallback", fakeOps{del: errSecInvalidOwnerEdit}, false, "OSStatus=-25244", 0, 0},
		{"owner edit, the lookup finds nothing", fakeOps{del: errSecInvalidOwnerEdit, ref: errSecItemNotFound, after: MEKAbsent}, true, "OSStatus=-25244", 1, 0},
		{"owner edit, the lookup would have asked", fakeOps{del: errSecInvalidOwnerEdit, ref: errSecInteractionNotAllowed}, true, "OSStatus=-25308", 1, 0},
		{"owner edit, removed through the reference", fakeOps{del: errSecInvalidOwnerEdit, ref: errSecSuccess, after: MEKAbsent}, true, "", 1, 1},
		{"owner edit, the reference delete said yes and the item stayed", fakeOps{del: errSecInvalidOwnerEdit, ref: errSecSuccess, after: MEKPresent}, true, "still there", 1, 1},
		{"owner edit, gone can't be confirmed", fakeOps{del: errSecInvalidOwnerEdit, ref: errSecSuccess, after: MEKIndeterminate}, true, "still there", 1, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ops := tc.ops
			err := deleteItem(&ops, tc.fallback, "delete failed")
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("got %v, want success", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("got %v, want an error containing %q", err, tc.wantErr)
			}
			if tc.wantErr != "" && !strings.Contains(err.Error(), "delete failed, OSStatus=") {
				t.Errorf("error %q lost the original status", err)
			}
			if ops.refs != tc.wantRefs || ops.pres != tc.wantPres {
				t.Errorf("reference deletes %d, presence checks %d; want %d, %d", ops.refs, ops.pres, tc.wantRefs, tc.wantPres)
			}
		})
	}
}

// kwWithoutUI, which the fallback's lookup and deletes and the quiet read
// run inside: interaction is off inside it and back to what it was after,
// whichever way it started. Nothing here touches a keychain item, so it runs
// in a plain `go test` with no dialog possible.
func TestKeychainUIIsOffOnlyInsideTheScope(t *testing.T) {
	for _, start := range []bool{true, false} {
		during, after := uiScopeProbe(start)
		if during {
			t.Errorf("started %v: keychain interaction was allowed inside the scope", start)
		}
		if after != start {
			t.Errorf("started %v: left at %v after the scope", start, after)
		}
	}
}

// The queries the no-dialog promises rest on, as built: presence (status
// and doctor) and the delete never ask, and the fallback's lookup never asks
// and searches only the default (login) keychain.
func TestQueriesNeverAsk(t *testing.T) {
	const noUI, loginOnly, data = 1, 2, 4
	for _, tc := range []struct {
		name  string
		which int
		want  int
	}{
		{"presence", 0, noUI},
		{"the fallback's lookup", 1, noUI | loginOnly},
		{"the delete", 2, noUI},
	} {
		if got := queryTraits(tc.which); got != tc.want {
			t.Errorf("%s query: traits %03b, want %03b (1 no dialog, 2 login keychain only, 4 returns data)", tc.name, got, tc.want)
		}
	}
	if queryTraits(0)&data != 0 {
		t.Error("the presence query reads the item's data")
	}
}

// errSecInteractionNotAllowed is what a keychain that would have had to ask
// answers the presence query with: indeterminate, never "absent", which
// doctor would report as a lost key.
func TestPresenceFromStatus(t *testing.T) {
	for status, want := range map[int32]MEKPresence{
		errSecSuccess:               MEKPresent,
		errSecItemNotFound:          MEKAbsent,
		errSecInteractionNotAllowed: MEKIndeterminate,
		-25293:                      MEKIndeterminate,
	} {
		if got := presenceFromStatus(status); got != want {
			t.Errorf("status %d: %v, want %v", status, got, want)
		}
	}
}

// InstallMEK over an item whose presence could not be checked: setMEK
// deletes first, so going ahead could replace a different key. Refused.
func TestInstallMEKWontWriteOverAnUncheckedItem(t *testing.T) {
	w := testWrapper(noChallenge)
	cleanupTestMEK(t, w)
	first := randomMEK(t)
	if err := w.InstallMEK(first); err != nil {
		t.Fatal(err)
	}
	orig := mekPresence
	mekPresence = func(*Wrapper) MEKPresence { return MEKIndeterminate }
	t.Cleanup(func() { mekPresence = orig })
	if err := w.InstallMEK(randomMEK(t)); err == nil {
		t.Fatal("wrote over an item it could not check")
	}
	mekPresence = orig
	if same, err := w.MatchesMEK(first); err != nil || !same {
		t.Fatalf("the stored key changed: same=%v err=%v", same, err)
	}
}

// CountOpens: the vault's own key opens its wrapped keys, another key opens
// none, and a wrapped key under the wrong class does not count.
func TestCountOpens(t *testing.T) {
	w := testWrapper(noChallenge)
	cleanupTestMEK(t, w)
	if err := w.EnsureMEK(); err != nil {
		t.Fatal(err)
	}
	var keys []WrappedKey
	for _, class := range []string{"manual", "dotenv"} {
		wrapped, err := w.WrapKeyLabeled(bytes.Repeat([]byte{9}, 32), "", class)
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, WrappedKey{Wrapped: wrapped, Class: class})
	}
	if n, err := testWrapper(noChallenge).CountOpens(keys); err != nil || n != 2 {
		t.Fatalf("the key the DEKs were wrapped under opened %d, err %v; want 2", n, err)
	}
	if n, _ := testWrapper(noChallenge).CountOpens([]WrappedKey{{keys[0].Wrapped, "dotenv"}}); n != 0 {
		t.Error("a wrapped key opened under the wrong class")
	}
	other := &Wrapper{service: "com.jitpass.vault.mek.TEST-ONLY", account: "other", challenge: noChallenge}
	cleanupTestMEK(t, other)
	if err := other.EnsureMEK(); err != nil {
		t.Fatal(err)
	}
	if n, err := other.CountOpens(keys); err != nil || n != 0 {
		t.Fatalf("a different key opened %d, err %v; want 0", n, err)
	}
	missing := &Wrapper{service: "com.jitpass.vault.mek.TEST-ONLY", account: "missing", challenge: noChallenge}
	if _, err := missing.CountOpens(keys); err == nil {
		t.Fatal("no item, and no error")
	}
}

// Every comparison of key bytes in this package is constant-time. bytes.Equal
// returns at the first differing byte; a key check must not.
func TestKeyComparisonsAreConstantTime(t *testing.T) {
	assertConstantTimeCompares(t, "rekey.go", "MatchesMEK", "InstallMEK", "PromoteStagedRekeyMEK")
}

// assertConstantTimeCompares fails if any named function in file calls
// bytes.Equal, or never calls subtle.ConstantTimeCompare.
func assertConstantTimeCompares(t *testing.T, file string, funcs ...string) {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok {
			continue
		}
		name := fn.Name.Name
		want := false
		for _, n := range funcs {
			want = want || n == name
		}
		if !want {
			continue
		}
		seen[name] = true
		calls := map[string]int{}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok {
				if sel, ok := c.Fun.(*ast.SelectorExpr); ok {
					if pkg, ok := sel.X.(*ast.Ident); ok {
						calls[pkg.Name+"."+sel.Sel.Name]++
					}
				}
			}
			return true
		})
		if calls["bytes.Equal"] > 0 {
			t.Errorf("%s compares with bytes.Equal", name)
		}
		if calls["subtle.ConstantTimeCompare"] == 0 {
			t.Errorf("%s never calls subtle.ConstantTimeCompare", name)
		}
	}
	for _, n := range funcs {
		if !seen[n] {
			t.Errorf("%s not found in %s", n, file)
		}
	}
}

// TestMain turns keychain interaction off for a hardware run
// (scripts/se-test.sh sets JIT_SE_TEST=1) before any test starts, so no
// test in it can raise a keychain dialog on the Mac running it.
func TestMain(m *testing.M) {
	if os.Getenv("JIT_SE_TEST") == "1" {
		DisallowKeychainUITesting()
	}
	os.Exit(m.Run())
}
