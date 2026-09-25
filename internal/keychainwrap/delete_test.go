// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package keychainwrap

import (
	"bytes"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// fakeOps answers deleteItem's and setMEK's calls and counts them.
type fakeOps struct {
	del, ref      int32
	after         MEKPresence // presenceInDefault
	anywhere      MEKPresence // presence (every keychain)
	addErr        error
	refs, pres    int // refs: the CLI reference delete (the process switch)
	refsAsIs      int // the service's reference delete (no switch)
	anyPres, adds int
}

func (f *fakeOps) secItemDelete() int32   { return f.del }
func (f *fakeOps) deleteByRefNoUI() int32 { f.refs++; return f.ref }
func (f *fakeOps) deleteByRefAsIs() int32 { f.refsAsIs++; return f.ref }
func (f *fakeOps) presenceInDefault() MEKPresence {
	f.pres++
	return f.after
}
func (f *fakeOps) presence() MEKPresence { f.anyPres++; return f.anywhere }
func (f *fakeOps) add([]byte) error      { f.adds++; return f.addErr }

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
		{"owner edit, gone can't be confirmed", fakeOps{del: errSecInvalidOwnerEdit, ref: errSecSuccess, after: MEKIndeterminate}, true, "couldn't confirm it is gone", 1, 1},
	} {
		// The same decisions whichever form of the fallback is asked for;
		// only which reference delete runs differs.
		forms := []refFallback{noRefFallback}
		if tc.fallback {
			forms = []refFallback{cliRefFallback, serviceRefFallback}
		}
		for _, form := range forms {
			t.Run(fmt.Sprintf("%s/fallback %d", tc.name, form), func(t *testing.T) {
				ops := tc.ops
				_, err := deleteItem(&ops, deleteOpts{fallback: form, verb: "delete failed"})
				switch {
				case tc.wantErr == "" && err != nil:
					t.Fatalf("got %v, want success", err)
				case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
					t.Fatalf("got %v, want an error containing %q", err, tc.wantErr)
				}
				if tc.wantErr != "" && !strings.Contains(err.Error(), "delete failed, OSStatus=") {
					t.Errorf("error %q lost the original status", err)
				}
				wantCLI, wantAsIs := tc.wantRefs, 0
				if form == serviceRefFallback {
					wantCLI, wantAsIs = 0, tc.wantRefs
				}
				if ops.refs != wantCLI || ops.refsAsIs != wantAsIs || ops.pres != tc.wantPres {
					t.Errorf("reference deletes %d with the switch, %d without; presence checks %d; want %d, %d, %d",
						ops.refs, ops.refsAsIs, ops.pres, wantCLI, wantAsIs, tc.wantPres)
				}
			})
		}
	}
}

// The check after a reference delete looks where the reference delete
// deleted, the default keychain, and nowhere else: an item of the same name
// in another keychain on the search list is not the one that was deleted,
// and must not turn a delete that worked into "still there".
func TestDeleteChecksOnlyTheDefaultKeychain(t *testing.T) {
	ops := fakeOps{del: errSecInvalidOwnerEdit, ref: errSecSuccess, after: MEKAbsent, anywhere: MEKPresent}
	if _, err := deleteItem(&ops, deleteOpts{fallback: cliRefFallback, verb: "delete failed"}); err != nil {
		t.Fatalf("an item in another keychain failed the delete: %v", err)
	}
	if ops.anyPres != 0 || ops.pres != 1 {
		t.Errorf("presence over every keychain %d times, over the default one %d; want 0 and 1", ops.anyPres, ops.pres)
	}
}

// setMEK over a reference delete whose result can't be confirmed: the old
// item is most likely gone, so the add goes ahead, and the add is what
// finds out. It used to abort with the old key already deleted and no new
// one written.
func TestSetMEKOverAnUnconfirmedDelete(t *testing.T) {
	mek := bytes.Repeat([]byte{1}, 32)
	ops := fakeOps{del: errSecInvalidOwnerEdit, ref: errSecSuccess, after: MEKIndeterminate}
	if err := setMEKWith(&ops, mek); err != nil {
		t.Fatalf("an unconfirmed delete stopped the replace: %v", err)
	}
	if ops.adds != 1 {
		t.Fatalf("adds = %d, want 1", ops.adds)
	}
	// The item really was still there: the add fails on a duplicate, and
	// the error says both halves.
	ops = fakeOps{del: errSecInvalidOwnerEdit, ref: errSecSuccess, after: MEKIndeterminate,
		addErr: errors.New("storing key in keychain failed, OSStatus=-25299")}
	err := setMEKWith(&ops, mek)
	if err == nil || !strings.Contains(err.Error(), "couldn't confirm it was gone") || !strings.Contains(err.Error(), "-25299") {
		t.Fatalf("got %v, want the unconfirmed delete and the duplicate named", err)
	}
	// A confirmed-present item never reaches the add.
	ops = fakeOps{del: errSecInvalidOwnerEdit, ref: errSecSuccess, after: MEKPresent}
	if err := setMEKWith(&ops, mek); err == nil || ops.adds != 0 {
		t.Fatalf("err %v, adds %d: want a refusal before any add", err, ops.adds)
	}
}

// The service deletes grant and job keys (revoke, expiry, the unused-key
// cleanup, a move). A key another jit made at another path answers
// SecItemDelete with errSecInvalidOwnerEdit (S3g), and the delete must get
// past it, or a revoked grant's key stays and the cleanup fails on it at
// every start. But never through the CLI's reference delete, which switches
// keychain UI off for the whole process: through the service's form, which
// leaves the switch alone.
func TestGrantKeyDeleteFallsBackWithoutTheProcessSwitch(t *testing.T) {
	var got *fakeOps
	orig := newItemOps
	t.Cleanup(func() { newItemOps = orig })
	for _, tc := range []struct {
		name    string
		ref     int32
		after   MEKPresence
		wantErr string
	}{
		{"deleted through its reference", errSecSuccess, MEKAbsent, ""},
		{"the reference delete fails", errSecInteractionNotAllowed, MEKPresent, "OSStatus=-25244 (deleting it through its reference: OSStatus=-25308)"},
		{"the item stays", errSecSuccess, MEKPresent, "still there"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			newItemOps = func(*Wrapper) itemOps {
				got = &fakeOps{del: errSecInvalidOwnerEdit, ref: tc.ref, after: tc.after, anywhere: MEKPresent}
				return got
			}
			err := GrantKeys{service: "com.jitpass.grant.key.TEST-ONLY"}.Delete("g-1")
			if got == nil {
				t.Fatal("the delete did not go through newItemOps")
			}
			if got.refs != 0 {
				t.Fatalf("the grant key delete called the CLI reference delete %d times; it switches keychain UI off process-wide", got.refs)
			}
			if got.refsAsIs != 1 {
				t.Fatalf("the grant key delete called the service's reference delete %d times, want 1", got.refsAsIs)
			}
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("got %v, want the key deleted", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("got %v, want %q", err, tc.wantErr)
			}
		})
	}
}

// kwWithoutUI, which the fallback's lookup and deletes and the quiet read
// run inside: interaction is off inside it (and inside a nested use) and
// back to what it was after, whichever way it started. Nothing here touches
// a keychain item, so it runs in a plain `go test` with no dialog possible.
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

// Many overlapping kwWithoutUI scopes: interaction stays off inside every
// one of them for as long as it runs, and the process ends where it started.
// Before the guard each scope saved and restored on its own, so a scope
// that began while another had the switch off saved "off" and put it back
// last, leaving interaction off for good, and one that ended early turned it
// back on under the others. No keychain item is touched.
func TestKeychainUIGuardSurvivesOverlap(t *testing.T) {
	orig := uiAllowed()
	t.Cleanup(func() { setUIAllowed(orig) })
	for _, start := range []bool{true, false} {
		setUIAllowed(start)
		var wg sync.WaitGroup
		var broken atomic.Int32
		for g := 0; g < 32; g++ {
			wg.Add(1)
			go func(g int) {
				defer wg.Done()
				for i := 0; i < 20; i++ {
					if !uiOverlapProbe(50 + (g*37+i*11)%300) {
						broken.Add(1)
					}
				}
			}(g)
		}
		wg.Wait()
		if n := broken.Load(); n > 0 {
			t.Errorf("started %v: interaction came back on inside %d scopes", start, n)
		}
		if got := uiAllowed(); got != start {
			t.Errorf("started %v: left at %v after every scope ended", start, got)
		}
	}
}

// Every query keychain.m builds, walked from its registry (kw_query_count),
// against the traits it must have. A query added to the registry with no
// line here fails, so none can be left out; the ones status, doctor, the
// presence checks, the deletes and the quiet read use must never ask.
func TestEveryQueryIsChecked(t *testing.T) {
	const noUI, loginOnly, data, attrs, refs = 1, 2, 4, 8, 16
	want := map[string]int{
		"presence":                         noUI,
		"presence in the default keychain": noUI | loginOnly,
		"the reference delete's lookup":    noUI | loginOnly | refs,
		"the delete":                       noUI,
		"the quiet read":                   noUI | data,
		// The read behind jit's own Touch ID check may show the login
		// keychain's access dialog (keychain.m, KW_Q_FETCH); nothing that
		// must stay silent uses it.
		"the read behind Touch ID": data,
		"the check before an add":  0,
		"the grant key list":       attrs,
	}
	n := queryCount()
	if n != len(want) {
		t.Errorf("the registry holds %d queries, this test states %d", n, len(want))
	}
	seen := map[string]bool{}
	for i := 0; i < n; i++ {
		name := queryName(i)
		traits, ok := want[name]
		if !ok {
			t.Errorf("query %d (%q) has no stated traits here", i, name)
			continue
		}
		seen[name] = true
		if got := queryTraits(i); got != traits {
			t.Errorf("%s query: traits %05b, want %05b (1 no dialog, 2 login keychain only, 4 data, 8 attributes, 16 refs)", name, got, traits)
		}
	}
	for name := range want {
		if !seen[name] {
			t.Errorf("%q is stated here but not in the registry", name)
		}
	}
}

// No query is built outside the registry: keychain.m calls
// SecItemCopyMatching and SecItemDelete once each, inside kwCopyMatchingIn
// and kwDeleteItemIn, which take a registry number.
func TestEveryQueryGoesThroughTheRegistry(t *testing.T) {
	_, self, _, _ := runtime.Caller(0)
	data, err := os.ReadFile(filepath.Join(filepath.Dir(self), "keychain.m"))
	if err != nil {
		t.Fatal(err)
	}
	var code strings.Builder
	for _, line := range strings.Split(string(data), "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		code.WriteString(line + "\n")
	}
	src := code.String()
	for call, inside := range map[string]string{
		"SecItemCopyMatching(":   "static OSStatus kwCopyMatchingIn(",
		"SecItemDelete(":         "static OSStatus kwDeleteItemIn(",
		"SecKeychainItemDelete(": "static OSStatus kwDeleteRefsIn(",
	} {
		if n := strings.Count(src, call); n != 1 {
			t.Errorf("keychain.m calls %s %d times, want once (through the registry)", call, n)
			continue
		}
		fn := strings.LastIndex(src, inside) // the definition, after any prototype
		at := strings.Index(src, call)
		if fn < 0 || at < fn || strings.Contains(src[fn+len(inside):at], "\nstatic ") {
			t.Errorf("%s is not inside %s", call, inside)
		}
	}
	// The service's delete by reference leaves the process switch alone,
	// and the CLI's switches it off: each passes its own withoutUI.
	for fn, want := range map[string]string{
		"int kw_item_delete_by_ref_no_switch(": "kwDeleteByRefInDefault(service, account, 0)",
		"int kw_item_delete_by_ref(":           "kwDeleteByRefInDefault(service, account, 1)",
	} {
		at := strings.Index(src, fn)
		if at < 0 {
			t.Errorf("keychain.m has no %s", fn)
			continue
		}
		body := src[at:]
		body = body[:strings.Index(body, "\n}\n")]
		if !strings.Contains(body, want) {
			t.Errorf("%s...) does not call %s:\n%s", fn, want, body)
		}
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
	// Beside this test file, not the working directory: scripts/se-test.sh
	// runs the test binary from the repository root.
	_, self, _, _ := runtime.Caller(0)
	f, err := parser.ParseFile(token.NewFileSet(), filepath.Join(filepath.Dir(self), file), nil, 0)
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
