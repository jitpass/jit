// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package secureenclave

import (
	"bytes"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/agent"
)

// The agent builds a fetcher per unlock and closes it after copying the MEK
// out (agent/fetcher.go); a Wrapper that stopped satisfying ClosableFetcher
// would leak a MEK per unlock without failing anything else.
var _ agent.ClosableFetcher = (*Wrapper)(nil)

const testTag = "com.jitpass.vault.kek.TEST-ONLY"

func testMEK(t *testing.T) []byte {
	t.Helper()
	mek := make([]byte, mekSize)
	if _, err := rand.Read(mek); err != nil {
		t.Fatal(err)
	}
	return mek
}

func installed(t *testing.T) (*Wrapper, *fakeEnclave, []byte) {
	t.Helper()
	f := newFake(t)
	w := newWrapper(t.TempDir(), testTag, f)
	mek := testMEK(t)
	if err := w.Install(mek); err != nil {
		t.Fatal(err)
	}
	return w, f, mek
}

func TestProductionIdentifiersNeverInTests(t *testing.T) {
	if !strings.Contains(testTag, "TEST-ONLY") || testTag == prodTag {
		t.Fatalf("test tag %q must be TEST-ONLY and not %q", testTag, prodTag)
	}
	if w := New(t.TempDir()); w.tag != prodTag {
		t.Fatalf("New's tag is %q, want the production %q", w.tag, prodTag)
	}
}

func TestInstallThenFetchReturnsTheSameMEK(t *testing.T) {
	w, f, mek := installed(t)
	if len(f.opens) != 0 {
		t.Fatalf("Install opened (prompted) %d times; sealing must never prompt", len(f.opens))
	}
	got, err := w.FetchMEK("unlock for a test")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, mek) {
		t.Fatal("fetched MEK differs from the installed one")
	}
	if len(f.opens) != 1 || f.opens[0] != "unlock for a test" {
		t.Fatalf("opens = %q, want the caller's reason once", f.opens)
	}
}

// One dialog per Wrapper, as with keychainwrap: a profile resolving many
// secrets asks once.
func TestFetchCachesAndHandsOutCopies(t *testing.T) {
	w, f, _ := installed(t)
	a, err := w.FetchMEK("r")
	if err != nil {
		t.Fatal(err)
	}
	b, err := w.FetchMEK("r")
	if err != nil {
		t.Fatal(err)
	}
	if len(f.opens) != 1 {
		t.Fatalf("opened %d times, want 1", len(f.opens))
	}
	wipe(a)
	if bytes.Equal(a, b) {
		t.Fatal("wiping one caller's copy changed another's: copies are shared")
	}
	c, _ := w.FetchMEK("r")
	if !bytes.Equal(b, c) {
		t.Fatal("the cache was damaged by a caller's wipe")
	}
}

func TestCloseWipesAndTheNextFetchOpensAgain(t *testing.T) {
	w, f, _ := installed(t)
	if _, err := w.FetchMEK("r"); err != nil {
		t.Fatal(err)
	}
	cached := w.mek
	w.Close()
	if w.mek != nil || !bytes.Equal(cached, make([]byte, mekSize)) {
		t.Fatal("Close left the MEK in memory")
	}
	w.Close() // idempotent
	if _, err := w.FetchMEK("r"); err != nil {
		t.Fatal(err)
	}
	if len(f.opens) != 2 {
		t.Fatalf("opened %d times, want 2 (Close must bound the key's life)", len(f.opens))
	}
}

func TestRequireUserPresenceAsksNow(t *testing.T) {
	w, f, _ := installed(t)
	if err := w.RequireUserPresence("delete a secret"); err != nil {
		t.Fatal(err)
	}
	if len(f.opens) != 1 || f.opens[0] != "delete a secret" {
		t.Fatalf("opens = %q", f.opens)
	}
}

func TestCanceledDialogFailsAndCachesNothing(t *testing.T) {
	w, f, _ := installed(t)
	f.openErr = classify(statusLAUserCancel, "")
	if _, err := w.FetchMEK("r"); !errors.Is(err, ErrCanceled) {
		t.Fatalf("got %v, want ErrCanceled", err)
	}
	if w.mek != nil {
		t.Fatal("a refused open left a MEK cached")
	}
}

func TestWrapUnwrapBindsClass(t *testing.T) {
	w, _, _ := installed(t)
	dek := testMEK(t)
	wrapped, err := w.WrapKeyLabeled(dek, "stripe/key", "env")
	if err != nil {
		t.Fatal(err)
	}
	got, err := w.UnwrapKeyLabeled(wrapped, "any label", "env")
	if err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("unwrap = %v", err)
	}
	if _, err := w.UnwrapKeyLabeled(wrapped, "", "aws"); err == nil {
		t.Fatal("unwrapped under the wrong class: the class is not bound")
	}
	legacy, err := w.WrapKey(dek)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := w.UnwrapKey(legacy); err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("legacy empty-class round trip: %v", err)
	}
}

func TestInstallRefusesOverAnExistingSealedKey(t *testing.T) {
	w, _, _ := installed(t)
	err := w.Install(testMEK(t))
	if err == nil || !strings.Contains(err.Error(), "rekey") {
		t.Fatalf("second Install: %v, want a refusal naming rekey", err)
	}
}

func TestInstallRefusesAWrongSizedMEK(t *testing.T) {
	w := newWrapper(t.TempDir(), testTag, newFake(t))
	if err := w.Install(make([]byte, 16)); err == nil {
		t.Fatal("installed a 16-byte MEK")
	}
	if _, err := os.Stat(w.path); err == nil {
		t.Fatal("a refused Install wrote a file")
	}
}

// The file is writable by any program running as the user; the tag in it
// must not choose which key opens it.
func TestFetchRefusesAFileSealedUnderAnotherTag(t *testing.T) {
	w, _, _ := installed(t)
	k, blob, err := readSealed(w.path)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeSealed(w.path, k.Tag+".other", blob); err != nil {
		t.Fatal(err)
	}
	if _, err := w.FetchMEK("r"); err == nil || !strings.Contains(err.Error(), "sealed by key") {
		t.Fatalf("got %v, want a tag-mismatch refusal", err)
	}
}

func TestFetchRefusesAWrongSizedSecret(t *testing.T) {
	f := newFake(t)
	w := newWrapper(t.TempDir(), testTag, f)
	if err := f.create(); err != nil {
		t.Fatal(err)
	}
	blob, err := f.seal(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	if err := writeSealed(w.path, testTag, blob); err != nil {
		t.Fatal(err)
	}
	if _, err := w.FetchMEK("r"); err == nil || !strings.Contains(err.Error(), "want 32") {
		t.Fatalf("got %v, want a length refusal", err)
	}
}

func TestFetchWithoutASealedFile(t *testing.T) {
	w := newWrapper(t.TempDir(), testTag, newFake(t))
	if _, err := w.FetchMEK("r"); !errors.Is(err, errNoSealed) {
		t.Fatalf("got %v, want errNoSealed", err)
	}
}

func TestPresence(t *testing.T) {
	t.Run("absent", func(t *testing.T) {
		if p := newWrapper(t.TempDir(), testTag, newFake(t)).Presence(); p != Absent {
			t.Fatalf("got %v", p)
		}
	})
	t.Run("present", func(t *testing.T) {
		w, _, _ := installed(t)
		if p := w.Presence(); p != Present {
			t.Fatalf("got %v", p)
		}
	})
	t.Run("key lost", func(t *testing.T) {
		w, f, _ := installed(t)
		_ = f.remove()
		if p := w.Presence(); p != KeyLost {
			t.Fatalf("got %v", p)
		}
	})
	t.Run("unavailable", func(t *testing.T) {
		w, f, _ := installed(t)
		f.presErr = ErrUnavailable
		if p := w.Presence(); p != Unavailable {
			t.Fatalf("got %v", p)
		}
	})
	t.Run("indeterminate", func(t *testing.T) {
		w, f, _ := installed(t)
		f.presErr = errors.New("something else")
		if p := w.Presence(); p != Indeterminate {
			t.Fatalf("got %v", p)
		}
	})
	t.Run("presence never opens", func(t *testing.T) {
		w, f, _ := installed(t)
		_ = w.Presence()
		if len(f.opens) != 0 {
			t.Fatal("Presence used the key (would prompt)")
		}
	})
}

func TestDeleteRemovesFileThenKeyAndIsIdempotent(t *testing.T) {
	w, f, _ := installed(t)
	if _, err := w.FetchMEK("r"); err != nil {
		t.Fatal(err)
	}
	if err := w.Delete(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(w.path); err == nil {
		t.Fatal("sealed file survived Delete")
	}
	if f.exists {
		t.Fatal("enclave key survived Delete")
	}
	if w.mek != nil {
		t.Fatal("Delete left the MEK cached")
	}
	if err := w.Delete(); err != nil {
		t.Fatalf("second Delete: %v", err)
	}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		status int
		want   error
	}{
		{statusMissingEntitlement, ErrUnavailable},
		{statusItemNotFound, ErrNoKey},
		{statusUserCanceled, ErrCanceled},
		{statusLAUserCancel, ErrCanceled},
		{statusLASystemCancel, ErrCanceled},
		{statusLAAppCancel, ErrCanceled},
		{statusInteractionNotAllowed, ErrLocked},
	}
	for _, c := range cases {
		if err := classify(c.status, "msg"); !errors.Is(err, c.want) {
			t.Errorf("classify(%d) = %v, want %v", c.status, err, c.want)
		}
	}
	if err := classify(-1, "the bridge's sentence"); err == nil || err.Error() != "the bridge's sentence" {
		t.Errorf("an unknown status lost the bridge's message: %v", err)
	}
}

func TestSealedPathIsTheVaultRoot(t *testing.T) {
	root := t.TempDir()
	if w := New(root); w.path != filepath.Join(root, "vault-key.sealed") {
		t.Fatalf("path %q", w.path)
	}
}

// A symlink where the sealed file belongs, dangling or not, says nothing
// about the key: never Absent, which callers treat as "the key is gone".
func TestPresenceOfASymlinkIsIndeterminate(t *testing.T) {
	root := t.TempDir()
	w := newWrapper(root, testTag, newFake(t))
	if err := os.Symlink(filepath.Join(root, "nowhere"), w.path); err != nil {
		t.Fatal(err)
	}
	if p := w.Presence(); p != Indeterminate {
		t.Fatalf("a dangling symlink reads as %v, want Indeterminate", p)
	}
}
