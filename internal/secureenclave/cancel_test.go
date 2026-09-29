// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package secureenclave

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jitpass/jit/internal/authprompt"
)

// cancelFake is the fake enclave with a withdrawable open, as the hardware
// has. block makes the open wait for the withdrawal, like a dialog nobody
// answers.
type cancelFake struct {
	*fakeEnclave
	block    bool
	cancels  int
	withdraw <-chan struct{}
}

func (f *cancelFake) openCancel(ct []byte, reason string, withdraw <-chan struct{}) ([]byte, error) {
	f.cancels++
	f.withdraw = withdraw
	if f.block {
		<-withdraw
		return nil, authprompt.Outcome(ErrCanceled, true)
	}
	return f.open(ct, reason)
}

func cancelFakeWrapper(t *testing.T, block bool) (*Wrapper, *cancelFake) {
	t.Helper()
	f := &cancelFake{fakeEnclave: newFake(t), block: block}
	w := newWrapper(t.TempDir(), "com.jitpass.vault.kek.TEST-ONLY", func(string) enclave { return f })
	if err := w.Install(testMEK(t)); err != nil {
		t.Fatal(err)
	}
	w.Close() // drop the MEK Install cached, so the next fetch opens
	return w, f
}

// FetchMEKCancel opens through the withdrawable open with the caller's
// channel; FetchMEK never does.
func TestFetchMEKCancelOpensWithdrawably(t *testing.T) {
	w, f := cancelFakeWrapper(t, false)
	withdraw := make(chan struct{})
	if _, err := w.FetchMEKCancel("test", withdraw); err != nil {
		t.Fatalf("FetchMEKCancel: %v", err)
	}
	if f.cancels != 1 || f.withdraw != withdraw {
		t.Errorf("withdrawable opens = %d (channel passed through: %v), want 1 with the caller's channel", f.cancels, f.withdraw == withdraw)
	}
	w.Close()
	if _, err := w.FetchMEK("test"); err != nil {
		t.Fatalf("FetchMEK: %v", err)
	}
	if f.cancels != 1 {
		t.Error("FetchMEK used the withdrawable open")
	}
}

// A withdrawn open fails as ErrWithdrawn (still a cancel, for callers that
// ask) and caches nothing.
func TestWithdrawnOpenIsErrWithdrawnAndCachesNothing(t *testing.T) {
	w, f := cancelFakeWrapper(t, true)
	withdraw := make(chan struct{})
	go func() { time.Sleep(20 * time.Millisecond); close(withdraw) }()
	_, err := w.FetchMEKCancel("test", withdraw)
	if !errors.Is(err, authprompt.ErrWithdrawn) || !errors.Is(err, ErrCanceled) {
		t.Fatalf("withdrawn open = %v, want ErrWithdrawn wrapping ErrCanceled", err)
	}
	f.block = false
	before := len(f.opens)
	if _, err := w.FetchMEK("test"); err != nil {
		t.Fatalf("FetchMEK after the withdrawal: %v", err)
	}
	if len(f.opens) != before+1 {
		t.Error("the fetch after a withdrawal did not open again (something was cached)")
	}
}

// Withdrawn before the fetch: no open of either kind runs, so no dialog.
// The failure is still a cancel.
func TestPreWithdrawnFetchNeverOpens(t *testing.T) {
	w, f := cancelFakeWrapper(t, false)
	before := len(f.opens)
	withdraw := make(chan struct{})
	close(withdraw)
	_, err := w.FetchMEKCancel("test", withdraw)
	if !errors.Is(err, authprompt.ErrWithdrawn) || !errors.Is(err, ErrCanceled) {
		t.Fatalf("pre-withdrawn fetch = %v, want ErrWithdrawn and ErrCanceled", err)
	}
	if f.cancels != 0 || len(f.opens) != before {
		t.Errorf("a pre-withdrawn fetch opened (withdrawable %d, plain %d)", f.cancels, len(f.opens)-before)
	}
}

// An enclave without a withdrawable open (the grant key's shape, the plain
// fake) still opens when handed a channel.
func TestNoWithdrawableOpenFallsBack(t *testing.T) {
	f := newFake(t)
	w := newWrapper(t.TempDir(), "com.jitpass.vault.kek.TEST-ONLY", func(string) enclave { return f })
	mek := testMEK(t)
	if err := w.Install(mek); err != nil {
		t.Fatal(err)
	}
	w.Close()
	got, err := w.FetchMEKCancel("test", make(chan struct{}))
	if err != nil || !bytes.Equal(got, mek) {
		t.Fatalf("FetchMEKCancel on a plain enclave: %v", err)
	}
}

// The hardware has the withdrawable open. Without it the service's Deny
// would leave every enclave dialog on screen.
func TestHardwareIsWithdrawable(t *testing.T) {
	var e enclave = hardware{}
	if _, ok := e.(cancelableOpener); !ok {
		t.Fatal("hardware has no withdrawable open")
	}
}

// The real dialog on a TEST-ONLY user-presence key, taken down. Only when a
// person is at the keyboard, and don't touch the sensor:
// JIT_SE_INTERACTIVE=1 scripts/se-test.sh -test.run TestHardwareOpenWithdrawn
func TestHardwareOpenWithdrawn(t *testing.T) {
	needSignedBundle(t)
	if os.Getenv("JIT_SE_INTERACTIVE") != "1" {
		t.Skip("shows a Touch ID dialog: set JIT_SE_INTERACTIVE=1")
	}
	tag := hardwareTag(t)
	w := newWrapper(t.TempDir(), tag, func(tag string) enclave {
		if !strings.Contains(tag, "TEST-ONLY") {
			t.Fatalf("hardware test built key %q", tag)
		}
		return hardware{tag: tag, group: AccessGroup, presence: true}
	})
	t.Cleanup(func() { _ = hardware{tag: tag, group: AccessGroup}.remove() })
	if err := w.Install(testMEK(t)); err != nil {
		t.Fatal(err)
	}
	w.Close()

	// On a key from the keychain, as the vault's is: the open must ask on
	// its own context first, or the dialog cannot be taken down at all
	// (FINDINGS.md, "A key from the keychain").
	direct := 0
	OnUnwithdrawable = func() { direct++ }
	t.Cleanup(func() { OnUnwithdrawable = func() {} })

	withdraw := make(chan struct{})
	start := time.Now()
	go func() { time.Sleep(time.Second); close(withdraw) }()
	_, err := w.FetchMEKCancel("check that jit can take its own prompt down (jit test; don't touch the sensor)", withdraw)
	elapsed := time.Since(start)
	if direct != 0 {
		t.Errorf("the withdrawable open prompted by itself %d time(s): the key's access control was not asked first", direct)
	}
	if !errors.Is(err, authprompt.ErrWithdrawn) {
		t.Fatalf("withdrawn open = %v, want ErrWithdrawn", err)
	}
	if elapsed > 3*time.Second {
		t.Errorf("the withdrawn dialog took %s to go away, want about 1 s", elapsed)
	}
	if errors.Is(err, ErrWrongKey) {
		t.Errorf("a withdrawn open was reported as a wrong key: %v", err)
	}
	t.Logf("withdrawn after %s: %v", elapsed.Round(time.Millisecond), err)

	// A withdrawal that slips in after fetchMEK's check meets a dead
	// context. The spike never measured this path: it must fail at once
	// with no dialog. The status it fails with is logged for the record.
	_, blob, err := readSealed(w.path)
	if err != nil {
		t.Fatal(err)
	}
	h := hardware{tag: tag, group: AccessGroup, presence: true}
	start = time.Now()
	if _, err := h.openOnDeadContext(blob, "must never show (jit test)"); err == nil {
		t.Fatal("an open on an invalidated context succeeded")
	} else {
		if d := time.Since(start); d > 500*time.Millisecond {
			t.Errorf("an open on an invalidated context took %s, want it to fail at once", d)
		}
		t.Logf("dead context: %v", err)
	}
}

// A Wrapper holding a key from an earlier fetch still hands nothing over
// once withdrawn: the Deny wins over the cache as it does over the dialog.
func TestWithdrawnFetchNeverReturnsACachedKey(t *testing.T) {
	w, f := cancelFakeWrapper(t, false)
	if _, err := w.FetchMEK("test"); err != nil {
		t.Fatalf("setup fetch: %v", err)
	}
	opens := len(f.opens)
	defer func() {
		if len(f.opens) != opens || f.cancels != 0 {
			t.Error("the withdrawn fetch opened the sealed key")
		}
	}()
	withdraw := make(chan struct{})
	close(withdraw)
	if k, err := w.FetchMEKCancel("test", withdraw); !errors.Is(err, authprompt.ErrWithdrawn) || k != nil {
		t.Fatalf("withdrawn fetch on a cached key = %v (key returned: %v), want ErrWithdrawn and no key", err, k != nil)
	}
}
