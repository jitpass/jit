// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package secureenclave

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"testing"
)

// These tests use the real enclave. They run only inside a test binary that
// scripts/se-test.sh has wrapped in a bundle and signed with the development
// profile, which sets JIT_SE_TEST=1. Every key they make has a TEST-ONLY tag
// with a random suffix and is deleted before the test ends.

func hardwareTag(t *testing.T) string {
	t.Helper()
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return testTag + "." + hex.EncodeToString(b)
}

func needSignedBundle(t *testing.T) {
	t.Helper()
	if os.Getenv("JIT_SE_TEST") != "1" {
		t.Skip("real enclave: run scripts/se-test.sh (needs the development profile)")
	}
}

// A plain `go test` binary is exactly the "jit outside JitPass.app" case:
// it must be refused, and cleanly.
func TestUnsignedBinaryCannotMakeAKey(t *testing.T) {
	if os.Getenv("JIT_SE_TEST") == "1" {
		t.Skip("this binary is signed; the refusal is tested unsigned")
	}
	h := hardware{tag: hardwareTag(t), group: AccessGroup}
	err := h.create()
	if err == nil {
		_ = h.remove()
		t.Fatal("an unsigned test binary created an enclave key")
	}
	// A developer's Mac answers errSecMissingEntitlement. A CI runner is a VM
	// that may have no enclave at all and answer differently; both refuse.
	if os.Getenv("CI") == "" && !errors.Is(err, ErrUnavailable) {
		t.Fatalf("got %v, want ErrUnavailable", err)
	}
}

func TestHardwareKeyNeverAsking(t *testing.T) {
	needSignedBundle(t)
	for _, afterFirstUnlock := range []bool{false, true} {
		h := hardware{tag: hardwareTag(t), group: AccessGroup, afterFirstUnlock: afterFirstUnlock}
		t.Cleanup(func() { _ = h.remove() })
		if ok, err := h.present(); err != nil || ok {
			t.Fatalf("fresh tag present=%v err=%v", ok, err)
		}
		if err := h.create(); err != nil {
			t.Fatal(err)
		}
		if ok, err := h.present(); err != nil || !ok {
			t.Fatalf("after create present=%v err=%v", ok, err)
		}
		pt := []byte("0123456789abcdef0123456789abcdef")
		ct, err := h.seal(pt)
		if err != nil {
			t.Fatal(err)
		}
		got, err := h.open(ct, "spike reason, never shown")
		if err != nil || !bytes.Equal(got, pt) {
			t.Fatalf("open: %v", err)
		}
		ct[len(ct)-1] ^= 1
		// Measured 2026-09-26: OSStatus -50, "ECIES: Failed to aes-gcm
		// decrypt data". It is what makes a never-ask job's stop sticky, so
		// it must not be mistaken for a key that can't be used right now.
		if _, err := h.open(ct, "x"); !errors.Is(err, ErrWrongKey) {
			t.Fatalf("a tampered blob: %v, want ErrWrongKey", err)
		}
		if err := h.remove(); err != nil {
			t.Fatal(err)
		}
		if ok, _ := h.present(); ok {
			t.Fatal("key survived remove")
		}
		if err := h.remove(); err != nil {
			t.Fatalf("second remove: %v", err)
		}
	}
}

func TestHardwareWrapperLifecycle(t *testing.T) {
	needSignedBundle(t)
	tag := hardwareTag(t)
	h := hardware{tag: tag, group: AccessGroup}
	t.Cleanup(func() { _ = h.remove() })
	w := newWrapper(t.TempDir(), tag, h)
	mek := testMEK(t)
	if err := w.Install(mek); err != nil {
		t.Fatal(err)
	}
	if p := w.Presence(); p != Present {
		t.Fatalf("presence %v", p)
	}
	got, err := w.FetchMEK("x")
	if err != nil || !bytes.Equal(got, mek) {
		t.Fatalf("fetch: %v", err)
	}
	_ = h.remove()
	if p := w.Presence(); p != KeyLost {
		t.Fatalf("presence after the key went: %v, want KeyLost", p)
	}
	w.Close()
	if _, err := w.FetchMEK("x"); !errors.Is(err, ErrNoKey) {
		t.Fatalf("fetch with the key gone: %v, want ErrNoKey", err)
	}
	if err := w.Delete(); err != nil {
		t.Fatal(err)
	}
	if p := w.Presence(); p != Absent {
		t.Fatalf("presence after Delete: %v", p)
	}
}

// The vault key's own shape, with the dialog. Only when a person is at the
// keyboard: JIT_SE_INTERACTIVE=1 scripts/se-test.sh.
func TestHardwarePresenceKeyAsksOncePerWrapper(t *testing.T) {
	needSignedBundle(t)
	if os.Getenv("JIT_SE_INTERACTIVE") != "1" {
		t.Skip("shows a Touch ID dialog: set JIT_SE_INTERACTIVE=1")
	}
	tag := hardwareTag(t)
	h := hardware{tag: tag, group: AccessGroup, presence: true}
	t.Cleanup(func() { _ = h.remove() })
	w := newWrapper(t.TempDir(), tag, h)
	mek := testMEK(t)
	if err := w.Install(mek); err != nil {
		t.Fatal(err)
	}
	got, err := w.FetchMEK("check the Secure Enclave vault key (jit test)")
	if err != nil || !bytes.Equal(got, mek) {
		t.Fatalf("fetch: %v", err)
	}
	if _, err := w.FetchMEK("must not show"); err != nil {
		t.Fatal(err)
	}
}
