// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package keychainwrap

import (
	"bytes"
	"testing"
)

// cleanupTestRekey removes both the primary and the staged TEST-ONLY
// items, before and after — same discipline as cleanupTestMEK, extended
// to the staged account a rekey test creates.
func cleanupTestRekey(t *testing.T, w *Wrapper) {
	t.Helper()
	_ = w.deleteMEK()
	_ = w.DeleteStagedRekeyMEK()
	t.Cleanup(func() {
		_ = w.deleteMEK()
		_ = w.DeleteStagedRekeyMEK()
	})
}

func TestRekeyStagePromoteRoundTrip(t *testing.T) {
	w := testWrapper(noChallenge)
	cleanupTestRekey(t, w)
	if err := w.EnsureMEK(); err != nil {
		t.Fatalf("EnsureMEK: %v", err)
	}

	if err := w.EnsureStagedRekeyMEK(); err != nil {
		t.Fatalf("EnsureStagedRekeyMEK: %v", err)
	}
	// Idempotent: a resume must reuse the same staged key, not mint a third.
	stagedBefore, err := w.StagedRekeyWrapper().fetchMEK("")
	if err != nil {
		t.Fatalf("fetching staged: %v", err)
	}
	if err := w.EnsureStagedRekeyMEK(); err != nil {
		t.Fatalf("EnsureStagedRekeyMEK (second): %v", err)
	}
	stagedAfter, err := w.StagedRekeyWrapper().fetchMEK("")
	if err != nil {
		t.Fatalf("fetching staged again: %v", err)
	}
	if !bytes.Equal(stagedBefore, stagedAfter) {
		t.Fatal("EnsureStagedRekeyMEK replaced an existing staged key, a resumed rekey would lose the key half the vault is wrapped under")
	}

	// Wrap under the staged key, promote, and unwrap under the primary:
	// exactly the hand-off the vault's envelopes experience.
	dek := bytes.Repeat([]byte{0x07}, 32)
	wrapped, err := w.StagedRekeyWrapper().WrapKey(dek)
	if err != nil {
		t.Fatalf("WrapKey under staged: %v", err)
	}
	if err := w.PromoteStagedRekeyMEK(); err != nil {
		t.Fatalf("PromoteStagedRekeyMEK: %v", err)
	}

	fresh := testWrapper(noChallenge) // no cache from before the promote
	got, err := fresh.UnwrapKey(wrapped)
	if err != nil {
		t.Fatalf("UnwrapKey under promoted primary: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Error("promoted primary unwrapped to different bytes")
	}

	// The staged item is gone after promote.
	if fresh.StagedRekeyWrapper().HasMEK() {
		t.Error("staged key still exists after promote")
	}
}

func TestHasMEK(t *testing.T) {
	w := testWrapper(noChallenge)
	cleanupTestRekey(t, w)

	if w.HasMEK() {
		t.Fatal("HasMEK true before EnsureMEK")
	}
	if err := w.EnsureMEK(); err != nil {
		t.Fatalf("EnsureMEK: %v", err)
	}
	if !w.HasMEK() {
		t.Error("HasMEK false after EnsureMEK")
	}
}
