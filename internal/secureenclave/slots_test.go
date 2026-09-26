// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package secureenclave

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// todaysSealedFile is a sealed file byte for byte as every jit before the
// slots wrote it (writeSealed under New's tag): the format the owner's
// vault is in. The slots must read it as slot A, exactly as before.
func todaysSealedFile(blob []byte) []byte {
	return []byte(fmt.Sprintf("{\n  \"version\": 1,\n  \"wrap\": \"se-p256-ecies-v1\",\n  \"kek_tag\": \"com.jitpass.vault.kek\",\n  \"blob\": %q\n}\n", hex.EncodeToString(blob)))
}

// TestTodaysSealedFileReadsAsSlotA uses the PRODUCTION tag names, over
// fakes only: no enclave is reached (the key func hands back in-memory
// fakes and fails the test on any other tag).
func TestTodaysSealedFileReadsAsSlotA(t *testing.T) {
	root := t.TempDir()
	a, b := newFake(t), newFake(t)
	w := newWrapper(root, prodTag, func(tag string) enclave {
		switch tag {
		case "com.jitpass.vault.kek":
			return a
		case "com.jitpass.vault.kek.b":
			return b
		}
		t.Fatalf("built a key for %q", tag)
		return nil
	})
	if err := a.create(); err != nil {
		t.Fatal(err)
	}
	mek := testMEK(t)
	blob, err := a.seal(mek)
	if err != nil {
		t.Fatal(err)
	}
	file := todaysSealedFile(blob)
	if err := os.WriteFile(w.path, file, 0o600); err != nil {
		t.Fatal(err)
	}

	if p := w.Presence(); p != Present {
		t.Fatalf("Presence = %v, want Present", p)
	}
	got, err := w.FetchMEK("r")
	if err != nil || !bytes.Equal(got, mek) {
		t.Fatalf("FetchMEK = %v", err)
	}
	if len(a.opens) != 1 || len(b.opens) != 0 {
		t.Fatalf("opens: slot A %d, slot B %d; want 1 and 0", len(a.opens), len(b.opens))
	}

	// And slot A is still written in exactly those bytes.
	again := filepath.Join(t.TempDir(), SealedFile)
	if err := writeSealed(again, prodTag, blob); err != nil {
		t.Fatal(err)
	}
	if wrote, _ := os.ReadFile(again); !bytes.Equal(wrote, file) {
		t.Fatalf("slot A's file changed format:\n%s\nwant:\n%s", wrote, file)
	}
}

// sealIn writes the sealed file naming tag, sealed by f (making its key).
func sealIn(t *testing.T, w *Wrapper, f *fakeEnclave, tag string, mek []byte) {
	t.Helper()
	if !f.exists {
		if err := f.create(); err != nil {
			t.Fatal(err)
		}
	}
	blob, err := f.seal(mek)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeSealed(w.path, tag, blob); err != nil {
		t.Fatal(err)
	}
}

// What a jit that rotates leaves: the file names slot B, and slot A is
// empty. This jit must open it from slot B.
func TestSlotBFileReadsFromSlotB(t *testing.T) {
	a, b := newFake(t), newFake(t)
	w := fakeWrapper(t.TempDir(), a, b)
	mek := testMEK(t)
	sealIn(t, w, b, testTag+".b", mek)

	got, err := w.FetchMEK("unlock")
	if err != nil || !bytes.Equal(got, mek) {
		t.Fatalf("FetchMEK = %v", err)
	}
	if len(b.opens) != 1 || b.opens[0] != "unlock" || len(a.opens) != 0 {
		t.Fatalf("opens: slot A %q, slot B %q; want only slot B, once", a.opens, b.opens)
	}
}

// Presence checks the slot the file names, never the other.
func TestPresenceFollowsTheFilesSlot(t *testing.T) {
	for _, c := range []struct {
		name         string
		fileSlot     string // "a" or "b"
		keyA, keyB   bool
		wantPresence Presence
	}{
		{"file A, key A", "a", true, false, Present},
		{"file B, key B", "b", false, true, Present},
		{"file B, both keys", "b", true, true, Present},
		{"file A, only key B", "a", false, true, KeyLost},
		// The risk the plan accepts: a file naming an empty slot is a lost
		// key, even with a key in the other slot.
		{"file B, only key A", "b", true, false, KeyLost},
	} {
		t.Run(c.name, func(t *testing.T) {
			a, b := newFake(t), newFake(t)
			w := fakeWrapper(t.TempDir(), a, b)
			f, tag := a, testTag
			if c.fileSlot == "b" {
				f, tag = b, testTag+".b"
			}
			sealIn(t, w, f, tag, testMEK(t))
			for _, s := range []struct {
				f    *fakeEnclave
				want bool
			}{{a, c.keyA}, {b, c.keyB}} {
				if s.want && !s.f.exists {
					if err := s.f.create(); err != nil {
						t.Fatal(err)
					}
				}
				if !s.want {
					_ = s.f.remove()
				}
			}
			if p := w.Presence(); p != c.wantPresence {
				t.Fatalf("Presence = %v, want %v", p, c.wantPresence)
			}
			if len(a.opens)+len(b.opens) != 0 {
				t.Fatal("Presence used a key (would prompt)")
			}
		})
	}
}

// A slot this jit does not know (a later jit's slot C) fails closed, saying
// to update jit: never a lost key, never an open of either slot's key.
func TestUnknownSlotFailsClosed(t *testing.T) {
	for _, keys := range []bool{true, false} {
		t.Run(fmt.Sprintf("keys %v", keys), func(t *testing.T) {
			a, b := newFake(t), newFake(t)
			w := fakeWrapper(t.TempDir(), a, b)
			sealIn(t, w, a, testTag+".c", testMEK(t))
			if keys {
				if err := b.create(); err != nil {
					t.Fatal(err)
				}
			} else {
				_ = a.remove()
			}
			if p := w.Presence(); p != NeedsNewerJit {
				t.Fatalf("Presence = %v, want NeedsNewerJit", p)
			}
			_, err := w.FetchMEK("r")
			if !errors.Is(err, ErrSealedByNewerJit) || err.Error() != "this vault's key was sealed by a newer jit; update jit" {
				t.Fatalf("FetchMEK = %v, want the newer-jit refusal", err)
			}
			if len(a.opens)+len(b.opens) != 0 {
				t.Fatal("a slot's key was opened for a file naming neither")
			}
		})
	}
}

// A version or sealing this jit does not know is a newer jit's too.
func TestNewerFormatIsNeedsNewerJit(t *testing.T) {
	w, _, _ := installed(t)
	data, err := os.ReadFile(w.path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(w.path, bytes.Replace(data, []byte(`"version": 1`), []byte(`"version": 2`), 1), 0o600); err != nil {
		t.Fatal(err)
	}
	if p := w.Presence(); p != NeedsNewerJit {
		t.Fatalf("Presence of a version 2 file = %v, want NeedsNewerJit", p)
	}
	if _, err := w.FetchMEK("r"); err == nil || !strings.HasSuffix(err.Error(), "; update jit") {
		t.Fatalf("FetchMEK = %v", err)
	}
}

// The file is writable by any program running as the user: a tag outside
// the two slots, such as a grant's key that never asks, must not choose the
// key that opens it.
func TestFileNeverChoosesAKeyOutsideTheSlots(t *testing.T) {
	w, f, _ := installed(t)
	k, blob, err := readSealed(w.path)
	if err != nil {
		t.Fatal(err)
	}
	for _, tag := range []string{"com.jitpass.grant.g-1", k.Tag + "x", ""} {
		if err := writeSealed(w.path, tag, blob); err != nil {
			t.Fatal(err)
		}
		if _, err := w.FetchMEK("r"); err == nil || !strings.Contains(err.Error(), "sealed by key") {
			t.Fatalf("tag %q: FetchMEK = %v, want a refusal", tag, err)
		}
		if p := w.Presence(); p != Indeterminate {
			t.Fatalf("tag %q: Presence = %v, want Indeterminate", tag, p)
		}
	}
	if len(f.opens) != 0 {
		t.Fatalf("opened %d times for a tag outside the slots", len(f.opens))
	}
}

// Delete takes both slots' keys, with or without the file: `jit vault
// delete` removes the file first, and a rotation may have left a key in the
// slot the file does not name.
func TestDeleteRemovesBothSlots(t *testing.T) {
	for _, withFile := range []bool{true, false} {
		t.Run(fmt.Sprintf("file %v", withFile), func(t *testing.T) {
			a, b := newFake(t), newFake(t)
			w := fakeWrapper(t.TempDir(), a, b)
			sealIn(t, w, b, testTag+".b", testMEK(t))
			if err := a.create(); err != nil {
				t.Fatal(err)
			}
			if !withFile {
				if err := os.Remove(w.path); err != nil {
					t.Fatal(err)
				}
			}
			if err := w.Delete(); err != nil {
				t.Fatal(err)
			}
			if a.exists || b.exists {
				t.Fatalf("keys left: slot A %v, slot B %v", a.exists, b.exists)
			}
			if _, err := os.Stat(w.path); err == nil {
				t.Fatal("the sealed file survived")
			}
		})
	}
}

// One slot's key failing to go does not keep the other.
func TestDeleteTriesBothSlots(t *testing.T) {
	w, _, _ := installed(t)
	stuck := &stuckEnclave{fakeEnclave: newFake(t)}
	if err := stuck.create(); err != nil {
		t.Fatal(err)
	}
	b := newFake(t)
	if err := b.create(); err != nil {
		t.Fatal(err)
	}
	w.slots[0].enc, w.slots[1].enc = stuck, b
	if err := w.Delete(); err == nil {
		t.Fatal("a key that would not go was not reported")
	}
	if b.exists {
		t.Fatal("slot B's key was kept because slot A's would not go")
	}
}

// A failure both slots share, as a jit outside JitPass.app gets, reaches
// `jit vault delete`'s warning once, not twice.
func TestDeleteSaysASharedFailureOnce(t *testing.T) {
	w, _, _ := installed(t)
	w.slots[0].enc = &stuckEnclave{fakeEnclave: newFake(t)}
	w.slots[1].enc = &stuckEnclave{fakeEnclave: newFake(t)}
	if err := w.Delete(); err == nil || err.Error() != "will not go" {
		t.Fatalf("Delete = %q, want the shared failure once", err)
	}
}

type stuckEnclave struct{ *fakeEnclave }

func (stuckEnclave) remove() error { return errors.New("will not go") }

// The move back to the keychain, from a slot B vault, as the mover does it
// (internal/cli newKeyMoverWith): a fresh Wrapper opens and is closed, the
// sealed file goes, a fresh Wrapper deletes.
func TestMoveBackFromSlotB(t *testing.T) {
	root := t.TempDir()
	m := NewMemoryTesting(root)
	mek := testMEK(t)
	if err := m.SealInSlotB(mek); err != nil {
		t.Fatal(err)
	}
	w := m.Wrapper()
	got, err := w.FetchMEK("move back")
	w.Close()
	if err != nil || !bytes.Equal(got, mek) {
		t.Fatalf("open from slot B: %v", err)
	}
	if err := os.Remove(filepath.Join(root, SealedFile)); err != nil {
		t.Fatal(err)
	}
	if err := m.Wrapper().Delete(); err != nil {
		t.Fatal(err)
	}
	if m.Has("a") || m.Has("b") {
		t.Fatalf("keys left: slot A %v, slot B %v", m.Has("a"), m.Has("b"))
	}
}
