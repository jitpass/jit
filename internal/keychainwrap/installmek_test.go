// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package keychainwrap

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func randomMEK(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, mekSize)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// The keychain half of moving a vault's key out of the Secure Enclave: the
// exact bytes land, and read back the same.
func TestInstallMEKStoresExactlyTheseBytes(t *testing.T) {
	w := testWrapper(noChallenge)
	cleanupTestMEK(t, w)
	mek := randomMEK(t)
	if err := w.InstallMEK(mek); err != nil {
		t.Fatal(err)
	}
	got, err := testWrapper(noChallenge).FetchMEK("r")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, mek) {
		t.Fatal("the keychain holds different bytes than were installed")
	}
}

// A resumed move installs again: the same bytes are success.
func TestInstallMEKIsIdempotentForTheSameKey(t *testing.T) {
	w := testWrapper(noChallenge)
	cleanupTestMEK(t, w)
	mek := randomMEK(t)
	if err := w.InstallMEK(mek); err != nil {
		t.Fatal(err)
	}
	if err := w.InstallMEK(mek); err != nil {
		t.Fatalf("installing the same key again: %v", err)
	}
}

// A different key already there is some other vault state's key: refused,
// never overwritten.
func TestInstallMEKRefusesToReplaceADifferentKey(t *testing.T) {
	w := testWrapper(noChallenge)
	cleanupTestMEK(t, w)
	first := randomMEK(t)
	if err := w.InstallMEK(first); err != nil {
		t.Fatal(err)
	}
	if err := w.InstallMEK(randomMEK(t)); err == nil {
		t.Fatal("replaced a different master key")
	}
	got, err := testWrapper(noChallenge).FetchMEK("r")
	if err != nil || !bytes.Equal(got, first) {
		t.Fatalf("the refusal changed the stored key: %v", err)
	}
}

func TestInstallMEKRefusesAWrongSize(t *testing.T) {
	w := testWrapper(noChallenge)
	cleanupTestMEK(t, w)
	if err := w.InstallMEK(make([]byte, 16)); err == nil {
		t.Fatal("installed a 16-byte key")
	}
}

func TestNewTestingRefusesProductionNames(t *testing.T) {
	for _, service := range []string{prodService, "com.jitpass.vault.mek.other"} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("NewTesting(%q) did not refuse", service)
				}
			}()
			NewTesting(service, "a", noChallenge)
		}()
	}
}
