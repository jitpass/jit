// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package secureenclave

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

// fakeGrantKeys is GrantKeys over in-memory fake enclave keys, one per tag.
func fakeGrantKeys(t *testing.T) (GrantKeys, map[string]*fakeEnclave) {
	t.Helper()
	keys := map[string]*fakeEnclave{}
	return GrantKeys{tagPrefix: "com.jitpass.grant.TEST-ONLY.", newKey: func(tag string) enclave {
		if keys[tag] == nil {
			keys[tag] = newFake(t)
		}
		return keys[tag]
	}}, keys
}

func TestGrantKeySealOpenBindsClass(t *testing.T) {
	g, _ := fakeGrantKeys(t)
	k, err := g.Create("g-1")
	if err != nil {
		t.Fatal(err)
	}
	if k.Wrap() != GrantWrap {
		t.Fatalf("wrap %q", k.Wrap())
	}
	dek := testMEK(t)
	sealed, err := k.Seal(dek, "aws")
	if err != nil {
		t.Fatal(err)
	}
	got, err := k.Open(sealed, "aws")
	if err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("open: %v", err)
	}
	if _, err := k.Open(sealed, "env"); err == nil {
		t.Fatal("opened under the wrong class: the class is not bound")
	}
	if _, err := k.Open(sealed, "aw"); err == nil {
		t.Fatal("opened under a prefix of the class")
	}
	empty, err := k.Seal(dek, "")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := k.Open(empty, ""); err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("empty class round trip: %v", err)
	}
}

func TestGrantKeyCreateRefusesAnExistingKey(t *testing.T) {
	g, _ := fakeGrantKeys(t)
	if _, err := g.Create("g-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Create("g-1"); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("second Create: %v", err)
	}
}

// Revoking deletes the key, and every copy sealed to it stops opening.
func TestGrantKeyDeleteMakesCopiesUnreadable(t *testing.T) {
	g, _ := fakeGrantKeys(t)
	k, _ := g.Create("g-1")
	sealed, _ := k.Seal(testMEK(t), "env")
	if err := g.Delete("g-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Load("g-1"); err == nil {
		t.Fatal("Load found a deleted key")
	}
	if _, err := k.Open(sealed, "env"); err == nil {
		t.Fatal("a copy opened after its key was deleted")
	}
	if err := g.Delete("g-1"); err != nil {
		t.Fatalf("second Delete: %v", err)
	}
}

func TestGrantKeyOpenRefusesDamage(t *testing.T) {
	g, _ := fakeGrantKeys(t)
	k, _ := g.Create("g-1")
	sealed, _ := k.Seal(testMEK(t), "env")
	sealed[len(sealed)-1] ^= 1
	if _, err := k.Open(sealed, "env"); err == nil {
		t.Fatal("a damaged copy opened")
	}
}

func TestGrantKeysTagsNeverProductionInTests(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("NewTestingGrantKeys accepted a production prefix")
		}
	}()
	NewTestingGrantKeys(grantTagPrefix)
}

// On the real enclave: a grant key that never asks, used as a grant uses it.
// Unattended (no dialog), through scripts/se-test.sh.
func TestHardwareGrantKey(t *testing.T) {
	if os.Getenv("JIT_SE_TEST") != "1" {
		t.Skip("real enclave: run scripts/se-test.sh")
	}
	g := NewTestingGrantKeys("com.jitpass.grant.TEST-ONLY." + strings.TrimPrefix(hardwareTag(t), testTag+".") + ".")
	t.Cleanup(func() { _ = g.Delete("g-hw") })
	k, err := g.Create("g-hw")
	if err != nil {
		t.Fatal(err)
	}
	dek := testMEK(t)
	sealed, err := k.Seal(dek, "aws")
	if err != nil {
		t.Fatal(err)
	}
	if ids, err := g.List(); err != nil || len(ids) != 1 || ids[0] != "g-hw" {
		t.Fatalf("List on hardware = %v, %v; want exactly g-hw", ids, err)
	}
	loaded, err := g.Load("g-hw")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := loaded.Open(sealed, "aws"); err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("open after load: %v", err)
	}
	if _, err := loaded.Open(sealed, "env"); err == nil {
		t.Fatal("wrong class opened on hardware")
	}
	if err := g.Delete("g-hw"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := g.Present("g-hw"); ok {
		t.Fatal("key survived Delete")
	}
	if ids, err := g.List(); err != nil || len(ids) != 0 {
		t.Fatalf("List after Delete = %v, %v; want none", ids, err)
	}
}

// Open tells a copy that doesn't open under the key (ErrWrongKey: the
// class, a damaged frame; the hardware's -50 is pinned in
// TestHardwareKeyNeverAsking) from a key that can't be used right now
// (the enclave's own ErrLocked or ErrUnavailable), which says nothing about
// the copy and must not be taken for it.
func TestGrantKeyOpenTellsAWrongKeyFromAnUnusableOne(t *testing.T) {
	g, keys := fakeGrantKeys(t)
	k, err := g.Create("g-1")
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := k.Seal(testMEK(t), "aws")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.Open(sealed, "mcp"); !errors.Is(err, ErrWrongKey) {
		t.Errorf("another class: %v, want ErrWrongKey", err)
	}
	fake := keys["com.jitpass.grant.TEST-ONLY.g-1"]
	short, err := fake.seal([]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.Open(short, "aws"); !errors.Is(err, ErrWrongKey) {
		t.Errorf("a damaged frame: %v, want ErrWrongKey", err)
	}
	for _, cause := range []error{ErrLocked, ErrUnavailable} {
		fake.openErr = cause
		_, err := k.Open(sealed, "aws")
		if !errors.Is(err, cause) || errors.Is(err, ErrWrongKey) || !NotNow(err) {
			t.Errorf("the enclave answering %v: Open = %v, want it, NotNow, and not ErrWrongKey", cause, err)
		}
	}
}

// Only the decryption's errSecParam is a wrong key: the same -50 from
// finding the key (se_open's lookup) is about the query, and any other
// status is the bridge's own error. Measured on hardware: a copy cut short
// is the decryption's -50; a damaged ephemeral key is CryptoTokenKit's -3
// (TestHardwareDamagedGrantCopiesAreAnswers).
func TestOpenFailureTellsTheStepApart(t *testing.T) {
	bridge := errors.New("the bridge's sentence")
	for _, tc := range []struct {
		name       string
		status     int
		decrypting bool
		wrong      bool
	}{
		{"the decryption's -50", statusParam, true, true},
		{"the lookup's -50", statusParam, false, false},
		{"CryptoTokenKit's -3", -3, true, false},
		{"a lookup that failed", -25291, false, false},
	} {
		err := openFailure(tc.status, tc.decrypting, bridge)
		if errors.Is(err, ErrWrongKey) != tc.wrong || !errors.Is(err, bridge) {
			t.Errorf("%s: %v; ErrWrongKey should be %v, the bridge's error kept", tc.name, err, tc.wrong)
		}
	}
}

// NotNow is the enclave's "can't be used right now", and nothing else: a
// lock and an unentitled jit. Every other failure is an answer, which a
// never-ask job stops on (the default the caller must not invert).
func TestNotNowIsOnlyALockOrAnUnentitledJit(t *testing.T) {
	for err, want := range map[error]bool{
		ErrLocked:                              true,
		ErrUnavailable:                         true,
		fmt.Errorf("grant key: %w", ErrLocked): true,
		classify(statusInteractionNotAllowed, "x"):      true,
		classify(statusMissingEntitlement, "x"):         true,
		ErrWrongKey:                                     false,
		ErrNoKey:                                        false,
		ErrNoGrantKey:                                   false,
		ErrCanceled:                                     false,
		classify(-3, "CryptoTokenKit error -3"):         false,
		classify(statusParam, "a lookup's -50"):         false,
		classify(-25293, "errSecAuthFailed"):            false,
		errors.New("grant key: sealed copy is damaged"): false,
	} {
		if NotNow(err) != want {
			t.Errorf("NotNow(%v) = %v, want %v", err, !want, want)
		}
	}
}

// The lookup-only store other packages' tests use answers Load from its
// lookup, with Load's own errors: a key it says is absent is ErrNoGrantKey.
func TestLookupOnlyGrantKeysAnswerThroughLoad(t *testing.T) {
	g := NewTestingGrantKeysLookup("com.jitpass.grant.TEST-ONLY.", func(tag string) (bool, error) {
		return tag == "com.jitpass.grant.TEST-ONLY.there", nil
	}, ErrLocked)
	if _, err := g.Load("gone"); !errors.Is(err, ErrNoGrantKey) {
		t.Fatalf("Load of an absent key = %v, want ErrNoGrantKey", err)
	}
	k, err := g.Load("there")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.Open([]byte{1}, "aws"); !errors.Is(err, ErrLocked) {
		t.Fatalf("Open = %v, want the openErr it was given", err)
	}
	defer func() {
		if recover() == nil {
			t.Error("a prefix without TEST-ONLY was accepted")
		}
	}()
	NewTestingGrantKeysLookup(grantTagPrefix, nil, nil)
}

// On the real enclave: a sealed copy damaged in ways other than the
// AES-GCM tag (an ephemeral public key that isn't one, a copy cut short)
// fails with whatever SecKeyCreateDecryptedData answers, and none of those
// answers may read as "can't be used right now" (NotNow): a never-ask job
// stops on them for good, cause named. A key that never asks, TEST-ONLY
// tags, no dialog: `IDENTIFIER=jit scripts/se-test.sh`.
func TestHardwareDamagedGrantCopiesAreAnswers(t *testing.T) {
	if os.Getenv("JIT_SE_TEST") != "1" {
		t.Skip("real enclave: run scripts/se-test.sh")
	}
	g := NewTestingGrantKeys("com.jitpass.grant.TEST-ONLY." + strings.TrimPrefix(hardwareTag(t), testTag+".") + ".")
	t.Cleanup(func() { _ = g.Delete("g-damaged") })
	k, err := g.Create("g-damaged")
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := k.Seal(testMEK(t), "aws")
	if err != nil {
		t.Fatal(err)
	}
	// The ECIES output starts with the ephemeral public key, uncompressed:
	// 0x04, then X and Y (65 bytes for P-256).
	if len(sealed) < 65+16 || sealed[0] != 0x04 {
		t.Fatalf("sealed copy is %d bytes starting %#x; not the ECIES layout this test damages", len(sealed), sealed[0])
	}
	damage := func(f func([]byte) []byte) []byte { return f(append([]byte(nil), sealed...)) }
	for _, tc := range []struct {
		name string
		copy []byte
	}{
		{"the ephemeral key's prefix", damage(func(b []byte) []byte { b[0] = 0x05; return b })},
		{"a coordinate of the ephemeral key", damage(func(b []byte) []byte { b[20] ^= 0x01; return b })},
		{"cut after the ephemeral key", damage(func(b []byte) []byte { return b[:65] })},
		{"cut inside the ephemeral key", damage(func(b []byte) []byte { return b[:30] })},
		{"cut by one byte", damage(func(b []byte) []byte { return b[:len(b)-1] })},
	} {
		_, err := k.Open(tc.copy, "aws")
		t.Logf("%s: %v", tc.name, err)
		if err == nil {
			t.Errorf("%s: opened", tc.name)
			continue
		}
		if NotNow(err) {
			t.Errorf("%s: %v reads as a key that can't be used right now; it is an answer about the copy", tc.name, err)
		}
	}
}
