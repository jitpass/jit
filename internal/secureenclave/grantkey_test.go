// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package secureenclave

import (
	"bytes"
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
}
