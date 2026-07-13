// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package cli

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/profile"
	"github.com/jitpass/jit/internal/vault"
)

// fakeKeyWrapper is a deterministic, fixed-key vault.KeyWrapper — lets
// resolveRunPlan be tested without a real Touch ID/passcode approval.
type fakeKeyWrapper struct{ key []byte }

func newFakeKeyWrapper() *fakeKeyWrapper {
	return &fakeKeyWrapper{key: bytes.Repeat([]byte{0x42}, 32)}
}

func (f *fakeKeyWrapper) WrapKey(dek []byte) ([]byte, error) {
	block, err := aes.NewCipher(f.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, dek, nil), nil
}

func (f *fakeKeyWrapper) UnwrapKey(wrapped []byte) ([]byte, error) {
	block, err := aes.NewCipher(f.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce, ciphertext := wrapped[:gcm.NonceSize()], wrapped[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func TestResolveRunPlan(t *testing.T) {
	v := &vault.Vault{Root: t.TempDir(), KeyWrapper: newFakeKeyWrapper(), RecipientID: "test-device"}
	if err := v.Set("stripe/dev-key", []byte("sk_test_fixture")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	p := profile.Profile{"STRIPE_API_KEY": "stripe/dev-key"}

	binary, argv, env, err := resolveRunPlan(v, p, []string{"echo", "hello"})
	if err != nil {
		t.Fatalf("resolveRunPlan: %v", err)
	}
	if !strings.HasSuffix(binary, "/echo") {
		t.Errorf("binary = %q, want it to resolve to an echo executable", binary)
	}
	if len(argv) != 2 || argv[0] != "echo" || argv[1] != "hello" {
		t.Errorf("argv = %v, want [echo hello] (original command name preserved)", argv)
	}

	found := false
	for _, kv := range env {
		if kv == "STRIPE_API_KEY=sk_test_fixture" {
			found = true
		}
	}
	if !found {
		t.Errorf("env missing STRIPE_API_KEY=sk_test_fixture, got: %v", env)
	}
}

func TestResolveRunPlanMissingCommand(t *testing.T) {
	v := &vault.Vault{Root: t.TempDir(), KeyWrapper: newFakeKeyWrapper(), RecipientID: "test-device"}
	p := profile.Profile{}

	if _, _, _, err := resolveRunPlan(v, p, []string{"this-command-does-not-exist-anywhere"}); err == nil {
		t.Fatal("expected an error for a command not found on PATH, got nil")
	}
}

func TestResolveRunPlanMissingSecretFailsLoud(t *testing.T) {
	v := &vault.Vault{Root: t.TempDir(), KeyWrapper: newFakeKeyWrapper(), RecipientID: "test-device"}
	p := profile.Profile{"STRIPE_API_KEY": "stripe/does-not-exist"}

	if _, _, _, err := resolveRunPlan(v, p, []string{"echo"}); err == nil {
		t.Fatal("expected an error for a profile referencing a missing secret, got nil")
	}
}

// resolveProfileName's old unit tests were superseded when it became
// resolveInjectionProfile/resolveSingleProjectProfile (envlayers.go) — the
// explicit-wins / auto-select / none / ambiguous behaviors are all covered
// by envlayers_test.go's TestResolveInjectionProfile* suite.
