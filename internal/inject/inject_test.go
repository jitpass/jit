// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package inject

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/profile"
	"github.com/jitpass/jit/internal/settings"
	"github.com/jitpass/jit/internal/vault"
)

// fakeKeyWrapper is a deterministic, fixed-key vault.KeyWrapper for tests —
// mirrors internal/vault's own test helper, duplicated locally since that
// one is unexported.
type fakeKeyWrapper struct{ key []byte }

func newFakeKeyWrapper() *fakeKeyWrapper {
	return &fakeKeyWrapper{key: bytes.Repeat([]byte{0x42}, 32)}
}

func (f *fakeKeyWrapper) WrapKey(dek []byte) ([]byte, error)       { return seal(f.key, dek) }
func (f *fakeKeyWrapper) UnwrapKey(wrapped []byte) ([]byte, error) { return open(f.key, wrapped) }

func seal(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
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
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func open(key, sealed []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce, ciphertext := sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func TestResolve(t *testing.T) {
	v := &vault.Vault{Root: t.TempDir(), KeyWrapper: newFakeKeyWrapper(), RecipientID: "test-device"}
	if err := v.Set("aws/s3-access-key", []byte("AKIA_FAKE")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := v.Set("aws/s3-secret-key", []byte("secret-value")); err != nil {
		t.Fatalf("Set: %v", err)
	}

	p := profile.Profile{
		"AWS_ACCESS_KEY_ID":     "aws/s3-access-key",
		"AWS_SECRET_ACCESS_KEY": "aws/s3-secret-key",
	}
	values, err := Resolve(v, p)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if values["AWS_ACCESS_KEY_ID"] != "AKIA_FAKE" {
		t.Errorf("AWS_ACCESS_KEY_ID = %q, want %q", values["AWS_ACCESS_KEY_ID"], "AKIA_FAKE")
	}
	if values["AWS_SECRET_ACCESS_KEY"] != "secret-value" {
		t.Errorf("AWS_SECRET_ACCESS_KEY = %q, want %q", values["AWS_SECRET_ACCESS_KEY"], "secret-value")
	}
}

func TestResolveMissingSecretFailsLoud(t *testing.T) {
	v := &vault.Vault{Root: t.TempDir(), KeyWrapper: newFakeKeyWrapper(), RecipientID: "test-device"}
	p := profile.Profile{"AWS_ACCESS_KEY_ID": "aws/does-not-exist"}

	if _, err := Resolve(v, p); err == nil {
		t.Fatal("expected an error resolving a profile entry with no matching vault secret, got nil")
	}
}

func TestMergeEnvOverridesExistingKey(t *testing.T) {
	base := []string{"PATH=/usr/bin", "STRIPE_API_KEY=old-stale-value", "HOME=/home/dev"}
	overrides := map[string]string{"STRIPE_API_KEY": "sk_live_real_value"}

	merged := MergeEnv(base, overrides)

	count := 0
	var gotValue string
	for _, kv := range merged {
		if kv == "STRIPE_API_KEY=old-stale-value" {
			t.Error("stale inherited value survived in the merged env — must be fully replaced, not duplicated")
		}
		if k, v, _ := strings.Cut(kv, "="); k == "STRIPE_API_KEY" {
			count++
			gotValue = v
		}
	}
	if count != 1 {
		t.Fatalf("STRIPE_API_KEY appears %d times in merged env, want exactly 1", count)
	}
	if gotValue != "sk_live_real_value" {
		t.Errorf("STRIPE_API_KEY = %q, want %q", gotValue, "sk_live_real_value")
	}
}

func TestMergeEnvPreservesUnrelatedKeys(t *testing.T) {
	base := []string{"PATH=/usr/bin", "HOME=/home/dev"}
	overrides := map[string]string{"STRIPE_API_KEY": "sk_live_real_value"}

	merged := MergeEnv(base, overrides)
	want := []string{"PATH=/usr/bin", "HOME=/home/dev", "STRIPE_API_KEY=sk_live_real_value"}
	sort.Strings(merged)
	sort.Strings(want)
	if !reflect.DeepEqual(merged, want) {
		t.Errorf("MergeEnv = %v, want %v", merged, want)
	}
}

func TestMergeEnvEmptyBase(t *testing.T) {
	merged := MergeEnv(nil, map[string]string{"A": "1"})
	if len(merged) != 1 || merged[0] != "A=1" {
		t.Errorf("MergeEnv(nil, {A:1}) = %v, want [A=1]", merged)
	}
}

// A setting resolves from the store beside the vault, next to a secret that
// still decrypts, and never reaches the vault at all.
func TestResolveReadsSettingsBesideSecrets(t *testing.T) {
	v := &vault.Vault{Root: t.TempDir(), KeyWrapper: newFakeKeyWrapper(), RecipientID: "test-device"}
	if err := v.Set("billing-sync/CLIENT_SECRET", []byte("fixture-secret")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := settings.New(v.Root).Set("billing-sync/BILLING_URL", []byte("https://billing.example.com")); err != nil {
		t.Fatalf("settings Set: %v", err)
	}
	got, err := Resolve(v, profile.Profile{
		"CLIENT_SECRET": "billing-sync/CLIENT_SECRET",
		"BILLING_URL":   settings.Pointer("billing-sync/BILLING_URL"),
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	want := map[string]string{"CLIENT_SECRET": "fixture-secret", "BILLING_URL": "https://billing.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Resolve = %v, want %v", got, want)
	}
	if ok, _ := v.Exists("billing-sync/BILLING_URL"); ok {
		t.Error("the setting reached the vault")
	}
}

// A missing setting fails as loudly as a missing secret: a program started
// without a variable it expects is worse than one that does not start.
func TestResolveMissingSettingFailsLoud(t *testing.T) {
	v := &vault.Vault{Root: t.TempDir(), KeyWrapper: newFakeKeyWrapper(), RecipientID: "test-device"}
	_, err := Resolve(v, profile.Profile{"BILLING_URL": settings.Pointer("billing-sync/BILLING_URL")})
	if !errors.Is(err, settings.ErrNotFound) {
		t.Errorf("Resolve with a missing setting = %v, want settings.ErrNotFound", err)
	}
}
