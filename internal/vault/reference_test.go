// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package vault

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeResolver resolves any op:// reference to a canned value, recording
// what it was asked for.
type fakeResolver struct {
	value []byte
	err   error
	asked []string
}

func (r *fakeResolver) ResolveRef(ref string) ([]byte, error) {
	r.asked = append(r.asked, ref)
	if r.err != nil {
		return nil, r.err
	}
	return bytes.Clone(r.value), nil
}

const testRef = "op://vaultid123/itemid456/fieldid789"

func TestReferenceRoundTripResolvesThroughResolver(t *testing.T) {
	v := newTestVault(t)
	r := &fakeResolver{value: []byte("live-credential")}
	v.RefResolver = r

	if err := v.SetReference("stripe/live", testRef, Meta{Class: ClassOnePassword}); err != nil {
		t.Fatalf("SetReference: %v", err)
	}
	got, err := v.Get("stripe/live")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != "live-credential" {
		t.Errorf("Get = %q, want the resolver's value", got)
	}
	if len(r.asked) != 1 || r.asked[0] != testRef {
		t.Errorf("resolver asked for %v, want exactly [%s]", r.asked, testRef)
	}

	info, err := v.Info("stripe/live")
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if info.Storage != StorageOpRef {
		t.Errorf("Info.Storage = %q, want %q", info.Storage, StorageOpRef)
	}
	if info.Class != ClassOnePassword {
		t.Errorf("Info.Class = %q, want %q", info.Class, ClassOnePassword)
	}
}

func TestReferenceGetWithoutResolverFailsTyped(t *testing.T) {
	v := newTestVault(t)
	if err := v.SetReference("stripe/live", testRef, Meta{}); err != nil {
		t.Fatalf("SetReference: %v", err)
	}
	_, err := v.Get("stripe/live")
	if !errors.Is(err, ErrRefUnresolvable) {
		t.Fatalf("Get without a resolver = %v, want ErrRefUnresolvable", err)
	}
	// The typed failure must not leak the reference URI into the error: an
	// op:// path names the user's 1Password layout and the caller may print
	// this error anywhere.
	if err != nil && strings.Contains(err.Error(), "op://") {
		t.Errorf("error %q leaks the reference URI", err)
	}
}

func TestReferenceResolverErrorSurfaces(t *testing.T) {
	v := newTestVault(t)
	v.RefResolver = &fakeResolver{err: errors.New("1password is locked")}
	if err := v.SetReference("stripe/live", testRef, Meta{}); err != nil {
		t.Fatalf("SetReference: %v", err)
	}
	_, err := v.Get("stripe/live")
	if err == nil || !strings.Contains(err.Error(), "1password is locked") {
		t.Fatalf("Get = %v, want the resolver's error surfaced", err)
	}
}

// TestStorageMarkerIsAADBound is the property the explicit-marker design
// exists for: flipping storage on disk (either direction) must fail
// decryption, never change what Get does.
func TestStorageMarkerIsAADBound(t *testing.T) {
	flip := func(t *testing.T, v *Vault, path, newStorage string) {
		t.Helper()
		file := filepath.Join(v.Root, "vault", path+".enc")
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("reading envelope: %v", err)
		}
		var env envelope
		if err := json.Unmarshal(data, &env); err != nil {
			t.Fatalf("parsing envelope: %v", err)
		}
		env.Storage = newStorage
		edited, err := json.Marshal(env)
		if err != nil {
			t.Fatalf("re-encoding envelope: %v", err)
		}
		if err := os.WriteFile(file, edited, 0o600); err != nil {
			t.Fatalf("writing edited envelope: %v", err)
		}
	}

	t.Run("literal marked as reference", func(t *testing.T) {
		v := newTestVault(t)
		v.RefResolver = &fakeResolver{value: []byte("attacker-controlled")}
		if err := v.Set("db/password", []byte("op://looks/like/a-ref")); err != nil {
			t.Fatalf("Set: %v", err)
		}
		flip(t, v, "db/password", StorageOpRef)
		if _, err := v.Get("db/password"); err == nil {
			t.Fatal("Get succeeded on a literal flipped to reference, want AAD failure")
		}
	})

	t.Run("reference marked as literal", func(t *testing.T) {
		v := newTestVault(t)
		if err := v.SetReference("db/password", testRef, Meta{}); err != nil {
			t.Fatalf("SetReference: %v", err)
		}
		flip(t, v, "db/password", "")
		if _, err := v.Get("db/password"); err == nil {
			t.Fatal("Get succeeded on a reference flipped to literal, want AAD failure")
		}
	})
}

// A literal Set over a linked path replaces the pointer with a value: the
// storage marker must clear, and Get must return the new literal without
// consulting any resolver.
func TestLiteralSetOverReferenceClearsStorage(t *testing.T) {
	v := newTestVault(t)
	r := &fakeResolver{value: []byte("resolved")}
	v.RefResolver = r

	if err := v.SetReference("api/key", testRef, Meta{Class: ClassOnePassword}); err != nil {
		t.Fatalf("SetReference: %v", err)
	}
	if err := v.Set("api/key", []byte("literal-now")); err != nil {
		t.Fatalf("Set over reference: %v", err)
	}

	got, err := v.Get("api/key")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != "literal-now" {
		t.Errorf("Get = %q, want the literal value", got)
	}
	if len(r.asked) != 0 {
		t.Errorf("resolver was consulted %v times for a literal secret", r.asked)
	}
	info, err := v.Info("api/key")
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if info.Storage != "" {
		t.Errorf("Info.Storage = %q after literal Set, want empty", info.Storage)
	}
	// Provenance rotates as always: birth class survives the overwrite.
	if info.Class != ClassOnePassword {
		t.Errorf("Info.Class = %q, want birth class preserved on rotation", info.Class)
	}
}

// TestRekeyCarriesStorage pins that a rekey round-trips the storage
// marker: rewrapFile re-encodes the whole envelope struct, and a dropped
// field here would silently turn a pointer into garbage.
func TestRekeyCarriesStorage(t *testing.T) {
	v := newTestVault(t)
	if err := v.SetReference("linked/secret", testRef, Meta{}); err != nil {
		t.Fatalf("SetReference: %v", err)
	}

	oldKW := v.KeyWrapper
	newKW := newFakeKeyWrapper()
	if _, _, err := v.RewrapAll(oldKW, newKW); err != nil {
		t.Fatalf("RewrapAll: %v", err)
	}

	v.KeyWrapper = newKW
	r := &fakeResolver{value: []byte("still-linked")}
	v.RefResolver = r
	got, err := v.Get("linked/secret")
	if err != nil {
		t.Fatalf("Get after rekey: %v", err)
	}
	if string(got) != "still-linked" {
		t.Errorf("Get after rekey = %q, want the resolver's value", got)
	}
	if len(r.asked) != 1 || r.asked[0] != testRef {
		t.Errorf("resolver asked for %v after rekey, want exactly [%s]", r.asked, testRef)
	}
}

// Export must carry the reference, not a resolved value (an export is a
// vault backup, not a 1Password read), and Import must restore a link AS
// a link.
func TestExportImportRoundTripsReference(t *testing.T) {
	v := newTestVault(t)
	// No resolver on either side: if export or import tried to resolve,
	// it would fail with ErrRefUnresolvable and the test would catch it.
	if err := v.SetReference("linked/secret", testRef, Meta{}); err != nil {
		t.Fatalf("SetReference: %v", err)
	}
	if err := v.Set("plain/secret", []byte("value")); err != nil {
		t.Fatalf("Set: %v", err)
	}

	env, err := v.Export([]byte("passphrase"))
	if err != nil {
		t.Fatalf("Export: %v", err)
	}

	restored := newTestVault(t)
	n, err := restored.Import(env, []byte("passphrase"))
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if n != 2 {
		t.Errorf("Import restored %d secrets, want 2", n)
	}

	info, err := restored.Info("linked/secret")
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if info.Storage != StorageOpRef {
		t.Errorf("restored Info.Storage = %q, want %q — the link froze into a literal", info.Storage, StorageOpRef)
	}
	r := &fakeResolver{value: []byte("resolved-on-new-machine")}
	restored.RefResolver = r
	got, err := restored.Get("linked/secret")
	if err != nil {
		t.Fatalf("Get restored reference: %v", err)
	}
	if string(got) != "resolved-on-new-machine" {
		t.Errorf("Get = %q, want resolution through the restored link", got)
	}
	if len(r.asked) != 1 || r.asked[0] != testRef {
		t.Errorf("resolver asked for %v, want the original reference", r.asked)
	}

	plain, err := restored.Get("plain/secret")
	if err != nil {
		t.Fatalf("Get restored literal: %v", err)
	}
	if string(plain) != "value" {
		t.Errorf("restored literal = %q, want %q", plain, "value")
	}
}

// A version-1 export (bare path→value map, written by every jit before
// the storage marker existed) must import forever.
func TestImportReadsVersionOneExports(t *testing.T) {
	v := newTestVault(t)

	// Hand-build a v1 export exactly as the old Export wrote it.
	values := map[string][]byte{"old/secret": []byte("v1-value")}
	plaintext, err := json.Marshal(values)
	if err != nil {
		t.Fatalf("encoding v1 payload: %v", err)
	}
	salt := bytes.Repeat([]byte{0x01}, argon2SaltSize)
	key := deriveExportKey([]byte("passphrase"), salt)
	sealed, err := seal(key, plaintext, nil)
	if err != nil {
		t.Fatalf("sealing v1 payload: %v", err)
	}
	env := &ExportEnvelope{
		Version: 1,
		Salt:    hex.EncodeToString(salt),
		Payload: hex.EncodeToString(sealed),
	}

	n, err := v.Import(env, []byte("passphrase"))
	if err != nil {
		t.Fatalf("Import of v1 export: %v", err)
	}
	if n != 1 {
		t.Errorf("Import restored %d secrets, want 1", n)
	}
	got, err := v.Get("old/secret")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != "v1-value" {
		t.Errorf("Get = %q, want %q", got, "v1-value")
	}
}
