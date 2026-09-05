// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package vault

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// rewriteEnvelope edits one stored envelope in place through fn, the way
// a hostile hand (or an older jit) would touch the file: parsed, changed,
// re-encoded, never re-sealed.
func rewriteEnvelope(t *testing.T, v *Vault, path string, fn func(*envelope)) {
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
	fn(&env)
	edited, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("re-encoding envelope: %v", err)
	}
	if err := os.WriteFile(file, edited, 0o600); err != nil {
		t.Fatalf("writing edited envelope: %v", err)
	}
}

func TestExpiryRoundTripsWithoutDecrypting(t *testing.T) {
	v := newTestVault(t)
	const stamp = int64(1_800_000_000)
	if err := v.SetWithMeta("aws-stage/SESSION_TOKEN", []byte("tok"), Meta{Class: ClassAWS, ExpiresUnix: stamp}); err != nil {
		t.Fatalf("SetWithMeta: %v", err)
	}
	// Info never touches the KeyWrapper: a listing must answer "is this
	// session live" without a prompt.
	info, err := v.Info("aws-stage/SESSION_TOKEN")
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if info.ExpiresUnix != stamp {
		t.Errorf("Info.ExpiresUnix = %d, want %d", info.ExpiresUnix, stamp)
	}
	if info.Version != envelopeVersion {
		t.Errorf("Version = %d, want %d", info.Version, envelopeVersion)
	}
	if got, err := v.Get("aws-stage/SESSION_TOKEN"); err != nil || string(got) != "tok" {
		t.Fatalf("Get = %q, %v; want tok, nil", got, err)
	}
}

// A re-minted session has a new end: unlike provenance, the stamp follows
// the value, so a rotation replaces it and a stampless Set clears it.
func TestExpiryFollowsTheValueNotThePath(t *testing.T) {
	v := newTestVault(t)
	if err := v.SetWithMeta("aws-stage/SESSION_TOKEN", []byte("old"), Meta{Class: ClassAWS, Origin: "/home/u/.clisso.yaml", ExpiresUnix: 100}); err != nil {
		t.Fatalf("first SetWithMeta: %v", err)
	}
	if err := v.SetWithMeta("aws-stage/SESSION_TOKEN", []byte("new"), Meta{Class: ClassAWS, ExpiresUnix: 200}); err != nil {
		t.Fatalf("second SetWithMeta: %v", err)
	}
	info, err := v.Info("aws-stage/SESSION_TOKEN")
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if info.ExpiresUnix != 200 {
		t.Errorf("after rotation ExpiresUnix = %d, want 200 (the new mint's end)", info.ExpiresUnix)
	}
	if info.Origin != "/home/u/.clisso.yaml" {
		t.Errorf("after rotation Origin = %q, want the birth origin preserved", info.Origin)
	}

	if err := v.Set("aws-stage/SESSION_TOKEN", []byte("manual")); err != nil {
		t.Fatalf("bare Set: %v", err)
	}
	info, err = v.Info("aws-stage/SESSION_TOKEN")
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if info.ExpiresUnix != 0 {
		t.Errorf("after a stampless Set ExpiresUnix = %d, want 0 (no known expiry)", info.ExpiresUnix)
	}
	if got, err := v.Get("aws-stage/SESSION_TOKEN"); err != nil || string(got) != "manual" {
		t.Fatalf("Get after bare Set = %q, %v; want manual, nil", got, err)
	}
}

// The stamp is plaintext on disk and must be tamper-EVIDENT: moving it
// forward would resurrect a dead session in every listing, moving it back
// (or clearing it) would hide a live one. Both directions fail decryption.
func TestExpiryIsAADBound(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*envelope)
	}{
		{"pushed into the future", func(e *envelope) { e.ExpiresUnix += 3600 }},
		{"cleared", func(e *envelope) { e.ExpiresUnix = 0 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := newTestVault(t)
			if err := v.SetWithMeta("aws-stage/SESSION_TOKEN", []byte("tok"), Meta{ExpiresUnix: 1_800_000_000}); err != nil {
				t.Fatalf("SetWithMeta: %v", err)
			}
			rewriteEnvelope(t, v, "aws-stage/SESSION_TOKEN", tc.edit)
			if got, err := v.Get("aws-stage/SESSION_TOKEN"); err == nil {
				t.Fatalf("Get = %q on an edited expiry, want AAD failure", got)
			}
		})
	}
}

// A stamp added to an envelope that predates it is exactly as forged as an
// edited one: a v4 file with expires_unix written in must not open. And a
// v4 file left alone reads as "no known expiry", not as expired.
func TestExpiryOnPreStampEnvelope(t *testing.T) {
	v := newTestVault(t)
	if err := v.Set("aws-stage/SESSION_TOKEN", []byte("tok")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	// Downgrade the file to the shape a v4 jit wrote: same AAD minus the
	// expiry, so the payload has to be re-sealed under v4's string.
	file := filepath.Join(v.Root, "vault", "aws-stage/SESSION_TOKEN.enc")
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var env envelope
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatal(err)
	}
	wrappedDEK, err := hex.DecodeString(env.Recipients[v.RecipientID])
	if err != nil {
		t.Fatalf("decoding wrapped DEK: %v", err)
	}
	dek, err := v.KeyWrapper.UnwrapKey(wrappedDEK)
	if err != nil {
		t.Fatalf("unwrapping test DEK: %v", err)
	}
	sealed, err := seal(dek, []byte("tok"), envelopeAAD("aws-stage/SESSION_TOKEN", envelopeVersionStorage, env.CreatedUnix, env.UpdatedUnix, env.Class, env.GroupID, env.Origin, env.Storage, 0))
	if err != nil {
		t.Fatal(err)
	}
	env.Version = envelopeVersionStorage
	env.ExpiresUnix = 0
	env.Payload = hex.EncodeToString(sealed)
	v4, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, v4, 0o600); err != nil {
		t.Fatal(err)
	}

	info, err := v.Info("aws-stage/SESSION_TOKEN")
	if err != nil {
		t.Fatalf("Info on v4: %v", err)
	}
	if info.ExpiresUnix != 0 {
		t.Errorf("v4 Info.ExpiresUnix = %d, want 0 (unknown)", info.ExpiresUnix)
	}
	if got, err := v.Get("aws-stage/SESSION_TOKEN"); err != nil || string(got) != "tok" {
		t.Fatalf("Get on v4 = %q, %v; want tok, nil — older envelopes must read forever", got, err)
	}

	// The v4 AAD has no expiry field, so a stamp written into a v4 file
	// is bound by nothing — it has to be refused at the parse, for every
	// reader, or Info would repeat the forgery while Get opened cleanly.
	rewriteEnvelope(t, v, "aws-stage/SESSION_TOKEN", func(e *envelope) { e.ExpiresUnix = 1_800_000_000 })
	if got, err := v.Get("aws-stage/SESSION_TOKEN"); err == nil {
		t.Fatalf("Get = %q on a v4 file with a stamp written in, want refusal", got)
	}
	if info, err := v.Info("aws-stage/SESSION_TOKEN"); err == nil {
		t.Fatalf("Info = %+v on a v4 file with a stamp written in, want refusal", info)
	}
}

// Rekey re-encodes the whole envelope; a stamp must survive the MEK
// rotation, and so must the AAD that binds it.
func TestRekeyCarriesExpiry(t *testing.T) {
	v := newTestVault(t)
	if err := v.SetWithMeta("aws-stage/SESSION_TOKEN", []byte("tok"), Meta{ExpiresUnix: 1_800_000_000}); err != nil {
		t.Fatalf("SetWithMeta: %v", err)
	}
	oldKW := v.KeyWrapper
	newKW := newFakeKeyWrapper()
	if _, _, err := v.RewrapAll(oldKW, newKW); err != nil {
		t.Fatalf("RewrapAll: %v", err)
	}
	v.KeyWrapper = newKW
	info, err := v.Info("aws-stage/SESSION_TOKEN")
	if err != nil {
		t.Fatalf("Info after rekey: %v", err)
	}
	if info.ExpiresUnix != 1_800_000_000 {
		t.Errorf("ExpiresUnix after rekey = %d, want 1800000000", info.ExpiresUnix)
	}
	if got, err := v.Get("aws-stage/SESSION_TOKEN"); err != nil || string(got) != "tok" {
		t.Fatalf("Get after rekey = %q, %v; want tok, nil", got, err)
	}
}
