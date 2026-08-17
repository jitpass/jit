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

// fakeKeyWrapper is a deterministic, fixed-key stand-in for a real
// KeyWrapper (internal/keychainwrap in production) — lets vault.go's
// envelope/storage logic be tested without touching the real OS keychain
// or requiring an interactive Touch ID/passcode approval.
type fakeKeyWrapper struct {
	key []byte
}

func newFakeKeyWrapper() *fakeKeyWrapper {
	return &fakeKeyWrapper{key: bytes.Repeat([]byte{0x42}, dekSize)}
}

func (f *fakeKeyWrapper) WrapKey(dek []byte) ([]byte, error)       { return seal(f.key, dek, nil) }
func (f *fakeKeyWrapper) UnwrapKey(wrapped []byte) ([]byte, error) { return open(f.key, wrapped, nil) }

func newTestVault(t *testing.T) *Vault {
	t.Helper()
	return &Vault{
		Root:        t.TempDir(),
		KeyWrapper:  newFakeKeyWrapper(),
		RecipientID: "test-device",
	}
}

func TestVaultSetGetRoundTrip(t *testing.T) {
	v := newTestVault(t)
	want := []byte("sk_test_51Mz...")

	if err := v.Set("stripe/dev-key", want); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := v.Get("stripe/dev-key")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("Get = %q, want %q", got, want)
	}
}

func TestVaultGetNotFound(t *testing.T) {
	v := newTestVault(t)
	if _, err := v.Get("nope/nothing-here"); err != ErrNotFound {
		t.Errorf("Get on missing secret = %v, want ErrNotFound", err)
	}
}

func TestVaultOverwrite(t *testing.T) {
	v := newTestVault(t)
	if err := v.Set("stripe/dev-key", []byte("first")); err != nil {
		t.Fatalf("Set 1: %v", err)
	}
	if err := v.Set("stripe/dev-key", []byte("second")); err != nil {
		t.Fatalf("Set 2: %v", err)
	}
	got, err := v.Get("stripe/dev-key")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != "second" {
		t.Errorf("Get after overwrite = %q, want %q", got, "second")
	}
}

func TestVaultList(t *testing.T) {
	v := newTestVault(t)
	paths := []string{"stripe/dev-key", "stripe/webhook-secret", "aws/s3-access-key"}
	for _, p := range paths {
		if err := v.Set(p, []byte("value")); err != nil {
			t.Fatalf("Set(%q): %v", p, err)
		}
	}

	got, err := v.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	want := []string{"aws/s3-access-key", "stripe/dev-key", "stripe/webhook-secret"}
	if len(got) != len(want) {
		t.Fatalf("List = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("List[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestVaultListEmptyVault(t *testing.T) {
	v := newTestVault(t)
	got, err := v.List()
	if err != nil {
		t.Fatalf("List on a vault that's never had Set called: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("List = %v, want empty", got)
	}
}

func TestVaultRemove(t *testing.T) {
	v := newTestVault(t)
	if err := v.Set("stripe/dev-key", []byte("value")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := v.Remove("stripe/dev-key"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := v.Get("stripe/dev-key"); err != ErrNotFound {
		t.Errorf("Get after Remove = %v, want ErrNotFound", err)
	}
	if err := v.Remove("stripe/dev-key"); err != ErrNotFound {
		t.Errorf("Remove on already-removed secret = %v, want ErrNotFound", err)
	}
}

func TestVaultPathTraversalRejected(t *testing.T) {
	v := newTestVault(t)
	bad := []string{
		"../../etc/passwd",
		"/etc/passwd",
		"a/../../b",
		"",
		"a b",
		"a/../b",
	}
	for _, p := range bad {
		if err := v.Set(p, []byte("x")); err == nil {
			t.Errorf("Set(%q) succeeded, want a rejection", p)
		}
	}

	// Confirm nothing escaped the vault directory.
	outside := filepath.Join(filepath.Dir(v.Root), "passwd")
	if _, err := os.Stat(outside); err == nil {
		t.Errorf("a file was created outside the vault root at %s", outside)
	}
}

func TestVaultTamperedCiphertextRejected(t *testing.T) {
	v := newTestVault(t)
	if err := v.Set("stripe/dev-key", []byte("sk_test_51Mz...")); err != nil {
		t.Fatalf("Set: %v", err)
	}

	path := filepath.Join(v.vaultDir(), "stripe", "dev-key.enc")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading raw envelope: %v", err)
	}
	var env envelope
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	payload, err := hex.DecodeString(env.Payload)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	payload[len(payload)-1] ^= 0xFF // flip a byte in the GCM tag/ciphertext
	env.Payload = hex.EncodeToString(payload)
	tampered, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal tampered envelope: %v", err)
	}
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatalf("writing tampered envelope: %v", err)
	}

	if _, err := v.Get("stripe/dev-key"); err == nil {
		t.Error("Get on a tampered envelope succeeded, want an authentication error")
	}
}

func TestVaultWrongKeyRejected(t *testing.T) {
	root := t.TempDir()
	vA := &Vault{Root: root, KeyWrapper: newFakeKeyWrapper(), RecipientID: "device-a"}
	if err := vA.Set("stripe/dev-key", []byte("secret")); err != nil {
		t.Fatalf("Set: %v", err)
	}

	wrongWrapper := &fakeKeyWrapper{key: bytes.Repeat([]byte{0x99}, dekSize)}
	vB := &Vault{Root: root, KeyWrapper: wrongWrapper, RecipientID: "device-a"}
	if _, err := vB.Get("stripe/dev-key"); err == nil {
		t.Error("Get with the wrong unwrap key succeeded, want an error")
	}
}

// TestVaultDifferentRecipientAndKeyRejected: a genuinely different machine
// (different KeyWrapper key, not just a different recipient label) must
// still fail. This test used to assert the label mismatch ALONE was
// rejected — that behavior turned out to be the bug, not the guarantee: a
// hostname-keyed label drifts with a Mac rename/DHCP name while the key
// material doesn't move an inch, locking a device out of its own vault
// (see EnsureDeviceID and Get's single-recipient fallback). The KeyWrapper
// is, and always was, what actually gates decryption.
func TestVaultDifferentRecipientAndKeyRejected(t *testing.T) {
	root := t.TempDir()
	vA := &Vault{Root: root, KeyWrapper: newFakeKeyWrapper(), RecipientID: "device-a"}
	if err := vA.Set("stripe/dev-key", []byte("secret")); err != nil {
		t.Fatalf("Set: %v", err)
	}

	wrongWrapper := &fakeKeyWrapper{key: bytes.Repeat([]byte{0x99}, dekSize)}
	vB := &Vault{Root: root, KeyWrapper: wrongWrapper, RecipientID: "device-b"}
	if _, err := vB.Get("stripe/dev-key"); err == nil {
		t.Error("Get from a machine with a different key succeeded, want an error, the single-recipient fallback must never bypass the KeyWrapper itself")
	}
}

func TestVaultSetIsAtomicNoLeftoverTempFiles(t *testing.T) {
	v := newTestVault(t)
	if err := v.Set("stripe/dev-key", []byte("value")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(v.vaultDir(), "stripe"))
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "dev-key.enc" {
		t.Errorf("directory contents = %v, want exactly [dev-key.enc]", entries)
	}
}

// fakeLabeledKeyWrapper also implements LabeledKeyWrapper, recording the
// labels Vault passes — pinning that Get/Set hand the secret's own vault
// path to a wrapper that can carry it (the agent-backed one does, for its
// audit history).
type fakeLabeledKeyWrapper struct {
	fakeKeyWrapper
	wrapLabels   []string
	unwrapLabels []string
}

func (f *fakeLabeledKeyWrapper) WrapKeyLabeled(dek []byte, label, class string) ([]byte, error) {
	f.wrapLabels = append(f.wrapLabels, label)
	return f.WrapKey(dek)
}

func (f *fakeLabeledKeyWrapper) UnwrapKeyLabeled(wrapped []byte, label, class string) ([]byte, error) {
	f.unwrapLabels = append(f.unwrapLabels, label)
	return f.UnwrapKey(wrapped)
}

func TestVaultPassesSecretPathAsLabelWhenWrapperSupportsIt(t *testing.T) {
	kw := &fakeLabeledKeyWrapper{fakeKeyWrapper: *newFakeKeyWrapper()}
	v := &Vault{Root: t.TempDir(), KeyWrapper: kw, RecipientID: "test-device"}

	if err := v.Set("stripe/dev-key", []byte("sk_test")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if _, err := v.Get("stripe/dev-key"); err != nil {
		t.Fatalf("Get: %v", err)
	}

	if len(kw.wrapLabels) != 1 || kw.wrapLabels[0] != "stripe/dev-key" {
		t.Errorf("wrap labels = %v, want the secret's own path", kw.wrapLabels)
	}
	if len(kw.unwrapLabels) != 1 || kw.unwrapLabels[0] != "stripe/dev-key" {
		t.Errorf("unwrap labels = %v, want the secret's own path", kw.unwrapLabels)
	}
}

// writeV1Envelope hand-writes a version-1 (AAD-less, metadata-less)
// envelope the way every jit before envelope v2 did — the fixture for
// pinning that old vaults keep decrypting with zero migration.
func writeV1Envelope(t *testing.T, v *Vault, path string, value []byte) {
	t.Helper()
	kw := v.KeyWrapper.(*fakeKeyWrapper)
	dek := bytes.Repeat([]byte{0x07}, dekSize)
	sealedPayload, err := seal(dek, value, nil)
	if err != nil {
		t.Fatalf("sealing v1 payload: %v", err)
	}
	wrapped, err := kw.WrapKey(dek)
	if err != nil {
		t.Fatalf("wrapping v1 DEK: %v", err)
	}
	env := envelope{
		Version:    envelopeVersionAADLess,
		Recipients: map[string]string{v.RecipientID: hex.EncodeToString(wrapped)},
		Payload:    hex.EncodeToString(sealedPayload),
	}
	data, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("encoding v1 envelope: %v", err)
	}
	dest := filepath.Join(v.Root, "vault", path+".enc")
	if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dest, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestVaultReadsV1EnvelopesForever(t *testing.T) {
	v := newTestVault(t)
	writeV1Envelope(t, v, "legacy/old-key", []byte("pre-v2 value"))

	got, err := v.Get("legacy/old-key")
	if err != nil {
		t.Fatalf("Get on a v1 envelope: %v", err)
	}
	if string(got) != "pre-v2 value" {
		t.Errorf("Get = %q, want %q", got, "pre-v2 value")
	}
}

func TestVaultRejectsNewerEnvelopeVersion(t *testing.T) {
	v := newTestVault(t)
	if err := v.Set("stripe/dev-key", []byte("sk_test")); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// Bump the stored version past what this jit understands.
	p := filepath.Join(v.Root, "vault", "stripe/dev-key.enc")
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var env envelope
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatal(err)
	}
	env.Version = envelopeVersion + 1
	data, err = json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}

	_, err = v.Get("stripe/dev-key")
	if err == nil {
		t.Fatal("Get on a newer-versioned envelope succeeded, want a version error")
	}
	if !strings.Contains(err.Error(), "upgrade jit") {
		t.Errorf("error %q should say the fix (upgrade jit), not read as corruption", err)
	}
}

func TestVaultSwappedEnvelopeFilesFailClosed(t *testing.T) {
	v := newTestVault(t)
	if err := v.Set("stripe/dev-key", []byte("sk_test")); err != nil {
		t.Fatalf("Set dev: %v", err)
	}
	if err := v.Set("stripe/live-key", []byte("sk_live")); err != nil {
		t.Fatalf("Set live: %v", err)
	}

	// Copy live's envelope over dev's — the swap that used to decrypt
	// cleanly and hand the live key to whatever asked for the dev one.
	dir := filepath.Join(v.Root, "vault", "stripe")
	liveData, err := os.ReadFile(filepath.Join(dir, "live-key.enc"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "dev-key.enc"), liveData, 0o600); err != nil {
		t.Fatal(err)
	}

	if got, err := v.Get("stripe/dev-key"); err == nil {
		t.Fatalf("Get on a swapped envelope = %q, want AAD failure", got)
	}
	// The un-swapped secret is untouched.
	if got, err := v.Get("stripe/live-key"); err != nil || string(got) != "sk_live" {
		t.Fatalf("Get live after swap = %q, %v; want sk_live, nil", got, err)
	}
}

func TestVaultTamperedTimestampFailsClosed(t *testing.T) {
	v := newTestVault(t)
	if err := v.Set("stripe/dev-key", []byte("sk_test")); err != nil {
		t.Fatalf("Set: %v", err)
	}

	p := filepath.Join(v.Root, "vault", "stripe/dev-key.enc")
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var env envelope
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatal(err)
	}
	env.UpdatedUnix++ // "freshen" a stale credential by one second
	data, err = json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}

	if got, err := v.Get("stripe/dev-key"); err == nil {
		t.Fatalf("Get with a tampered timestamp = %q, want AAD failure", got)
	}
}

func TestVaultOverwritePreservesCreatedUnix(t *testing.T) {
	v := newTestVault(t)
	if err := v.Set("stripe/dev-key", []byte("first")); err != nil {
		t.Fatalf("Set 1: %v", err)
	}
	first, err := v.Info("stripe/dev-key")
	if err != nil {
		t.Fatalf("Info 1: %v", err)
	}
	if first.CreatedUnix == 0 || first.UpdatedUnix == 0 {
		t.Fatalf("fresh secret Info = %+v, want nonzero timestamps", first)
	}

	// Backdate created on disk (re-sealing so the AAD still matches) to
	// prove the overwrite below reads and preserves it rather than
	// coincidentally writing the same "now."
	backdated := first.CreatedUnix - 3600
	if err := rewriteEnvelopeTimestamps(v, "stripe/dev-key", []byte("first"), backdated, first.UpdatedUnix); err != nil {
		t.Fatal(err)
	}

	if err := v.Set("stripe/dev-key", []byte("second")); err != nil {
		t.Fatalf("Set 2: %v", err)
	}
	second, err := v.Info("stripe/dev-key")
	if err != nil {
		t.Fatalf("Info 2: %v", err)
	}
	if second.CreatedUnix != backdated {
		t.Errorf("CreatedUnix after overwrite = %d, want the original %d", second.CreatedUnix, backdated)
	}
	if second.UpdatedUnix < first.UpdatedUnix {
		t.Errorf("UpdatedUnix after overwrite = %d, want >= %d", second.UpdatedUnix, first.UpdatedUnix)
	}
	if got, _ := v.Get("stripe/dev-key"); string(got) != "second" {
		t.Errorf("Get after overwrite = %q, want %q", got, "second")
	}
}

// rewriteEnvelopeTimestamps re-seals value at path with the given
// timestamps — test-only plumbing for constructing envelopes whose
// metadata differs from wall-clock now while keeping the AAD valid.
func rewriteEnvelopeTimestamps(v *Vault, path string, value []byte, createdUnix, updatedUnix int64) error {
	kw := v.KeyWrapper.(*fakeKeyWrapper)
	dek := bytes.Repeat([]byte{0x0a}, dekSize)
	sealedPayload, err := seal(dek, value, envelopeAAD(path, envelopeVersion, createdUnix, updatedUnix, "", "", "", ""))
	if err != nil {
		return err
	}
	wrapped, err := kw.WrapKey(dek)
	if err != nil {
		return err
	}
	env := envelope{
		Version:     envelopeVersion,
		CreatedUnix: createdUnix,
		UpdatedUnix: updatedUnix,
		Recipients:  map[string]string{v.RecipientID: hex.EncodeToString(wrapped)},
		Payload:     hex.EncodeToString(sealedPayload),
	}
	data, err := json.Marshal(env)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(v.Root, "vault", path+".enc"), data, 0o600)
}

// failingWrapKW fails WrapKey the way Vault.Set sees a canceled Touch
// ID/passcode prompt, while unwrap still works (reads keep succeeding).
type failingWrapKW struct{ inner KeyWrapper }

func (f *failingWrapKW) WrapKey([]byte) ([]byte, error) {
	return nil, errors.New("user canceled authentication")
}
func (f *failingWrapKW) UnwrapKey(w []byte) ([]byte, error) { return f.inner.UnwrapKey(w) }

// TestFailedSetLeavesHistoryUntouched pins a confirmed bug: Set archived
// the outgoing envelope BEFORE wrapKey (where a prompt can be canceled),
// so a failed Set still mutated history — it added a duplicate of the
// live value and, at HistoryKeep capacity, pruned the oldest REAL
// version to make room. A failed Set must change nothing.
func TestFailedSetLeavesHistoryUntouched(t *testing.T) {
	v := newTestVault(t)
	for _, val := range []string{"v0", "v1", "v2", "v3", "v4", "v5"} {
		if err := v.Set("p/key", []byte(val)); err != nil {
			t.Fatal(err)
		}
	}
	before, err := v.HistoryVersions("p/key")
	if err != nil {
		t.Fatal(err)
	}

	good := v.KeyWrapper
	v.KeyWrapper = &failingWrapKW{inner: good}
	if err := v.Set("p/key", []byte("never-stored")); err == nil {
		t.Fatal("expected the canceled-auth Set to fail")
	}
	v.KeyWrapper = good

	after, err := v.HistoryVersions("p/key")
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) || after[len(after)-1].ArchiveStamp != before[len(before)-1].ArchiveStamp {
		t.Errorf("failed Set mutated history: before=%v after=%v", before, after)
	}
	if got, _ := v.Get("p/key"); string(got) != "v5" {
		t.Errorf("live value after failed Set = %q, want untouched %q", got, "v5")
	}
}

// TestDotSegmentPathRejected: "." segments are collapsed by filepath.Join,
// so "a/./b" used to store its file at a/b.enc while sealing the AAD to
// "a/./b" — List then showed a/b and Get(a/b) failed with the
// corrupted/tampered message on a perfectly healthy vault.
func TestDotSegmentPathRejected(t *testing.T) {
	v := newTestVault(t)
	for _, p := range []string{"a/./b", "./a", "a/."} {
		if err := v.Set(p, []byte("x")); err == nil {
			t.Errorf("Set(%q) succeeded, want a rejection", p)
		}
	}
}

// TestCaseVariantPathRefusedClearly: on the default (case-insensitive)
// macOS filesystem, a case-variant path opened the stored file and failed
// its AAD check as if tampered with; on a case-sensitive one it reported
// not-found beside a listing showing a near-identical name. Both now get
// the same honest refusal naming the stored spelling — and the exact
// spelling keeps working.
func TestCaseVariantPathRefusedClearly(t *testing.T) {
	v := newTestVault(t)
	if err := v.Set("stripe/Dev-Key", []byte("value")); err != nil {
		t.Fatal(err)
	}

	_, err := v.Get("stripe/dev-key")
	if err == nil {
		t.Fatal("Get with a case-variant path succeeded, want a clear refusal")
	}
	if !strings.Contains(err.Error(), "letter case") || !strings.Contains(err.Error(), "stripe/Dev-Key") {
		t.Errorf("error should name the stored spelling, got: %v", err)
	}
	if strings.Contains(err.Error(), "tampered") {
		t.Errorf("a case variant must never read as tampering, got: %v", err)
	}

	if err := v.Set("Stripe/other", []byte("x")); err == nil {
		t.Error("Set with a case-variant directory segment succeeded, want a refusal")
	}

	if got, err := v.Get("stripe/Dev-Key"); err != nil || string(got) != "value" {
		t.Errorf("exact spelling must keep working, got %q, %v", got, err)
	}
}

// TestHistoryPrefixReserved: _history/ is the version-history tree; a
// user secret planted there would read as an archived version of the
// path it names, and Restore would rename it over the real secret.
// EqualFold matters: on the default case-insensitive macOS filesystem,
// "_History" is the same directory. _backups/ stays writable — jit
// migrate stores its file backups through Set under that prefix.
func TestHistoryPrefixReserved(t *testing.T) {
	v := newTestVault(t)
	for _, p := range []string{"_history/stripe/dev-key/123", "_History/x", "_history"} {
		if err := v.Set(p, []byte("x")); err == nil {
			t.Errorf("Set(%q) succeeded, want the reserved-prefix rejection", p)
		}
	}
	if err := v.Set("_backups/some/file", []byte("x")); err != nil {
		t.Errorf("Set(_backups/...) must stay allowed for jit migrate, got: %v", err)
	}
}

// countingUnwrapKW counts UnwrapKey calls — each one is where a real
// KeyWrapper would fire a Touch ID/passcode prompt.
type countingUnwrapKW struct {
	inner   KeyWrapper
	unwraps int
}

func (c *countingUnwrapKW) WrapKey(d []byte) ([]byte, error) { return c.inner.WrapKey(d) }
func (c *countingUnwrapKW) UnwrapKey(w []byte) ([]byte, error) {
	c.unwraps++
	return c.inner.UnwrapKey(w)
}

// TestCorruptPayloadFailsBeforeUnwrap: Get used to decode the payload hex
// AFTER unwrapKey, so a corrupt envelope cost the user an authentication
// prompt that could only ever turn into an error. Every fallible decode
// must run before the KeyWrapper is touched.
func TestCorruptPayloadFailsBeforeUnwrap(t *testing.T) {
	v := newTestVault(t)
	if err := v.Set("stripe/dev-key", []byte("value")); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(v.vaultDir(), "stripe", "dev-key.enc")
	data, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	var env envelope
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatal(err)
	}
	env.Payload = "not-hex!"
	corrupted, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dest, corrupted, 0o600); err != nil {
		t.Fatal(err)
	}

	counter := &countingUnwrapKW{inner: v.KeyWrapper}
	v.KeyWrapper = counter
	_, err = v.Get("stripe/dev-key")
	if err == nil {
		t.Fatal("Get on a corrupt payload succeeded, want an error")
	}
	if !strings.Contains(err.Error(), "invalid payload encoding") {
		t.Errorf("want the corrupt-payload error, got: %v", err)
	}
	if counter.unwraps != 0 {
		t.Errorf("Get called UnwrapKey %d time(s) on a corrupt envelope — that's a wasted auth prompt on real hardware", counter.unwraps)
	}
}

// writeRawEnc writes literal bytes to a secret's .enc path, bypassing Set's
// encryption entirely — for testing Verify against envelopes it must reject.
func writeRawEnc(t *testing.T, v *Vault, path, content string) {
	t.Helper()
	dest := filepath.Join(v.Root, "vault", path+".enc")
	if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dest, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestVaultVerify(t *testing.T) {
	v := newTestVault(t)
	if err := v.Set("stripe/dev-key", []byte("sk_test_value")); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// A healthy secret verifies clean — without ever touching the KeyWrapper.
	counter := &countingUnwrapKW{inner: v.KeyWrapper}
	v.KeyWrapper = counter
	if err := v.Verify("stripe/dev-key"); err != nil {
		t.Errorf("Verify on a healthy secret: %v", err)
	}
	if counter.unwraps != 0 {
		t.Errorf("Verify unwrapped a key %d time(s) — it must never touch the KeyWrapper", counter.unwraps)
	}

	// v.RecipientID is "test-device". The single-recipient "test" cases rely
	// on wrappedDEKFor's single-recipient fallback (Get's own behavior) to
	// still select that lone key despite the id mismatch.
	cases := []struct {
		name    string
		content string
		wantErr string
	}{
		{"malformed json", "{not json", "parsing envelope"},
		{"future version", `{"version":999,"recipients":{"test":"00"},"payload":"00"}`, "newer than this jit understands"},
		{"no recipients", `{"version":2,"recipients":{},"payload":"00"}`, "no recipients"},
		{"unreadable wrapped key", `{"version":2,"recipients":{"test":"zz"},"payload":"00"}`, "unreadable wrapped key"},
		{"empty payload", `{"version":2,"recipients":{"test":"00"},"payload":""}`, "empty payload"},
		{"unreadable payload", `{"version":2,"recipients":{"test":"00"},"payload":"zz"}`, "unreadable payload"},
		// Multi-recipient, none of them this device: Verify must report it
		// as not-for-this-device exactly like Get, not as corrupt.
		{"not for this device", `{"version":2,"recipients":{"laptop-a":"00","laptop-b":"01"},"payload":"00"}`, "no key for this device"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			writeRawEnc(t, v, "broken/secret", tc.content)
			err := v.Verify("broken/secret")
			if err == nil {
				t.Fatalf("Verify accepted a %s envelope, want an error", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("Verify error = %q, want it to contain %q", err, tc.wantErr)
			}
		})
	}

	// A multi-recipient envelope where THIS device's key is valid but a
	// co-recipient's is garbage must verify clean — Verify only checks the
	// key Get would actually open, mirroring Get. Before the shared selector
	// this was a false [corrupt] report.
	t.Run("co-recipient garbage is irrelevant", func(t *testing.T) {
		writeRawEnc(t, v, "shared/secret", `{"version":2,"recipients":{"test-device":"00","laptop-b":"zz"},"payload":"00"}`)
		if err := v.Verify("shared/secret"); err != nil {
			t.Errorf("Verify on an envelope this device CAN open: %v", err)
		}
	})

	if err := v.Verify("does/not-exist"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Verify on a missing secret = %v, want ErrNotFound", err)
	}
}

func TestWrappedDEKReadsWithoutDecrypting(t *testing.T) {
	v := newTestVault(t)
	if err := v.SetWithMeta("jamf/api-pass", []byte("hunter2"), Meta{Class: ClassMCP}); err != nil {
		t.Fatalf("SetWithMeta: %v", err)
	}

	wrapped, class, err := v.WrappedDEK("jamf/api-pass")
	if err != nil {
		t.Fatalf("WrappedDEK: %v", err)
	}
	if class != ClassMCP {
		t.Errorf("class = %q, want %q", class, ClassMCP)
	}
	// The bytes must be exactly what Get would unwrap: the DEK inside must
	// open under the same wrapper the vault wrote with.
	dek, err := v.KeyWrapper.UnwrapKey(wrapped)
	if err != nil {
		t.Fatalf("returned wrapped DEK does not unwrap: %v", err)
	}
	if len(dek) != dekSize {
		t.Errorf("unwrapped DEK is %d bytes, want %d", len(dek), dekSize)
	}

	if _, _, err := v.WrappedDEK("nope/missing"); err != ErrNotFound {
		t.Errorf("WrappedDEK on missing secret = %v, want ErrNotFound", err)
	}
}

// UnboundPaths is how a user finds out they are carrying pre-v0.57.0
// envelopes at all: nothing else reports it, and it never heals on its own
// (RewrapAll rewraps the DEK and leaves the envelope alone). It must name
// exactly the v1 files — a v3 secret listed here would send someone through
// a full export/import round-trip for nothing.
func TestUnboundPathsNamesOnlyPreAADEnvelopes(t *testing.T) {
	v := newTestVault(t)
	writeV1Envelope(t, v, "legacy/old-key", []byte("pre-v2 value"))
	writeV1Envelope(t, v, "legacy/another", []byte("also old"))
	if err := v.Set("modern/current", []byte("today")); err != nil {
		t.Fatalf("Set: %v", err)
	}

	got, err := v.UnboundPaths()
	if err != nil {
		t.Fatalf("UnboundPaths: %v", err)
	}
	want := []string{"legacy/another", "legacy/old-key"} // sorted, so a report reads the same twice
	if len(got) != len(want) {
		t.Fatalf("UnboundPaths = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("UnboundPaths = %v, want %v", got, want)
		}
	}
}

// A vault written entirely by a current jit must report nothing at all —
// otherwise doctor grows a line every user sees forever, recommending an
// export/import round-trip that would rewrite every secret they own for no
// reason.
func TestUnboundPathsSilentOnACurrentVault(t *testing.T) {
	v := newTestVault(t)
	if err := v.Set("modern/one", []byte("a")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := v.Set("modern/two", []byte("b")); err != nil {
		t.Fatalf("Set: %v", err)
	}

	got, err := v.UnboundPaths()
	if err != nil {
		t.Fatalf("UnboundPaths: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("UnboundPaths = %v on an all-v3 vault, want none", got)
	}
}

// The whole point of re-sealing: writing the secret again is what upgrades
// it, and it is the ONLY thing that does. This pins the remediation the
// doctor finding recommends (export/import writes through Set), so a change
// that broke the upgrade would fail here rather than leave users following
// advice that no longer works.
func TestSettingAV1SecretAgainUpgradesItsEnvelope(t *testing.T) {
	v := newTestVault(t)
	writeV1Envelope(t, v, "legacy/old-key", []byte("pre-v2 value"))

	if err := v.Set("legacy/old-key", []byte("rewritten")); err != nil {
		t.Fatalf("Set: %v", err)
	}

	got, err := v.UnboundPaths()
	if err != nil {
		t.Fatalf("UnboundPaths: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("UnboundPaths = %v after rewriting, want none: Set must seal at the current version", got)
	}
	info, err := v.Info("legacy/old-key")
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if info.Version != envelopeVersion {
		t.Errorf("Version = %d after rewrite, want %d", info.Version, envelopeVersion)
	}
}
