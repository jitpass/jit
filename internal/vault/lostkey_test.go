// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package vault

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

func plantSealedKey(t *testing.T, root, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, SealedKeyFile), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func setSecrets(t *testing.T, v *Vault, paths ...string) {
	t.Helper()
	for _, p := range paths {
		if err := v.Set(p, []byte("value of "+p)); err != nil {
			t.Fatal(err)
		}
	}
}

func sealedToLost(t *testing.T, root string) []string {
	t.Helper()
	got, known, err := SealedToLostKey(root)
	if err != nil || !known {
		t.Fatalf("SealedToLostKey: known=%v err=%v", known, err)
	}
	return got
}

// The whole point: after the lost key is set aside, exactly the envelopes
// still sealed to it are reported, however the vault changes afterwards,
// and reading them never needs a key (the Vault here has none).
func TestSealedToLostKeyTracksWhatTheNewKeyCannotOpen(t *testing.T) {
	v := newTestVault(t)
	setSecrets(t, v, "aws/key", "stripe/key", "github/token")
	if got := sealedToLost(t, v.Root); got != nil {
		t.Fatalf("no key set aside yet, got %q", got)
	}
	plantSealedKey(t, v.Root, "sealed-to-the-old-key")
	if err := SetAsideLostSealedKey(v.Root, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(v.Root, SealedKeyFile)); !os.IsNotExist(err) {
		t.Fatalf("the sealed key file is still in place: %v", err)
	}
	if got, want := sealedToLost(t, v.Root), []string{"aws/key", "github/token", "stripe/key"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("right after set-aside: %q, want %q", got, want)
	}

	// A restore rewrites a path (fresh DEK, different bytes); a removal
	// takes one away; a new secret was never the old key's.
	setSecrets(t, v, "aws/key", "new/secret")
	if err := v.Remove("stripe/key"); err != nil {
		t.Fatal(err)
	}
	if got, want := sealedToLost(t, v.Root), []string{"github/token"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("after a partial restore: %q, want %q", got, want)
	}
}

// A restore that leaves secrets behind settles nothing: the lost key's
// file stays, so the state stays reported, and what was left is named.
// Once nothing is left the file is retired, renamed and never deleted.
func TestSettleLostKeyKeepsTheStateUntilNothingIsLeft(t *testing.T) {
	v := newTestVault(t)
	setSecrets(t, v, "a", "b")
	plantSealedKey(t, v.Root, "sealed-to-the-old-key")
	if err := SetAsideLostSealedKey(v.Root, time.Now()); err != nil {
		t.Fatal(err)
	}
	setSecrets(t, v, "a")

	settle, err := SettleLostKey(v.Root, time.Now(), true)
	if err != nil || settle.Unchecked || settle.Settled || !reflect.DeepEqual(settle.Remaining, []string{"b"}) {
		t.Fatalf("partial restore: %+v err=%v, want [b] remaining", settle, err)
	}
	if _, err := os.Stat(filepath.Join(v.Root, LostSealedKeyFile)); err != nil {
		t.Fatalf("a partial restore retired the lost key's file: %v", err)
	}

	setSecrets(t, v, "b")
	settle, err = SettleLostKey(v.Root, time.Now(), true)
	if err != nil || settle.Unchecked || !settle.Settled || settle.Remaining != nil {
		t.Fatalf("full restore: %+v err=%v", settle, err)
	}
	if got := sealedToLost(t, v.Root); got != nil {
		t.Fatalf("after a full restore still reported: %q", got)
	}
	retired, _ := filepath.Glob(filepath.Join(v.Root, LostSealedKeyFile+"-*"))
	var kept []string
	for _, f := range retired {
		if data, err := os.ReadFile(f); err == nil && string(data) == "sealed-to-the-old-key" {
			kept = append(kept, f)
		}
	}
	if len(kept) != 1 {
		t.Fatalf("the lost key's sealed file was not kept under a retired name: %q", retired)
	}
}

// A second loss before the first was settled must not overwrite the first
// one's sealed file: it is the only thing that could open those secrets.
func TestSetAsideKeepsAnEarlierLostKey(t *testing.T) {
	v := newTestVault(t)
	setSecrets(t, v, "a")
	plantSealedKey(t, v.Root, "first")
	if err := SetAsideLostSealedKey(v.Root, time.Now()); err != nil {
		t.Fatal(err)
	}
	plantSealedKey(t, v.Root, "second")
	if err := SetAsideLostSealedKey(v.Root, time.Now()); err != nil {
		t.Fatal(err)
	}
	contents := map[string]bool{}
	files, _ := filepath.Glob(filepath.Join(v.Root, LostSealedKeyFile+"*"))
	for _, f := range files {
		if data, err := os.ReadFile(f); err == nil {
			contents[string(data)] = true
		}
	}
	if !contents["first"] || !contents["second"] {
		t.Fatalf("after two losses the kept sealed files hold %v, want both", contents)
	}
	if got := sealedToLost(t, v.Root); !reflect.DeepEqual(got, []string{"a"}) {
		t.Fatalf("after the second loss: %q, want [a]", got)
	}
}

// Without a snapshot (set aside by an older jit) nothing can say which
// secrets the new key opens: every one is reported rather than none, and an
// import settles it, saying it could not check.
func TestSealedToLostKeyWithoutASnapshotFailsClosed(t *testing.T) {
	v := newTestVault(t)
	setSecrets(t, v, "a", "b")
	plantSealedKey(t, v.Root, "old")
	if err := SetAsideLostSealedKey(v.Root, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(v.Root, lostKeySnapshotFile)); err != nil {
		t.Fatal(err)
	}
	setSecrets(t, v, "a")
	got, known, err := SealedToLostKey(v.Root)
	if err != nil || known || !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Fatalf("no snapshot: %q known=%v err=%v, want every path and known=false", got, known, err)
	}
	settle, err := SettleLostKey(v.Root, time.Now(), true)
	if err != nil || !settle.Unchecked || !settle.Settled || settle.Remaining != nil {
		t.Fatalf("settle without a snapshot: %+v err=%v", settle, err)
	}
	if got, _, _ := SealedToLostKey(v.Root); got != nil {
		t.Fatalf("still reported after settling: %q", got)
	}
}

// lostKeyVault is a vault whose secrets were written under lost (the
// Secure Enclave-era key), then set aside the way `jit vault init` does, and
// switched to current, the new key an import writes under.
func lostKeyVault(t *testing.T, paths ...string) (v *Vault, lost, current *fakeKeyWrapper) {
	t.Helper()
	lost = newFakeKeyWrapper()
	current = &fakeKeyWrapper{key: bytes.Repeat([]byte{0x77}, dekSize)}
	v = &Vault{Root: t.TempDir(), KeyWrapper: lost, RecipientID: "test-device"}
	setSecrets(t, v, paths...)
	plantSealedKey(t, v.Root, "sealed-to-the-old-key")
	if err := SetAsideLostSealedKey(v.Root, time.Now()); err != nil {
		t.Fatal(err)
	}
	v.KeyWrapper = current
	return v, lost, current
}

func historyFiles(t *testing.T, v *Vault, path string) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(v.historyDir(path), "*.enc"))
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func fileBytes(t *testing.T, file string) []byte {
	t.Helper()
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// Review finding 1: _history/ holds envelopes sealed to the lost key, and a
// later `jit vault rekey` used to stop on them ("cannot decrypt with the
// current or the staged master key") with its marker left, refusing every
// vault change. Rewrap now keeps every envelope a record lists, live or
// archived, exactly as it is, and reports it; everything else rotates.
func TestRewrapKeepsEnvelopesSealedToALostKey(t *testing.T) {
	lost := newFakeKeyWrapper()
	v := &Vault{Root: t.TempDir(), KeyWrapper: lost, RecipientID: "test-device"}
	setSecrets(t, v, "a", "b")
	setSecrets(t, v, "a") // an archived copy of a, sealed to the lost key
	plantSealedKey(t, v.Root, "sealed-to-the-old-key")
	if err := SetAsideLostSealedKey(v.Root, time.Now()); err != nil {
		t.Fatal(err)
	}
	current := &fakeKeyWrapper{key: bytes.Repeat([]byte{0x77}, dekSize)}
	v.KeyWrapper = current
	setSecrets(t, v, "a", "c") // a restored (archiving another lost-key copy), c new

	before := map[string][]byte{}
	for _, f := range historyFiles(t, v, "a") {
		before[f] = fileBytes(t, f)
	}
	bFile := filepath.Join(v.vaultDir(), "b.enc")
	before[bFile] = fileBytes(t, bFile)

	staged := &fakeKeyWrapper{key: bytes.Repeat([]byte{0x55}, dekSize)}
	r, err := v.Rewrap(current, staged)
	if err != nil {
		t.Fatalf("Rewrap stopped on a lost-key copy: %v", err)
	}
	if r.Rewrapped != 2 || len(r.Kept) != 3 {
		t.Fatalf("Rewrap = %+v, want a and c rewrapped, b and two history copies kept", r)
	}
	for f, want := range before {
		if got := fileBytes(t, f); !bytes.Equal(got, want) {
			t.Errorf("Rewrap changed a lost-key copy %s", f)
		}
	}
	v.KeyWrapper = staged
	for _, p := range []string{"a", "c"} {
		if _, err := v.Get(p); err != nil {
			t.Errorf("%s does not open under the new key: %v", p, err)
		}
	}
}

// The exception is only for what a record lists: an envelope no key opens
// and no record names still stops a rotation, as it always has.
func TestRewrapStillStopsOnAnUnrecordedEnvelopeNoKeyOpens(t *testing.T) {
	v, _, current := lostKeyVault(t, "a")
	other := &Vault{Root: v.Root, KeyWrapper: &fakeKeyWrapper{key: bytes.Repeat([]byte{0x11}, dekSize)}, RecipientID: "test-device"}
	setSecrets(t, other, "stranger") // written after the set-aside, under neither key
	staged := &fakeKeyWrapper{key: bytes.Repeat([]byte{0x55}, dekSize)}
	if _, err := v.Rewrap(current, staged); err == nil || !strings.Contains(err.Error(), "stranger") {
		t.Fatalf("Rewrap over an unrecorded envelope no key opens: %v, want it to stop naming it", err)
	}
}

// A record lists bytes, not keys: if the old key does open a listed
// envelope (the "lost" key was the same MEK after all), it is rotated like
// any other, never left behind under a key the rotation deletes.
func TestRewrapRotatesARecordedEnvelopeTheOldKeyOpens(t *testing.T) {
	v, lost, _ := lostKeyVault(t, "a")
	staged := &fakeKeyWrapper{key: bytes.Repeat([]byte{0x55}, dekSize)}
	r, err := v.Rewrap(lost, staged)
	if err != nil || r.Rewrapped != 1 || len(r.Kept) != 0 {
		t.Fatalf("Rewrap = %+v, %v; want a rewrapped, nothing kept", r, err)
	}
}

// restore_pending counts live secrets only: archived copies sealed to the
// lost key are kept, never pending, so once every live secret is back the
// state settles even though those copies stay.
func TestSealedToLostKeyCountsLiveSecretsOnly(t *testing.T) {
	v, _, _ := lostKeyVault(t, "a")
	v.KeyWrapper = newFakeKeyWrapper()
	setSecrets(t, v, "a") // archive a lost-key copy of a
	plantSealedKey(t, v.Root, "second")
	if err := SetAsideLostSealedKey(v.Root, time.Now()); err != nil {
		t.Fatal(err)
	}
	v.KeyWrapper = &fakeKeyWrapper{key: bytes.Repeat([]byte{0x77}, dekSize)}
	setSecrets(t, v, "a") // live a restored
	if len(historyFiles(t, v, "a")) < 2 {
		t.Fatal("expected archived copies of a")
	}
	if got := sealedToLost(t, v.Root); got != nil {
		t.Fatalf("pending = %q, want none: only history copies are left", got)
	}
	settle, err := SettleLostKey(v.Root, time.Now(), true)
	if err != nil || !settle.Settled {
		t.Fatalf("settle = %+v, %v; want settled", settle, err)
	}
}

// Review finding 2: only an absent record means "no record". A record that
// is there but can't be read is an error: nothing settles on it.
func TestACorruptLostKeyRecordFailsClosed(t *testing.T) {
	v, _, _ := lostKeyVault(t, "a", "b")
	if err := os.WriteFile(filepath.Join(v.Root, lostKeySnapshotFile), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	setSecrets(t, v, "a", "b") // an import that brought everything back
	if _, _, err := SealedToLostKey(v.Root); err == nil {
		t.Fatal("a corrupt record read as no record")
	}
	if settle, err := SettleLostKey(v.Root, time.Now(), true); err == nil || settle.Settled {
		t.Fatalf("settle over a corrupt record = %+v, %v; want an error and nothing settled", settle, err)
	}
	if _, err := os.Stat(filepath.Join(v.Root, LostSealedKeyFile)); err != nil {
		t.Fatalf("the lost key's file was retired over a corrupt record: %v", err)
	}
}

// Review finding 3: `jit vault restore <path> --version <old>` renames an
// archived lost-key envelope into place. Its bytes are a recorded
// _history/ file's, not the recorded live file's, so a per-path comparison
// called it fine.
func TestAByteForByteRestoreOfALostKeyCopyIsStillPending(t *testing.T) {
	v := newTestVault(t)
	setSecrets(t, v, "a")
	setSecrets(t, v, "a") // history: the first value, sealed to the lost key
	plantSealedKey(t, v.Root, "old")
	if err := SetAsideLostSealedKey(v.Root, time.Now()); err != nil {
		t.Fatal(err)
	}
	v.KeyWrapper = &fakeKeyWrapper{key: bytes.Repeat([]byte{0x77}, dekSize)}
	setSecrets(t, v, "a") // restored from a recovery file
	if got := sealedToLost(t, v.Root); got != nil {
		t.Fatalf("after the import: %q, want none", got)
	}
	versions, err := v.HistoryVersions("a")
	if err != nil || len(versions) < 2 {
		t.Fatalf("history: %+v, %v", versions, err)
	}
	oldest := versions[len(versions)-1].ArchiveStamp
	if err := v.Restore("a", oldest); err != nil {
		t.Fatal(err)
	}
	if got := sealedToLost(t, v.Root); !reflect.DeepEqual(got, []string{"a"}) {
		t.Fatalf("after restoring a lost-key version: %q, want [a]", got)
	}
}

// Review finding 4: pruning history must never delete a version sealed to
// the lost key, while the state is pending or after it settled.
func TestHistoryPruningKeepsLostKeyCopies(t *testing.T) {
	v := newTestVault(t)
	for range HistoryKeep + 1 {
		setSecrets(t, v, "a")
	}
	plantSealedKey(t, v.Root, "old")
	if err := SetAsideLostSealedKey(v.Root, time.Now()); err != nil {
		t.Fatal(err)
	}
	lostCopies := historyFiles(t, v, "a")
	if len(lostCopies) != HistoryKeep {
		t.Fatalf("setup: %d history copies, want %d", len(lostCopies), HistoryKeep)
	}
	v.KeyWrapper = &fakeKeyWrapper{key: bytes.Repeat([]byte{0x77}, dekSize)}
	setSecrets(t, v, "a")
	if settle, err := SettleLostKey(v.Root, time.Now(), true); err != nil || !settle.Settled {
		t.Fatalf("settle = %+v, %v", settle, err)
	}
	for range HistoryKeep + 2 {
		setSecrets(t, v, "a")
	}
	for _, f := range lostCopies {
		if _, err := os.Stat(f); err != nil {
			t.Errorf("a history copy sealed to the lost key was pruned: %v", err)
		}
	}
	// The new key's versions are still bounded, beside the kept copies: the
	// five archived before the loss, plus the live one the import archived.
	if got, want := len(historyFiles(t, v, "a")), HistoryKeep+1+HistoryKeep; got != want {
		t.Errorf("%d history files, want %d kept lost-key copies plus %d current", got, HistoryKeep+1, HistoryKeep)
	}
}

// Review finding 5: an envelope that can't be read must not block init. It
// is recorded as unknown and counts as sealed until it is rewritten.
func TestSetAsideRecordsAnUnreadableEnvelopeAndCarriesOn(t *testing.T) {
	v := newTestVault(t)
	setSecrets(t, v, "a", "b")
	bFile := filepath.Join(v.vaultDir(), "b.enc")
	if err := os.Chmod(bFile, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(bFile, 0o600) })
	plantSealedKey(t, v.Root, "old")
	if err := SetAsideLostSealedKey(v.Root, time.Now()); err != nil {
		t.Fatalf("one unreadable envelope blocked the set-aside: %v", err)
	}
	if _, err := os.Stat(filepath.Join(v.Root, LostSealedKeyFile)); err != nil {
		t.Fatalf("the key was not set aside: %v", err)
	}
	v.KeyWrapper = &fakeKeyWrapper{key: bytes.Repeat([]byte{0x77}, dekSize)}
	setSecrets(t, v, "a")
	if got := sealedToLost(t, v.Root); !reflect.DeepEqual(got, []string{"b"}) {
		t.Fatalf("still unreadable: %q, want [b]", got)
	}
	if err := os.Chmod(bFile, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := sealedToLost(t, v.Root); !reflect.DeepEqual(got, []string{"b"}) {
		t.Fatalf("readable but never rewritten: %q, want [b]", got)
	}
	setSecrets(t, v, "b")
	if got := sealedToLost(t, v.Root); got != nil {
		t.Fatalf("after b was rewritten: %q, want none", got)
	}
}

// Review finding 5: a walk that can't see every file still sets the key
// aside, and records that it is incomplete, so every secret counts.
func TestSetAsideRecordsAnIncompleteWalkAndCarriesOn(t *testing.T) {
	v := newTestVault(t)
	setSecrets(t, v, "a", "group/b")
	dir := filepath.Join(v.vaultDir(), "group")
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	plantSealedKey(t, v.Root, "old")
	if err := SetAsideLostSealedKey(v.Root, time.Now()); err != nil {
		t.Fatalf("an unreadable directory blocked the set-aside: %v", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	v.KeyWrapper = &fakeKeyWrapper{key: bytes.Repeat([]byte{0x77}, dekSize)}
	setSecrets(t, v, "a")
	got, known, err := SealedToLostKey(v.Root)
	if err != nil || known || !reflect.DeepEqual(got, []string{"a", "group/b"}) {
		t.Fatalf("incomplete record: %q known=%v err=%v, want every secret and known=false", got, known, err)
	}
}

// An envelope that can't be read when checked counts as sealed: jit can't
// show it was restored.
func TestAnEnvelopeUnreadableAtCheckTimeCountsAsSealed(t *testing.T) {
	v, _, _ := lostKeyVault(t, "a")
	setSecrets(t, v, "a")
	aFile := filepath.Join(v.vaultDir(), "a.enc")
	if err := os.Chmod(aFile, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(aFile, 0o600) })
	if got := sealedToLost(t, v.Root); !reflect.DeepEqual(got, []string{"a"}) {
		t.Fatalf("unreadable envelope: %q, want [a]", got)
	}
}

// `jit vault rm` settles too, but only once nothing is left: removing some
// of what a recovery file didn't hold keeps the state.
func TestSettleAfterARemovalWaitsUntilNothingIsLeft(t *testing.T) {
	v, _, _ := lostKeyVault(t, "a", "b")
	if err := v.Remove("a"); err != nil {
		t.Fatal(err)
	}
	if settle, err := SettleLostKey(v.Root, time.Now(), false); err != nil || settle.Settled || !reflect.DeepEqual(settle.Remaining, []string{"b"}) {
		t.Fatalf("after removing a: %+v, %v; want b remaining", settle, err)
	}
	if err := v.Remove("b"); err != nil {
		t.Fatal(err)
	}
	if settle, err := SettleLostKey(v.Root, time.Now(), false); err != nil || !settle.Settled || settle.Unchecked {
		t.Fatalf("after removing b: %+v, %v; want settled", settle, err)
	}
}

// corruptSnapshot overwrites the current lost key's record with bytes that
// are not a snapshot, the way a disk error or a hand edit would.
func corruptSnapshot(t *testing.T, root string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, lostKeySnapshotFile), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// strangerEnvelope writes an envelope under a key that is neither the
// lost one nor the one a rotation starts from, and gives it an old time,
// so a rule that presumes by time alone would call it a lost-key copy.
func strangerEnvelope(t *testing.T, v *Vault, path string, mod time.Time) string {
	t.Helper()
	other := &Vault{Root: v.Root, KeyWrapper: &fakeKeyWrapper{key: bytes.Repeat([]byte{0x11}, dekSize)}, RecipientID: "test-device"}
	setSecrets(t, other, path)
	file := filepath.Join(v.vaultDir(), path+".enc")
	if err := os.Chtimes(file, mod, mod); err != nil {
		t.Fatal(err)
	}
	return file
}

// Review 3, finding 1: a lost key whose record is unreadable used to
// presume every envelope sealed to it (with no time bound at all), so
// rekey kept an envelope NO record lists, finished the rotation and
// destroyed the old master key. Rekey now leaves only provable copies
// behind, and stops on this one, naming it and saying why.
func TestRewrapStopsOnAnUnprovenEnvelopeWhenTheRecordIsCorrupt(t *testing.T) {
	v, _, current := lostKeyVault(t) // nothing sealed: the stranger is the only envelope
	corruptSnapshot(t, v.Root)
	strangerEnvelope(t, v, "stranger", time.Now().Add(-time.Hour))
	staged := &fakeKeyWrapper{key: bytes.Repeat([]byte{0x55}, dekSize)}
	r, err := v.Rewrap(current, staged)
	if err == nil {
		t.Fatalf("Rewrap finished over an envelope no key opens and no record lists: %+v", r)
	}
	for _, want := range []string{"stranger", "unreadable", "can't show"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("Rewrap error %q does not say %q", err, want)
		}
	}
}

// The same with no record at all, and for a retired key whose record is
// gone: nothing proves the envelope is a lost-key copy.
func TestRewrapStopsWhenALostKeyHasNoRecord(t *testing.T) {
	for _, retired := range []bool{false, true} {
		v, _, current := lostKeyVault(t)
		if err := os.Remove(filepath.Join(v.Root, lostKeySnapshotFile)); err != nil {
			t.Fatal(err)
		}
		if retired {
			if err := retireLostKey(v.Root, time.Now().Add(time.Hour)); err != nil {
				t.Fatal(err)
			}
		}
		strangerEnvelope(t, v, "stranger", time.Now().Add(-time.Hour))
		staged := &fakeKeyWrapper{key: bytes.Repeat([]byte{0x55}, dekSize)}
		if r, err := v.Rewrap(current, staged); err == nil || !strings.Contains(err.Error(), "stranger") {
			t.Errorf("retired=%v: Rewrap = %+v, %v; want it to stop naming stranger", retired, r, err)
		}
	}
}

// Proof by the unknown list: an envelope that could not be read at the
// set-aside and has not been written since is a lost-key copy, and rekey
// keeps it.
func TestRewrapKeepsAnEnvelopeTheRecordNamesAsUnreadable(t *testing.T) {
	lost := newFakeKeyWrapper()
	v := &Vault{Root: t.TempDir(), KeyWrapper: lost, RecipientID: "test-device"}
	setSecrets(t, v, "a", "b")
	bFile := filepath.Join(v.vaultDir(), "b.enc")
	if err := os.Chmod(bFile, 0o000); err != nil {
		t.Fatal(err)
	}
	plantSealedKey(t, v.Root, "old")
	if err := SetAsideLostSealedKey(v.Root, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(bFile, 0o600); err != nil {
		t.Fatal(err)
	}
	current := &fakeKeyWrapper{key: bytes.Repeat([]byte{0x77}, dekSize)}
	v.KeyWrapper = current
	setSecrets(t, v, "a")
	staged := &fakeKeyWrapper{key: bytes.Repeat([]byte{0x55}, dekSize)}
	r, err := v.Rewrap(current, staged)
	if err != nil || !slices.Contains(r.Kept, "b.enc") {
		t.Fatalf("Rewrap = %+v, %v; want b.enc kept", r, err)
	}
}

// Pruning stays generous over an unreadable record, but bounded: a
// version archived after the key was set aside is pruned as usual.
func TestHistoryPruningOverACorruptRecordIsBounded(t *testing.T) {
	v := newTestVault(t)
	for range HistoryKeep + 1 {
		setSecrets(t, v, "a")
	}
	plantSealedKey(t, v.Root, "old")
	if err := SetAsideLostSealedKey(v.Root, time.Now()); err != nil {
		t.Fatal(err)
	}
	lostCopies := historyFiles(t, v, "a")
	corruptSnapshot(t, v.Root)
	back := time.Now().Add(-time.Hour) // the record's own time is the set-aside
	if err := os.Chtimes(filepath.Join(v.Root, lostKeySnapshotFile), back, back); err != nil {
		t.Fatal(err)
	}
	for _, f := range lostCopies {
		if err := os.Chtimes(f, back.Add(-time.Minute), back.Add(-time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	w := &Vault{Root: v.Root, KeyWrapper: &fakeKeyWrapper{key: bytes.Repeat([]byte{0x77}, dekSize)}, RecipientID: "test-device"}
	for range HistoryKeep + 3 {
		setSecrets(t, w, "a")
	}
	for _, f := range lostCopies {
		if _, err := os.Stat(f); err != nil {
			t.Errorf("a copy from before the set-aside was pruned: %v", err)
		}
	}
	if got, want := len(historyFiles(t, v, "a")), len(lostCopies)+HistoryKeep; got != want {
		t.Errorf("%d history files, want %d: later versions must still be bounded", got, want)
	}
}

// Review 3, finding 3: a snapshot written by bae7b90 (version 1: live
// secrets only, under "envelopes") reads correctly, not as corrupt.
func TestAVersion1SnapshotIsRead(t *testing.T) {
	v := newTestVault(t)
	setSecrets(t, v, "a", "b")
	setSecrets(t, v, "a") // a history copy, which version 1 never listed
	plantSealedKey(t, v.Root, "old")
	if err := SetAsideLostSealedKey(v.Root, time.Now()); err != nil {
		t.Fatal(err)
	}
	envelopes := map[string]string{}
	for _, p := range []string{"a", "b"} {
		envelopes[p] = digest(fileBytes(t, filepath.Join(v.vaultDir(), p+".enc")))
	}
	v1, err := json.Marshal(map[string]any{"version": 1, "set_aside": time.Now().UTC().Format(time.RFC3339), "envelopes": envelopes})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(v.Root, lostKeySnapshotFile), v1, 0o600); err != nil {
		t.Fatal(err)
	}
	current := &fakeKeyWrapper{key: bytes.Repeat([]byte{0x77}, dekSize)}
	v.KeyWrapper = current
	setSecrets(t, v, "a")
	if got := sealedToLost(t, v.Root); !reflect.DeepEqual(got, []string{"b"}) {
		t.Fatalf("version 1 record: pending %q, want [b]", got)
	}
	// The live copy of a it listed was archived by the import: proven, so
	// rekey keeps it; the history copy it never listed stops rekey.
	staged := &fakeKeyWrapper{key: bytes.Repeat([]byte{0x55}, dekSize)}
	if _, err := v.Rewrap(current, staged); err == nil || !strings.Contains(err.Error(), "_history") {
		t.Fatalf("Rewrap over a history copy version 1 never listed: %v, want it to stop there", err)
	}
}

// Review 3, finding 4: one rule for status, history and rekey. An envelope
// a record names as unreadable at set-aside, untouched since, is pending
// for status, kept by history, and kept by rekey; the same bytes written
// after the set-aside are none of those.
func TestStatusHistoryAndRekeyShareOneRule(t *testing.T) {
	rec := lostKeyRecord{
		snap:   lostKeySnapshot{Unknown: []string{"b.enc"}},
		hashes: map[string]bool{"listed": true},
		upTo:   1000,
	}
	at := func(ns int64) time.Time { return time.Unix(0, ns) }
	cases := []struct {
		rel, sum string
		mod      int64
		want     lostKeyMatch
	}{
		{"a.enc", "listed", 5000, provenLost},        // bytes listed, whenever written
		{"b.enc", "other", 900, provenLost},          // named unreadable, untouched since
		{"b.enc", "other", 1100, notLost},            // written since the set-aside
		{"c.enc", "other", 900, presumedLost},        // not listed, record couldn't see all
		{"c.enc", "", 5000, presumedLost},            // unreadable now
		{"_history/c/1.enc", "x", 900, presumedLost}, // same rule for history
	}
	for _, c := range cases {
		if got := rec.match(c.rel, c.sum, at(c.mod)); got != c.want {
			t.Errorf("match(%s, %s, %d) = %d, want %d", c.rel, c.sum, c.mod, got, c.want)
		}
	}
	corrupt := lostKeyRecord{err: errLostKeyRecord, upTo: 1000}
	if got := corrupt.match("a.enc", "listed", at(900)); got != presumedLost {
		t.Errorf("corrupt record, before: %d, want presumed", got)
	}
	if got := corrupt.match("a.enc", "listed", at(1100)); got != notLost {
		t.Errorf("corrupt record, after its time: %d, want not lost", got)
	}
}

// Review 3, finding 5: archiving reads the lost-key records once per
// Vault, and hashes nothing when there is no lost key.
func TestHistoryPruningReadsTheRecordsOncePerVault(t *testing.T) {
	var loads, hashes int
	loadHook, digestHook = func() { loads++ }, func() { hashes++ }
	t.Cleanup(func() { loadHook, digestHook = nil, nil })

	v := newTestVault(t)
	for range 3 * HistoryKeep {
		setSecrets(t, v, "a")
	}
	if loads != 1 || hashes != 0 {
		t.Fatalf("no lost key: %d loads, %d hashes; want 1 and 0", loads, hashes)
	}

	plantSealedKey(t, v.Root, "old")
	if err := SetAsideLostSealedKey(v.Root, time.Now()); err != nil {
		t.Fatal(err)
	}
	loads, hashes = 0, 0
	w := &Vault{Root: v.Root, KeyWrapper: &fakeKeyWrapper{key: bytes.Repeat([]byte{0x77}, dekSize)}, RecipientID: "test-device"}
	const writes = 3 * HistoryKeep
	for range writes {
		setSecrets(t, w, "a")
	}
	if loads != 1 {
		t.Errorf("with a lost key: %d loads over %d writes, want 1", loads, writes)
	}
	// Each history file is hashed once, however many archives consult it:
	// the HistoryKeep lost-key copies plus one new version per write.
	if limit := HistoryKeep + writes; hashes > limit {
		t.Errorf("with a lost key: %d hashes over %d writes, want at most %d", hashes, writes, limit)
	}
}
