// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package vault

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

// A vault whose Secure Enclave key is lost (internal/keystore, KeyLost)
// starts over on a new keychain key at `jit vault init`, and its secrets
// come back through `jit vault import`. Until that import has landed, every
// envelope still on disk is sealed to the lost key and cannot be opened, and
// nothing about the vault looks wrong: the new key is present, every
// envelope is structurally intact, and envelopes name no key. This file is
// how jit keeps knowing, without ever reading a key (so status and doctor
// never prompt):
//
//   - SetAsideLostSealedKey renames the sealed key file to
//     LostSealedKeyFile and records a snapshot: the SHA-256 of every
//     envelope file under vault/ at that moment (live secrets, _backups/ and
//     _history/ alike), all of them sealed to the lost key. A file it cannot
//     read is recorded by name as unknown; a walk that cannot see every file
//     marks the snapshot incomplete. Neither stops the set-aside: `jit vault
//     init` is the only way back, so it must not be blocked, and both are
//     read fail-closed below.
//   - SealedToLostKey reports which LIVE secrets (List's paths) the current
//     key cannot open: those whose bytes match any recorded hash, whatever
//     path they sit at now (a byte-for-byte `jit vault restore` of an
//     archived copy moves a recorded file to a new name). A rewritten
//     envelope (import, set) has a fresh DEK and so different bytes; a
//     removed one is gone. History copies are never counted: they are kept,
//     not pending.
//   - SettleLostKey retires both files, renamed with a timestamp, once no
//     live secret is left sealed to the lost key: after an import, or after
//     a `jit vault rm` that removed the last one. It never deletes them: if
//     the enclave key was reported lost by mistake, the sealed file is the
//     one thing that could still open the old envelopes, and a retired
//     snapshot keeps protecting the copies it lists (below).
//   - FinishLostKeyRestore (`jit vault import --finish`) is the way out when
//     the record cannot say: it retires the files the same way, on the
//     user's word, and says what it could not verify.
//
// Every record, current or retired, keeps two promises for as long as it
// exists (lostKeyCopies, one rule for status, rekey and history alike):
//
//   - pruneHistory never deletes an archived version that is, or may be,
//     sealed to a lost key, and such versions do not take one of the
//     HistoryKeep places. Keeping is always safe, so "may be" is generous.
//   - `jit vault rekey` (Rewrap) leaves an envelope PROVABLY sealed to a
//     lost key untouched and reports it, instead of stopping on it with its
//     marker left behind, which would refuse every vault change. Proof is
//     strict: finishing a rotation destroys the old master key, so an
//     envelope jit merely presumes is a lost-key copy still stops it.
//
// Nothing here removes or rewrites an envelope. An envelope the import did
// not replace stays on disk and keeps the state pending, so the caller can
// name it; deleting it is the user's decision (`jit vault rm`, which deletes
// that secret's history with it, as rm always has).

// LostSealedKeyFile is where a lost key's sealed file is set aside.
const LostSealedKeyFile = SealedKeyFile + ".lost"

// lostKeySnapshotFile records the envelopes sealed to the lost key.
const lostKeySnapshotFile = LostSealedKeyFile + ".envelopes"

// lostKeySnapshot is lostKeySnapshotFile's JSON.
type lostKeySnapshot struct {
	Version  int    `json:"version"`
	SetAside string `json:"set_aside"`
	// SetAsideUnixNano is the same moment, precise enough to compare with a
	// file's modification time.
	SetAsideUnixNano int64 `json:"set_aside_unix_nano,omitempty"`
	// Files maps every envelope file under vault/, by its slash path
	// relative to vault/ ("aws/key.enc", "_history/aws/key/17….enc"), to
	// the hex SHA-256 of its bytes.
	Files map[string]string `json:"files,omitempty"`
	// Unknown names envelope files that were there but could not be read.
	Unknown []string `json:"unknown,omitempty"`
	// Incomplete says why the walk could not see every file. A snapshot
	// with it set cannot say which live secrets are fine, so every one
	// counts as pending, exactly as with no snapshot at all.
	Incomplete string `json:"incomplete,omitempty"`

	// Envelopes is version 1's only list: live secrets (List's paths, so
	// _backups/ but never _history/) to the hash of their envelope file.
	// Read, never written: readLostKeySnapshot moves it into Files.
	Envelopes map[string]string `json:"envelopes,omitempty"`
	// historyUnrecorded: a version 1 record, which never listed _history/.
	historyUnrecorded bool
}

// lostKeySnapshotVersion 2 records every envelope file (Files, Unknown,
// Incomplete, SetAsideUnixNano). Version 1 recorded live secrets only
// (Envelopes) and is still read.
const (
	lostKeySnapshotVersion   = 2
	lostKeySnapshotVersionV1 = 1
)

// errLostKeyRecord marks a snapshot that is there but cannot be used.
var errLostKeyRecord = errors.New("the record of secrets sealed to the lost key is unreadable")

// retiredSuffix names a retired lost-key file by when it was retired, so a
// second loss never overwrites the first one's record.
const retiredStampLayout = "20060102T150405.000000000Z"

func retiredSuffix(now time.Time) string {
	return "-" + now.UTC().Format(retiredStampLayout)
}

// SetAsideLostSealedKey records which envelopes are sealed to the lost key,
// then renames the sealed key file to LostSealedKeyFile. The snapshot is
// written first, so a failure to write it leaves the vault exactly as it
// was. A lost-key file already there (an earlier loss never settled) is
// retired with a timestamp rather than overwritten.
//
// A vault it cannot fully read does not stop it: an envelope it cannot read
// is recorded as unknown, and a walk that fails partway is recorded as
// incomplete, and both are read fail-closed (every secret, or every
// unreadable one, counts as still sealed). `jit vault init` is the only way
// back from a lost key, and it must never be blocked on one bad file.
func SetAsideLostSealedKey(root string, now time.Time) error {
	for _, name := range []string{LostSealedKeyFile, lostKeySnapshotFile} {
		old := filepath.Join(root, name)
		if _, err := os.Lstat(old); err == nil {
			if err := os.Rename(old, old+retiredSuffix(now)); err != nil {
				return fmt.Errorf("keeping the earlier lost key's %s: %w", name, err)
			}
		}
	}
	snap := lostKeySnapshot{
		Version:          lostKeySnapshotVersion,
		SetAside:         now.UTC().Format(time.RFC3339),
		SetAsideUnixNano: now.UnixNano(),
	}
	snap.Files, snap.Unknown, snap.Incomplete = hashEnvelopeFiles((&Vault{Root: root}).vaultDir())
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	if err := AtomicWriteFile(filepath.Join(root, lostKeySnapshotFile), data); err != nil {
		return fmt.Errorf("recording the secrets sealed to the lost key: %w", err)
	}
	if err := os.Rename(filepath.Join(root, SealedKeyFile), filepath.Join(root, LostSealedKeyFile)); err != nil {
		return fmt.Errorf("setting the lost vault key's file aside: %w", err)
	}
	return nil
}

// hashEnvelopeFiles hashes every .enc file under dir. It never fails: a
// file it cannot read goes in unknown, and an entry the walk cannot read
// (a directory, or dir itself) is described in incomplete, and the walk
// carries on past it.
func hashEnvelopeFiles(dir string) (files map[string]string, unknown []string, incomplete string) {
	files = map[string]string{}
	var problems, found []string
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if p == dir && errors.Is(err, fs.ErrNotExist) {
				return filepath.SkipDir // no vault/ yet: nothing sealed
			}
			problems = append(problems, err.Error())
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.IsDir() && strings.HasSuffix(d.Name(), ".enc") {
			found = append(found, p)
		}
		return nil
	})
	// Read after the walk, not inside it, like the rekey walk does.
	for _, p := range found {
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			problems = append(problems, err.Error())
			continue
		}
		rel = filepath.ToSlash(rel)
		data, err := os.ReadFile(p) // #nosec G304 -- p comes from walking jit's own vault directory
		if err != nil {
			unknown = append(unknown, rel)
			continue
		}
		files[rel] = digest(data)
	}
	sort.Strings(unknown)
	return files, unknown, strings.Join(problems, "; ")
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// readLostKeySnapshot reads one snapshot file. An absent file is returned
// as an error satisfying errors.Is(err, fs.ErrNotExist); anything else that
// stops it being used (unreadable, not JSON, an unknown version, no list of
// files) wraps errLostKeyRecord.
//
// A version 1 snapshot is read into the current shape: its Envelopes (vault
// path to hash) become Files (path + ".enc" to hash), and, since it kept the
// set-aside moment only to the second, SetAsideUnixNano becomes the
// snapshot file's own modification time (it was written at that moment,
// and renaming it on retirement keeps the time), or, failing that, the end
// of the recorded second. It never listed _history/, which
// historyUnrecorded carries to the rule (lostKeyRecord.match): archived
// copies from before the set-aside are presumed, never proven.
func readLostKeySnapshot(file string) (lostKeySnapshot, error) {
	data, err := os.ReadFile(file) // #nosec G304 -- a fixed name under the vault root
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return lostKeySnapshot{}, err
		}
		return lostKeySnapshot{}, fmt.Errorf("%w: %v", errLostKeyRecord, err)
	}
	var snap lostKeySnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return lostKeySnapshot{}, fmt.Errorf("%w: %v", errLostKeyRecord, err)
	}
	switch {
	case snap.Version == lostKeySnapshotVersion && snap.Files != nil:
	case snap.Version == lostKeySnapshotVersionV1 && snap.Envelopes != nil:
		snap.Files = make(map[string]string, len(snap.Envelopes))
		for p, h := range snap.Envelopes {
			snap.Files[p+".enc"] = h
		}
		snap.Envelopes = nil
		snap.historyUnrecorded = true
		snap.SetAsideUnixNano = 0
		if info, err := os.Stat(file); err == nil {
			snap.SetAsideUnixNano = info.ModTime().UnixNano()
		} else if t, err := time.Parse(time.RFC3339, snap.SetAside); err == nil {
			snap.SetAsideUnixNano = t.Add(time.Second - 1).UnixNano()
		}
		if snap.SetAsideUnixNano == 0 {
			return lostKeySnapshot{}, fmt.Errorf("%w: version 1 with no time it was set aside", errLostKeyRecord)
		}
	default:
		return lostKeySnapshot{}, fmt.Errorf("%w: version %d", errLostKeyRecord, snap.Version)
	}
	return snap, nil
}

// lostKeyRecord is one lost key's record, current or retired.
type lostKeyRecord struct {
	// snap is the snapshot, valid only when err is nil; hashes is its
	// Files' hashes as a set.
	snap   lostKeySnapshot
	hashes map[string]bool
	// err: why the snapshot can't be used. errors.Is(err, fs.ErrNotExist)
	// when there is none (a key set aside by a jit older than the snapshot);
	// errLostKeyRecord when it is there but unreadable.
	err error
	// upTo (Unix nanoseconds): an envelope last written after this was
	// written under a later key. The set-aside moment when jit knows it
	// (the snapshot, or the snapshot file's own time); else, for a retired
	// key, when it was retired; else math.MaxInt64, nothing known.
	upTo int64
}

// lostKeyMatch is how far an envelope is known to be sealed to a lost key.
type lostKeyMatch int

const (
	// notLost: written under a later key, as far as any record can tell.
	notLost lostKeyMatch = iota
	// presumedLost: a record that could not list everything dates from
	// after the file was last written, or the file can't be read to
	// compare. Enough to keep it (history) or count it (status), never
	// enough for rekey to leave it behind.
	presumedLost
	// provenLost: a record lists its bytes, or names it as unreadable at
	// set-aside and it has not been written since.
	provenLost
)

// match is THE rule, for one record: status, rekey and history pruning all
// come here, through lostKeyCopies.matchFile. rel is the file's slash path
// relative to vault/, sum the hex SHA-256 of its bytes ("" when it could
// not be read), mod its modification time.
func (r lostKeyRecord) match(rel, sum string, mod time.Time) lostKeyMatch {
	if sum == "" {
		return presumedLost
	}
	before := mod.UnixNano() <= r.upTo
	switch {
	case r.err != nil:
		if before {
			return presumedLost
		}
		return notLost
	case r.hashes[sum]:
		return provenLost
	case !before:
		return notLost
	case slices.Contains(r.snap.Unknown, rel):
		return provenLost
	case len(r.snap.Unknown) > 0 || r.snap.Incomplete != "",
		r.snap.historyUnrecorded && strings.HasPrefix(rel, historyDirName+"/"):
		return presumedLost
	}
	return notLost
}

// lostKeyCopies is the records a caller consults, with each file's verdict
// kept once reached: an envelope file is only ever replaced whole, by a
// rename, so one whose size and time are unchanged is the same file, and
// is not hashed again.
type lostKeyCopies struct {
	records []lostKeyRecord

	mu    sync.Mutex
	known map[string]fileVerdict
}

type fileVerdict struct {
	size  int64
	mod   time.Time
	match lostKeyMatch
}

func newLostKeyCopies(records []lostKeyRecord) *lostKeyCopies {
	return &lostKeyCopies{records: records, known: map[string]fileVerdict{}}
}

// any: at least one lost key's sealed file exists.
func (c *lostKeyCopies) any() bool { return c != nil && len(c.records) > 0 }

// matchFile is match for a file under vaultDir, against every record: the
// strongest verdict wins. It hashes the file at most once.
func (c *lostKeyCopies) matchFile(vaultDir, file string) lostKeyMatch {
	if !c.any() {
		return notLost
	}
	rel, err := filepath.Rel(vaultDir, file)
	if err != nil {
		return presumedLost
	}
	info, err := os.Stat(file)
	if err != nil {
		return presumedLost
	}
	c.mu.Lock()
	v, seen := c.known[file]
	c.mu.Unlock()
	if seen && v.size == info.Size() && v.mod.Equal(info.ModTime()) {
		return v.match
	}
	var sum string
	if data, err := os.ReadFile(file); err == nil { // #nosec G304 -- file is under jit's own vault directory
		if digestHook != nil {
			digestHook()
		}
		sum = digest(data)
	}
	best := notLost
	for _, r := range c.records {
		best = max(best, r.match(filepath.ToSlash(rel), sum, info.ModTime()))
	}
	if sum != "" {
		c.mu.Lock()
		c.known[file] = fileVerdict{size: info.Size(), mod: info.ModTime(), match: best}
		c.mu.Unlock()
	}
	return best
}

// unproven says why an envelope neither key opens is not provably a
// lost-key copy, for rekey's error: empty when no lost key exists.
func (c *lostKeyCopies) unproven() string {
	if !c.any() {
		return ""
	}
	for _, r := range c.records {
		if r.err != nil {
			if errors.Is(r.err, fs.ErrNotExist) {
				return "a lost key was set aside with no record of its secrets, so jit can't show this is one of them"
			}
			return r.err.Error() + ", so jit can't show this is one of the lost key's secrets"
		}
	}
	return "no record of a lost key lists it"
}

// loadLostKeyCopies reads every lost key's record under root, current and
// retired. One ReadDir of root when there is none.
func loadLostKeyCopies(root string) (*lostKeyCopies, error) {
	if loadHook != nil {
		loadHook()
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return newLostKeyCopies(nil), nil
		}
		return nil, fmt.Errorf("looking for a lost vault key: %w", err)
	}
	var records []lostKeyRecord
	for _, e := range entries {
		suffix, isSealed := strings.CutPrefix(e.Name(), LostSealedKeyFile)
		if !isSealed || (suffix != "" && !strings.HasPrefix(suffix, "-")) {
			continue // not a lost key's sealed file (the snapshot shares the prefix: ".envelopes")
		}
		records = append(records, loadLostKeyRecord(root, suffix))
	}
	return newLostKeyCopies(records), nil
}

// loadHook and digestHook, when set (tests only), are called on every
// loadLostKeyCopies and on every envelope hashed to compare with a record.
var loadHook, digestHook func()

// loadLostKeyRecord reads the record of the lost key whose sealed file is
// LostSealedKeyFile+suffix ("" for the current one).
func loadLostKeyRecord(root, suffix string) lostKeyRecord {
	file := filepath.Join(root, lostKeySnapshotFile+suffix)
	snap, err := readLostKeySnapshot(file)
	if err == nil {
		upTo := snap.SetAsideUnixNano
		if upTo == 0 {
			upTo = math.MaxInt64 // a version 2 snapshot always has it; never guess low
		}
		hashes := make(map[string]bool, len(snap.Files))
		for _, h := range snap.Files {
			hashes[h] = true
		}
		return lostKeyRecord{snap: snap, hashes: hashes, upTo: upTo}
	}
	r := lostKeyRecord{err: err, upTo: math.MaxInt64}
	switch info, statErr := os.Stat(file); {
	case statErr == nil:
		// Unreadable, but its own time is when it was written: at the
		// set-aside.
		r.upTo = info.ModTime().UnixNano()
	case suffix != "":
		if t, perr := time.Parse(retiredStampLayout, strings.TrimPrefix(suffix, "-")); perr == nil {
			r.upTo = t.UnixNano()
		}
	}
	return r
}

// lostKeyCopies returns the Vault's lost-key records, read once for the
// life of this Vault value (every archive consults them, and a Vault lives
// for one command or one service operation). Records change only through
// the package functions in this file, which never run on a Vault a caller
// is still writing through.
func (v *Vault) lostKeyCopies() (*lostKeyCopies, error) {
	v.lost.mu.Lock()
	defer v.lost.mu.Unlock()
	if v.lost.copies == nil && v.lost.err == nil {
		v.lost.copies, v.lost.err = loadLostKeyCopies(v.Root)
	}
	return v.lost.copies, v.lost.err
}

// lostKeyCache holds a Vault's lost-key records (Vault.lostKeyCopies).
type lostKeyCache struct {
	mu     sync.Mutex
	copies *lostKeyCopies
	err    error
}

// SealedToLostKey returns the live vault paths (as List names them) whose
// envelopes are still sealed to a lost Secure Enclave key, sorted. It reads
// files only: no key, no prompt. Archived versions under _history/ are not
// counted: they are kept, never pending.
//
// Empty when no lost key's file is set aside. known is false when the file
// is there without a snapshot (a vault set aside by a jit older than the
// snapshot) or with an incomplete one: then every stored path is returned,
// because jit cannot tell which of them the current key opens, and claiming
// none would hide the loss. An envelope that cannot be read to compare is
// counted as still sealed, for the same reason.
//
// A snapshot that is there but unreadable or corrupt is an error, never
// "no snapshot": the caller must report the restore as pending and say it
// could not check, and nothing may be settled on it.
func SealedToLostKey(root string) (paths []string, known bool, err error) {
	if _, err := os.Lstat(filepath.Join(root, LostSealedKeyFile)); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, true, nil
		}
		return nil, false, fmt.Errorf("checking for a lost vault key: %w", err)
	}
	return sealedToLostKey(root)
}

// sealedToLostKey is SealedToLostKey once LostSealedKeyFile is known to be
// there. Only the current record counts: a retired key's secrets were
// settled when it was retired.
func sealedToLostKey(root string) (paths []string, known bool, err error) {
	v := &Vault{Root: root}
	current, err := v.List()
	if err != nil {
		return nil, false, err
	}
	rec := loadLostKeyRecord(root, "")
	switch {
	case errors.Is(rec.err, fs.ErrNotExist):
		return current, false, nil
	case rec.err != nil:
		return nil, false, rec.err
	case rec.snap.Incomplete != "":
		return current, false, nil
	}
	copies := newLostKeyCopies([]lostKeyRecord{rec})
	for _, p := range current {
		file, err := sanitizeSecretPath(v.vaultDir(), p)
		if err != nil || copies.matchFile(v.vaultDir(), file) != notLost {
			paths = append(paths, p)
		}
	}
	sort.Strings(paths)
	return paths, true, nil
}

// LostKeySettle is what SettleLostKey did.
type LostKeySettle struct {
	// Remaining lists the live secrets still sealed to the lost key; when
	// it is set nothing was settled.
	Remaining []string
	// Settled: the lost key's files were retired just now.
	Settled bool
	// Unchecked: an import settled a lost key that had no usable snapshot,
	// so jit could not check that the recovery file held every secret.
	Unchecked bool
}

// SettleLostKey is called after a successful `jit vault import` (imported
// true) or `jit vault rm` (false). When no live secret is left sealed to
// the lost key, it retires the lost key's sealed file and snapshot
// (renamed with a timestamp, never deleted). When some are left, it
// changes nothing and returns them, so the caller can name what the
// recovery file did not hold.
//
// A lost key with no snapshot, or an incomplete one, counts every secret
// as left. An import settles it anyway: nothing can tell which secrets the
// import covered, and keeping the state would leave it pending forever;
// Unchecked says so. A removal settles it only once the vault holds no
// secret at all.
//
// A snapshot that is there but cannot be read settles nothing: that is an
// error, never "no snapshot" (FinishLostKeyRestore is the way out).
func SettleLostKey(root string, now time.Time, imported bool) (LostKeySettle, error) {
	if _, err := os.Lstat(filepath.Join(root, LostSealedKeyFile)); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return LostKeySettle{}, nil
		}
		return LostKeySettle{}, fmt.Errorf("checking for a lost vault key: %w", err)
	}
	left, known, err := sealedToLostKey(root)
	if err != nil {
		return LostKeySettle{}, err
	}
	if len(left) > 0 && (known || !imported) {
		return LostKeySettle{Remaining: left}, nil
	}
	if err := retireLostKey(root, now); err != nil {
		return LostKeySettle{}, err
	}
	return LostKeySettle{Settled: true, Unchecked: !known && imported}, nil
}

// retireLostKey renames the current lost key's sealed file and snapshot
// with a timestamp. Never a delete.
func retireLostKey(root string, now time.Time) error {
	suffix := retiredSuffix(now)
	for _, name := range []string{LostSealedKeyFile, lostKeySnapshotFile} {
		old := filepath.Join(root, name)
		if err := os.Rename(old, old+suffix); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("retiring the lost key's %s: %w", name, err)
		}
	}
	return nil
}

// LostKeyFinish is what `jit vault import --finish` would do, and did.
type LostKeyFinish struct {
	// Pending: a lost key's file is set aside. False means there is nothing
	// to finish.
	Pending bool
	// Remaining: the record is readable and lists these live secrets as
	// still sealed to the lost key. Finish refuses: an import or `jit vault
	// rm` is the way, and the record can prove when they are done.
	Remaining []string
	// Unverified says why jit cannot check which secrets are still sealed
	// to the lost key (the record unreadable or missing, a walk that saw
	// only part of the vault, or the vault itself unreadable). Empty when
	// the record could check, and found nothing left.
	Unverified string
	// MayBeSealed lists the live secrets last written at or before the key
	// was set aside, which may still be sealed to it; SetAsideKnown is false
	// when jit can't tell when that was, and then any secret may be.
	MayBeSealed   []string
	SetAsideKnown bool
	// Settled: the lost key's files were retired (FinishLostKeyRestore).
	Settled bool
}

// PlanLostKeyFinish reports what FinishLostKeyRestore would do, changing
// nothing. Files only, no key.
func PlanLostKeyFinish(root string) (LostKeyFinish, error) {
	if _, err := os.Lstat(filepath.Join(root, LostSealedKeyFile)); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return LostKeyFinish{}, nil
		}
		return LostKeyFinish{}, fmt.Errorf("checking for a lost vault key: %w", err)
	}
	plan := LostKeyFinish{Pending: true}
	left, known, err := sealedToLostKey(root)
	switch {
	case err == nil && known && len(left) > 0:
		plan.Remaining = left
		return plan, nil
	case err == nil && known:
		return plan, nil
	case err != nil:
		plan.Unverified = err.Error()
	default:
		rec := loadLostKeyRecord(root, "")
		switch {
		case rec.err != nil:
			plan.Unverified = "the lost key was set aside with no record of its secrets"
		default:
			plan.Unverified = "the record of the lost key's secrets covers only part of the vault: " + rec.snap.Incomplete
		}
	}
	rec := loadLostKeyRecord(root, "")
	plan.SetAsideKnown = rec.upTo != math.MaxInt64
	v := &Vault{Root: root}
	live, listErr := v.List()
	if listErr != nil {
		plan.SetAsideKnown = false
		return plan, nil
	}
	for _, p := range live {
		file, err := sanitizeSecretPath(v.vaultDir(), p)
		if err != nil {
			plan.MayBeSealed = append(plan.MayBeSealed, p)
			continue
		}
		info, err := os.Stat(file)
		if err != nil || info.ModTime().UnixNano() <= rec.upTo {
			plan.MayBeSealed = append(plan.MayBeSealed, p)
		}
	}
	return plan, nil
}

// FinishLostKeyRestore settles a lost key's restore on the user's word,
// for when the record cannot (unreadable, missing, or covering only part
// of the vault): it retires the lost key's sealed file and record, renamed
// with a timestamp, never deleted, and returns the plan it acted on so the
// caller can say what it could not verify. It refuses, changing nothing,
// when the record is readable and still lists live secrets (Remaining).
//
// A retired record keeps its promises (lostKeyCopies): history keeps what
// may be sealed to it, and rekey still stops on anything it can't prove.
func FinishLostKeyRestore(root string, now time.Time) (LostKeyFinish, error) {
	plan, err := PlanLostKeyFinish(root)
	if err != nil || !plan.Pending || len(plan.Remaining) > 0 {
		return plan, err
	}
	if err := retireLostKey(root, now); err != nil {
		return plan, err
	}
	plan.Settled = true
	return plan, nil
}
