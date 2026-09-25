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
	"sort"
	"strings"
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
//
// Every record, current or retired, keeps two promises for as long as it
// exists (lostKeyCopies):
//
//   - pruneHistory never deletes an archived version sealed to a lost key,
//     and such versions do not take one of the HistoryKeep places.
//   - `jit vault rekey` (Rewrap) leaves an envelope sealed to a lost key
//     untouched and reports it, instead of stopping on it with its marker
//     left behind, which would refuse every vault change.
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
	// file's modification time (presumedSealed).
	SetAsideUnixNano int64 `json:"set_aside_unix_nano"`
	// Files maps every envelope file under vault/, by its slash path
	// relative to vault/ ("aws/key.enc", "_history/aws/key/17….enc"), to
	// the hex SHA-256 of its bytes.
	Files map[string]string `json:"files"`
	// Unknown names envelope files that were there but could not be read.
	Unknown []string `json:"unknown,omitempty"`
	// Incomplete says why the walk could not see every file. A snapshot
	// with it set cannot say which live secrets are fine, so every one
	// counts as pending, exactly as with no snapshot at all.
	Incomplete string `json:"incomplete,omitempty"`
}

const lostKeySnapshotVersion = 1

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
// stops it being used (unreadable, not JSON, another version, no files
// map) wraps errLostKeyRecord.
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
	if snap.Version != lostKeySnapshotVersion || snap.Files == nil {
		return lostKeySnapshot{}, fmt.Errorf("%w: version %d", errLostKeyRecord, snap.Version)
	}
	return snap, nil
}

// presumedSealed: a snapshot that could not hash every file (unknown
// entries, or an incomplete walk) cannot prove which files are sealed to
// the lost key, so a file last written at or before the set-aside is
// presumed to be. A file written since (an import, a set) was sealed to
// the new key; a byte-for-byte restore keeps the archived copy's old time.
func (s lostKeySnapshot) presumedSealed(mod time.Time) bool {
	return (len(s.Unknown) > 0 || s.Incomplete != "") && mod.UnixNano() <= s.SetAsideUnixNano
}

func (s lostKeySnapshot) hashes() map[string]bool {
	set := make(map[string]bool, len(s.Files))
	for _, h := range s.Files {
		set[h] = true
	}
	return set
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
// there.
func sealedToLostKey(root string) (paths []string, known bool, err error) {
	v := &Vault{Root: root}
	current, err := v.List()
	if err != nil {
		return nil, false, err
	}
	snap, err := readLostKeySnapshot(filepath.Join(root, lostKeySnapshotFile))
	if errors.Is(err, fs.ErrNotExist) {
		return current, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if snap.Incomplete != "" {
		return current, false, nil
	}
	recorded := snap.hashes()
	for _, p := range current {
		file, err := sanitizeSecretPath(v.vaultDir(), p)
		if err != nil || envelopeSealedTo(file, recorded, snap.presumedSealed) {
			paths = append(paths, p)
		}
	}
	sort.Strings(paths)
	return paths, true, nil
}

// envelopeSealedTo reports whether file is one of the recorded envelopes:
// its bytes hash to a recorded hash, or presumed says so from its
// modification time. A file that cannot be read counts as sealed.
func envelopeSealedTo(file string, recorded map[string]bool, presumed func(time.Time) bool) bool {
	info, err := os.Stat(file)
	if err != nil {
		return true
	}
	data, err := os.ReadFile(file) // #nosec G304 -- file is under jit's own vault directory
	if err != nil {
		return true
	}
	return recorded[digest(data)] || presumed(info.ModTime())
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
// error, never "no snapshot".
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
	suffix := retiredSuffix(now)
	for _, name := range []string{LostSealedKeyFile, lostKeySnapshotFile} {
		old := filepath.Join(root, name)
		if err := os.Rename(old, old+suffix); err != nil && !errors.Is(err, os.ErrNotExist) {
			return LostKeySettle{}, fmt.Errorf("retiring the lost key's %s: %w", name, err)
		}
	}
	return LostKeySettle{Settled: true, Unchecked: !known && imported}, nil
}

// lostKeyCopies is every record jit holds of envelopes sealed to a lost
// key, the current one and every retired one, for the two promises in the
// file comment: history keeps them, rekey leaves them alone.
type lostKeyCopies struct {
	// any: at least one lost key's file or snapshot exists.
	any bool
	// recorded holds every recorded hash.
	recorded map[string]bool
	// presumeUpTo: a file last written at or before this (Unix
	// nanoseconds) is presumed sealed to a lost key, because some lost key
	// has a record that could not hash everything, or none at all. Zero
	// when every lost key's record is complete.
	presumeUpTo int64
}

// sealed reports whether an envelope with these bytes and this
// modification time is (or is presumed to be) sealed to a lost key.
func (c lostKeyCopies) sealed(data []byte, mod time.Time) bool {
	if !c.any {
		return false
	}
	return c.recorded[digest(data)] || (c.presumeUpTo != 0 && mod.UnixNano() <= c.presumeUpTo)
}

// sealedFile is sealed for a file on disk; one it cannot read counts as
// sealed (kept, never deleted).
func (c lostKeyCopies) sealedFile(file string) bool {
	if !c.any {
		return false
	}
	info, err := os.Stat(file)
	if err != nil {
		return true
	}
	data, err := os.ReadFile(file) // #nosec G304 -- file is under jit's own vault directory
	if err != nil {
		return true
	}
	return c.sealed(data, info.ModTime())
}

// loadLostKeyCopies reads every lost key's record under root.
//
// A lost key's sealed file with no usable snapshot beside it (none, or an
// unreadable one) cannot prove anything, so everything written before it
// was retired (or, while it is current, everything) is presumed sealed to
// it. Presumption only ever keeps a file: history keeps it, rekey leaves
// it untouched when neither key opens it.
func loadLostKeyCopies(root string) (lostKeyCopies, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return lostKeyCopies{}, nil
		}
		return lostKeyCopies{}, fmt.Errorf("looking for a lost vault key: %w", err)
	}
	c := lostKeyCopies{recorded: map[string]bool{}}
	presume := func(upTo int64) {
		c.presumeUpTo = max(c.presumeUpTo, upTo)
	}
	for _, e := range entries {
		name := e.Name()
		suffix, isSealed := strings.CutPrefix(name, LostSealedKeyFile)
		if !isSealed || (suffix != "" && !strings.HasPrefix(suffix, "-")) {
			continue // not a lost key's sealed file (the snapshot shares the prefix: ".envelopes")
		}
		c.any = true
		// The moment up to which files are presumed sealed when this key's
		// record can't say: while current, now and forever; once retired,
		// when it was retired.
		upTo := int64(math.MaxInt64)
		if suffix != "" {
			if t, err := time.Parse(retiredStampLayout, strings.TrimPrefix(suffix, "-")); err == nil {
				upTo = t.UnixNano()
			}
		}
		snap, err := readLostKeySnapshot(filepath.Join(root, lostKeySnapshotFile+suffix))
		if err != nil {
			presume(upTo)
			continue
		}
		for h := range snap.hashes() {
			c.recorded[h] = true
		}
		if len(snap.Unknown) > 0 || snap.Incomplete != "" {
			presume(snap.SetAsideUnixNano)
		}
	}
	return c, nil
}
