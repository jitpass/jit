// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package vault

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
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
//     envelope file on disk at that moment, all of them sealed to the lost
//     key.
//   - SealedToLostKey compares the snapshot with the files now on disk. A
//     rewritten envelope (import, set) has a fresh DEK and so different
//     bytes; a removed one is gone. What is left is exactly what the current
//     key cannot open.
//   - SettleLostKey, after a successful import, retires both files once
//     nothing is left, renaming them with a timestamp. It never deletes
//     them: if the enclave key was reported lost by mistake, the sealed file
//     is the one thing that could still open the old envelopes.
//
// Nothing here removes or rewrites an envelope. An envelope the import did
// not replace stays on disk and keeps the state pending, so the caller can
// name it; deleting it is the user's decision (`jit vault rm`).

// LostSealedKeyFile is where a lost key's sealed file is set aside.
const LostSealedKeyFile = SealedKeyFile + ".lost"

// lostKeySnapshotFile records the envelopes sealed to the lost key.
const lostKeySnapshotFile = LostSealedKeyFile + ".envelopes"

// lostKeySnapshot is lostKeySnapshotFile's JSON: vault path (as List names
// it) to the hex SHA-256 of its envelope file.
type lostKeySnapshot struct {
	Version   int               `json:"version"`
	SetAside  string            `json:"set_aside"`
	Envelopes map[string]string `json:"envelopes"`
}

const lostKeySnapshotVersion = 1

// retiredSuffix names a retired lost-key file by when it was retired, so a
// second loss never overwrites the first one's record.
func retiredSuffix(now time.Time) string {
	return "-" + now.UTC().Format("20060102T150405.000000000Z")
}

// SetAsideLostSealedKey records which envelopes are sealed to the lost key,
// then renames the sealed key file to LostSealedKeyFile. The snapshot is
// written first, so a failure leaves the vault exactly as it was. A lost-key
// file already there (an earlier loss never settled) is retired with a
// timestamp rather than overwritten.
func SetAsideLostSealedKey(root string, now time.Time) error {
	for _, name := range []string{LostSealedKeyFile, lostKeySnapshotFile} {
		old := filepath.Join(root, name)
		if _, err := os.Lstat(old); err == nil {
			if err := os.Rename(old, old+retiredSuffix(now)); err != nil {
				return fmt.Errorf("keeping the earlier lost key's %s: %w", name, err)
			}
		}
	}
	v := &Vault{Root: root}
	paths, err := v.List()
	if err != nil {
		return err
	}
	snap := lostKeySnapshot{
		Version:   lostKeySnapshotVersion,
		SetAside:  now.UTC().Format(time.RFC3339),
		Envelopes: make(map[string]string, len(paths)),
	}
	for _, p := range paths {
		sum, err := v.envelopeDigest(p)
		if err != nil {
			return fmt.Errorf("recording the secrets sealed to the lost key: %w", err)
		}
		snap.Envelopes[p] = sum
	}
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

// envelopeDigest is the hex SHA-256 of path's envelope file.
func (v *Vault) envelopeDigest(path string) (string, error) {
	file, err := sanitizeSecretPath(v.vaultDir(), path)
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(file) // #nosec G304 -- file is sanitizeSecretPath's output
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// SealedToLostKey returns the vault paths whose envelopes are still sealed to
// a lost Secure Enclave key, sorted. It reads files only: no key, no prompt.
//
// Empty when no lost key's file is set aside. known is false when the file
// is there but its snapshot is missing or unreadable (a vault set aside by
// a jit older than the snapshot): then every stored path is returned,
// because jit cannot tell which of them the current key opens, and claiming
// none would hide the loss. An envelope that cannot be read to compare is
// counted as still sealed, for the same reason.
func SealedToLostKey(root string) (paths []string, known bool, err error) {
	if _, err := os.Lstat(filepath.Join(root, LostSealedKeyFile)); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, true, nil
		}
		return nil, false, fmt.Errorf("checking for a lost vault key: %w", err)
	}
	v := &Vault{Root: root}
	current, err := v.List()
	if err != nil {
		return nil, false, err
	}
	snap, ok := readLostKeySnapshot(root)
	if !ok {
		return current, false, nil
	}
	for _, p := range current {
		want, listed := snap.Envelopes[p]
		if !listed {
			continue // written after the key was set aside: the new key's
		}
		got, err := v.envelopeDigest(p)
		if err != nil || got == want {
			paths = append(paths, p)
		}
	}
	sort.Strings(paths)
	return paths, true, nil
}

func readLostKeySnapshot(root string) (lostKeySnapshot, bool) {
	data, err := os.ReadFile(filepath.Join(root, lostKeySnapshotFile)) // #nosec G304 -- fixed name under the vault root
	if err != nil {
		return lostKeySnapshot{}, false
	}
	var snap lostKeySnapshot
	if json.Unmarshal(data, &snap) != nil || snap.Version != lostKeySnapshotVersion || snap.Envelopes == nil {
		return lostKeySnapshot{}, false
	}
	return snap, true
}

// SettleLostKey is called after a successful `jit vault import`. When no
// envelope is left sealed to the lost key, it retires the lost key's sealed
// file and snapshot (renamed with a timestamp, never deleted) and returns
// nothing. When some are left, it changes nothing and returns them, so the
// caller can name what the recovery file did not hold.
//
// A vault set aside without a snapshot (known false in SealedToLostKey) is
// settled by the import itself: nothing can tell which secrets it covered,
// and keeping the state would leave it pending forever. unknown reports
// that case, so the caller can say it could not check.
func SettleLostKey(root string, now time.Time) (remaining []string, unknown bool, err error) {
	left, known, err := SealedToLostKey(root)
	if err != nil {
		return nil, false, err
	}
	if _, statErr := os.Lstat(filepath.Join(root, LostSealedKeyFile)); errors.Is(statErr, os.ErrNotExist) {
		return nil, false, nil
	}
	if known && len(left) > 0 {
		return left, false, nil
	}
	suffix := retiredSuffix(now)
	for _, name := range []string{LostSealedKeyFile, lostKeySnapshotFile} {
		old := filepath.Join(root, name)
		if err := os.Rename(old, old+suffix); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, false, fmt.Errorf("retiring the lost key's %s: %w", name, err)
		}
	}
	return nil, !known, nil
}
