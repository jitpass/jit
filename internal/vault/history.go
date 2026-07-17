// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Version history: overwriting a secret used to destroy the old value
// permanently — `jit vault set` even warned "the current value can't be
// recovered afterward" — which turns a botched token rotation (new token
// stored, old one revoked... no wait, NOT yet revoked, and now gone) into
// a real loss. Set now archives the outgoing envelope under
// _history/<path>/<archive-stamp>.enc first, bounded to the newest
// HistoryKeep per secret.
//
// Everything here moves envelope files whole and never decrypts: a v2
// envelope's payload is AAD-bound to its LIVE path (envelopeAAD), so the
// archived bytes decrypt if and only if they're sitting back at the path
// they were written for — re-encrypting on restore would both need a
// KeyWrapper (a prompt) and break that binding's audit value. Restore is
// therefore a rename, exactly like `jit migrate undo`'s byte-for-byte
// promise, and the archived file keeps proving where it belongs.
//
// _history/ is jit's own bookkeeping, like _backups/: excluded from List
// (and with it export and completion), surfaced only through
// HistoryVersions / `jit vault history`.

const (
	// historyDirName lives directly under vault/ alongside the secrets it
	// shadows and _backups/.
	historyDirName = "_history"
	// HistoryKeep bounds versions kept per secret. Five covers "the last
	// few rotations" without ever letting a set-in-a-loop script grow the
	// vault without bound.
	HistoryKeep = 5
)

// HistoryVersion is one archived version of a secret, described without
// decrypting it (same contract as SecretInfo).
type HistoryVersion struct {
	// ArchiveStamp identifies this version — the UnixNano of the moment it
	// was archived, which is also its filename. Opaque handle for Restore.
	ArchiveStamp int64
	// Version/CreatedUnix/UpdatedUnix are the archived envelope's own
	// claims; zero timestamps mean a v1 envelope that predates metadata.
	Version     int
	CreatedUnix int64
	UpdatedUnix int64
}

func (v *Vault) historyDir(path string) string {
	return filepath.Join(v.vaultDir(), historyDirName, path)
}

// archiveVersion stores data (an outgoing envelope's raw bytes) as a new
// history version for path, then prunes past HistoryKeep. Called by Set
// with the live file still in place — a crash mid-archive loses nothing.
// _backups/ entries are deliberately never archived: they're already the
// safety copy of something else, and history-of-backups is pure bloat.
func (v *Vault) archiveVersion(path string, data []byte, stamp int64) error {
	if strings.HasPrefix(path, "_backups/") {
		return nil
	}
	dest := filepath.Join(v.historyDir(path), fmt.Sprintf("%d.enc", stamp))
	if err := AtomicWriteFile(dest, data); err != nil {
		return fmt.Errorf("archiving previous version of %s: %w", path, err)
	}
	return v.pruneHistory(path)
}

// pruneHistory drops the oldest versions past HistoryKeep. Best-effort on
// the removes themselves — a leftover extra version is untidy, not wrong.
func (v *Vault) pruneHistory(path string) error {
	stamps, err := v.historyStamps(path)
	if err != nil {
		return err
	}
	for _, s := range stamps[:max(0, len(stamps)-HistoryKeep)] {
		_ = os.Remove(filepath.Join(v.historyDir(path), fmt.Sprintf("%d.enc", s)))
	}
	return nil
}

// historyStamps returns path's archive stamps, oldest first. A missing
// history directory is simply zero versions.
func (v *Vault) historyStamps(path string) ([]int64, error) {
	entries, err := os.ReadDir(v.historyDir(path))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("listing history for %s: %w", path, err)
	}
	var stamps []int64
	for _, e := range entries {
		name, ok := strings.CutSuffix(e.Name(), ".enc")
		if e.IsDir() || !ok {
			continue
		}
		stamp, err := strconv.ParseInt(name, 10, 64)
		if err != nil {
			continue // not a version file jit wrote; leave it alone
		}
		stamps = append(stamps, stamp)
	}
	sort.Slice(stamps, func(i, j int) bool { return stamps[i] < stamps[j] })
	return stamps, nil
}

// HistoryVersions lists path's archived versions, NEWEST first (the order
// a human asks "what were the last few values" in). Never decrypts, never
// prompts — same contract as List/Info.
func (v *Vault) HistoryVersions(path string) ([]HistoryVersion, error) {
	if _, err := sanitizeSecretPath(v.vaultDir(), path); err != nil {
		return nil, err
	}
	stamps, err := v.historyStamps(path)
	if err != nil {
		return nil, err
	}
	out := make([]HistoryVersion, 0, len(stamps))
	for i := len(stamps) - 1; i >= 0; i-- {
		hv := HistoryVersion{ArchiveStamp: stamps[i]}
		if data, err := os.ReadFile(filepath.Join(v.historyDir(path), fmt.Sprintf("%d.enc", stamps[i]))); err == nil { // #nosec G304 -- jit's own history dir, stamp parsed from its own filenames
			var env envelope
			if json.Unmarshal(data, &env) == nil {
				hv.Version = env.Version
				hv.CreatedUnix = env.CreatedUnix
				hv.UpdatedUnix = env.UpdatedUnix
			}
		}
		out = append(out, hv)
	}
	return out, nil
}

// Restore brings an archived version of path back as its live value.
// stamp names which version (from HistoryVersions); 0 means the newest.
// The currently-live envelope, if any, is archived first — a restore is
// itself restorable, so flipping between two versions can never lose
// either. The restored version leaves history (it's live now).
//
// Never decrypts and never touches the KeyWrapper — see the file comment
// for why moving bytes is the only correct mechanics here. The CLI layer
// adds its own fresh-auth speed bump for the same reason `jit migrate
// remove` does (GAPS.md #60): a mutation this consequential must not ride
// silently on a cached session.
func (v *Vault) Restore(path string, stamp int64) error {
	dest, err := sanitizeSecretPath(v.vaultDir(), path)
	if err != nil {
		return err
	}

	stamps, err := v.historyStamps(path)
	if err != nil {
		return err
	}
	if len(stamps) == 0 {
		return fmt.Errorf("no history kept for %s", path)
	}
	if stamp == 0 {
		stamp = stamps[len(stamps)-1]
	} else if !slices.Contains(stamps, stamp) {
		return fmt.Errorf("no version %d in %s's history, see `jit vault history %s`", stamp, path, path)
	}
	src := filepath.Join(v.historyDir(path), fmt.Sprintf("%d.enc", stamp))

	// Archive the displaced live value WITHOUT pruning (not via
	// archiveVersion): with history at HistoryKeep capacity, the archive
	// pushes the count past the cap and the oldest entry can be src
	// itself — pruning here deleted the very version being restored, so
	// the rename below failed AND the requested version was gone for
	// good. Prune only after the rename takes src out of history.
	if live, err := os.ReadFile(dest); err == nil { // #nosec G304 -- dest is sanitizeSecretPath's output
		archived := filepath.Join(v.historyDir(path), fmt.Sprintf("%d.enc", nowUnixNano()))
		if err := AtomicWriteFile(archived, live); err != nil {
			return fmt.Errorf("archiving previous version of %s: %w", path, err)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("reading %s: %w", dest, err)
	}

	if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		return fmt.Errorf("creating %s: %w", filepath.Dir(dest), err)
	}
	if err := os.Rename(src, dest); err != nil {
		return fmt.Errorf("restoring %s: %w", path, err)
	}
	// Same durability standard as AtomicWriteFile's own rename: without
	// the directory fsync, a power cut could leave the restore not yet
	// durable (the version would still be safe in history, but the
	// command's success would be a lie).
	syncDir(filepath.Dir(dest))
	// Best-effort, like pruneHistory's own removes: the restore already
	// succeeded, and a leftover extra version is untidy, not wrong.
	_ = v.pruneHistory(path)
	return nil
}

// removeHistory deletes every archived version of path — Remove calls
// this so `jit vault rm` means GONE: leaving recoverable copies behind a
// command whose whole point is deletion would betray it.
func (v *Vault) removeHistory(path string) error {
	if err := os.RemoveAll(v.historyDir(path)); err != nil {
		return fmt.Errorf("removing history for %s: %w", path, err)
	}
	return nil
}

// nowUnixNano stamps a fresh archive entry. Nanoseconds, not seconds:
// two Sets inside the same second (a script re-running `jit vault set`)
// must never collide onto one filename and silently drop a version.
func nowUnixNano() int64 {
	return time.Now().UnixNano()
}
