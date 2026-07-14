// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// lastExportFile is where RecordExport notes when the most recent
// successful `jit vault export` happened. The export file itself lands
// wherever the user pointed it (a USB drive, a synced folder), so jit
// can't stat it later — this marker is what lets `jit status` say
// "you've never exported" or "your newest secret isn't in any export"
// instead of the vault's one disaster-recovery path staying invisible
// until the disaster.
const lastExportFile = "last-export"

// RecordExport stamps now as the most recent successful export time.
// RFC3339Nano, not RFC3339: the staleness comparison is against .enc file
// mtimes, and a second-truncated stamp would call a secret written in the
// same second as the export "not covered" — a false stale-nudge right
// after the user did exactly what the nudge asks.
func RecordExport(root string) error {
	stamp := time.Now().UTC().Format(time.RFC3339Nano) + "\n"
	return AtomicWriteFile(filepath.Join(root, lastExportFile), []byte(stamp))
}

// LastExport returns when the most recent export was recorded, or
// ok=false if none ever was (including exports made by builds that
// predate the marker — an unavoidable false "never" that costs one
// redundant nudge, not data).
func LastExport(root string) (at time.Time, ok bool, err error) {
	data, err := os.ReadFile(filepath.Join(root, lastExportFile)) // #nosec G304 -- fixed, well-known path under jit's own config directory
	if os.IsNotExist(err) {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, fmt.Errorf("reading %s: %w", lastExportFile, err)
	}
	at, err = time.Parse(time.RFC3339Nano, strings.TrimSpace(string(data)))
	if err != nil {
		return time.Time{}, false, fmt.Errorf("parsing %s: %w", lastExportFile, err)
	}
	return at, true, nil
}

// NewestSecretTime returns the modification time of the most recently
// written secret (any .enc file under the vault's secret store), or the
// zero time if the vault is empty — compared against LastExport to
// decide whether the most recent export still covers everything.
func (v *Vault) NewestSecretTime() (time.Time, error) {
	var newest time.Time
	err := filepath.WalkDir(v.vaultDir(), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".enc") {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.ModTime().After(newest) {
			newest = info.ModTime()
		}
		return nil
	})
	if os.IsNotExist(err) {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("scanning vault for newest secret: %w", err)
	}
	return newest, nil
}
