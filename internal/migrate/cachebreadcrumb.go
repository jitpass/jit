// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// The automatic sweep on `jit migrate` skips a cache file an agent is writing
// live (a rename under a live writer would strand its appends). That copy is
// the one the design cannot otherwise recover: once the migration turns the
// origin into a jit://vault pointer, the value is invisible to `jit scan` (no
// needle) and to a future `jit migrate` (nothing new vaulted). The user has to
// come back and run `jit migrate caches` once the session ends.
//
// This breadcrumb is how jit remembers to remind them. It is deliberately the
// thinnest possible note: a count and a time, nothing else. Not a path, not a
// vault name, not a value — a reader of this file learns only "a recent
// migrate left N copies in live sessions", which reveals strictly less than
// the cache file the copy sits in (that file holds the plaintext). This is the
// nudge, NOT a to-do list jit auto-completes: the earlier review rejected a
// persisted work list because completing an entry needs auth and only fires on
// the next migrate, which never comes once everything is migrated. `jit status`
// reads this and suggests the command; `jit migrate caches` clears it.

// cacheBreadcrumbName is the state file's basename under the config root.
const cacheBreadcrumbName = "agent-cache-pending.json"

// CacheBreadcrumb is the whole persisted note. UnixNano dates it so `jit
// status` can phrase the nudge ("a migrate 2 hours ago left…") and so a stale
// crumb is recognisable; Count is how many live-session copies were left.
type CacheBreadcrumb struct {
	UnixNano int64 `json:"unix_nano"`
	Count    int   `json:"count"`
}

func cacheBreadcrumbPath(root string) string {
	return filepath.Join(root, cacheBreadcrumbName)
}

// WriteCacheBreadcrumb records that a migrate left count live-session copies
// behind. A count of zero clears the note instead (see ClearCacheBreadcrumb),
// so the common clean run leaves nothing on disk. Best-effort: a breadcrumb
// that cannot be written is a missed reminder, never a failed migration.
func WriteCacheBreadcrumb(root string, count int, nowUnixNano int64) {
	if count <= 0 {
		ClearCacheBreadcrumb(root)
		return
	}
	data, err := json.Marshal(CacheBreadcrumb{UnixNano: nowUnixNano, Count: count})
	if err != nil {
		return
	}
	_ = os.WriteFile(cacheBreadcrumbPath(root), data, 0o600)
}

// ReadCacheBreadcrumb returns the pending note, or ok=false when there is
// none (the common case) or it cannot be read. Never an error: a reminder that
// cannot be read is simply not shown.
func ReadCacheBreadcrumb(root string) (CacheBreadcrumb, bool) {
	data, err := os.ReadFile(cacheBreadcrumbPath(root)) // #nosec G304 -- fixed name under the config root
	if err != nil {
		return CacheBreadcrumb{}, false
	}
	var c CacheBreadcrumb
	if json.Unmarshal(data, &c) != nil || c.Count <= 0 {
		return CacheBreadcrumb{}, false
	}
	return c, true
}

// ClearCacheBreadcrumb removes the note. Called by `jit migrate caches` after
// it runs: a whole-vault sweep has just given the user the complete current
// picture, so whatever an earlier automatic run deferred is now accounted for.
// Idempotent, and a no-op when nothing is pending.
func ClearCacheBreadcrumb(root string) {
	_ = os.Remove(cacheBreadcrumbPath(root))
}

// Age returns how long ago the breadcrumb was written, for phrasing the nudge.
func (c CacheBreadcrumb) Age(now time.Time) time.Duration {
	return now.Sub(time.Unix(0, c.UnixNano))
}
