// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"github.com/jitpass/jit/internal/audit"
)

// RedactAgentCacheShapes is `jit migrate redact`: the Protect half of the
// scan's shape sweep over agent caches (audit/agentcachepatterns.go). The
// value sweep (CleanAgentCaches) removes copies of secrets the vault holds;
// this removes tokens the scan recognised by their format — a Notion key
// pasted into a prompt, a Stripe key in a snapshot — that were never
// vaulted, replacing each span with <jit:redacted:VENDOR NAME>, the same
// marker the value sweep writes with a variable's name.
//
// No vault, no backup, no prompt — decided 2026-09-21. A backup here would
// store an agent's whole transcript, token and all, in the vault the user
// never chose to put it in, and opening the vault for it is the one thing
// that would keep this from running unattended after a scheduled scan. The
// marker is the record of what was there; the change is one-way, and the
// command says so before it acts.
//
// Everything else matches the value sweep: agent caches only (never a file
// of the user's), the guarded read, the size bound, a binary store reported
// and never rewritten, a multiply-linked file left alone, a file the agent
// wrote to between the read and the rewrite left alone, an atomic rename
// that keeps the permission bits, and bytes outside the spans copied
// untouched.
//
// `only` limits the sweep to those files (absolute paths); nil is every
// cache. `lines` limits it further to tokens on those 1-based lines, for a
// Redact… on one row of the app; nil is every line. `apply` false plans.
func RedactAgentCacheShapes(home string, only []string, lines []int, apply bool) (AgentCacheCleanup, error) {
	var out AgentCacheCleanup
	wanted := map[string]bool{}
	for _, p := range only {
		wanted[filepath.Clean(p)] = true
	}
	wantedLine := map[int]bool{}
	for _, l := range lines {
		wantedLine[l] = true
	}
	note := func(path, reason string, kind SkipKind) {
		out.Skipped = append(out.Skipped, AgentCacheSkip{
			Path:   path,
			Agent:  audit.AgentLabelForPath(home, path),
			Area:   audit.AgentCacheArea(home, path),
			Reason: reason,
			Kind:   kind,
		})
	}

	err := audit.WalkAgentCaches(home, func(path string, d fs.DirEntry) error {
		if len(wanted) > 0 && !wanted[filepath.Clean(path)] {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		data, err := audit.ReadCacheFileGuarded(path)
		if err != nil {
			return nil
		}
		if len(data) > maxAgentCacheEditSize {
			return nil
		}
		tokens := audit.CachePatternTokens(data)
		if len(wantedLine) > 0 {
			kept := tokens[:0]
			for _, tk := range tokens {
				if wantedLine[tk.Line] {
					kept = append(kept, tk)
				}
			}
			tokens = kept
		}
		if len(tokens) == 0 {
			return nil
		}
		head := data
		if len(head) > 512 {
			head = head[:512]
		}
		if bytes.IndexByte(head, 0) >= 0 {
			note(path, "a binary store; rewriting it would corrupt the file", SkipBinary)
			return nil
		}
		if err := refuseMultiplyLinked(info, path); err != nil {
			note(path, "it has more than one hard link, so rewriting one name would leave the token readable through the other", SkipHardLink)
			return nil
		}
		edit := AgentCacheEdit{
			Path:        path,
			Agent:       audit.AgentLabelForPath(home, path),
			Area:        audit.AgentCacheArea(home, path),
			Occurrences: len(tokens),
		}
		if !apply {
			out.Edited = append(out.Edited, edit)
			return nil
		}
		spans := make([]agentSpan, 0, len(tokens))
		for _, tk := range tokens {
			spans = append(spans, agentSpan{start: tk.Start, end: tk.End, varName: tk.Vendor})
		}
		sort.Slice(spans, func(a, b int) bool { return spans[a].start < spans[b].start })
		redacted := spliceAgentSpans(data, spans)
		after, err := os.Lstat(path)
		if err != nil || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
			note(path, "the agent wrote to it while jit was working; left alone", SkipLive)
			return nil
		}
		if err := replaceShellHistory(path, redacted, info.Mode().Perm()); err != nil {
			return fmt.Errorf("rewriting %s: %w", path, err)
		}
		out.Edited = append(out.Edited, edit)
		return nil
	})
	return out, err
}
