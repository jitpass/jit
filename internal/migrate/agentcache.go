// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strings"

	"github.com/jitpass/jit/internal/audit"
	"github.com/jitpass/jit/internal/vault"
)

// The write half of internal/audit/agentcache.go: `jit scan` reports that an
// AI agent kept a verbatim copy of a credential, and this removes the copy.
//
// It exists because `jit migrate` currently tells a true but incomplete story.
// It vaults the value, rewrites the .env, and reports success, while nine
// plaintext copies of the same credential sit in ~/.claude/file-history from
// the days the agent edited that file. The scanner already says so, and says
// out loud that migrate will not clean them. This closes that.
//
// Scope is the values THIS run vaulted, never the whole vault. The
// authentication the user gave authorised vaulting these secrets; decrypting
// every secret they own for a sweep they did not ask for is the blast-radius
// growth the broker architecture exists to prevent, and `jit migrate
// token.txt` rewriting dozens of unrelated agent files would break the
// "guided fix path for the thing you pointed it at" contract. The
// sweep-everything form belongs to an explicitly-consented command, where
// that IS the stated purpose.
//
// Three rules the shell-history redactor did not need:
//
//   - Binary stores are REPORTED, never rewritten. A marker is a different
//     length than the credential it replaces, and a length change inside a
//     SQLite page invalidates the offsets around it; OpenCode ships an
//     opencode.db and Cursor keeps chat in a state.vscdb. Same-length
//     overwriting would be structurally valid and is still wrong here, because
//     the WAL holds a second copy and the owning process holds a page cache.
//     A copy jit cannot safely remove is named, so the user can decide.
//
//   - A file being written WHILE we work on it is skipped, not raced. Agent
//     transcripts are appended to live. The rewrite lands by rename, which
//     replaces the path: an agent holding the old descriptor keeps appending
//     to an unlinked inode and loses everything it writes after the swap.
//     Stat before and after building the replacement, and skip on any
//     movement.
//
//   - Needles are spliced longest-first. A vaulted DATABASE_URL can contain a
//     separately-vaulted password as a substring, and splicing the short one
//     first leaves the long one's span pointing into a marker.

// AgentCacheSecret is one credential this migrate run vaulted, with the vault
// variable holding it. The variable name goes into the marker left behind, so
// the file itself documents where the value went.
type AgentCacheSecret struct {
	Value string
	Var   string
}

// AgentCacheEdit is one cache file jit rewrote.
type AgentCacheEdit struct {
	Path        string
	Agent       string
	Area        string
	Occurrences int
	BackupPath  string
}

// AgentCacheSkip is one cache file jit found a credential in and deliberately
// did not touch, with the reason in the user's terms.
type AgentCacheSkip struct {
	Path   string
	Agent  string
	Area   string
	Reason string
}

// AgentCacheCleanup is the result of one sweep.
type AgentCacheCleanup struct {
	Edited  []AgentCacheEdit
	Skipped []AgentCacheSkip
}

// Occurrences totals the credential spans removed.
func (c AgentCacheCleanup) Occurrences() int {
	n := 0
	for _, e := range c.Edited {
		n += e.Occurrences
	}
	return n
}

// maxAgentCacheEditSize bounds a file this will rewrite. Well above any
// transcript measured (22 MiB), and a file past it is reported rather than
// silently passed over.
const maxAgentCacheEditSize = 64 << 20

// eligibleAgentNeedles drops values that must never be searched for.
//
// A marker jit itself wrote is the case that matters: after one sweep the
// string "<jit:redacted:STRIPE_KEY>" exists in every file that was cleaned, so
// admitting it as a needle on a later run would have jit hunting its own
// handiwork and splicing markers into markers. The length floor mirrors
// audit's eligibleNeedle for the same reason it exists there: a short value
// matches everywhere and turns one credential into a thousand edits.
func eligibleAgentNeedles(secrets []AgentCacheSecret) []AgentCacheSecret {
	var out []AgentCacheSecret
	seen := map[string]bool{}
	for _, s := range secrets {
		if len(s.Value) < 12 || seen[s.Value] {
			continue
		}
		if strings.Contains(s.Value, historyRedactedPrefix) {
			continue
		}
		if strings.ContainsAny(s.Value, " \t\r\n") {
			continue
		}
		seen[s.Value] = true
		out = append(out, s)
	}
	// Longest first: a needle that contains another must claim its span before
	// the shorter one can splice inside it.
	sort.SliceStable(out, func(a, b int) bool { return len(out[a].Value) > len(out[b].Value) })
	return out
}

// PreviewAgentCaches reports what CleanAgentCaches would do, without touching
// anything. `jit migrate --dry-run` promises the plan is what a real run would
// do, so this shares the discovery half rather than re-deriving it.
func PreviewAgentCaches(home string, secrets []AgentCacheSecret) (AgentCacheCleanup, error) {
	return sweepAgentCaches(nil, home, secrets, false)
}

// CleanAgentCaches removes verbatim copies of the given credentials from every
// AI agent cache under home, replacing each with a marker naming the vault
// variable that now holds the value.
//
// Order matches every other Apply* in this package: the encrypted backup lands
// before the file is touched, so a failure partway never leaves a cache file
// altered with nothing to restore. The rewrite is atomic (temp file + rename
// in the same directory) and preserves the permission bits.
func CleanAgentCaches(v *vault.Vault, home string, secrets []AgentCacheSecret) (AgentCacheCleanup, error) {
	return sweepAgentCaches(v, home, secrets, true)
}

func sweepAgentCaches(v *vault.Vault, home string, secrets []AgentCacheSecret, apply bool) (AgentCacheCleanup, error) {
	var out AgentCacheCleanup
	needles := eligibleAgentNeedles(secrets)
	if len(needles) == 0 {
		return out, nil
	}

	note := func(path, reason string) {
		out.Skipped = append(out.Skipped, AgentCacheSkip{
			Path:   path,
			Agent:  audit.AgentLabelForPath(home, path),
			Area:   audit.AgentCacheArea(home, path),
			Reason: reason,
		})
	}

	err := audit.WalkAgentCaches(home, func(path string, d fs.DirEntry) error {
		info, err := d.Info()
		if err != nil {
			return nil
		}
		if info.Size() > maxAgentCacheEditSize {
			return nil // too big to hold a credential we can act on; audit reports it
		}
		data, err := os.ReadFile(path) // #nosec G304 -- a path from audit's own agent-cache walk
		if err != nil {
			return nil
		}
		spans := agentNeedleSpans(data, needles)
		if len(spans) == 0 {
			return nil
		}
		// Binary content is reported, never rewritten. See the package note.
		head := data
		if len(head) > 512 {
			head = head[:512]
		}
		if bytes.IndexByte(head, 0) >= 0 {
			note(path, "a binary store; rewriting it would corrupt the file")
			return nil
		}
		if err := refuseMultiplyLinked(info, path); err != nil {
			note(path, "it has more than one hard link, so rewriting one name would leave the credential readable through the other")
			return nil
		}
		if !apply {
			out.Edited = append(out.Edited, AgentCacheEdit{
				Path:        path,
				Agent:       audit.AgentLabelForPath(home, path),
				Area:        audit.AgentCacheArea(home, path),
				Occurrences: len(spans),
			})
			return nil
		}

		redacted := spliceAgentSpans(data, spans)

		// The live-writer check. Between the read above and the rename below an
		// agent may have appended to this file; the rename would then replace
		// the path under a process still holding the old descriptor, and
		// everything it wrote after our read is lost with the unlinked inode.
		// Cheap stat comparison rather than anything cleverer: per CLAUDE.md,
		// reader identification explains and audits, it never decides.
		after, err := os.Lstat(path)
		if err != nil || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
			note(path, "the agent wrote to it while jit was working; left alone")
			return nil
		}

		backupPath, err := backupSecretBytes(v, path, data)
		if err != nil {
			return fmt.Errorf("backing up %s: %w", path, err)
		}
		if err := replaceShellHistory(path, redacted, info.Mode().Perm()); err != nil {
			return fmt.Errorf("rewriting %s: %w", path, err)
		}
		out.Edited = append(out.Edited, AgentCacheEdit{
			Path:        path,
			Agent:       audit.AgentLabelForPath(home, path),
			Area:        audit.AgentCacheArea(home, path),
			Occurrences: len(spans),
			BackupPath:  backupPath,
		})
		return nil
	})
	return out, err
}

// agentSpan is one credential occurrence in a cache file.
type agentSpan struct {
	start, end int
	varName    string
}

// agentNeedleSpans returns every occurrence of every needle, in file order,
// with overlaps resolved first-claim-wins. needles arrive longest-first, so
// the longer of two overlapping credentials wins its span.
func agentNeedleSpans(data []byte, needles []AgentCacheSecret) []agentSpan {
	var spans []agentSpan
	claimed := func(lo, hi int) bool {
		for _, s := range spans {
			if lo < s.end && s.start < hi {
				return true
			}
		}
		return false
	}
	for _, n := range needles {
		nb := []byte(n.Value)
		for off := 0; ; {
			i := bytes.Index(data[off:], nb)
			if i < 0 {
				break
			}
			lo := off + i
			hi := lo + len(nb)
			if !claimed(lo, hi) {
				spans = append(spans, agentSpan{start: lo, end: hi, varName: n.Var})
			}
			off = hi
		}
	}
	sort.Slice(spans, func(a, b int) bool { return spans[a].start < spans[b].start })
	return spans
}

// spliceAgentSpans copies data forward, replacing each credential span with a
// marker naming the vault variable that holds it. Splice, never re-serialise:
// a transcript is JSONL, a file-history entry is a copy of whatever the user
// was editing, and a rewrite that parsed and re-emitted either would have to
// prove it round-trips byte-for-byte. Every other byte is copied untouched.
func spliceAgentSpans(data []byte, spans []agentSpan) []byte {
	var out bytes.Buffer
	out.Grow(len(data))
	prev := 0
	for _, s := range spans {
		if s.start < prev || s.end > len(data) {
			continue // belt and braces on the ordering agentNeedleSpans guarantees
		}
		out.Write(data[prev:s.start])
		out.WriteString(historyRedactedPrefix + s.varName + historyRedactedSuffix)
		prev = s.end
	}
	out.Write(data[prev:])
	return out.Bytes()
}
