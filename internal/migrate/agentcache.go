// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
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

// SkipKind classifies why a copy was left in place, because the three reasons
// call for different follow-ups: a live file is TRANSIENT (re-running once the
// session ends will get it), while a binary store or a hard-linked file is a
// standing condition re-running cannot fix. Only the transient case is worth a
// later nudge.
type SkipKind string

const (
	SkipLive     SkipKind = "live"     // an agent was writing the file; re-run later
	SkipBinary   SkipKind = "binary"   // a store a length-changing edit would corrupt
	SkipHardLink SkipKind = "hardlink" // rewriting one name would leave the other exposed
)

// AgentCacheSkip is one cache file jit found a credential in and deliberately
// did not touch, with the reason in the user's terms.
type AgentCacheSkip struct {
	Path   string
	Agent  string
	Area   string
	Reason string
	Kind   SkipKind
}

// LiveSkips counts the copies left only because a session was live — the ones
// a later `jit migrate caches` will still be able to reach.
func (c AgentCacheCleanup) LiveSkips() int {
	n := 0
	for _, s := range c.Skipped {
		if s.Kind == SkipLive {
			n++
		}
	}
	return n
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
		if seen[s.Value] {
			continue
		}
		// A marker jit itself wrote must never become a needle (see below), and
		// otherwise the bar is audit's own: the exact predicate the scanner
		// uses to decide a value is distinctive enough to hunt copies of, so a
		// redaction needle and a scan needle can never disagree about what is
		// worth searching for. That rules out the short, all-lowercase,
		// all-digit and whitespace-bearing values a naive floor would admit and
		// then match all over 300 MB of prose.
		if strings.Contains(s.Value, historyRedactedPrefix) || !audit.EligibleNeedle(s.Value) {
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
		info, err := d.Info()
		if err != nil {
			return nil
		}
		// Read through audit's guarded open, never os.ReadFile(path): a FIFO
		// swapped into ~/.claude between the dirent and the read would hang
		// jit migrate in open(2) forever, after Touch ID, with the vault
		// unlocked and the migration half-applied. ~/.claude is written by a
		// third-party tool running arbitrary code, so this is not a
		// theoretical adversary. The guard also enforces the size bound on the
		// opened descriptor, where a pre-open stat bounds nothing.
		data, err := audit.ReadCacheFileGuarded(path)
		if err != nil {
			return nil
		}
		if len(data) > maxAgentCacheEditSize {
			return nil // too big to hold a credential we can act on; audit reports it
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
			note(path, "a binary store; rewriting it would corrupt the file", SkipBinary)
			return nil
		}
		if err := refuseMultiplyLinked(info, path); err != nil {
			note(path, "it has more than one hard link, so rewriting one name would leave the credential readable through the other", SkipHardLink)
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
			note(path, "the agent wrote to it while jit was working; left alone", SkipLive)
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

// --- Naming an agent's snapshot of a file ---

// SnapshotOriginHash is the name Claude Code gives its snapshot of the file at
// path: the first 16 hex characters of sha256 over the ABSOLUTE PATH, which
// the on-disk entry then suffixes with "@v1", "@v2", … per session.
//
// Established by measurement (2026-08-06), not from documentation: every one
// of the 1,224 file-history entries on the development machine is explained by
// this rule, cross-referenced against the file paths named in each session's
// own transcript, and a forward prediction for a file created that day found
// its snapshots exactly where the rule said they would be.
//
// Two things follow, and both matter.
//
// The name encodes the PATH, never the content — so rewriting a snapshot to
// remove a credential cannot invalidate its name. That was the open question
// behind "should jit delete these instead of editing them", and the answer is
// that the premise was wrong: there is no name-to-content relationship to
// break, nothing on disk records a checksum, and a redacted snapshot is
// structurally indistinguishable from an untouched one. Redaction keeps the
// agent's undo history intact, where deletion would remove a step of it.
//
// And it runs backwards. Given a file the user is migrating, jit can compute
// the name its snapshots would have and go straight to them, instead of
// reading every file in a 300 MB tree.
func SnapshotOriginHash(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	sum := sha256.Sum256([]byte(abs))
	return hex.EncodeToString(sum[:])[:16]
}

// SnapshotsOf returns every agent snapshot of the file at path, across all
// sessions — the fast path SnapshotOriginHash makes possible.
func SnapshotsOf(home, path string) []string {
	prefix := SnapshotOriginHash(path)
	var out []string
	_ = audit.WalkAgentCaches(home, func(p string, d fs.DirEntry) error {
		name := d.Name()
		if strings.HasPrefix(name, prefix) &&
			(len(name) == len(prefix) || strings.HasPrefix(name[len(prefix):], "@v")) {
			out = append(out, p)
		}
		return nil
	})
	sort.Strings(out)
	return out
}

// CollectVaultSecrets reads every credential currently in the vault and turns
// it into a needle for the cache sweep — the input to a whole-vault
// `jit migrate caches` run, as opposed to the this-run values `jit migrate`
// collects through vault.Vault.OnSet.
//
// This is the only path that reaches a copy the per-run sweep cannot: a
// secret migrated before the sweep existed, one whose live-session transcript
// was skipped and is now a pointer nothing can search for, a wrap-captured
// token vaulted after the run's file sweep had already finished. It holds all
// of the vault's plaintext at once, which is exactly why it belongs behind an
// explicit command with its own fresh-auth prompt and not on the automatic
// path — the authentication is consent for decrypting everything, and the
// caller (jit migrate caches) makes that the stated purpose.
//
// _backups/ and _history/ are jit's own bookkeeping, never a credential the
// user typed; List already omits _history, and this omits _backups so a
// whole-file backup never becomes a needle (the marker naming it would point
// at a prunable bookkeeping entry, not a variable).
func CollectVaultSecrets(v *vault.Vault) ([]AgentCacheSecret, error) {
	paths, err := v.List()
	if err != nil {
		return nil, err
	}
	var out []AgentCacheSecret
	for _, p := range paths {
		if strings.HasPrefix(p, "_backups/") || strings.HasPrefix(p, "_history/") {
			continue
		}
		val, err := v.Get(p)
		if err != nil {
			// One unreadable entry (a torn envelope, a since-removed secret)
			// must not sink a whole-vault sweep; skip it and clean the rest.
			continue
		}
		name := p
		if i := strings.LastIndex(name, "/"); i >= 0 {
			name = name[i+1:]
		}
		out = append(out, AgentCacheSecret{Value: string(val), Var: name})
	}
	return out, nil
}
