// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"sort"
	"strings"
)

// This file is the audit side of `jit migrate --clean`
// (design/migrate-clean.md): the classification that decides which findings
// are delete-class, shared with the triage renderer's own precedence so the
// red section and migrate's clean plan can never disagree about what deletion
// is the remedy for. Classification only — this package stays read-only in
// every mode; the consent, verification and the delete itself live in
// internal/migrate and internal/cli.

// CleanClass says which `jit migrate --clean` shape a finding falls into, or
// CleanNone for the (default) findings the clean pass must never touch.
type CleanClass string

const (
	// CleanNone: not a clean candidate. The zero value on purpose, so every
	// finding type this file never heard of is out until argued in.
	CleanNone CleanClass = ""
	// CleanTrash: the file sits under a Trash directory. The user already
	// decided it should not exist; finishing the deletion is the remedy the
	// report states today (kindTrash), and no vault check gates it.
	CleanTrash CleanClass = "trash"
	// CleanAgentLeftover: a secret-holding file inside an AI agent's
	// file-shaped cache (paste-cache, shell snapshots, agent-made backups).
	// remedy.go already rules these "something to delete, not to relocate";
	// deletion is gated on every detected value being in the vault.
	CleanAgentLeftover CleanClass = "agent"
	// CleanArchivedCopy: a copy under an archive/backup folder whose live
	// original may already be protected. Deletion is gated on every detected
	// value being in the vault (archivedDeletionNote's "already protected the
	// live copy?" test, made checkable — see agentcache.go's note that this
	// question is answerable only with vault access, which scan does not have).
	CleanArchivedCopy CleanClass = "archived"
)

// CleanClassOf classifies one finding for `jit migrate --clean`. The branch
// order mirrors manualAction's (trash before archived, because every trash
// path also looks archived); TestCleanClassAgreesWithTriage pins the two
// together.
//
// Deliberate exclusions, each a decision from design/migrate-clean.md:
//   - agent_cached_secret: a verbatim copy inside a text file redaction can
//     splice — the cache sweep's job, and deletion would take the agent's
//     undo history with it (migrate/agentcache.go).
//   - shell history: line-granular, redaction's job; the file is live and
//     the shell rewrites it on exit.
//   - private keys outside the Trash: rotation is the fix, the body is never
//     vaulted, and a half-fix that deletes without revoking must not be
//     automated. In the Trash the user already condemned the file, and the
//     result output carries the rotation caveat.
//   - agent credential stores (hosts.json, auth.json, …): the tool's live
//     sign-in, not a leftover — AgentSweepDirFile excludes them by listing
//     only the sweep DIRECTORIES.
func CleanClassOf(home string, f Finding) CleanClass {
	if !CountedAsSecret(f) || f.FilePath == "" {
		return CleanNone
	}
	if f.FindingType == FindingTypeAgentCachedSecret ||
		f.FindingType == FindingTypeShellHistorySecret {
		return CleanNone
	}
	switch {
	case InTrash(f.FilePath):
		return CleanTrash
	case AgentSweepDirFile(home, f.FilePath):
		return CleanAgentLeftover
	case f.Archived && f.FindingType != FindingTypePrivateKeyRisk:
		return CleanArchivedCopy
	}
	return CleanNone
}

// AgentSweepDirFile reports whether path lies strictly inside one of the
// agent cache sweep directories (agentCacheSweepDirs) — the file-shaped
// caches whose contents exist only as copies. It is deliberately narrower
// than AgentLabelForPath: an agent's credential store or transcript tree is
// inside an agent root too, and must never read as a deletable leftover.
func AgentSweepDirFile(home, path string) bool {
	rel := strings.TrimPrefix(strings.TrimPrefix(path, home), string(filepath.Separator))
	for _, dir := range agentCacheSweepDirs {
		if strings.HasPrefix(rel, dir+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// FileSecretDigests is SecretDigestsByFile's per-file result: the sha256 hex
// digests of every credential value scan detected in the file, and whether
// that set is complete. Complete is false when any counted finding for the
// file contributed no value (a file-presence finding whose per-value parse
// claimed nothing) — a file the clean pass cannot prove redundant and so
// must leave alone.
type FileSecretDigests struct {
	Digests  []string
	Complete bool
}

// SecretDigestsByFile exports, per file path, digests of the secret values
// the findings carry — the raw values themselves stay unexported
// (Finding.rawValue's contract holds: nothing here can reach encoding/json,
// and no plaintext crosses the package boundary). Digest equality is value
// equality, which is all `jit migrate --clean`'s verifier needs: it digests
// the vault's plaintext on its own, authenticated side and compares.
//
// In-process only by construction — the digests are unsalted, so they must
// never be serialized (the offline-dictionary concern that keeps cause_group
// salted, remedy.go).
func SecretDigestsByFile(findings []Finding) map[string]FileSecretDigests {
	type acc struct {
		digests    map[string]bool
		incomplete bool
	}
	byFile := map[string]*acc{}
	for _, f := range findings {
		if !CountedAsSecret(f) || f.FilePath == "" {
			continue
		}
		a := byFile[f.FilePath]
		if a == nil {
			a = &acc{digests: map[string]bool{}}
			byFile[f.FilePath] = a
		}
		contributed := false
		if f.rawValueDigest != "" {
			a.digests[f.rawValueDigest] = true
			contributed = true
		}
		for _, cv := range f.claimedRawValues {
			sum := sha256.Sum256([]byte(cv.Value))
			a.digests[hex.EncodeToString(sum[:])] = true
			contributed = true
		}
		if !contributed {
			a.incomplete = true
		}
	}
	out := make(map[string]FileSecretDigests, len(byFile))
	for path, a := range byFile {
		fd := FileSecretDigests{Complete: !a.incomplete}
		for d := range a.digests {
			fd.Digests = append(fd.Digests, d)
		}
		sort.Strings(fd.Digests)
		out[path] = fd
	}
	return out
}
