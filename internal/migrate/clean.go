// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

// jit migrate --clean (design/migrate-clean.md): the consented delete pass
// for findings whose stated remedy is deletion. This file is the mechanism —
// plan (pre-auth, read-only), verify (post-auth, against the vault's own
// plaintext), execute (encrypted backup, then unlink). Consent, rendering
// and the fresh-auth gate live in internal/cli.
//
// The safety order per file is fixed and load-bearing, same shape as every
// migration in this package: prove redundancy → encrypt a backup into the
// vault and index it for `jit migrate undo` → re-check the bytes are the
// ones the plan showed → only then os.Remove. A failure at any step leaves
// the file exactly where it was.

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"sort"

	"github.com/jitpass/jit/internal/audit"
	"github.com/jitpass/jit/internal/vault"
)

// CleanCandidate is one file the plan proposes deleting. The unexported
// fields are the proof obligations ApplyClean re-checks after consent.
type CleanCandidate struct {
	Path  string
	Class audit.CleanClass

	// digests are the sha256 hex digests of every secret value scan detected
	// in the file — the set that must be covered by the vault before a
	// value-gated class (archived copy, agent leftover) may delete. Empty and
	// unused for CleanTrash: the user already condemned that file.
	digests []string
	// sha256 is the whole file's content hash at plan time. ApplyClean
	// re-reads and re-hashes immediately before the unlink; any mismatch —
	// the user edited it, an agent rewrote it — voids the consent for this
	// file and it is left alone.
	sha256 string
}

// CleanSkip is one file the pass looked at and left alone, with the reason
// in the user's terms. Err marks a failure (backup or unlink error) rather
// than a deliberate refusal; the CLI exits non-zero when any Err row exists.
type CleanSkip struct {
	Path   string
	Reason string
	Err    bool
}

// CleanPlan is what the [y/N] consent covers: delete at most Candidates,
// each only if its post-auth checks still hold. LeftAlone are the plan-time
// refusals, printed so a finding the scan showed never silently vanishes
// from the plan (the printSkippedFindings lesson).
type CleanPlan struct {
	Candidates []CleanCandidate
	LeftAlone  []CleanSkip
}

// CleanDeletion is one file ApplyClean deleted, with the vault path of the
// encrypted backup that makes `jit migrate undo` able to restore it.
type CleanDeletion struct {
	Path       string
	Class      audit.CleanClass
	BackupPath string
}

// CleanOutcome is one apply's result. Deleted and LeftAlone together cover
// every candidate the plan listed — nothing is dropped silently.
type CleanOutcome struct {
	Deleted   []CleanDeletion
	LeftAlone []CleanSkip
}

// Errors reports whether any LeftAlone row is a failure rather than a
// deliberate refusal.
func (o CleanOutcome) Errors() bool {
	for _, s := range o.LeftAlone {
		if s.Err {
			return true
		}
	}
	return false
}

// PlanClean builds the delete plan from one scan's in-process findings.
// Read-only and prompt-free by contract — it runs before consent and before
// any authentication, so it may read candidate files (scan already did) but
// must never touch the vault.
//
// exclude lists files this run's migrate phase will itself act on: a file
// being vaulted must not also be planned for deletion — the migration
// rewrites it, which would void the hash check anyway; excluding it up front
// keeps the plan from promising a delete that can never happen.
//
// A file qualifies only when EVERY counted finding on it agrees on one
// clean class (audit.CleanClassOf). A mixed file — say an archived .env
// that also holds a private key — stays manual exactly as today, because
// the class that would refuse it must win over the one that would not.
func PlanClean(home string, findings []audit.Finding, exclude map[string]bool) CleanPlan {
	var plan CleanPlan
	classes := map[string]map[audit.CleanClass]bool{}
	for _, f := range findings {
		if !audit.CountedAsSecret(f) || f.FilePath == "" {
			continue
		}
		if classes[f.FilePath] == nil {
			classes[f.FilePath] = map[audit.CleanClass]bool{}
		}
		classes[f.FilePath][audit.CleanClassOf(home, f)] = true
	}
	digestsByFile := audit.SecretDigestsByFile(findings)

	paths := make([]string, 0, len(classes))
	for p := range classes {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	for _, path := range paths {
		set := classes[path]
		if len(set) != 1 {
			continue // mixed classes: the refusing finding wins, file stays manual
		}
		var class audit.CleanClass
		for c := range set {
			class = c
		}
		if class == audit.CleanNone || exclude[path] {
			continue
		}

		skip := func(reason string) {
			plan.LeftAlone = append(plan.LeftAlone, CleanSkip{Path: path, Reason: reason})
		}

		info, err := os.Lstat(path)
		if err != nil {
			skip("that couldn't be read")
			continue
		}
		if !info.Mode().IsRegular() {
			skip("that aren't regular files")
			continue
		}

		cand := CleanCandidate{Path: path, Class: class}
		if class != audit.CleanTrash {
			fd, ok := digestsByFile[path]
			if !ok || !fd.Complete || len(fd.Digests) == 0 {
				skip("whose secrets jit couldn't pin one by one")
				continue
			}
			cand.digests = fd.Digests
		}

		// Read through the guarded open (no symlink follow, no FIFO block,
		// size-bounded on the descriptor): candidates live in the Trash and
		// in agent-written directories, both places arbitrary code writes.
		data, err := audit.ReadCacheFileGuarded(path)
		if err != nil {
			skip("that couldn't be read")
			continue
		}
		sum := sha256.Sum256(data)
		cand.sha256 = hex.EncodeToString(sum[:])
		plan.Candidates = append(plan.Candidates, cand)
	}
	return plan
}

// ApplyClean runs the consented plan. It must be called with a fresh-auth
// vault, after the [y/N] and the explicit user-presence challenge — the
// caller owns that ceremony (internal/cli).
//
// runValues are the plaintext values this run's migrate phase vaulted (the
// same set the agent-cache sweep hunts); together with the vault's standing
// secrets they form the proof set for the value-gated classes. swept lists
// files this run's cache sweep already redacted: a redacted file's exposure
// is gone and its bytes no longer match the plan, so it is reported as fixed
// another way, never deleted.
//
// Per-file failures never abort the batch (jit migrate undo's runRestores
// precedent): each candidate ends up in Deleted or LeftAlone, and the caller
// exits non-zero if Outcome.Errors().
func ApplyClean(v *vault.Vault, plan CleanPlan, runValues []AgentCacheSecret, swept map[string]bool) (CleanOutcome, error) {
	var out CleanOutcome
	out.LeftAlone = append(out.LeftAlone, plan.LeftAlone...)

	vaulted, err := vaultValueDigests(v, runValues)
	if err != nil {
		return out, err
	}

	for _, cand := range plan.Candidates {
		skip := func(reason string, isErr bool) {
			out.LeftAlone = append(out.LeftAlone, CleanSkip{Path: cand.Path, Reason: reason, Err: isErr})
		}

		if swept[cand.Path] {
			skip("this run's cache sweep already redacted", false)
			continue
		}
		if cand.Class != audit.CleanTrash && !allDigestsVaulted(cand.digests, vaulted) {
			switch cand.Class {
			case audit.CleanArchivedCopy:
				skip("whose secrets aren't all in the vault yet", false)
			default:
				skip("whose secret isn't in the vault", false)
			}
			continue
		}

		info, err := os.Lstat(cand.Path)
		if os.IsNotExist(err) {
			skip("already deleted", false)
			continue
		}
		if err != nil || !info.Mode().IsRegular() {
			skip("that aren't regular files", false)
			continue
		}
		if err := refuseMultiplyLinked(info, cand.Path); err != nil {
			skip("hard-linked under another name", false)
			continue
		}
		data, err := audit.ReadCacheFileGuarded(cand.Path)
		if err != nil {
			skip("that couldn't be read", false)
			continue
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != cand.sha256 {
			skip("that changed since the plan", false)
			continue
		}

		// Backup strictly before unlink, and the exact bytes just hashed —
		// the byte-for-byte undo promise (backupSecretBytes' contract).
		backupPath, err := backupCleanedBytes(v, cand.Path, data)
		if err != nil {
			skip("backing it up failed ("+err.Error()+"); NOT deleted", true)
			continue
		}
		if err := os.Remove(cand.Path); err != nil {
			skip("deleting failed ("+err.Error()+"); its backup is kept", true)
			continue
		}
		out.Deleted = append(out.Deleted, CleanDeletion{Path: cand.Path, Class: cand.Class, BackupPath: backupPath})
	}
	return out, nil
}

// vaultValueDigests digests every plaintext value the vault holds plus this
// run's own, forming the set a value-gated candidate must be covered by.
// Holding all of the vault's plaintext at once is exactly why ApplyClean
// belongs behind the fresh-auth ceremony — CollectVaultSecrets' contract.
func vaultValueDigests(v *vault.Vault, runValues []AgentCacheSecret) (map[string]bool, error) {
	secrets, err := CollectVaultSecrets(v)
	if err != nil {
		return nil, err
	}
	set := make(map[string]bool, len(secrets)+len(runValues))
	add := func(val string) {
		if val == "" {
			return
		}
		sum := sha256.Sum256([]byte(val))
		set[hex.EncodeToString(sum[:])] = true
	}
	for _, s := range secrets {
		add(s.Value)
	}
	for _, s := range runValues {
		add(s.Value)
	}
	return set, nil
}

func allDigestsVaulted(digests []string, vaulted map[string]bool) bool {
	if len(digests) == 0 {
		return false
	}
	for _, d := range digests {
		if !vaulted[d] {
			return false
		}
	}
	return true
}
