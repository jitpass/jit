// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"errors"
	"fmt"
	"os"

	"github.com/jitpass/jit/internal/profile"
	"github.com/jitpass/jit/internal/vault"
)

// ApplyMCPConfig migrates a config's servers in two phases: every selected
// server is PLANNED (namespace claimed, carried values read, the secrets,
// manifest and sidecar it would write worked out) before any of them is
// COMMITTED. It used to be one phase, each server writing its vault secrets,
// manifest and .source sidecar before the next was looked at, so a later
// server failing — carriedProfileValues refusing a wrapper whose profile names
// a secret gone from the vault is an error by design — aborted with the config
// untouched and the earlier servers' fresh profiles and secrets stranded
// (found in the field: a new mcp-caido-3 left behind by a run that then
// stopped on the next server). The next run would bump past the leftovers to
// yet another namespace.
//
// The guarantee, stated at its real strength:
//
//   - A failure while planning ANY server writes nothing at all: not to the
//     vault, the profile store, or a sidecar.
//   - A failure while committing (a refused Touch ID prompt, a full disk) is
//     followed by a best-effort rollback of every write this run made:
//     secrets and files it created are removed, and ones that existed are put
//     back — a secret by restoring the exact envelope the write archived
//     (vault.Restore, byte-for-byte, no decryption), a manifest or sidecar by
//     rewriting the bytes read just before overwriting it. Best effort means a
//     crash mid-commit, or a rollback step that itself fails, can still leave
//     part of the run behind; the latter is named in the returned error.
//     Restoring a secret leaves the rolled-back value as an extra version in
//     that secret's history — the same value the config file still holds in
//     plaintext, so nothing is exposed that was not already.
//   - Once every server has committed, the rest of ApplyMCPConfig (pointer
//     files for absorbed --env-files, the config's backup and rewrite) keeps
//     its existing vault-first ordering and is NOT rolled back: a pointer file
//     names the new vault paths, so undoing the vault under it would be worse
//     than the leftovers this exists to prevent.

// mcpPendingWrites is the overlay planning reads through: the vault secrets,
// manifests and sidecars that servers planned EARLIER in this run will write,
// consulted before the disk and the vault. It exists so that planning server
// N sees exactly what it would have seen had servers 1..N-1 already been
// written — in particular two servers in one file claiming namespaces, where
// the second must find the first's claim (its manifest and sidecar) and bump
// rather than share it. Without the overlay the second would find the
// namespace free on disk and both would commit into it.
type mcpPendingWrites struct {
	secrets   map[string][]byte          // vault path -> value
	manifests map[string]profile.Profile // manifest path -> entries
	sidecars  map[string]string          // sidecar path -> contents
}

func newMCPPendingWrites() *mcpPendingWrites {
	return &mcpPendingWrites{
		secrets:   map[string][]byte{},
		manifests: map[string]profile.Profile{},
		sidecars:  map[string]string{},
	}
}

// add records one planned server's writes, later ones replacing earlier ones
// at the same path — the order commit applies them in.
func (p *mcpPendingWrites) add(plan mcpServerPlan) {
	for _, name := range plan.varNames {
		p.secrets[plan.profileName+"/"+name] = []byte(plan.values[name])
	}
	entries := make(profile.Profile, len(plan.entries))
	for k, v := range plan.entries {
		entries[k] = v
	}
	p.manifests[plan.profilePath] = entries
	p.sidecars[profileSourceSidecarPath(plan.profilePath)] = plan.sidecar
}

// loadProfile is profile.LoadFile through the overlay. A pending manifest
// returns a copy, and an empty one fails the way LoadFile fails on the empty
// manifest writeProfileManifest would have left on disk.
func (p *mcpPendingWrites) loadProfile(path string) (profile.Profile, error) {
	if entries, ok := p.manifests[path]; ok {
		if len(entries) == 0 {
			return nil, fmt.Errorf("profile %s has no entries", path)
		}
		out := make(profile.Profile, len(entries))
		for k, v := range entries {
			out[k] = v
		}
		return out, nil
	}
	return profile.LoadFile(path)
}

// readSidecar is os.ReadFile of a .source sidecar through the overlay.
func (p *mcpPendingWrites) readSidecar(path string) ([]byte, error) {
	if content, ok := p.sidecars[path]; ok {
		return []byte(content), nil
	}
	return os.ReadFile(path) // #nosec G304 -- a fixed-suffix sibling of jit's own profile manifest
}

// secretExists is v.Exists through the overlay.
func (p *mcpPendingWrites) secretExists(v *vault.Vault, secretPath string) (bool, error) {
	if _, ok := p.secrets[secretPath]; ok {
		return true, nil
	}
	return v.Exists(secretPath)
}

// getSecret is v.Get through the overlay.
func (p *mcpPendingWrites) getSecret(v *vault.Vault, secretPath string) ([]byte, error) {
	if value, ok := p.secrets[secretPath]; ok {
		return append([]byte(nil), value...), nil
	}
	return v.Get(secretPath)
}

// mcpServerPlan is everything one server's migration writes, worked out
// without writing it: the secrets (varNames, values, meta), the manifest
// (entries at profilePath) and the ownership sidecar.
type mcpServerPlan struct {
	scope       string // mcpSourceScope, for error context
	serverName  string
	profileName string
	profilePath string
	varNames    []string
	values      map[string]string
	meta        vault.Meta
	entries     profile.Profile
	sidecar     string
	migration   MCPServerMigration
}

// commitMCPPlans performs every planned write, in plan order and, within a
// server, in the order a single-phase migration used: secrets, then the
// manifest, then the sidecar stamp (see the comment at the sidecar write for
// why that order). On failure it rolls back what this call already wrote
// (see the guarantee above) and returns the write's error, wrapped exactly as
// a failure inside that server always was.
func commitMCPPlans(v *vault.Vault, plans []mcpServerPlan) error {
	j := &mcpWriteJournal{v: v, touched: map[string]bool{}}
	for _, plan := range plans {
		if err := commitMCPPlan(j, plan); err != nil {
			err = fmt.Errorf("%s: server %q: %w", plan.scope, plan.serverName, err)
			if rbErr := j.rollback(); rbErr != nil {
				return fmt.Errorf("%w (undoing this run's earlier writes also failed, some may remain: %v)", err, rbErr)
			}
			return err
		}
	}
	return nil
}

func commitMCPPlan(j *mcpWriteJournal, plan mcpServerPlan) error {
	for _, name := range plan.varNames {
		if err := j.setSecret(plan.profileName+"/"+name, []byte(plan.values[name]), plan.meta); err != nil {
			return fmt.Errorf("storing %s in vault: %w", name, err)
		}
	}
	if err := j.writeFile(plan.profilePath, func() error {
		return writeProfileManifest(plan.profilePath, plan.entries, nil)
	}); err != nil {
		return fmt.Errorf("writing profile %s: %w", plan.profilePath, err)
	}
	// Stamp ownership AFTER the manifest write: a crash in between leaves a
	// legacy-shaped (unstamped) profile, which the next run treats with the
	// cautious legacy rules rather than trusting a stamp for content that
	// never landed.
	sidecar := profileSourceSidecarPath(plan.profilePath)
	if err := j.writeFile(sidecar, func() error {
		return os.WriteFile(sidecar, []byte(plan.sidecar), 0o600)
	}); err != nil {
		return fmt.Errorf("recording profile source %s: %w", plan.profilePath, err)
	}
	return nil
}

// mcpWriteJournal performs commit's writes and remembers how to undo each
// one, keyed by the state BEFORE this run first touched it — a path written
// twice in one run (two servers sharing a namespace) is rolled back to its
// pre-run state, not to the first write.
type mcpWriteJournal struct {
	v       *vault.Vault
	touched map[string]bool
	undo    []func() error
}

// setSecret writes a vault secret. The undo is registered only once the write
// has succeeded: a failed SetWithMeta leaves the live value as it was (the
// vault writes atomically), so there is nothing of it to undo.
func (j *mcpWriteJournal) setSecret(secretPath string, value []byte, meta vault.Meta) error {
	key := "vault:" + secretPath
	first := !j.touched[key]
	var existed bool
	var before map[int64]bool
	if first {
		var err error
		if existed, err = j.v.Exists(secretPath); err != nil {
			return fmt.Errorf("checking vault path %s: %w", secretPath, err)
		}
		if existed {
			versions, err := j.v.HistoryVersions(secretPath)
			if err != nil {
				return err
			}
			before = make(map[int64]bool, len(versions))
			for _, hv := range versions {
				before[hv.ArchiveStamp] = true
			}
		}
	}
	if err := j.v.SetWithMeta(secretPath, value, meta); err != nil {
		return err
	}
	if !first {
		return nil
	}
	j.touched[key] = true
	if !existed {
		j.undo = append(j.undo, func() error {
			if err := j.v.Remove(secretPath); err != nil && !errors.Is(err, vault.ErrNotFound) {
				return err
			}
			return nil
		})
		return nil
	}
	// Overwriting archived the previous envelope into history; that archive
	// is the newest version this run did not see before writing. 0 (the
	// newest) is the fallback should the listing fail, which after a write
	// that just archived is the same version barring a concurrent writer.
	var archived int64
	if versions, err := j.v.HistoryVersions(secretPath); err == nil {
		for _, hv := range versions { // newest first
			if !before[hv.ArchiveStamp] {
				archived = hv.ArchiveStamp
				break
			}
		}
	}
	j.undo = append(j.undo, func() error { return j.v.Restore(secretPath, archived) })
	return nil
}

// writeFile runs write for a manifest or sidecar at path. The undo is
// registered BEFORE the write, unlike a secret's: a failed os.WriteFile can
// already have truncated the file, and restoring the captured bytes is right
// whether or not the write got that far.
func (j *mcpWriteJournal) writeFile(path string, write func() error) error {
	key := "file:" + path
	if !j.touched[key] {
		prev, err := os.ReadFile(path) // #nosec G304 -- jit's own profile manifest or its .source sibling
		switch {
		case err == nil:
			j.undo = append(j.undo, func() error { return vault.AtomicWriteFile(path, prev) })
		case errors.Is(err, os.ErrNotExist):
			j.undo = append(j.undo, func() error {
				if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
					return err
				}
				return nil
			})
		default:
			return fmt.Errorf("reading %s before overwriting it: %w", path, err)
		}
		j.touched[key] = true
	}
	return write()
}

// rollback runs every registered undo, newest first, and keeps going past a
// failing one so a single stuck file does not strand the rest.
func (j *mcpWriteJournal) rollback() error {
	var errs []error
	for i := len(j.undo) - 1; i >= 0; i-- {
		if err := j.undo[i](); err != nil {
			errs = append(errs, err)
		}
	}
	j.undo = nil
	return errors.Join(errs...)
}
