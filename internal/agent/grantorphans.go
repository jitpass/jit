// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package agent

import (
	"errors"
	"fmt"
	"sort"
)

// Deleting grant and job keys nothing refers to (design/secure-enclave-plan.md,
// step C4). They come from a grant or job approval that failed after its
// key was made, a crash, a revoke whose delete did not reach the key, or a
// move (C3) whose last delete was interrupted. A key nobody names opens
// nothing anyone asked for; left alone, the keychain and the enclave only
// fill up.
//
// Deleting a key a grant still needs would silently stop that grant, so the
// cleanup is narrow on purpose:
//   - It runs only when BOTH the grant ledger and the job list loaded. A
//     ledger that failed to parse leaves the service believing there are no
//     grants, and every key would look orphaned.
//   - It runs at service start, before the socket opens, so no approval is
//     making a key at the same moment.
//   - It touches only ids jit mints (g- or j- and eight hex digits).
//   - An id is known if the ledger or the job list NAMES it, read raw as the
//     files stood when they loaded (before a move could rewrite them), not
//     only if a loader accepted the record: a grant SetGrantLedger dropped
//     (no anchor, no name), a job job.Load skipped (a name or an ask value
//     from a newer jit), and a grant whose entries this build cannot open
//     (C1's unread) all keep their keys.

// GrantKeyLister is what a GrantKeyStore offers when it can list its keys.
type GrantKeyLister interface {
	// ListGrantKeyIDs returns every id with a key of any kind, from
	// metadata only: never reads a key, never prompts.
	ListGrantKeyIDs() ([]string, error)
}

// errCleanupSkipped says why nothing was deleted.
var errCleanupSkipped = errors.New("the grant ledger or the job list did not load, so no key can be judged unused")

// DeleteOrphanGrantKeys deletes every grant or job key no standing grant and
// no job names. Call it once at service start, after SetGrantLedger,
// SetJobStore and MoveGrantKeys, before Listen. It returns the ids deleted,
// and an error when it skipped or could not list; a key that would not
// delete is reported and left for the next start.
func (s *Server) DeleteOrphanGrantKeys() (deleted []string, errs []error) {
	lister, ok := s.GrantKeys.(GrantKeyLister)
	if !ok {
		return nil, nil
	}
	// SetGrantLedger sets ledgerPath under grantMu and clears it on any
	// failure to load, which is what makes it the "loaded" signal.
	// The raw names are set only when a file was read raw in full, so a nil
	// set is also "did not load".
	s.grantMu.Lock()
	ledgerLoaded := s.ledgerPath != "" && s.ledgerNames != nil
	known := map[string]bool{}
	for id := range s.ledgerNames {
		known[id] = true
	}
	for id := range s.standing {
		known[id] = true
	}
	s.grantMu.Unlock()
	s.jobMu.Lock()
	jobsLoaded := s.jobsPath != "" && s.jobNames != nil
	for id := range s.jobNames {
		known[id] = true
	}
	for _, j := range s.jobs {
		if j.KeyID != "" {
			known[j.KeyID] = true
		}
	}
	s.jobMu.Unlock()
	if !ledgerLoaded || !jobsLoaded {
		return nil, []error{errCleanupSkipped}
	}

	ids, err := lister.ListGrantKeyIDs()
	if err != nil {
		return nil, []error{fmt.Errorf("listing grant keys: %w", err)}
	}
	sort.Strings(ids)
	for _, id := range ids {
		if known[id] || !mintedKeyID.MatchString(id) {
			continue
		}
		// An enclave this jit cannot reach listed nothing, so the id came
		// from the keychain, and that key is gone: the unreachable half is
		// not a failure here.
		if err := withoutUnreachable(s.GrantKeys.Delete(id)); err != nil {
			errs = append(errs, fmt.Errorf("deleting unused key %s: %w", id, err))
			continue
		}
		deleted = append(deleted, id)
	}
	return deleted, errs
}
