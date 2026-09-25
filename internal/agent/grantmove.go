// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package agent

import (
	"encoding/hex"
	"fmt"
	"sort"
)

// Moving existing grant and job keys to where the vault's key is
// (design/secure-enclave-plan.md, step C3). A vault that moved into the
// Secure Enclave keeps its older standing grants and never-ask AI Jobs on
// keychain keys until the service next starts; then each is re-sealed under
// an enclave key, with no prompt and no re-approval. A vault that moved back
// has its enclave-keyed ones moved back the same way.
//
// The rule: for every grant (and then every job), open each secret with its
// old key and seal it to the new one, in memory; write the ledger (or
// jobs.json) once, durably, for all of them; and only then delete the old
// keys. A grant or job that fails to re-seal is left exactly as it was and
// the rest go on. A crash or a failed write before the file is written
// leaves the old records and both keys: serving loads the kind a record
// names (loadGrantKey), so each still works on its old key, and the next
// start does it again (CreateWrap returns the key the crashed run made). A
// crash after the write leaves an old key nothing names, which the next
// start deletes. At no point is a grant's only key gone.

// GrantWrapKeychain and GrantWrapEnclave name the two kinds of grant key, as
// the ledger and jobs.json record them.
const (
	GrantWrapKeychain = standingWrapAEAD
	GrantWrapEnclave  = standingWrapEnclave
)

// GrantKeyMover is what a GrantKeyStore offers when it can hold both kinds.
// The CLI's store implements it; a store that does not is simply never
// asked to move anything.
type GrantKeyMover interface {
	// TargetWrap is the kind every grant and job key should be: the kind the
	// vault's own key is.
	TargetWrap() string
	LoadWrap(id, wrap string) (GrantKey, error)
	// CreateWrap makes a key of that kind, or returns the one a crashed move
	// already made.
	CreateWrap(id, wrap string) (GrantKey, error)
	// DeleteWrap destroys the key of that kind; a key already gone is done.
	DeleteWrap(id, wrap string) error
}

// MoveGrantKeys moves every standing grant's and never-ask job's key to the
// store's target kind. Call it once at service start, after SetGrantLedger
// and SetJobStore and before Listen, so nothing serves mid-move. It returns
// how many grants and jobs moved, and one error per one that could not
// (left exactly as it was, still working on its old key).
func (s *Server) MoveGrantKeys() (moved int, errs []error) {
	mover, ok := s.GrantKeys.(GrantKeyMover)
	if !ok {
		return 0, nil
	}
	target := mover.TargetWrap()
	m, e := s.moveStandingKeys(mover, target)
	moved, errs = moved+m, append(errs, e...)
	m, e = s.moveJobKeys(mover, target)
	return moved + m, append(errs, e...)
}

// otherWraps is every kind but target, for deleting what a finished move
// left behind.
func otherWraps(target string) []string {
	var out []string
	for _, w := range []string{GrantWrapKeychain, GrantWrapEnclave} {
		if w != target {
			out = append(out, w)
		}
	}
	return out
}

// sealedItem is one secret to re-seal: its class, its sealed bytes and the
// kind of key they are sealed for.
type sealedItem struct {
	class  string
	sealed []byte
	wrap   string
}

// reseal opens each item with the old key of its kind and seals it to the
// new key. It returns the new sealed bytes, index for index, or the first
// failure, having changed nothing: a new key it made for a failure is
// deleted again, while one an earlier, crashed move made is kept for the
// next start to reuse. Either way the entries still name their old kind,
// and serving loads that kind (loadGrantKey), so a key of the new kind left
// beside them never stops the grant.
func reseal(mover GrantKeyMover, id, target string, items []sealedItem) (_ [][]byte, err error) {
	existed := false
	if k, lerr := mover.LoadWrap(id, target); lerr == nil {
		k.Close()
		existed = true
	}
	newKey, err := mover.CreateWrap(id, target)
	if err != nil {
		return nil, fmt.Errorf("making its %s key: %w", target, err)
	}
	defer newKey.Close()
	defer func() {
		if err != nil && !existed {
			_ = mover.DeleteWrap(id, target)
		}
	}()
	old := map[string]GrantKey{}
	defer func() {
		for _, k := range old {
			k.Close()
		}
	}()
	out := make([][]byte, len(items))
	for i, it := range items {
		if it.wrap == target {
			out[i] = it.sealed
			continue
		}
		k, ok := old[it.wrap]
		if !ok {
			k, err = mover.LoadWrap(id, it.wrap)
			if err != nil {
				return nil, fmt.Errorf("loading its %s key: %w", it.wrap, err)
			}
			old[it.wrap] = k
		}
		dek, err := k.Open(it.sealed, it.class)
		if err != nil {
			return nil, fmt.Errorf("opening a secret with its %s key: %w", it.wrap, err)
		}
		gw, err := newKey.Seal(dek, it.class)
		wipe(dek)
		if err != nil {
			return nil, fmt.Errorf("sealing a secret to its %s key: %w", target, err)
		}
		out[i] = gw
	}
	return out, nil
}

// deleteOthers removes the keys of every other kind, after the record that
// needed them is gone. Best effort: a key left over is only clutter, and
// the next start tries again.
func deleteOthers(mover GrantKeyMover, id, target string) {
	for _, w := range otherWraps(target) {
		_ = mover.DeleteWrap(id, w)
	}
}

func (s *Server) moveStandingKeys(mover GrantKeyMover, target string) (int, []error) {
	// One grant's move: what to re-seal, and what it was, to put back.
	type move struct {
		g       *standingGrant
		digests []string
		items   []sealedItem
		sealed  [][]byte
		before  []standingSecret
	}
	s.grantMu.Lock()
	ids := make([]string, 0, len(s.standing))
	for id := range s.standing {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var todo []*move
	var settled []string // already on the target
	for _, id := range ids {
		g := s.standing[id]
		m := &move{g: g}
		pending := false
		for d, sec := range g.secrets {
			w := sec.wrap
			if w == "" {
				w = GrantWrapKeychain
			}
			m.digests = append(m.digests, d)
			m.items = append(m.items, sealedItem{class: sec.class, sealed: sec.grantWrapped, wrap: w})
			pending = pending || w != target
		}
		if pending {
			todo = append(todo, m)
		} else {
			settled = append(settled, id)
		}
	}
	s.grantMu.Unlock()

	// Already on the target: whatever key of the other kind a crashed move
	// left can go now.
	for _, id := range settled {
		deleteOthers(mover, id, target)
	}

	// Re-seal every grant in memory first. A grant that fails stays exactly
	// as it was, and the rest go on.
	var errs []error
	var moving []*move
	for _, m := range todo {
		sealed, err := reseal(mover, m.g.id, target, m.items)
		if err != nil {
			errs = append(errs, fmt.Errorf("standing grant %s kept its key: %w", m.g.id, err))
			continue
		}
		m.sealed = sealed
		moving = append(moving, m)
	}
	if len(moving) == 0 {
		return 0, errs
	}
	s.grantMu.Lock()
	for _, m := range moving {
		m.before = make([]standingSecret, len(m.digests))
		for i, d := range m.digests {
			sec := m.g.secrets[d]
			m.before[i] = sec
			sec.grantWrapped, sec.wrap = m.sealed[i], target
			m.g.secrets[d] = sec
		}
	}
	s.grantMu.Unlock()

	// Then write the ledger once, for all of them.
	if err := s.saveLedger(); err != nil {
		// Not written: put every record back, so memory matches the file.
		// Both keys are kept, each grant serves with its old one (serving
		// loads the kind its entries name), and the next start moves it
		// again, reusing the new key.
		s.grantMu.Lock()
		for _, m := range moving {
			for i, d := range m.digests {
				m.g.secrets[d] = m.before[i]
			}
		}
		s.grantMu.Unlock()
		for _, m := range moving {
			errs = append(errs, fmt.Errorf("standing grant %s kept its key: writing the ledger: %w", m.g.id, err))
		}
		return 0, errs
	}

	// Only now, with the ledger durably naming the new keys, do the old go.
	for _, m := range moving {
		m.g.keyMu.Lock()
		if m.g.key != nil {
			m.g.key.Close()
			m.g.key = nil
		}
		m.g.keyMu.Unlock()
		deleteOthers(mover, m.g.id, target)
	}
	return len(moving), errs
}

func (s *Server) moveJobKeys(mover GrantKeyMover, target string) (int, []error) {
	s.jobMu.Lock()
	defer s.jobMu.Unlock()
	if s.jobsPath == "" {
		return 0, nil
	}
	names := make([]string, 0, len(s.jobs))
	for name := range s.jobs {
		names = append(names, name)
	}
	sort.Strings(names)

	// One job's move, and what its record was, to put back.
	type was struct{ sealed, wrap string }
	type move struct {
		name   string
		sealed [][]byte
		before []was
	}
	var errs []error
	var moving []*move
	for _, name := range names {
		j := s.jobs[name]
		if j.KeyID == "" {
			continue // an each-time job has no key of its own
		}
		items := make([]sealedItem, len(j.Secrets))
		pending, damaged := false, false
		for i, sec := range j.Secrets {
			raw, err := hex.DecodeString(sec.KeyWrapped)
			if err != nil {
				errs = append(errs, fmt.Errorf("AI job %s kept its key: %s's sealed key is damaged", name, sec.Var))
				damaged = true
				break
			}
			items[i] = sealedItem{class: sec.Class, sealed: raw, wrap: sec.Wrap}
			pending = pending || sec.Wrap != target
		}
		if damaged {
			continue
		}
		if !pending {
			deleteOthers(mover, j.KeyID, target)
			continue
		}
		sealed, err := reseal(mover, j.KeyID, target, items)
		if err != nil {
			errs = append(errs, fmt.Errorf("AI job %s kept its key: %w", name, err))
			continue
		}
		moving = append(moving, &move{name: name, sealed: sealed})
	}
	if len(moving) == 0 {
		return 0, errs
	}
	for _, m := range moving {
		j := s.jobs[m.name]
		m.before = make([]was, len(j.Secrets))
		for i := range j.Secrets {
			m.before[i] = was{j.Secrets[i].KeyWrapped, j.Secrets[i].Wrap}
			j.Secrets[i].KeyWrapped = hex.EncodeToString(m.sealed[i])
			j.Secrets[i].Wrap = target
		}
	}
	if err := s.saveJobsLocked(); err != nil {
		// The file was not written: put every record back as it was, so
		// memory matches disk. The old keys are kept, and a job run loads
		// the kind its record names, so each job still opens.
		for _, m := range moving {
			j := s.jobs[m.name]
			for i := range j.Secrets {
				j.Secrets[i].KeyWrapped, j.Secrets[i].Wrap = m.before[i].sealed, m.before[i].wrap
			}
			errs = append(errs, fmt.Errorf("AI job %s kept its key: writing the job list: %w", m.name, err))
		}
		return 0, errs
	}
	for _, m := range moving {
		deleteOthers(mover, s.jobs[m.name].KeyID, target)
	}
	return len(moving), errs
}
