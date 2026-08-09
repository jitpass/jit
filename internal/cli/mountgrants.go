// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jitpass/jit/internal/agent"
	"github.com/jitpass/jit/internal/lineage"
)

// This file is the grant MODE's attach step and its per-read gate. The
// shared lifecycle (registry, teardown, prune, status, exit watcher) lives
// in mountruns.go; the swap mode's attach lives in mountswap.go. What's
// here is grant-specific: registering a --live run and deciding, per FIFO
// rendezvous, whether the reader is inside the granted process tree.
//
// Doctrine note: spike/fifo-reader-identify ruled reader identity must
// never be a security boundary, and it still isn't one here. The boundary
// is the attachment itself — created only after ensureUnlocked, for a
// caller that already holds every one of these values in memory to inject
// into the child's environment. Lineage only NARROWS that grant: every
// classification failure (scan truncation, unreadable ancestry, recycled
// pid, dead target) serves decoys, and the worst an identity-racing
// adversary can win is what the accepted reveal-window baseline already
// hands every same-user process for 60 seconds after each unlock.

// grantVerdictTTL caches per-(holder,root) ancestry verdicts so a read
// storm doesn't pay the ancestry walk per read — same motivation as
// lineageScanMinGap, except a gating scan can't be SKIPPED (that would mean
// guessing), only amortized.
const grantVerdictTTL = 2 * time.Second

// grantVerdictKey caches "is holder inside root's tree" per PAIR — not per
// holder — so one grant root dying can never let a holder classified under
// it keep riding a different, still-live root's authorization. rootStart (the
// root's fork-time stamp) is part of the key so a recycled root pid — same
// number, new process — gets a fresh key rather than inheriting the exited
// process's verdict, closing a narrow fail-open where a positive verdict
// could authorize a holder that isn't in the NEW root's tree.
type grantVerdictKey struct {
	holder    int32
	root      int32
	rootStart int64
}

type grantVerdict struct {
	inTree  bool
	expires time.Time
}

// validateGrantMount is revealForPID's grant-mode check for one mount: it
// must be currently served AND have real content resolved. The real-content
// rule is the GAPS.md #46 honesty rule: a "grant" on a mount that can only
// serve decoys would report success while changing nothing. A non-nil error
// is the skip reason revealForPID logs and collects.
func (m *mountManager) validateGrantMount(path string) error {
	m.mu.Lock()
	sm, served := m.served[path]
	m.mu.Unlock()
	if !served {
		return fmt.Errorf("no such mount: %s", path)
	}
	sm.mu.Lock()
	hasReal := sm.real != nil
	resolveErr := sm.lastResolveErr
	sm.mu.Unlock()
	if !hasReal {
		if resolveErr != "" {
			return fmt.Errorf("%s has nothing real to serve (resolving its secrets failed: %s)", path, resolveErr)
		}
		return fmt.Errorf("%s has nothing real to serve", path)
	}
	return nil
}

// canGrantAll is OnCanGrant's handler: the all-or-nothing pre-check a
// disclosed --with grant runs BEFORE its challenge, so jit run --with fails
// (without prompting) if any named credential can't be served, rather than
// prompting and then partially granting. It attaches nothing — just runs
// validateGrantMount for every grant-mode mount. Swap-mode mounts are ignored
// (a --with only ever sends grants).
func (m *mountManager) canGrantAll(mounts []agent.RunMount) error {
	for _, rm := range mounts {
		if rm.Mode != agent.MountModeGrant {
			continue
		}
		if err := m.validateGrantMount(rm.Path); err != nil {
			return err
		}
	}
	return nil
}

// describeGrant is OnDescribeGrant's handler: it names, in the user's own
// vocabulary, what a disclosed --with grant is about to hand over — "your gcp
// credential", "your gcp, sops credentials".
//
// Every name it returns comes from credentialMount, i.e. from jit's OWN
// registry of global credential mounts, keyed by the mount path. The caller's
// path strings are used only to LOOK UP that table and are never echoed: a
// path that isn't a known global credential mount contributes nothing to the
// sentence. That is the whole point of deriving the wording here instead of
// accepting it over the wire — an unrecognized or made-up path can make this
// prompt vaguer, never more reassuring than the truth.
func (m *mountManager) describeGrant(mounts []agent.RunMount) string {
	var names []string
	for _, rm := range mounts {
		if rm.Mode != agent.MountModeGrant {
			continue
		}
		cred, ok := m.credentialMount(rm.Path)
		if !ok || slices.Contains(names, cred) {
			continue
		}
		names = append(names, cred)
	}
	if len(names) == 0 {
		return ""
	}
	slices.Sort(names)
	noun := "credential"
	if len(names) > 1 {
		noun = "credentials"
	}
	return fmt.Sprintf("your %s %s on this machine", strings.Join(names, ", "), noun)
}

// serveContent is the ONE content decision, called by mount.Serve on every
// reader rendezvous. Real content flows ONLY when the read is authorized by
// a run-scoped grant (this run's own process tree, jit run --live / --with);
// every other reader gets decoys. There is no reveal window: unlocking the
// vault never makes a mount serve real. With no grant runs anywhere the
// grant gate is skipped outright (the grantModeRuns fast path), so an
// ungranted mount pays exactly what it did before grants existed. A swapped
// mount never reaches here — it's a plain file with no Serve goroutine.
func (m *mountManager) serveContent(path string, sm *servedMount) []byte {
	authorized := false
	grantServed := false
	if atomic.LoadInt32(&m.grantModeRuns) > 0 {
		if m.grantAuthorizes(path, sm) {
			authorized = true
			grantServed = true
		}
	}

	// No run-scoped grant covered this read. If consent is on and this is a
	// machine-global credential mount (gcp/npm/netrc), fall back to a
	// best-effort per-reader consent decision: identify who's holding the
	// mount and prompt (or honor a --trust'd tree / a session-cached answer).
	// Limited to credential mounts so a project .env read never pays the
	// holder scan, and done BEFORE sm.mu so the prompt can't block the mount's
	// state. Fail-closed: no holders / not credential-mounts / any deny leaves
	// it decoy.
	if !authorized && m.consent != nil {
		if cred, ok := m.credentialMount(path); ok {
			if holders, ok := m.grantHolders(path); ok && len(holders) > 0 {
				if m.consentAuthorizes(sm, cred, holders) {
					authorized = true
				}
			}
		}
	}

	now := time.Now()
	sm.mu.Lock()
	content, decoy := sm.decoy, true
	if sm.real != nil && authorized {
		content, decoy = sm.real, false
	}
	rec := serveRecord{at: now, decoy: decoy, reader: sm.pendingReader, grantServed: !decoy && grantServed}
	sm.lastServe = &rec
	hadReal, resolveErr := sm.real != nil, sm.lastResolveErr
	sm.mu.Unlock()

	// Durable audit, outside sm.mu on purpose: the auditor takes its own lock
	// and a finished aggregate is appended to a file, neither of which belongs
	// on a mount's critical section — every reader of every mount waits behind
	// it. The auditor collapses before writing, so this call is a map lookup
	// and a counter increment on all but one read in a window.
	m.serveAudit.record(now, path, serveReason(decoy, grantServed, hadReal, resolveErr), rec)
	return content
}

// serveAuditLabel names the credential a mount holds the way the user would,
// so `jit audit --secret gcp` finds reads of the gcp mount. Falls back to the
// display path, which is what a project .env has instead of a name — an
// unnamed mount must still be identifiable in the trail.
func (m *mountManager) serveAuditLabel(path string) string {
	if cred, ok := m.credentialMount(path); ok {
		return cred
	}
	return displayPath(m.home, path)
}

// consentVerdict caches serveContent's best-effort consent decision for one
// mount, valid only while the holder set is byte-for-byte the set it was
// decided for. holderKey is the sorted pid-set; a different set (any join or
// departure) fails the equality check and forces a fresh decision, so a reader
// that wasn't in the authorized set can never inherit a cached true.
type consentVerdict struct {
	holderKey  string
	authorized bool
	expires    time.Time
}

// consentAuthorizes is serveContent's consent fallback with the per-holder
// identity work amortized: on a cache hit for the identical holder set it
// returns the remembered answer, skipping the libproc scan + trust-ancestry
// walk ConsentReaders does per holder. On a miss (first read, changed set, or
// expiry) it asks ConsentReaders and caches the result under this mount's
// short TTL — the same amortize-don't-skip rule the grant gate uses.
func (m *mountManager) consentAuthorizes(sm *servedMount, cred string, holders []int32) bool {
	key := holderSetKey(holders)
	now := time.Now()

	sm.mu.Lock()
	v := sm.consentVerdict
	sm.mu.Unlock()
	if v != nil && v.holderKey == key && now.Before(v.expires) {
		return v.authorized
	}

	authorized := m.consent.ConsentReaders(cred, holders)

	sm.mu.Lock()
	sm.consentVerdict = &consentVerdict{holderKey: key, authorized: authorized, expires: now.Add(grantVerdictTTL)}
	sm.mu.Unlock()
	return authorized
}

// holderSetKey renders a holder pid set into a stable cache key, order-
// independent so the same set found in a different scan order still hits.
func holderSetKey(holders []int32) string {
	sorted := append([]int32(nil), holders...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	var b strings.Builder
	for i, pid := range sorted {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.Itoa(int(pid)))
	}
	return b.String()
}

// credentialMount reports whether path is a machine-global credential mount
// (gcp/npm/netrc/sops) and, if so, the credential name used in the consent
// prompt and cache key. A cheap path comparison (no scan), so the serve path
// can check it per read and skip the consent machinery for ordinary project
// mounts.
func (m *mountManager) credentialMount(path string) (string, bool) {
	g, ok := globalMountGuidanceForPath(m.home, path)
	if !ok {
		return "", false
	}
	return g.name, true
}

// grantAuthorizes applies the fail-closed rule: real content flows only
// when the holder set is completely enumerable, non-empty, and EVERY holder
// verifies inside some live grant root's tree. Any uncertainty at any step
// — no live root, truncated scan, an unclassifiable holder — means decoy.
// Enumerating all holders (not just one) is what makes a piggybacking
// stranger downgrade the read to decoys instead of riding along (spike
// scenario: mixed concurrent holders).
func (m *mountManager) grantAuthorizes(path string, sm *servedMount) bool {
	roots := m.grantRootsForPath(path)
	if len(roots) == 0 {
		return false
	}
	holders, ok := m.grantHolders(path)
	if !ok || len(holders) == 0 {
		return false
	}
	now := time.Now()
	for _, holder := range holders {
		if !m.holderAuthorized(sm, holder, roots, now) {
			return false
		}
	}
	return true
}

// holderAuthorized reports whether holder sits inside any of roots' trees,
// consulting (and filling) the per-pair verdict cache. Negative verdicts
// are cached too: a stranger holding the mount open in a read loop would
// otherwise force a full ancestry walk per read.
func (m *mountManager) holderAuthorized(sm *servedMount, holder int32, roots []grantRoot, now time.Time) bool {
	for _, root := range roots {
		key := grantVerdictKey{holder: holder, root: root.pid, rootStart: root.startMicro}
		sm.mu.Lock()
		v, cached := sm.grantVerdicts[key]
		sm.mu.Unlock()
		if cached && now.Before(v.expires) {
			if v.inTree {
				return true
			}
			continue
		}
		inTree := m.grantAncestry(holder, root.pid)
		sm.mu.Lock()
		if sm.grantVerdicts == nil {
			sm.grantVerdicts = map[grantVerdictKey]grantVerdict{}
		}
		if len(sm.grantVerdicts) > 256 {
			// A pathological churn of holder pids could otherwise grow this
			// map for the life of the grant; resetting just re-walks a few
			// ancestries on the next reads.
			sm.grantVerdicts = map[grantVerdictKey]grantVerdict{}
		}
		sm.grantVerdicts[key] = grantVerdict{inTree: inTree, expires: now.Add(grantVerdictTTL)}
		sm.mu.Unlock()
		if inTree {
			return true
		}
	}
	return false
}

// grantHolders/grantAncestry/grantStart are the gate's kernel lookups,
// indirected through mountManager's test seams (nil = real lineage).
func (m *mountManager) grantHolders(path string) ([]int32, bool) {
	if m.grantHoldersFn != nil {
		return m.grantHoldersFn(path)
	}
	return lineage.FIFOHolders(path)
}

func (m *mountManager) grantAncestry(pid, root int32) bool {
	if m.grantAncestryFn != nil {
		return m.grantAncestryFn(pid, root)
	}
	return lineage.AncestryContainsPID(pid, root)
}

func (m *mountManager) grantStart(pid int32) (int64, bool) {
	if m.grantStartFn != nil {
		return m.grantStartFn(pid)
	}
	return lineage.ProcessStartTime(pid)
}
