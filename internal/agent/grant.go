// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package agent

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jitpass/jit/internal/lineage"
)

// This file is the process-grant store (design/process-grants.md): the one
// piece of authorization state that deliberately SURVIVES a re-lock.
//
// A process grant is a human decision moved earlier: while present, the user
// approves with one disclosed challenge that a specific running process tree
// may unwrap the secrets of named profiles until an absolute deadline —
// unattended, across screen lock. Mechanically it is a scoped DEK cache: at
// creation, while the challenge's MEK is in hand, the covered envelopes' DEKs
// are unwrapped and held (mlocked) keyed by a digest of their wrapped bytes;
// a later OpUnwrap whose caller descends from the grant's root and whose
// wrapped bytes match is answered from that cache, with no session, no
// consent prompt, and a full audit record. Everything else — wrong tree,
// expired, rotated secret, uncovered path — falls through to the ordinary
// path unchanged.
//
// The anchoring is trustRoots' exactly: pid plus fork-time stamp, descent by
// lineage.AncestryContainsPID, every uncertainty failing closed. The doctrine
// "identity explains, never decides" holds because the DECISION was the
// disclosed Touch ID at creation, bound to a kernel-vouched pid; descent
// afterwards only routes to a decision the human already made — the same
// footing as `jit run --trust`, narrowed from "everything, this session" to
// "these secrets, until this deadline".

// MaxGrantTTL caps a grant's lifetime, creation and extension alike. A week
// is deliberately generous (a machine left working over a long weekend) while
// still bounding a typo: `--for 30d` must fail loudly, not quietly mint a
// month of unattended access.
const MaxGrantTTL = 7 * 24 * time.Hour

// minGrantTTL rejects grants too short to mean anything: a sub-minute grant
// is either a typo or a caller trying to use grants as a session substitute.
const minGrantTTL = time.Minute

// GrantSecret is one secret a grant should cover, as resolved by the agent's
// own CLI wiring (Server.OnResolveGrant): the vault path, the envelope's
// wrapped DEK bytes, and its AAD-bound class. The class is what keeps the
// resolution honest end-to-end: creation unwraps each entry with the class as
// AAD, so an entry whose class was misreported fails the auth tag and the
// whole create fails — nothing is ever granted that the prompt didn't
// truthfully describe.
type GrantSecret struct {
	Path    string
	Wrapped []byte
	Class   string
}

// grantSecret is one covered secret inside a stored grant: its vault path
// (agent-verified at creation, unlike Request.Label) and its plaintext DEK.
type grantSecret struct {
	path string
	dek  []byte
}

// processGrant is one live grant. Immutable after creation except expires,
// serves and lastServe, all mutated under Server.grantMu.
type processGrant struct {
	id        string
	rootPID   int32
	rootStart int64 // fork-time stamp — the anti-pid-recycling anchor
	name      string
	command   string
	profiles  []string
	// deks maps hex(sha256(wrapped bytes)) -> the covered secret. Keyed on
	// the wrapped bytes themselves so the serve path needs no vault access
	// at all: the client already sends exactly those bytes on every unwrap.
	deks      map[string]grantSecret
	created   time.Time
	expires   time.Time
	serves    int64
	lastServe time.Time
}

// paths lists the covered vault paths, sorted for stable display and events.
func (g *processGrant) secretPaths() []string {
	out := make([]string, 0, len(g.deks))
	for _, s := range g.deks {
		out = append(out, s.path)
	}
	sort.Strings(out)
	return out
}

// status snapshots a grant for the wire. rootAlive is the caller's answer —
// liveness needs a sysctl the caller has usually just done.
func (g *processGrant) status(rootAlive bool) GrantStatus {
	st := GrantStatus{
		ID:          g.id,
		PID:         g.rootPID,
		Name:        g.name,
		Command:     g.command,
		Profiles:    append([]string(nil), g.profiles...),
		Secrets:     g.secretPaths(),
		CreatedUnix: g.created.Unix(),
		ExpiresUnix: g.expires.Unix(),
		Serves:      g.serves,
		RootAlive:   rootAlive,
	}
	if !g.lastServe.IsZero() {
		st.LastServeUnix = g.lastServe.Unix()
	}
	return st
}

// wipeDEKs zeroes and munlocks every cached DEK. Caller must hold grantMu (or
// own the grant exclusively, as a failed create does).
func (g *processGrant) wipeDEKs() {
	for k, s := range g.deks {
		wipe(s.dek)
		unlockMemory(s.dek)
		delete(g.deks, k)
	}
}

// grantEndCause values — the vocabulary KindGrantEnd.Cause draws from.
const (
	grantEndExpired = "expired"
	grantEndRevoked = "revoked"
	grantEndExited  = "process exited"
)

// newGrantID mints a short, non-guessable grant id ("g-3f9a2c81"). Random
// rather than sequential so an id never encodes how many grants exist, and
// short enough to type into `jit grant revoke`.
func newGrantID() (string, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("minting grant id: %w", err)
	}
	return "g-" + hex.EncodeToString(b[:]), nil
}

// wrappedDigest keys a grant's DEK cache: a digest of the wrapped bytes, so
// the map never holds the wrapped form and the plaintext side by side.
func wrappedDigest(wrapped []byte) string {
	sum := sha256.Sum256(wrapped)
	return hex.EncodeToString(sum[:])
}

// createGrant validates, prompts (one disclosed challenge), unwraps and
// stores a grant. It is OpGrantCreate's whole body, kept here so server.go's
// dispatch stays a switch.
func (s *Server) createGrant(req Request, c *caller) Response {
	if c == nil {
		return Response{OK: false, Error: "grant_create: caller could not be identified"}
	}
	if req.TargetPID <= 0 {
		return Response{OK: false, Error: "grant_create: missing target_pid"}
	}
	if len(req.GrantProfiles) == 0 {
		return Response{OK: false, Error: "grant_create: missing grant_profiles"}
	}
	ttl := time.Duration(req.TTLSeconds) * time.Second
	if ttl < minGrantTTL || ttl > MaxGrantTTL {
		return Response{OK: false, Error: fmt.Sprintf("grant_create: ttl must be between %s and %s", minGrantTTL, MaxGrantTTL)}
	}
	if s.OnResolveGrant == nil {
		return Response{OK: false, Error: "grant_create: this agent has no grant resolver wired"}
	}

	// The target is described by the KERNEL, from the pid alone — the name on
	// the prompt is never a string the requesting process typed. The fork-time
	// stamp is taken BEFORE the (up to ~120s) challenge and re-verified after,
	// so a target that dies and gets its pid recycled mid-prompt cannot
	// inherit the approval.
	target, ok := lineage.Describe(req.TargetPID)
	if !ok {
		return Response{OK: false, Error: fmt.Sprintf("grant_create: no such process (pid %d)", req.TargetPID)}
	}
	rootStart, ok := lineage.ProcessStartTime(req.TargetPID)
	if !ok {
		return Response{OK: false, Error: fmt.Sprintf("grant_create: process %d cannot be anchored (already exiting?)", req.TargetPID)}
	}

	// Resolution happens BEFORE the prompt (same ordering as OnCanGrant): an
	// unresolvable profile fails without burning a Touch ID, and the human
	// approves the whole named set or none of it.
	secrets, err := s.OnResolveGrant(req.GrantProfiles, req.ProjectRoot)
	if err != nil {
		return Response{OK: false, Error: fmt.Sprintf("grant_create: %s", err)}
	}
	if len(secrets) == 0 {
		return Response{OK: false, Error: "grant_create: the named profiles resolve to no secrets"}
	}

	reason := grantCreateReason(target.Name(), req.GrantProfiles, len(secrets), ttl)
	event, mek, err := s.discloseChallengeOp(reason, OpGrantCreate, c)
	if s.OnSessionEvent != nil {
		s.OnSessionEvent(*event)
	}
	if err != nil {
		return Response{OK: false, Error: err.Error()}
	}
	defer wipe(mek)

	id, err := newGrantID()
	if err != nil {
		return Response{OK: false, Error: err.Error()}
	}
	g := &processGrant{
		id:        id,
		rootPID:   req.TargetPID,
		rootStart: rootStart,
		name:      target.Name(),
		command:   target.Command(),
		profiles:  append([]string(nil), req.GrantProfiles...),
		deks:      make(map[string]grantSecret, len(secrets)),
		created:   time.Now(),
		expires:   time.Now().Add(ttl),
	}
	for _, sec := range secrets {
		dek, err := open(mek, sec.Wrapped, []byte(sec.Class))
		if err != nil {
			// One bad entry fails the whole create: the human approved a
			// specific count, and a grant quietly covering fewer secrets than
			// its prompt named is a prompt that lied by omission.
			g.wipeDEKs()
			return Response{OK: false, Error: fmt.Sprintf("grant_create: %s cannot be unwrapped (%s), no grant created", sec.Path, err)}
		}
		lockMemory(dek)
		g.deks[wrappedDigest(sec.Wrapped)] = grantSecret{path: sec.Path, dek: dek}
	}

	// The prompt has been answered; make sure the process it named is still
	// the process the grant will serve.
	if cur, ok := lineage.ProcessStartTime(req.TargetPID); !ok || cur != rootStart {
		g.wipeDEKs()
		return Response{OK: false, Error: fmt.Sprintf("grant_create: process %d exited while the prompt was up, no grant created", req.TargetPID)}
	}

	s.grantMu.Lock()
	if s.grants == nil {
		s.grants = map[string]*processGrant{}
	}
	s.grants[id] = g
	st := g.status(true)
	s.grantMu.Unlock()
	s.armGrantExpiry(g.id, g.expires)

	return Response{OK: true, Grants: []GrantStatus{st}}
}

// grantCreateReason words the creation prompt. Everything in it is
// agent-derived or abort-verified: the name comes from the kernel via the
// target pid, the count and duration ARE the grant's scope, and the profile
// names were resolved by the agent itself to exactly the secrets being
// granted (OnResolveGrant), never echoed from free text. The scope statement
// ("unattended, until ...") is the half that must never be the truncated
// half, same budget discipline as trustReason.
func grantCreateReason(name string, profiles []string, count int, ttl time.Duration) string {
	who := truncate(name, maxTrustWhoLen)
	if who == "" {
		who = "this process"
	}
	noun := "secrets"
	if count == 1 {
		noun = "secret"
	}
	// The name and profile budgets are sized so the whole sentence fits
	// maxReasonLen with room to spare: the trailing scope statement
	// ("unattended for …") is the half that changes the decision, so it must
	// never be the half a long tool name pushes off the prompt. The outer
	// truncate is a belt only.
	return truncate(fmt.Sprintf("let %s use %d %s (%s) unattended for %s",
		who, count, noun, truncate(strings.Join(profiles, ", "), 20), formatGrantTTL(ttl)), maxReasonLen)
}

// formatGrantTTL renders a duration the way a human typed it: "8h", "45m",
// "3d" — never time.Duration's "8h0m0s", which reads like a countdown.
func formatGrantTTL(d time.Duration) string {
	d = d.Round(time.Minute)
	if d >= 24*time.Hour && d%(24*time.Hour) == 0 {
		return fmt.Sprintf("%dd", d/(24*time.Hour))
	}
	if d >= time.Hour && d%time.Hour == 0 {
		return fmt.Sprintf("%dh", d/time.Hour)
	}
	if d >= time.Hour {
		return fmt.Sprintf("%dh%02dm", d/time.Hour, (d%time.Hour)/time.Minute)
	}
	return fmt.Sprintf("%dm", d/time.Minute)
}

// grantUnwrap answers an OpUnwrap from the grant store, or returns ok=false
// to send the request down the ordinary session path. On a hit it returns a
// COPY of the cached DEK (mekCopy's reasoning: the store wipes independently
// of the response being written) and the agent-verified vault path for the
// audit record.
//
// Fail-closed at every step, trustRoots-style: expired grants and dead roots
// are ended (with their KindGrantEnd event) rather than skipped, the root's
// fork-time is re-verified before descent, and any unreadable ancestry
// answers "no grant". A miss never errors — the ordinary path decides.
func (s *Server) grantUnwrap(c *caller, wrapped []byte) (dek []byte, path string, ok bool) {
	if c == nil {
		return nil, "", false
	}
	s.grantMu.Lock()
	if len(s.grants) == 0 {
		s.grantMu.Unlock()
		return nil, "", false
	}
	digest := wrappedDigest(wrapped)
	// Snapshot the candidates that cover these wrapped bytes, then verify
	// descent OUTSIDE grantMu — AncestryContainsPID walks sysctls, and list/
	// revoke must not queue behind it (trustRoots' exact discipline).
	type candidate struct {
		id        string
		rootPID   int32
		rootStart int64
	}
	var cands []candidate
	for _, g := range s.grants {
		if _, covered := g.deks[digest]; covered {
			cands = append(cands, candidate{id: g.id, rootPID: g.rootPID, rootStart: g.rootStart})
		}
	}
	s.grantMu.Unlock()
	if len(cands) == 0 {
		s.pruneGrants(time.Now())
		return nil, "", false
	}

	now := time.Now()
	for _, cand := range cands {
		if cur, alive := lineage.ProcessStartTime(cand.rootPID); !alive || cur != cand.rootStart {
			s.endGrant(cand.id, grantEndExited)
			continue
		}
		if !lineage.AncestryContainsPID(c.pid, cand.rootPID) {
			continue
		}
		s.grantMu.Lock()
		g := s.grants[cand.id] // re-check: a revoke may have won the race
		if g == nil {
			s.grantMu.Unlock()
			continue
		}
		if now.After(g.expires) {
			s.grantMu.Unlock()
			s.endGrant(cand.id, grantEndExpired)
			continue
		}
		sec, covered := g.deks[digest]
		if !covered {
			s.grantMu.Unlock()
			continue
		}
		out := make([]byte, len(sec.dek))
		copy(out, sec.dek)
		g.serves++
		g.lastServe = now
		s.grantMu.Unlock()
		return out, sec.path, true
	}
	return nil, "", false
}

// listGrants prunes, then snapshots every live grant for the wire, newest
// first. Prompt-free by design (OpHistory's reasoning: reading what standing
// access exists must never itself cost an authentication).
func (s *Server) listGrants() []GrantStatus {
	s.pruneGrants(time.Now())
	s.grantMu.Lock()
	grants := make([]*processGrant, 0, len(s.grants))
	for _, g := range s.grants {
		grants = append(grants, g)
	}
	s.grantMu.Unlock()

	sort.Slice(grants, func(i, j int) bool { return grants[i].created.After(grants[j].created) })
	out := make([]GrantStatus, 0, len(grants))
	for _, g := range grants {
		cur, alive := lineage.ProcessStartTime(g.rootPID)
		s.grantMu.Lock()
		st := g.status(alive && cur == g.rootStart)
		s.grantMu.Unlock()
		out = append(out, st)
	}
	return out
}

// revokeGrant ends a grant by id, attributing the revoker. Deliberately NO
// challenge: reducing access is always free, and revocation must be the
// easiest operation in the feature — an auth gate on the kill switch only
// ever delays the person pulling it.
func (s *Server) revokeGrant(id string, c *caller) Response {
	s.grantMu.Lock()
	_, exists := s.grants[id]
	s.grantMu.Unlock()
	if !exists {
		return Response{OK: false, Error: fmt.Sprintf("grant_revoke: no grant %q (it may have already expired — `jit grant list` shows what is live)", id)}
	}
	s.endGrantBy(id, grantEndRevoked, c)
	return Response{OK: true}
}

// extendGrant re-prompts (more time is a NEW decision — the original approval
// bounded exactly the window being widened) and moves a grant's deadline to
// now+ttl.
func (s *Server) extendGrant(req Request, c *caller) Response {
	if c == nil {
		return Response{OK: false, Error: "grant_extend: caller could not be identified"}
	}
	ttl := time.Duration(req.TTLSeconds) * time.Second
	if ttl < minGrantTTL || ttl > MaxGrantTTL {
		return Response{OK: false, Error: fmt.Sprintf("grant_extend: ttl must be between %s and %s", minGrantTTL, MaxGrantTTL)}
	}
	s.grantMu.Lock()
	g := s.grants[req.GrantID]
	var name string
	var count int
	var profiles []string
	if g != nil {
		name, count, profiles = g.name, len(g.deks), g.profiles
	}
	s.grantMu.Unlock()
	if g == nil {
		return Response{OK: false, Error: fmt.Sprintf("grant_extend: no grant %q (it may have expired — extend cannot resurrect one, create it again)", req.GrantID)}
	}

	// grantCreateReason already words the full scope; re-lead it as an
	// extension so the prompt says what is actually happening.
	reason := truncate("extend: "+grantCreateReason(name, profiles, count, ttl), maxReasonLen)
	event, mek, err := s.discloseChallengeOp(reason, OpGrantExtend, c)
	if s.OnSessionEvent != nil {
		s.OnSessionEvent(*event)
	}
	if err != nil {
		return Response{OK: false, Error: err.Error()}
	}
	wipe(mek)

	s.grantMu.Lock()
	g = s.grants[req.GrantID] // re-check: it may have ended during the prompt
	if g == nil {
		s.grantMu.Unlock()
		return Response{OK: false, Error: fmt.Sprintf("grant_extend: grant %q ended while the prompt was up", req.GrantID)}
	}
	g.expires = time.Now().Add(ttl)
	st := g.status(true)
	expires := g.expires
	s.grantMu.Unlock()
	s.armGrantExpiry(req.GrantID, expires)
	return Response{OK: true, Grants: []GrantStatus{st}}
}

// endGrant ends one grant with a cause, wiping its DEKs and emitting the
// KindGrantEnd event. Idempotent: a grant already gone is a no-op, so the
// lazy prune, the expiry timer and an explicit revoke can all race safely.
func (s *Server) endGrant(id, cause string) {
	s.endGrantBy(id, cause, nil)
}

func (s *Server) endGrantBy(id, cause string, c *caller) {
	s.grantMu.Lock()
	g := s.grants[id]
	if g == nil {
		s.grantMu.Unlock()
		return
	}
	delete(s.grants, id)
	paths := g.secretPaths()
	name := g.name
	g.wipeDEKs()
	s.grantMu.Unlock()

	event := SessionEvent{
		UnixTime: time.Now().Unix(),
		Kind:     KindGrantEnd,
		Op:       id,
		Cause:    fmt.Sprintf("%s's grant %s", name, cause),
		Labels:   paths,
	}
	if c != nil {
		event.By = c.command()
		event.ByPID = c.pid
		event.LaunchedBy = c.launchedBy()
	}
	s.mu.Lock()
	s.recordEvent(event)
	s.mu.Unlock()
	if s.OnSessionEvent != nil {
		s.OnSessionEvent(event)
	}
}

// pruneGrants ends every grant that is past its deadline or whose root no
// longer exists (fork-time mismatch included). Called lazily from the serve
// and list paths and by each grant's own expiry timer, so an ended grant's
// DEKs never linger much past the moment they stopped being authorized.
func (s *Server) pruneGrants(now time.Time) {
	s.grantMu.Lock()
	type check struct {
		id        string
		rootPID   int32
		rootStart int64
		expired   bool
	}
	var checks []check
	for _, g := range s.grants {
		checks = append(checks, check{id: g.id, rootPID: g.rootPID, rootStart: g.rootStart, expired: now.After(g.expires)})
	}
	s.grantMu.Unlock()

	for _, ch := range checks {
		if ch.expired {
			s.endGrant(ch.id, grantEndExpired)
			continue
		}
		if cur, alive := lineage.ProcessStartTime(ch.rootPID); !alive || cur != ch.rootStart {
			s.endGrant(ch.id, grantEndExited)
		}
	}
}

// armGrantExpiry schedules the expiry sweep for one grant. The timer fires a
// prune rather than ending the id unconditionally — an extend that moved the
// deadline re-arms, and the stale timer's prune then finds nothing expired
// (the same reason armLockTimer carries a generation; here the prune's own
// deadline re-check is the guard).
func (s *Server) armGrantExpiry(id string, expires time.Time) {
	delay := time.Until(expires) + time.Second
	time.AfterFunc(delay, func() {
		s.grantMu.Lock()
		g := s.grants[id]
		expired := g != nil && time.Now().After(g.expires)
		s.grantMu.Unlock()
		if expired {
			s.endGrant(id, grantEndExpired)
		}
	})
}
