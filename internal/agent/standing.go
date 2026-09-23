// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package agent

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/jitpass/jit/internal/lineage"
)

// This file is the standing-grant store (design/standing-grants.md): a grant
// with no deadline that is its own key.
//
// A timed grant (grant.go) is a cache of plaintext DEKs in mlocked memory,
// which is why it has a deadline and dies with the process. A standing grant
// re-wraps the covered DEKs under a GRANT KEY of its own at creation, under
// the same disclosed challenge, and keeps that key in the keychain
// (GrantKeyStore) and the wrapped copies in a ledger on disk. Serving needs
// the grant key and nothing else: not the session, not the MEK, not a prompt.
// It survives screen lock, the idle timer, a service restart and a reboot,
// and ends only when the human revokes it — which deletes the key, so the
// ledger's copies become garbage.
//
// The anchor is the executable path of the app the covered program must
// run under, plus the program's display name, verified by kernel ancestry on
// every serve (lineage.AncestryNamedUnderPath). Not a pid: a pid does not
// survive a reboot, and surviving one is the point. What that gives up, and
// keeps, is stated plainly in the design: a same-named program under the
// same app inside the user's own login session is covered; nothing outside
// that app's tree ever is. The decision is still the disclosed Touch ID at
// creation; ancestry afterwards only narrows.
//
// Nothing secret is written to disk: the ledger holds DEKs wrapped under a
// key that is not on disk, the same trust tier as the vault's envelopes and
// the MEK.

// GrantKey is one standing grant's own key, as the key store hands it back.
// Seal and Open bind the secret's class as AAD exactly as the MEK wrap does,
// so a wrapped copy carries the same class guarantee the original did.
// Close releases whatever the implementation caches; the store's Delete is
// what destroys the key itself.
type GrantKey interface {
	Seal(dek []byte, class string) ([]byte, error)
	Open(wrapped []byte, class string) ([]byte, error)
	Close()
}

// GrantKeyStore creates, loads and deletes grant keys by grant id. Create
// must mint a fresh random key and fail on an id that already has one; Load
// must never prompt; Delete must be idempotent. The CLI wires the keychain
// (internal/keychainwrap); tests wire memory.
type GrantKeyStore interface {
	Create(id string) (GrantKey, error)
	Load(id string) (GrantKey, error)
	Delete(id string) error
}

// standingWrapAEAD names the wrap the ledger carries today: AES-256-GCM
// under a 32-byte keychain-held grant key, class as AAD (seal/open in
// crypto.go). The Secure Enclave move introduces a second value (P-256 ECDH
// → HKDF → AEAD), and a ledger entry says which it is, so both can coexist
// during that migration and a re-wrap is a per-grant Touch ID rather than
// a flag day.
const standingWrapAEAD = "aead-v1"

// standingSecret is one covered secret inside a standing grant: its vault
// path, class, and the DEK sealed under the grant key. digest keys the serve
// path exactly as a timed grant's cache does — the hash of the envelope's
// device-recipient wrapped bytes, which is what the client sends on every
// unwrap — so a rotated secret (new wrapped bytes) simply misses.
type standingSecret struct {
	path         string
	class        string
	digest       string
	grantWrapped []byte
}

// standingGrant is one loaded standing grant. Immutable after creation
// except serves and lastServe, mutated under Server.grantMu. key is the
// lazily loaded GrantKey, guarded by keyMu so a keychain read never runs
// under grantMu.
type standingGrant struct {
	id      string
	created time.Time
	// anchorPath is the executable the covered program must run under;
	// anchorName its display name for the list and the prompt.
	anchorPath string
	anchorName string
	// name is the human's own word for the program (the tree filter);
	// execPath is where it ran from at creation, recorded and shown, never
	// gated (design: Claude Code's path carries its version).
	name      string
	execPath  string
	profiles  []GrantProfile
	secrets   map[string]standingSecret // digest -> secret
	serves    int64
	lastServe time.Time

	keyMu sync.Mutex
	key   GrantKey
}

func (g *standingGrant) secretPaths() []string {
	out := make([]string, 0, len(g.secrets))
	for _, s := range g.secrets {
		out = append(out, s.path)
	}
	sort.Strings(out)
	return out
}

func (g *standingGrant) profileNames() []string {
	out := make([]string, 0, len(g.profiles))
	for _, p := range g.profiles {
		out = append(out, p.Name)
	}
	return out
}

// status snapshots a standing grant for the wire. running is whether the
// anchor app exists right now (informational); rotated the paths whose
// secret changed since creation. Caller holds grantMu.
func (g *standingGrant) status(running bool, rotated []string) GrantStatus {
	st := GrantStatus{
		ID:           g.id,
		Name:         g.name,
		Command:      g.execPath,
		Anchor:       g.anchorName,
		AnchorPath:   g.anchorPath,
		Profiles:     g.profileNames(),
		ProfileRoots: append([]GrantProfile(nil), g.profiles...),
		Secrets:      g.secretPaths(),
		CreatedUnix:  g.created.Unix(),
		Serves:       g.serves,
		RootAlive:    running,
		Standing:     true,
		Rotated:      rotated,
	}
	if !g.lastServe.IsZero() {
		st.LastServeUnix = g.lastServe.Unix()
	}
	return st
}

// ---- the ledger ----

// GrantLedgerPath is where standing grants persist under jit's config
// directory: bookkeeping and wrapped material, never a key, so it sits
// beside the vault tree like the mount registry does.
func GrantLedgerPath(root string) string {
	return filepath.Join(root, "grants.json")
}

// ledgerVersion is bumped when an entry's shape changes incompatibly. A
// newer file than this build understands is refused rather than half-read.
const ledgerVersion = 1

type ledgerFile struct {
	Version int           `json:"version"`
	Grants  []ledgerGrant `json:"grants"`
}

type ledgerGrant struct {
	ID          string `json:"id"`
	CreatedUnix int64  `json:"created_unix"`
	Anchor      struct {
		ExecPath string `json:"exec_path"`
		Name     string `json:"name"`
	} `json:"anchor"`
	Program struct {
		Name     string `json:"name"`
		ExecPath string `json:"exec_path_at_creation,omitempty"`
	} `json:"program"`
	Profiles      []GrantProfile `json:"profiles"`
	Secrets       []ledgerSecret `json:"secrets"`
	Serves        int64          `json:"serves,omitempty"`
	LastServeUnix int64          `json:"last_serve_unix,omitempty"`
}

type ledgerSecret struct {
	Path         string `json:"path"`
	Class        string `json:"class,omitempty"`
	DeviceDigest string `json:"device_wrapped_sha256"`
	GrantWrapped string `json:"grant_wrapped"`
	Wrap         string `json:"wrap"`
}

// SetGrantLedger names the ledger file and loads whatever it holds. Called
// once at service start, before Listen. A missing file is an empty ledger;
// a malformed one is an error the service logs and starts without, since
// refusing to serve anything over one bad grant record would be the wrong
// trade — but nothing is ever written back over a file that failed to
// parse, so a human can still read it.
func (s *Server) SetGrantLedger(path string) (count int, err error) {
	s.grantMu.Lock()
	defer s.grantMu.Unlock()
	s.ledgerPath = path
	data, err := os.ReadFile(path) // #nosec G304 -- a fixed, well-known path under jit's own config directory
	if errors.Is(err, os.ErrNotExist) {
		s.standing = map[string]*standingGrant{}
		return 0, nil
	}
	if err != nil {
		s.ledgerPath = "" // never overwrite a file we could not read
		return 0, err
	}
	var f ledgerFile
	if err := json.Unmarshal(data, &f); err != nil {
		s.ledgerPath = ""
		return 0, fmt.Errorf("parsing %s: %w", path, err)
	}
	if f.Version > ledgerVersion {
		s.ledgerPath = ""
		return 0, fmt.Errorf("%s was written by a newer jit (version %d, this build reads %d)", path, f.Version, ledgerVersion)
	}
	loaded := map[string]*standingGrant{}
	for _, lg := range f.Grants {
		g := &standingGrant{
			id:         lg.ID,
			created:    time.Unix(lg.CreatedUnix, 0),
			anchorPath: lg.Anchor.ExecPath,
			anchorName: lg.Anchor.Name,
			name:       lg.Program.Name,
			execPath:   lg.Program.ExecPath,
			profiles:   append([]GrantProfile(nil), lg.Profiles...),
			secrets:    make(map[string]standingSecret, len(lg.Secrets)),
			serves:     lg.Serves,
		}
		if lg.LastServeUnix > 0 {
			g.lastServe = time.Unix(lg.LastServeUnix, 0)
		}
		for _, ls := range lg.Secrets {
			if ls.Wrap != standingWrapAEAD {
				// A wrap this build cannot open is skipped, not served: the
				// grant then reports fewer secrets than it was made with,
				// and the list shows the gap.
				continue
			}
			gw, err := hex.DecodeString(ls.GrantWrapped)
			if err != nil || ls.DeviceDigest == "" || ls.Path == "" {
				continue
			}
			g.secrets[ls.DeviceDigest] = standingSecret{path: ls.Path, class: ls.Class, digest: ls.DeviceDigest, grantWrapped: gw}
		}
		if g.id == "" || g.anchorPath == "" || g.name == "" {
			continue
		}
		loaded[g.id] = g
	}
	s.standing = loaded
	return len(loaded), nil
}

// saveLedger writes the current standing grants atomically (temp file,
// rename), 0600. Caller must NOT hold grantMu: it takes it to snapshot.
// A server with no ledger path (tests without persistence, a service whose
// ledger failed to parse) keeps its grants in memory only.
func (s *Server) saveLedger() error {
	s.grantMu.Lock()
	path := s.ledgerPath
	f := ledgerFile{Version: ledgerVersion, Grants: make([]ledgerGrant, 0, len(s.standing))}
	for _, g := range s.standing {
		lg := ledgerGrant{ID: g.id, CreatedUnix: g.created.Unix(), Profiles: append([]GrantProfile(nil), g.profiles...), Serves: g.serves}
		lg.Anchor.ExecPath, lg.Anchor.Name = g.anchorPath, g.anchorName
		lg.Program.Name, lg.Program.ExecPath = g.name, g.execPath
		if !g.lastServe.IsZero() {
			lg.LastServeUnix = g.lastServe.Unix()
		}
		for _, sec := range g.secrets {
			lg.Secrets = append(lg.Secrets, ledgerSecret{
				Path: sec.path, Class: sec.class, DeviceDigest: sec.digest,
				GrantWrapped: hex.EncodeToString(sec.grantWrapped), Wrap: standingWrapAEAD,
			})
		}
		sort.Slice(lg.Secrets, func(i, j int) bool { return lg.Secrets[i].Path < lg.Secrets[j].Path })
		f.Grants = append(f.Grants, lg)
	}
	s.grantMu.Unlock()
	if path == "" {
		return nil
	}
	sort.Slice(f.Grants, func(i, j int) bool { return f.Grants[i].CreatedUnix < f.Grants[j].CreatedUnix })
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ---- create ----

// createStandingGrant is the standing half of createGrant, entered after the
// disclosed challenge has been answered and the MEK is in hand: it mints the
// grant key, re-wraps every covered DEK under it, persists the record, and
// never lets a plaintext DEK outlive the loop iteration that made it.
func (s *Server) createStandingGrant(req Request, target lineage.Process, profiles []GrantProfile, secrets []GrantSecret, mek []byte) Response {
	id, err := newGrantID()
	if err != nil {
		return Response{OK: false, Error: err.Error()}
	}
	key, err := s.GrantKeys.Create(id)
	if err != nil {
		return Response{OK: false, Error: fmt.Sprintf("grant_create: making the grant's key: %s", err)}
	}
	g := &standingGrant{
		id:         id,
		created:    time.Now(),
		anchorPath: target.ExecPath,
		anchorName: target.Name(),
		name:       req.GrantName,
		profiles:   append([]GrantProfile(nil), profiles...),
		secrets:    make(map[string]standingSecret, len(secrets)),
		key:        key,
	}
	// Where the program runs from right now, for the record: the newest
	// process carrying the name under the anchor, if any.
	for _, p := range lineage.VisibleProcesses() {
		if p.MatchesName(req.GrantName) && lineage.AncestryNamedUnderPath(p.PID, target.ExecPath, req.GrantName) {
			g.execPath = p.ExecPath
			break
		}
	}
	fail := func(msg string) Response {
		key.Close()
		_ = s.GrantKeys.Delete(id)
		return Response{OK: false, Error: msg}
	}
	for _, sec := range secrets {
		dek, err := open(mek, sec.Wrapped, []byte(sec.Class))
		if err != nil {
			// One bad entry fails the whole create (grant.go's rule): the
			// human approved a specific count.
			return fail(fmt.Sprintf("grant_create: %s cannot be unwrapped (%s), no grant created", sec.Path, err))
		}
		gw, err := key.Seal(dek, sec.Class)
		wipe(dek)
		if err != nil {
			return fail(fmt.Sprintf("grant_create: %s cannot be sealed under the grant key (%s), no grant created", sec.Path, err))
		}
		g.secrets[wrappedDigest(sec.Wrapped)] = standingSecret{path: sec.Path, class: sec.Class, digest: wrappedDigest(sec.Wrapped), grantWrapped: gw}
	}

	s.grantMu.Lock()
	if s.standing == nil {
		s.standing = map[string]*standingGrant{}
	}
	s.standing[id] = g
	st := g.status(true, nil)
	s.grantMu.Unlock()
	if err := s.saveLedger(); err != nil {
		// The grant exists in memory and its key in the keychain; a ledger
		// that could not be written means it will not survive a restart.
		// Say so rather than pretend: the human just approved something
		// described as standing.
		s.grantMu.Lock()
		delete(s.standing, id)
		s.grantMu.Unlock()
		return fail(fmt.Sprintf("grant_create: the grant could not be recorded (%s), no grant created", err))
	}
	return Response{OK: true, Grants: []GrantStatus{st}}
}

// ---- serve ----

// standingUnwrap answers an OpUnwrap from the standing grants, or ok=false.
// Same fail-closed shape as grantUnwrap: candidates are snapshotted under
// grantMu, ancestry is walked outside it, the key is fetched outside it,
// and a miss never errors.
func (s *Server) standingUnwrap(c *caller, wrapped []byte) (dek []byte, path string, ok bool) {
	if c == nil || s.GrantKeys == nil {
		return nil, "", false
	}
	digest := wrappedDigest(wrapped)
	s.grantMu.Lock()
	var cands []*standingGrant
	for _, g := range s.standing {
		if _, covered := g.secrets[digest]; covered {
			cands = append(cands, g)
		}
	}
	s.grantMu.Unlock()
	for _, g := range cands {
		if !lineage.AncestryNamedUnderPath(c.pid, g.anchorPath, g.name) {
			continue
		}
		key, err := s.grantKey(g)
		if err != nil {
			// A grant whose key is gone (deleted out of band) cannot serve;
			// it falls through to the ordinary path, and the list will say
			// what happened when it is asked.
			continue
		}
		s.grantMu.Lock()
		sec, still := g.secrets[digest]
		if _, live := s.standing[g.id]; !live || !still { // a revoke may have won the race
			s.grantMu.Unlock()
			continue
		}
		s.grantMu.Unlock()
		out, err := key.Open(sec.grantWrapped, sec.class)
		if err != nil {
			continue
		}
		s.grantMu.Lock()
		g.serves++
		g.lastServe = time.Now()
		s.grantMu.Unlock()
		// Best-effort: a use count that did not reach disk is not worth
		// failing a serve over.
		_ = s.saveLedger()
		return out, sec.path, true
	}
	return nil, "", false
}

// grantKey returns a grant's key, loading it from the store on first use.
func (s *Server) grantKey(g *standingGrant) (GrantKey, error) {
	g.keyMu.Lock()
	defer g.keyMu.Unlock()
	if g.key != nil {
		return g.key, nil
	}
	key, err := s.GrantKeys.Load(g.id)
	if err != nil {
		return nil, err
	}
	g.key = key
	return key, nil
}

// ---- list ----

// standingStatuses snapshots every standing grant for the wire, newest
// first, with rotation checked against the vault's current wrapped bytes
// (OnWrappedDEK) and the anchor app's presence checked against the process
// table. Prompt-free: neither check decrypts anything.
func (s *Server) standingStatuses() []GrantStatus {
	s.grantMu.Lock()
	grants := make([]*standingGrant, 0, len(s.standing))
	for _, g := range s.standing {
		grants = append(grants, g)
	}
	s.grantMu.Unlock()
	if len(grants) == 0 {
		return nil
	}
	sort.Slice(grants, func(i, j int) bool { return grants[i].created.After(grants[j].created) })

	running := map[string]bool{}
	for _, p := range lineage.VisibleProcesses() {
		if p.ExecPath != "" {
			running[p.ExecPath] = true
		}
	}
	out := make([]GrantStatus, 0, len(grants))
	for _, g := range grants {
		var rotated []string
		if s.OnWrappedDEK != nil {
			s.grantMu.Lock()
			secs := make([]standingSecret, 0, len(g.secrets))
			for _, sec := range g.secrets {
				secs = append(secs, sec)
			}
			s.grantMu.Unlock()
			for _, sec := range secs {
				cur, _, err := s.OnWrappedDEK(sec.path)
				if err != nil || wrappedDigest(cur) != sec.digest {
					rotated = append(rotated, sec.path)
				}
			}
			sort.Strings(rotated)
		}
		s.grantMu.Lock()
		out = append(out, g.status(running[g.anchorPath], rotated))
		s.grantMu.Unlock()
	}
	return out
}

// ---- revoke ----

// revokeStanding ends a standing grant: the key is deleted first (so the
// ledger's copies are garbage before the record goes), then the record,
// then the ledger is rewritten. Idempotent on a missing id. No challenge,
// as with every revoke: reducing access is free.
func (s *Server) revokeStanding(id string, c *caller) bool {
	s.grantMu.Lock()
	g := s.standing[id]
	if g == nil {
		s.grantMu.Unlock()
		return false
	}
	delete(s.standing, id)
	paths := g.secretPaths()
	name := g.name
	s.grantMu.Unlock()

	g.keyMu.Lock()
	if g.key != nil {
		g.key.Close()
		g.key = nil
	}
	g.keyMu.Unlock()
	if s.GrantKeys != nil {
		_ = s.GrantKeys.Delete(id)
	}
	_ = s.saveLedger()

	event := SessionEvent{
		UnixTime: time.Now().Unix(),
		Kind:     KindGrantEnd,
		Op:       id,
		Cause:    fmt.Sprintf("%s's grant %s", name, grantEndRevoked),
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
	return true
}

// closeStanding releases every cached grant key. Called from Server.Close;
// the ledger and the keychain items are untouched, since the grants outlive
// the process by design.
func (s *Server) closeStanding() {
	s.grantMu.Lock()
	grants := make([]*standingGrant, 0, len(s.standing))
	for _, g := range s.standing {
		grants = append(grants, g)
	}
	s.grantMu.Unlock()
	for _, g := range grants {
		g.keyMu.Lock()
		if g.key != nil {
			g.key.Close()
			g.key = nil
		}
		g.keyMu.Unlock()
	}
}
