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
	"regexp"
	"sort"
	"sync"
	"time"

	"github.com/jitpass/jit/internal/atomicfile"
	"github.com/jitpass/jit/internal/jsonkeep"
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
// and the Secure Enclave behind one store (cli's grantKeyStore); tests wire
// memory.
//
// A Delete that removed what it could reach but could not reach where a key
// of the other kind may live (the Secure Enclave, from a jit without its
// entitlement) returns an error that is ErrGrantKeyUnreachable, joined with
// any real failure.
type GrantKeyStore interface {
	Create(id string) (GrantKey, error)
	Load(id string) (GrantKey, error)
	Delete(id string) error
}

// ErrGrantKeyUnreachable is a GrantKeyStore's Delete saying it could not
// reach the Secure Enclave, so a key there, if any, is still there. It is
// not a failure of the revoke or the remove: the record is gone, so nothing
// can use that key, and the start-up cleanup (grantorphans.go) deletes it
// once a jit that can reach the enclave runs the service, because nothing
// names it any more. But no one may be told it was deleted.
var ErrGrantKeyUnreachable = errors.New("the Secure Enclave could not be reached from this copy of jit")

// keyKeptNote is what a revoke or a remove says, instead of claiming a
// delete, when the key its entries are sealed for is in an enclave this
// copy of jit cannot reach.
const keyKeptNote = "Its Secure Enclave key couldn't be reached from this copy of jit; JitPass's service deletes it the next time it starts."

// keyNoteOf is what a revoke or a remove tells the caller about the key,
// from deleteKeyOf: nothing when it was deleted, keyKeptNote when it sits
// in an enclave this jit cannot reach, and the failure itself when the
// delete failed. The record is gone either way, so nothing names the key
// and the next start's cleanup (grantorphans.go) tries it again.
func keyNoteOf(note string, err error) string {
	if err != nil {
		return fmt.Sprintf("Its key couldn't be deleted (%s); JitPass's service tries again the next time it starts.", err)
	}
	return note
}

// deleteKeyOf deletes a grant's or job's key after its record is gone, and
// says what happened. note is keyKeptNote when the store could not reach
// the enclave and the record's entries may be sealed for a key there
// (mayBeEnclave: an enclave entry, or one this build cannot read); a record
// sealed only for the keychain had that key deleted, and whatever leftover
// the enclave may hold goes at the next start's cleanup. err is any other
// failure.
func (s *Server) deleteKeyOf(id string, mayBeEnclave bool) (note string, err error) {
	err = s.GrantKeys.Delete(id)
	if errors.Is(err, ErrGrantKeyUnreachable) {
		err = withoutUnreachable(err)
		if mayBeEnclave {
			note = keyKeptNote
		}
	}
	return note, err
}

// withoutUnreachable is err with every ErrGrantKeyUnreachable taken out of
// an errors.Join (the store's shape): nil if that was all it said.
func withoutUnreachable(err error) error {
	if j, ok := err.(interface{ Unwrap() []error }); ok {
		var rest []error
		for _, e := range j.Unwrap() {
			if e = withoutUnreachable(e); e != nil {
				rest = append(rest, e)
			}
		}
		return errors.Join(rest...)
	}
	if errors.Is(err, ErrGrantKeyUnreachable) {
		return nil
	}
	return err
}

// standingWrapAEAD names the wrap the ledger carries today: AES-256-GCM
// under a 32-byte keychain-held grant key, class as AAD (seal/open in
// crypto.go). The Secure Enclave grant key is the second value,
// standingWrapEnclave below, and a ledger entry says which it is, so both
// coexist; MoveGrantKeys re-seals a grant to the vault's kind at service
// start, with no prompt (plan C3).
const standingWrapAEAD = "aead-v1"

// standingWrapEnclave is the Secure Enclave grant key's wrap: ECIES to a
// P-256 enclave key, class bound inside the sealed bytes (plan C2). Spelled
// here, not imported, because this package never imports a CGo backend; a
// test in this package holds it equal to secureenclave.GrantWrap.
const standingWrapEnclave = "se-p256-v1"

// knownWrap reports whether this build can open a ledger entry's wrap with
// SOME key. Whether a given grant's key is that kind is keyWrap's question.
func knownWrap(w string) bool { return w == standingWrapAEAD || w == standingWrapEnclave }

// keyWrap names what k seals: a key that says (the enclave's), or the
// keychain's aead-v1 for one that predates saying.
func keyWrap(k GrantKey) string {
	if w, ok := k.(interface{ Wrap() string }); ok {
		return w.Wrap()
	}
	return standingWrapAEAD
}

// standingExpiryCompat is the ExpiresUnix a standing grant reports on the
// WIRE, and nothing else: 2099-12-31, an obviously synthetic date meaning
// "this does not expire".
//
// It exists for one reason. A client older than standing grants has no
// Standing field to read and renders the deadline it does have, so a zero
// ExpiresUnix came out as the Unix epoch — jit 2.2.6 printed a live
// standing grant as "expires Thu 02:00 (0m left)" and `jit status` as
// "next expires Thu 02:00". A grant that never expires reading as long
// expired is the worst direction for that error to point, and the old
// binary cannot be changed. A far-future instant is the standard way to
// say "no expiry" to a field that insists on one: the old renderer then
// shows a date decades out with tens of thousands of days remaining,
// which is true.
//
// Every current reader MUST branch on Standing and never read this: the
// CLI's grant list and status do, the app's Format.grantFact does, and
// TestStandingGrantReportsACompatExpiryOldClientsCanRender pins it.
// Nothing server-side ever reads GrantStatus back, so this value decides
// nothing — a standing grant's record genuinely has no deadline, which is
// why the serve path has no expiry check for one.
// The noon-UTC hour is deliberate. The old renderer drops the DATE for
// anything past tomorrow and prints a bare weekday and clock, so no
// instant can be made unambiguous there; midnight UTC happened to land on
// "Thu 02:00" in this timezone, the very string the epoch produced, which
// made the fix look like no fix at all when read side by side.
var standingExpiryCompat = time.Date(2099, time.December, 31, 12, 0, 0, 0, time.UTC)

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
	// wrap is how grantWrapped was sealed, written back as it was read:
	// the ledger holds more than one kind once grant keys move to the
	// Secure Enclave (design/secure-enclave-plan.md, C), and saving must
	// never relabel one as another.
	wrap string
	// raw is the ledger entry this secret was read from, if it was: its
	// fields this build does not know are written back with it (jsonkeep).
	raw []byte
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
	name     string
	execPath string
	profiles []GrantProfile
	secrets  map[string]standingSecret // digest -> secret
	// unread holds ledger entries this build cannot serve: sealed in a way
	// it cannot open (a newer jit's wrap), or not reading as an entry it
	// knows (sealed bytes that are not hex, no digest, no path). They are
	// not served, and they are written back byte for byte: an older jit
	// that dropped them would delete them from the ledger on its next save,
	// and a later upgrade could not get them back. Since nothing here knows
	// which kind of key such an entry needs, a grant holding one keeps
	// every kind (the move's deleteOthers, a revoke's key note).
	unread []ledgerSecret
	// raw is the ledger record this grant was read from, if it was: its
	// fields this build does not know are written back with it (jsonkeep).
	raw       []byte
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
		ExpiresUnix:  standingExpiryCompat.Unix(),
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

// rawLedgerFile is ledgerFile with every grant left as it was written.
type rawLedgerFile struct {
	Version int               `json:"version"`
	Grants  []json.RawMessage `json:"grants"`
}

// keptGrant is a ledger record SetGrantLedger could not accept (no id,
// anchor or program name, or a field that does not read as this build's),
// kept as the file held it. It is never served,
// listed or revoked: it is not a grant. saveLedger writes it back
// unchanged, so the record, and the key id it names, outlive every save
// (the start-up key cleanup keeps any key the ledger names).
type keptGrant struct {
	id  string // as written, possibly empty; a loaded grant of this id wins
	raw json.RawMessage
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

	// raw is the record as the file held it, for MarshalJSON.
	raw []byte
}

type ledgerSecret struct {
	Path         string `json:"path"`
	Class        string `json:"class,omitempty"`
	DeviceDigest string `json:"device_wrapped_sha256"`
	GrantWrapped string `json:"grant_wrapped"`
	Wrap         string `json:"wrap"`

	// raw is the entry as the file held it, for MarshalJSON; verbatim
	// writes it back exactly so (an unread entry).
	raw      []byte
	verbatim bool
}

// MarshalJSON writes the grant with every field of the record it was read
// from that this build does not know (jsonkeep), so a save by this jit
// never deletes what a newer one wrote.
func (lg ledgerGrant) MarshalJSON() ([]byte, error) {
	type plain ledgerGrant
	return jsonkeep.Marshal(plain(lg), lg.raw)
}

// UnmarshalJSON reads the grant and keeps the record it came from. A field
// of the wrong type still leaves the rest read, so a record SetGrantLedger
// keeps unread still has its id.
func (lg *ledgerGrant) UnmarshalJSON(b []byte) error {
	type plain ledgerGrant
	var p plain
	err := json.Unmarshal(b, &p)
	*lg = ledgerGrant(p)
	lg.raw = append([]byte(nil), b...)
	return err
}

// MarshalJSON is ledgerGrant's, for one entry; an unread entry is written
// exactly as it was read.
func (ls ledgerSecret) MarshalJSON() ([]byte, error) {
	if ls.verbatim && len(ls.raw) > 0 {
		return ls.raw, nil
	}
	type plain ledgerSecret
	return jsonkeep.Marshal(plain(ls), ls.raw)
}

// UnmarshalJSON is ledgerGrant's, for one entry.
func (ls *ledgerSecret) UnmarshalJSON(b []byte) error {
	type plain ledgerSecret
	var p plain
	err := json.Unmarshal(b, &p)
	*ls = ledgerSecret(p)
	ls.raw = append([]byte(nil), b...)
	return err
}

// SetGrantLedger names the ledger file and loads whatever it holds. Called
// once at service start, before Listen. A missing file is an empty ledger;
// a malformed one is an error the service logs and starts without, since
// refusing to serve anything over one bad grant record would be the wrong
// trade — but nothing is ever written back over a file that failed to
// parse, so a human can still read it. The file is read and parsed once:
// each record is decoded from the bytes that parse left it as, and the key
// ids it names are walked from the same bytes.
func (s *Server) SetGrantLedger(path string) (count int, err error) {
	s.grantMu.Lock()
	defer s.grantMu.Unlock()
	s.ledgerPath, s.ledgerNames, s.ledgerKept = path, nil, nil
	data, err := os.ReadFile(path) // #nosec G304 -- a fixed, well-known path under jit's own config directory
	if errors.Is(err, os.ErrNotExist) {
		s.standing = map[string]*standingGrant{}
		s.ledgerNames = map[string]bool{}
		return 0, nil
	}
	fail := func(err error) (int, error) {
		s.ledgerPath = "" // never overwrite a file we could not read
		return 0, err
	}
	if err != nil {
		return fail(err)
	}
	var f rawLedgerFile
	if err := json.Unmarshal(data, &f); err != nil {
		return fail(fmt.Errorf("parsing %s: %w", path, err))
	}
	if f.Version > ledgerVersion {
		return fail(fmt.Errorf("%s was written by a newer jit (version %d, this build reads %d)", path, f.Version, ledgerVersion))
	}
	names, err := namedKeyIDs(data)
	if err != nil {
		return fail(fmt.Errorf("parsing %s: %w", path, err))
	}
	loaded := map[string]*standingGrant{}
	var skipped []keptGrant
	for _, r := range f.Grants {
		var lg ledgerGrant
		if err := json.Unmarshal(r, &lg); err != nil || lg.ID == "" || lg.Anchor.ExecPath == "" || lg.Program.Name == "" {
			// Not served, but not dropped either: kept verbatim for
			// saveLedger, unless a loaded grant has its id (that one wins).
			skipped = append(skipped, keptGrant{id: lg.ID, raw: r})
			continue
		}
		loaded[lg.ID] = grantFromLedger(lg)
	}
	s.standing, s.ledgerNames = loaded, names
	s.ledgerKept = unshadowedGrants(skipped, loaded)
	return len(loaded), nil
}

// grantFromLedger is a loaded standing grant from its ledger record.
func grantFromLedger(lg ledgerGrant) *standingGrant {
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
		raw:        lg.raw,
	}
	if lg.LastServeUnix > 0 {
		g.lastServe = time.Unix(lg.LastServeUnix, 0)
	}
	for _, ls := range lg.Secrets {
		gw, err := hex.DecodeString(ls.GrantWrapped)
		if !knownWrap(ls.Wrap) || err != nil || ls.DeviceDigest == "" || ls.Path == "" {
			// A wrap this build cannot open, or an entry that does not
			// read as one, is not served: the grant then reports fewer
			// secrets than it was made with, and the list shows the gap.
			// It is kept, verbatim, for saveLedger.
			ls.verbatim = true
			g.unread = append(g.unread, ls)
			continue
		}
		g.secrets[ls.DeviceDigest] = standingSecret{path: ls.Path, class: ls.Class, digest: ls.DeviceDigest, grantWrapped: gw, wrap: ls.Wrap, raw: ls.raw}
	}
	return g
}

// unshadowedGrants is kept without every record a loaded grant has the id
// of: the loaded one wins, and the ledger never holds two grants of one id.
// The one place that rule is applied, at load and at every save.
func unshadowedGrants(kept []keptGrant, standing map[string]*standingGrant) []keptGrant {
	var out []keptGrant
	for _, k := range kept {
		if _, loaded := standing[k.id]; !loaded {
			out = append(out, k)
		}
	}
	return out
}

// mintedKeyID is the shape of every grant and job key id jit makes: g- or j-
// and eight hex digits.
var mintedKeyID = regexp.MustCompile(`^[gj]-[0-9a-f]{8}$`)

// namedKeyIDs is every string in a JSON document that has the shape of a key
// id jit mints, wherever it sits: the ids a file names, read raw, including
// records a loader skips and fields a newer jit may add. The orphan cleanup
// (grantorphans.go) keeps every key so named. A document that does not parse
// is an error, and the caller keeps no names at all.
func namedKeyIDs(data []byte) (map[string]bool, error) {
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, err
	}
	out := map[string]bool{}
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case string:
			if mintedKeyID.MatchString(x) {
				out[x] = true
			}
		case []any:
			for _, e := range x {
				walk(e)
			}
		case map[string]any:
			for k, e := range x {
				walk(k)
				walk(e)
			}
		}
	}
	walk(v)
	return out, nil
}

// ledgerServeInterval bounds how often the SERVE path rewrites the ledger.
// Nothing authorization-critical lives in a serve's update — only the serve
// count and the last-serve stamp, which are bookkeeping — so the cost of
// losing the last few seconds of them to a crash is a slightly low counter,
// against a full JSON marshal plus a write and a rename on every credential
// read. Structural changes (create, revoke) never wait: they call
// saveLedger directly, and Close flushes whatever a serve left dirty.
const ledgerServeInterval = 10 * time.Second

// saveLedgerAfterServe persists a serve's bookkeeping at most once per
// ledgerServeInterval, marking the rest dirty for the next writer or for
// Close.
func (s *Server) saveLedgerAfterServe() {
	s.ledgerMu.Lock()
	if time.Since(s.ledgerSavedAt) < ledgerServeInterval {
		s.ledgerDirty = true
		s.ledgerMu.Unlock()
		return
	}
	s.ledgerMu.Unlock()
	_ = s.saveLedger()
}

// flushLedger writes what a coalesced serve left behind. Called on the way
// out, so a clean stop never loses a count it could have kept.
func (s *Server) flushLedger() {
	s.ledgerMu.Lock()
	dirty := s.ledgerDirty
	s.ledgerMu.Unlock()
	if dirty {
		_ = s.saveLedger()
	}
}

// ledgerReady reports whether a standing grant made now could survive a
// restart: a ledger path is set, which SetGrantLedger clears on any file it
// refused to read rather than risk overwriting.
func (s *Server) ledgerReady() bool {
	s.grantMu.Lock()
	defer s.grantMu.Unlock()
	return s.ledgerPath != ""
}

// saveLedger writes the current standing grants atomically and durably,
// 0600 (writeState). Caller must NOT hold grantMu or ledgerMu: it takes
// both. A server with no ledger path (tests without persistence, a service
// whose ledger failed to parse) keeps its grants in memory only.
//
// ledgerMu spans the SNAPSHOT as well as the write, and both halves of that
// are load-bearing:
//
//   - Two concurrent saves used to write the same temp path and rename it
//     out from under each other, publishing a spliced file (the temp name is
//     random now, but the lock is what orders the renames). Measured, not
//     feared: six concurrent callers produced invalid JSON in a quarter of
//     a second. Every serve saves (it bumps serves/lastServe) and every
//     mount read and `jit run` is a serve, so the race is on the hot path,
//     and the payload length really does change between saves — the first
//     serve adds a last_serve_unix line, and a serve count rolls digits.
//     The cost of losing was total: the next start cannot parse the file,
//     disowns it, and every standing grant silently disappears with its
//     keychain key orphaned and nothing left that can name it for revoke.
//   - Snapshotting inside the same lock is what makes a revoke durable. A
//     serve that had already snapshotted could otherwise rename its older
//     picture over a revoke's, resurrecting a grant whose key was already
//     deleted: gone from memory, back on disk, unservable, and refused by
//     revoke because it is no longer in either store.
func (s *Server) saveLedger() error {
	s.ledgerMu.Lock()
	defer s.ledgerMu.Unlock()
	s.ledgerDirty = false
	s.ledgerSavedAt = time.Now()
	s.grantMu.Lock()
	path := s.ledgerPath
	f := ledgerFile{Version: ledgerVersion, Grants: make([]ledgerGrant, 0, len(s.standing))}
	for _, g := range s.standing {
		lg := ledgerGrant{ID: g.id, CreatedUnix: g.created.Unix(), Profiles: append([]GrantProfile(nil), g.profiles...), Serves: g.serves, raw: g.raw}
		lg.Anchor.ExecPath, lg.Anchor.Name = g.anchorPath, g.anchorName
		lg.Program.Name, lg.Program.ExecPath = g.name, g.execPath
		if !g.lastServe.IsZero() {
			lg.LastServeUnix = g.lastServe.Unix()
		}
		for _, sec := range g.secrets {
			wrap := sec.wrap
			if wrap == "" {
				wrap = standingWrapAEAD
			}
			lg.Secrets = append(lg.Secrets, ledgerSecret{
				Path: sec.path, Class: sec.class, DeviceDigest: sec.digest,
				GrantWrapped: hex.EncodeToString(sec.grantWrapped), Wrap: wrap, raw: sec.raw,
			})
		}
		lg.Secrets = append(lg.Secrets, g.unread...)
		sort.Slice(lg.Secrets, func(i, j int) bool { return lg.Secrets[i].Path < lg.Secrets[j].Path })
		f.Grants = append(f.Grants, lg)
	}
	// The records SetGrantLedger could not accept go back as they came,
	// after the grants. Nothing in memory changes here, so a write that
	// fails leaves every record where the caller's rollback expects it.
	kept := unshadowedGrants(s.ledgerKept, s.standing)
	s.grantMu.Unlock()
	if path == "" {
		return nil
	}
	sort.Slice(f.Grants, func(i, j int) bool { return f.Grants[i].CreatedUnix < f.Grants[j].CreatedUnix })
	out := rawLedgerFile{Version: f.Version, Grants: make([]json.RawMessage, 0, len(f.Grants)+len(kept))}
	for _, lg := range f.Grants {
		b, err := json.Marshal(lg)
		if err != nil {
			return err
		}
		out.Grants = append(out.Grants, b)
	}
	for _, k := range kept {
		out.Grants = append(out.Grants, k.raw)
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	return s.writeState(path, data)
}

// writeState writes one of the service's own state files (the grant ledger,
// the job list) with atomicfile.WriteFile, the one implementation behind
// vault.AtomicWriteFile too (this package never imports internal/vault): a
// temp file created exclusively under a fresh random name beside it (so a
// leftover temp, or a symlink planted where one would go, is never written
// through), mode 0600, fsynced, renamed over the old file, and the directory
// fsynced so the rename itself survives a power cut. The fsyncs matter here
// more than for most files: a move (plan C3) deletes a grant's old key right
// after the ledger names the new one, and a ledger that reverted on power
// loss would then name a key that no longer exists.
func (s *Server) writeState(path string, data []byte) error {
	if s.stateWriter != nil {
		return s.stateWriter(path, data)
	}
	return atomicfile.WriteFile(path, data)
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
		wrap := keyWrap(key)
		wipe(dek)
		if err != nil {
			return fail(fmt.Sprintf("grant_create: %s cannot be sealed under the grant key (%s), no grant created", sec.Path, err))
		}
		g.secrets[wrappedDigest(sec.Wrapped)] = standingSecret{path: sec.Path, class: sec.Class, digest: wrappedDigest(sec.Wrapped), grantWrapped: gw, wrap: wrap}
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
		s.grantMu.Lock()
		sec, still := g.secrets[digest]
		if _, live := s.standing[g.id]; !live || !still { // a revoke may have won the race
			s.grantMu.Unlock()
			continue
		}
		s.grantMu.Unlock()
		out, err := s.openStanding(g, sec)
		if err != nil {
			// A grant whose key is gone (deleted out of band) cannot serve;
			// it falls through to the ordinary path, and the list will say
			// what happened when it is asked.
			continue
		}
		s.grantMu.Lock()
		g.serves++
		g.lastServe = time.Now()
		s.grantMu.Unlock()
		// Best-effort and coalesced: a use count that did not reach disk is
		// not worth failing a serve over, and it is certainly not worth a
		// whole-ledger marshal, write and rename per credential read on the
		// path that serves every mount.
		s.saveLedgerAfterServe()
		return out, sec.path, true
	}
	return nil, "", false
}

// errOtherKind: the store handed back a key of another kind than the entry
// is sealed for, which is never tried.
var errOtherKind = errors.New("the grant's key is not the kind its entry is sealed for")

// openStanding opens sec with g's key of the kind sec is sealed for (not
// whichever kind exists: a move that made the new key and then failed
// leaves the grant sealed for its old one, and that is the key that opens
// it), loading it on first use or when the cached one is the other kind.
//
// keyMu is held from the load through the Open. The cached key is replaced,
// and the old one closed, only under keyMu, and a revoke, a move and Close
// close it only under keyMu too, so no serve ever opens with a key another
// has closed: a closed key's memory, in the Secure Enclave's cgo half, is
// freed. The price is that serves of ONE grant open one at a time; serves
// of different grants never wait on each other, and nothing under keyMu
// takes grantMu.
func (s *Server) openStanding(g *standingGrant, sec standingSecret) ([]byte, error) {
	wrap := sec.wrap
	if wrap == "" {
		wrap = standingWrapAEAD
	}
	g.keyMu.Lock()
	defer g.keyMu.Unlock()
	if g.key == nil || keyWrap(g.key) != wrap {
		key, err := s.loadGrantKey(g.id, wrap)
		if err != nil {
			return nil, err
		}
		if g.key != nil {
			g.key.Close()
		}
		g.key = key
	}
	if keyWrap(g.key) != wrap {
		return nil, errOtherKind
	}
	return g.key.Open(sec.grantWrapped, sec.class)
}

// loadGrantKey loads id's key of the kind wrap names. A store that holds
// both kinds (GrantKeyMover) is asked for exactly that kind: its plain Load
// prefers the enclave's whenever one exists, and an enclave key can exist
// beside a grant or job still sealed for its keychain key (a move that made
// the new key and then failed to re-seal or to save, or a move back). A
// store of one kind has nothing to choose between.
func (s *Server) loadGrantKey(id, wrap string) (GrantKey, error) {
	if wrap == "" {
		wrap = standingWrapAEAD
	}
	if m, ok := s.GrantKeys.(GrantKeyMover); ok {
		return m.LoadWrap(id, wrap)
	}
	return s.GrantKeys.Load(id)
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
//
// keyNote is keyKeptNote when the key could not be deleted from here (the
// grant's entries are sealed for a Secure Enclave this jit cannot reach):
// the grant is revoked all the same, and the caller must not be told the key
// went with it.
func (s *Server) revokeStanding(id string, c *caller) (revoked bool, keyNote string) {
	s.grantMu.Lock()
	g := s.standing[id]
	if g == nil {
		s.grantMu.Unlock()
		return false, ""
	}
	delete(s.standing, id)
	paths := g.secretPaths()
	name := g.name
	mayBeEnclave := len(g.unread) > 0
	for _, sec := range g.secrets {
		mayBeEnclave = mayBeEnclave || sec.wrap == standingWrapEnclave
	}
	s.grantMu.Unlock()

	g.keyMu.Lock()
	if g.key != nil {
		g.key.Close()
		g.key = nil
	}
	g.keyMu.Unlock()
	if s.GrantKeys != nil {
		keyNote = keyNoteOf(s.deleteKeyOf(id, mayBeEnclave))
	}
	_ = s.saveLedger()

	cause := fmt.Sprintf("%s's grant %s", name, grantEndRevoked)
	if keyNote != "" {
		cause += ". " + keyNote
	}
	event := SessionEvent{
		UnixTime: time.Now().Unix(),
		Kind:     KindGrantEnd,
		Op:       id,
		Cause:    cause,
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
	return true, keyNote
}

// closeStanding releases every cached grant key. Called from Server.Close;
// the ledger and the keychain items are untouched, since the grants outlive
// the process by design.
func (s *Server) closeStanding() {
	s.flushLedger()
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
