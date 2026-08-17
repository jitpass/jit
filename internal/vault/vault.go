// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package vault

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ErrNotFound is returned by Get/Remove when no secret exists at the given path.
var ErrNotFound = errors.New("secret not found")

// Vault is atomic, file-per-secret storage (RFC.md Pillar I) with envelope
// encryption (Pillar II) — the actual local-auth guarantee depends on
// KeyWrapper's implementation, see its doc comment. Root is the jit
// config directory (e.g. ~/Library/Application Support/jitpass) — secrets
// live under Root/vault/, kept structurally separate from non-secret
// application config (profile manifests, etc.) that lives directly under
// Root.
type Vault struct {
	Root        string
	KeyWrapper  KeyWrapper
	RecipientID string

	// RefResolver, when non-nil, is what Get uses to resolve a
	// reference-kind envelope (envelope.Storage) into the secret bytes it
	// names. Nil is a valid configuration meaning "this surface never
	// resolves": Get then fails a reference read with ErrRefUnresolvable
	// instead of blocking on an external tool. See refresolver.go.
	RefResolver RefResolver

	// OnSet, when non-nil, is called with every secret this Vault stores,
	// after the write succeeds. It exists so a caller can act on the set of
	// credentials IT just vaulted without every writer having to hand them
	// back: `jit migrate` uses it to find and remove the copies AI agents
	// keep of the values it has just moved (internal/migrate/agentcache.go),
	// and there are nineteen Apply* paths that would otherwise each have to
	// grow a plaintext return value.
	//
	// The value is the caller's own plaintext, on its way into the vault, so
	// this observes rather than discloses: nothing reaches the callback that
	// the caller did not already hold. It is deliberately NOT a general
	// audit hook — `jit audit` records vault activity through the agent, at
	// the trust boundary, where a callback in the writer's own process would
	// prove nothing.
	OnSet func(path string, value []byte)
}

func (v *Vault) vaultDir() string {
	return filepath.Join(v.Root, "vault")
}

// Exists reports whether a secret is currently stored at path.
func (v *Vault) Exists(path string) (bool, error) {
	target, err := sanitizeSecretPath(v.vaultDir(), path)
	if err != nil {
		return false, err
	}
	_, err = os.Stat(target)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, fmt.Errorf("checking %s: %w", target, err)
}

// Meta is the birth-time provenance a caller stamps onto a brand-new secret:
// which kind of source it came from (Class, one of the vault.Class* values),
// the surrogate GroupID every secret imported together shares, and the
// normalized source path (Origin). It is honored ONLY when the path is new —
// see SetWithMeta — because provenance describes where a secret was born, and
// rotating its value doesn't move its origin.
type Meta struct {
	Class   string
	GroupID string
	Origin  string
}

// NewGroupID mints a fresh surrogate group id: 128 bits of randomness, hex
// encoded. Callers importing several secrets from one source mint ONE and
// pass it to every Set, so the group survives any later rename of the source
// or of the secrets' vault paths (nothing about it is derived from a path).
func NewGroupID() (string, error) {
	b, err := randomBytes(16)
	if err != nil {
		return "", fmt.Errorf("generating group id: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// Set encrypts value and atomically writes it to path with no provenance —
// the thin, provenance-agnostic entry point (export/import, callers that
// genuinely have no source to record). A brand-new secret written this way
// has an empty class, exactly like a pre-provenance v1/v2 file.
func (v *Vault) Set(path string, value []byte) error {
	return v.SetWithMeta(path, value, Meta{})
}

// SetWithMeta encrypts value and atomically writes it to path, creating
// parent directories as needed, stamping meta as the secret's provenance.
//
// An existing secret at path is overwritten as a ROTATION of the same
// secret: its CreatedUnix carries over, and so do its Class/GroupID/Origin —
// meta is ignored on a rotation, because a new value from the same key is
// still that key, born where it was born. A genuinely new path gets
// CreatedUnix == UpdatedUnix and takes its provenance from meta (with Origin,
// when present, stamped as seen now).
//
// The storage marker does NOT rotate like provenance: SetWithMeta always
// writes a literal-value envelope, so a literal Set over a linked path
// (see SetReference) deliberately turns the pointer back into a value —
// the caller explicitly replaced it.
func (v *Vault) SetWithMeta(path string, value []byte, meta Meta) error {
	return v.setEnvelope(path, value, meta, "")
}

// SetReference stores ref (a 1Password op:// secret reference) at path as
// a reference-kind envelope: encrypted, provenance-stamped, and rotated
// exactly like any secret, but marked (AAD-bound, see envelope.Storage)
// so Get resolves it through the Vault's RefResolver instead of returning
// it. The reference is deliberately sealed like a value — an op:// URI
// names the user's 1Password credential map, and gating its unwrap is
// what keeps per-process consent meaningful for linked secrets.
//
// SetReference validates nothing about ref beyond the caller's own
// checks: whether it resolves is the resolver's business (the CLI's
// `jit vault link` trial-resolves before writing).
func (v *Vault) SetReference(path, ref string, meta Meta) error {
	return v.setEnvelope(path, []byte(ref), meta, StorageOpRef)
}

// setEnvelope is SetWithMeta and SetReference's shared core; storage says
// what the payload is (see envelope.Storage).
func (v *Vault) setEnvelope(path string, value []byte, meta Meta, storage string) error {
	dest, err := sanitizeSecretPath(v.vaultDir(), path)
	if err != nil {
		return err
	}

	now := time.Now().Unix()
	created := now
	class, groupID, origin := meta.Class, meta.GroupID, meta.Origin
	var originSeen int64
	if origin != "" {
		originSeen = now
	}
	// An existing secret at path is being rotated, not created: keep its
	// CreatedUnix and its birth-time provenance, and hold on to the outgoing
	// envelope's raw bytes so they can be archived below (still decryptable
	// only back at this same path — see history.go).
	var oldData []byte
	if data, err := os.ReadFile(dest); err == nil { // #nosec G304 -- dest is sanitizeSecretPath's output above
		oldData = data
		var old envelope
		if json.Unmarshal(oldData, &old) == nil {
			if old.CreatedUnix > 0 {
				created = old.CreatedUnix
			}
			class, groupID, origin, originSeen = old.Class, old.GroupID, old.Origin, old.OriginSeenUnix
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("reading existing %s: %w", dest, err)
	}

	dek, err := generateDEK()
	if err != nil {
		return err
	}
	defer wipe(dek)

	sealedPayload, err := seal(dek, value, envelopeAAD(path, envelopeVersion, created, now, class, groupID, origin, storage))
	if err != nil {
		return fmt.Errorf("encrypting secret: %w", err)
	}

	wrappedDEK, err := v.wrapKey(dek, path, class)
	if err != nil {
		return fmt.Errorf("wrapping data encryption key: %w", err)
	}

	// Archive only now, with every fallible step behind us — wrapKey above
	// is where a Touch ID/passcode prompt can be canceled, and archiving
	// before it let a canceled (failed) Set mutate history anyway: it
	// added a duplicate of the live value and, at HistoryKeep capacity,
	// pruned the oldest REAL version to make room. Archive-then-write is
	// still preserved: a crash between the two leaves the old value both
	// live and archived, never gone.
	if oldData != nil {
		if err := v.archiveVersion(path, oldData, nowUnixNano()); err != nil {
			return err
		}
	}

	env := envelope{
		Version:        envelopeVersion,
		CreatedUnix:    created,
		UpdatedUnix:    now,
		Class:          class,
		GroupID:        groupID,
		Origin:         origin,
		OriginSeenUnix: originSeen,
		Storage:        storage,
		Recipients: map[string]string{
			v.RecipientID: hex.EncodeToString(wrappedDEK),
		},
		Payload: hex.EncodeToString(sealedPayload),
	}
	data, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding envelope: %w", err)
	}

	if err := AtomicWriteFile(dest, data); err != nil {
		return err
	}
	// After the write succeeds, never before: a caller acting on "what did I
	// just vault" must not be told about a secret that failed to land.
	if v.OnSet != nil {
		v.OnSet(path, value)
	}
	return nil
}

// readEnvelope reads and parses the envelope stored at path without
// decrypting anything — shared by Get (which goes on to decrypt), Set
// (which preserves CreatedUnix across an overwrite), and Info.
func (v *Vault) readEnvelope(path string) (envelope, error) {
	src, err := sanitizeSecretPath(v.vaultDir(), path)
	if err != nil {
		return envelope{}, err
	}
	data, err := os.ReadFile(src) // #nosec G304 -- src is derived and validated by sanitizeSecretPath, not a raw external path
	if err != nil {
		if os.IsNotExist(err) {
			return envelope{}, ErrNotFound
		}
		return envelope{}, fmt.Errorf("reading %s: %w", src, err)
	}
	var env envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return envelope{}, fmt.Errorf("parsing envelope %s: %w", src, err)
	}
	return env, nil
}

// Get decrypts and returns the secret stored at path. A reference-kind
// envelope (envelope.Storage) is resolved through RefResolver, so every
// caller receives the secret VALUE and cannot tell a linked secret from a
// stored one; a Vault built without a resolver fails such a read with
// ErrRefUnresolvable instead. Export is the one caller that must NOT
// resolve (an export is a vault backup, not a 1Password read) and uses
// getStored directly.
func (v *Vault) Get(path string) ([]byte, error) {
	plaintext, storage, err := v.getStored(path)
	if err != nil {
		return nil, err
	}
	switch storage {
	case "":
		return plaintext, nil
	case StorageOpRef:
		if v.RefResolver == nil {
			wipe(plaintext)
			return nil, fmt.Errorf("secret %s: %w", path, ErrRefUnresolvable)
		}
		resolved, err := v.RefResolver.ResolveRef(string(plaintext))
		wipe(plaintext)
		if err != nil {
			return nil, fmt.Errorf("resolving %s: %w", path, err)
		}
		return resolved, nil
	default:
		// Fail closed on a storage kind this build doesn't know, exactly
		// like the version gate: returning the payload would hand a caller
		// expecting a credential some future marker's raw pointer.
		wipe(plaintext)
		return nil, fmt.Errorf("secret %s has storage kind %q, newer than this jit understands, upgrade jit to read it", path, storage)
	}
}

// getStored decrypts and returns the payload stored at path exactly as
// stored, plus its storage marker, never touching RefResolver — Get's
// core, and Export's non-resolving read.
func (v *Vault) getStored(path string) ([]byte, string, error) {
	env, err := v.readEnvelope(path)
	if err != nil {
		return nil, "", err
	}

	// The AAD the payload must open under is decided by the envelope's own
	// version — and an unknown version is rejected HERE, before any key
	// material is touched. Skipping this check was a real (latent) bug:
	// Version was written from day one and never read, so a future format
	// would have surfaced as "decryption failed (wrong key or corrupted...)"
	// — the exact message that makes a user fear their vault is gone —
	// instead of the actual answer, "a newer jit wrote this."
	var aad []byte
	switch env.Version {
	case envelopeVersionAADLess:
		// v1: no AAD, no metadata. Readable forever.
	case envelopeVersionMetaOnly, envelopeVersionProvenance, envelopeVersion:
		// v2, v3, and v4 all bind their metadata into the AAD; envelopeAAD
		// reconstructs the exact shape the stored version sealed under
		// (v3 appends class/group/origin, v4 adds storage — all empty on
		// the versions that predate them).
		aad = envelopeAAD(path, env.Version, env.CreatedUnix, env.UpdatedUnix, env.Class, env.GroupID, env.Origin, env.Storage)
	default:
		return nil, "", fmt.Errorf("secret %s has envelope version %d, newer than this jit understands (max %d), upgrade jit to read it", path, env.Version, envelopeVersion)
	}

	wrappedHex, err := env.wrappedDEKFor(v.RecipientID, path)
	if err != nil {
		return nil, "", err
	}
	wrappedDEK, err := hex.DecodeString(wrappedHex)
	if err != nil {
		return nil, "", fmt.Errorf("corrupt envelope %s: invalid recipient encoding: %w", path, err)
	}
	// Payload decoded BEFORE unwrapKey: that call is where a Touch
	// ID/passcode prompt can fire, and a corrupt envelope should fail
	// without first costing the user an authentication they'll only
	// watch turn into an error.
	sealedPayload, err := hex.DecodeString(env.Payload)
	if err != nil {
		return nil, "", fmt.Errorf("corrupt envelope %s: invalid payload encoding: %w", path, err)
	}

	dek, err := v.unwrapKey(wrappedDEK, path, env.Class)
	if err != nil {
		return nil, "", fmt.Errorf("unwrapping data encryption key: %w", err)
	}
	defer wipe(dek)

	plaintext, err := open(dek, sealedPayload, aad)
	if err != nil {
		return nil, "", fmt.Errorf("decrypting %s: %w", path, err)
	}
	return plaintext, env.Storage, nil
}

// WrappedDEK returns the wrapped data key this device would use to open the
// secret at path, plus its AAD-bound class — WITHOUT decrypting anything or
// touching the KeyWrapper, so it never prompts. It is the read the agent's
// process-grant resolution needs (design/process-grants.md): grant creation
// pre-unwraps exactly these bytes under the challenge's MEK, and the serve
// path later recognizes the same bytes arriving in an ordinary unwrap. Same
// version and recipient rules as Get, verbatim: a grant must never resolve an
// envelope Get would refuse.
func (v *Vault) WrappedDEK(path string) (wrapped []byte, class string, err error) {
	env, err := v.readEnvelope(path)
	if err != nil {
		return nil, "", err
	}
	if env.Version > envelopeVersion {
		return nil, "", fmt.Errorf("secret %s has envelope version %d, newer than this jit understands (max %d), upgrade jit to read it", path, env.Version, envelopeVersion)
	}
	wrappedHex, err := env.wrappedDEKFor(v.RecipientID, path)
	if err != nil {
		return nil, "", err
	}
	wrapped, err = hex.DecodeString(wrappedHex)
	if err != nil {
		return nil, "", fmt.Errorf("corrupt envelope %s: invalid recipient encoding: %w", path, err)
	}
	return wrapped, env.Class, nil
}

// SecretInfo describes a stored secret without decrypting it — everything
// the envelope says in plaintext. CreatedUnix/UpdatedUnix are zero for
// version-1 envelopes, which predate the metadata; callers must render
// that as unknown, not as 1970.
type SecretInfo struct {
	Path        string
	Version     int
	CreatedUnix int64
	UpdatedUnix int64
	// Class/GroupID/Origin are the birth-time provenance (see envelope);
	// all empty for v1/v2 secrets written before provenance existed.
	// OriginSeenUnix stamps when Origin was recorded, so a stale label can
	// be shown honestly ("originally from …, seen 3 weeks ago").
	Class          string
	GroupID        string
	Origin         string
	OriginSeenUnix int64
	// Storage is the envelope's payload-kind marker ("" for a literal
	// value, StorageOpRef for a 1Password reference) — what lets listings
	// tag a linked secret without decrypting anything. Like the rest of
	// Info it reports what the file claims; the AAD check that keeps the
	// claim honest runs in Get.
	Storage string
}

// Verify checks that the secret at path is structurally intact and readable
// by *this* build of jit — WITHOUT decrypting it, so it never touches the
// KeyWrapper and never prompts (same safe-to-run-often contract as Exists,
// Info, and List). It runs exactly the validation Get performs before it
// reaches for any key material: the envelope JSON parses, its version is one
// this jit understands, and both the recipient-wrapped DEK and the payload
// are present and hex-decodable. This is the gap `jit doctor` closes over a
// bare Exists() check — a truncated, hand-edited, or future-version .enc file
// passes Exists (the file is on disk) yet fails the moment an app actually
// needs the value; Verify surfaces that at diagnosis time instead. It cannot
// (and deliberately does not) prove the ciphertext decrypts to anything: that
// needs the key and a local-auth prompt, which doctor never wants to trigger.
func (v *Vault) Verify(path string) error {
	env, err := v.readEnvelope(path)
	if err != nil {
		return err // ErrNotFound, or a concrete "parsing envelope …" error
	}
	// Mirror Get's version gate: an unknown (newer) version is the one
	// "corruption" that isn't corruption at all, so name it as such rather
	// than letting it read as a damaged file.
	switch env.Version {
	case envelopeVersionAADLess, envelopeVersionMetaOnly, envelopeVersionProvenance, envelopeVersion:
	default:
		return fmt.Errorf("secret %s has envelope version %d, newer than this jit understands (max %d), upgrade jit to read it", path, env.Version, envelopeVersion)
	}
	// Select the recipient exactly as Get would (shared wrappedDEKFor), so
	// Verify validates the one key this device actually opens the secret
	// with — not every recipient, some of which Get never touches — and
	// reports a not-for-this-device envelope the same way Get does.
	wrappedHex, err := env.wrappedDEKFor(v.RecipientID, path)
	if err != nil {
		return err
	}
	if _, err := hex.DecodeString(wrappedHex); err != nil {
		return fmt.Errorf("corrupt envelope %s: unreadable wrapped key: %w", path, err)
	}
	if env.Payload == "" {
		return fmt.Errorf("corrupt envelope %s: empty payload, the secret value is gone", path)
	}
	if _, err := hex.DecodeString(env.Payload); err != nil {
		return fmt.Errorf("corrupt envelope %s: unreadable payload: %w", path, err)
	}
	return nil
}

// Info returns path's SecretInfo. Never touches the KeyWrapper, so it can
// never prompt — safe for listings and completion, same contract as List.
// Note the metadata is only tamper-evident at decryption time (the AAD
// check runs in Get, not here): Info reports what the file claims.
func (v *Vault) Info(path string) (SecretInfo, error) {
	env, err := v.readEnvelope(path)
	if err != nil {
		return SecretInfo{}, err
	}
	return SecretInfo{
		Path:           path,
		Version:        env.Version,
		CreatedUnix:    env.CreatedUnix,
		UpdatedUnix:    env.UpdatedUnix,
		Class:          env.Class,
		GroupID:        env.GroupID,
		Origin:         env.Origin,
		OriginSeenUnix: env.OriginSeenUnix,
		Storage:        env.Storage,
	}, nil
}

// wrapKey/unwrapKey route through the KeyWrapper, passing the secret's
// own vault path as the audit label when the wrapper supports it
// (LabeledKeyWrapper — the agent-backed wrapper does; keychainwrap
// doesn't). The label is the caller-reported "what was this key FOR"
// the agent's history is otherwise structurally blind to.
func (v *Vault) wrapKey(dek []byte, label, class string) ([]byte, error) {
	if lw, ok := v.KeyWrapper.(LabeledKeyWrapper); ok {
		return lw.WrapKeyLabeled(dek, label, class)
	}
	return v.KeyWrapper.WrapKey(dek)
}

func (v *Vault) unwrapKey(wrapped []byte, label, class string) ([]byte, error) {
	if lw, ok := v.KeyWrapper.(LabeledKeyWrapper); ok {
		return lw.UnwrapKeyLabeled(wrapped, label, class)
	}
	return v.KeyWrapper.UnwrapKey(wrapped)
}

// Remove deletes the secret stored at path — including its version
// history, because rm means gone: a recoverable copy surviving an
// explicit delete would betray the command's whole point.
func (v *Vault) Remove(path string) error {
	target, err := sanitizeSecretPath(v.vaultDir(), path)
	if err != nil {
		return err
	}
	if err := os.Remove(target); err != nil {
		if os.IsNotExist(err) {
			return ErrNotFound
		}
		return fmt.Errorf("removing %s: %w", target, err)
	}
	return v.removeHistory(path)
}

// List returns every secret path currently stored, sorted naturally
// (digit runs compare numerically, see naturalLess), e.g.
// ["aws/s3-access-key", "stripe/dev-key"] — names only, never values.
func (v *Vault) List() ([]string, error) {
	root := v.vaultDir()
	var paths []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) && p == root {
				return filepath.SkipDir
			}
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		if d.IsDir() {
			// _history/ is jit's own bookkeeping (see history.go): never a
			// listed secret, never exported, never completed. Unlike
			// _backups/ (which List returns and the CLI splits out for its
			// count line), history versions shadow paths that ARE listed —
			// including them would show every secret up to historyKeep+1
			// times.
			if rel == historyDirName {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".enc") {
			return nil
		}
		rel = strings.TrimSuffix(rel, ".enc")
		paths = append(paths, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("listing vault: %w", err)
	}
	sort.SliceStable(paths, func(i, j int) bool { return naturalLess(paths[i], paths[j]) })
	return paths, nil
}

// AtomicWriteFile writes data to a temp file in dest's directory, fsyncs
// it, then renames it into place — a reader never observes a partially-
// written file, and a crash or power loss mid-write leaves the old
// version (or nothing) rather than a corrupt one. The fsync before the
// rename matters: without it, the rename can be durable while the data
// isn't, so a power cut could leave a correctly-named empty/truncated
// file — the one outcome atomicity was supposed to rule out. Exported
// because internal/migrate's profile-manifest write needs the identical
// guarantee (a manifest half-written at the moment the source file is
// destroyed would orphan every secret it mapped).
func AtomicWriteFile(dest string, data []byte) error {
	dir := filepath.Dir(dest)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating %s: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("creating temp file in %s: %w", dir, err)
	}
	tmpPath := tmp.Name()
	// If anything below fails before the rename, clean up the temp file
	// rather than leaving it behind.
	success := false
	defer func() {
		if !success {
			_ = os.Remove(tmpPath)
		}
	}()

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("setting permissions on %s: %w", tmpPath, err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("writing %s: %w", tmpPath, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("syncing %s: %w", tmpPath, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing %s: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, dest); err != nil {
		return fmt.Errorf("renaming %s to %s: %w", tmpPath, dest, err)
	}
	success = true
	// Fsync the directory too, so the rename itself survives power loss —
	// best-effort: some filesystems don't support fsync on a directory,
	// and the data-before-rename ordering above already holds without it.
	syncDir(dir)
	return nil
}

// syncDir best-effort fsyncs a directory so a rename into it survives
// power loss — the durability tail of AtomicWriteFile, shared with
// Restore's own rename (which moves an already-synced file and needs
// only this directory half).
func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil { // #nosec G304 -- a parent directory of jit's own files, not external input
		_ = d.Sync()
		_ = d.Close()
	}
}

// UnboundPaths lists the secrets whose envelope predates AAD binding —
// v1 files, the only schema that sealed its payload with no additional
// authenticated data. Sorted, so a report reads the same twice.
//
// Why this is worth naming at all: a v1 payload opens under aad = nil
// forever, so nothing ties it to the secret it belongs to. Two v1 files can
// have their payloads exchanged and both still decrypt, which is exactly
// what envelopeAAD was introduced to prevent (see its comment). v2 and v3
// bind the path, so the same swap fails the auth tag.
//
// It is not self-healing. RewrapAll rewraps the DEK and leaves the envelope
// untouched, so even a full master-key rotation never upgrades a v1 file;
// only writing the secret again does, which is what `jit vault export`
// followed by `jit vault import` accomplishes for a whole vault at once.
// AAD binding shipped in v0.57.0, so any secret stored before it and not
// re-set since is still v1 — a real population, and one no command
// currently reports.
//
// Auth-free by construction: it reads envelope metadata through the same
// path Info does, never touching the KeyWrapper, so it can never prompt and
// is safe for jit doctor to run unattended. An unreadable envelope is
// skipped rather than reported — Verify owns corruption, and one bad file
// should not cost the count of the rest.
func (v *Vault) UnboundPaths() ([]string, error) {
	paths, err := v.List()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, p := range paths {
		info, err := v.Info(p)
		if err != nil {
			continue
		}
		if info.Version == envelopeVersionAADLess {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out, nil
}
