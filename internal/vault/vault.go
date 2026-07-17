// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

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

// Set encrypts value and atomically writes it to path, creating parent
// directories as needed. An existing secret at path is overwritten — its
// CreatedUnix carries over (this is a rotation of the same secret, not a
// new one), while a genuinely new path gets CreatedUnix == UpdatedUnix.
func (v *Vault) Set(path string, value []byte) error {
	dest, err := sanitizeSecretPath(v.vaultDir(), path)
	if err != nil {
		return err
	}

	now := time.Now().Unix()
	created := now
	// An existing secret at path is being rotated, not created: keep its
	// CreatedUnix, and hold on to the outgoing envelope's raw bytes so
	// they can be archived below (still decryptable only back at this
	// same path — see history.go).
	var oldData []byte
	if data, err := os.ReadFile(dest); err == nil { // #nosec G304 -- dest is sanitizeSecretPath's output above
		oldData = data
		var old envelope
		if json.Unmarshal(oldData, &old) == nil && old.CreatedUnix > 0 {
			created = old.CreatedUnix
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("reading existing %s: %w", dest, err)
	}

	dek, err := generateDEK()
	if err != nil {
		return err
	}
	defer wipe(dek)

	sealedPayload, err := seal(dek, value, envelopeAAD(path, envelopeVersion, created, now))
	if err != nil {
		return fmt.Errorf("encrypting secret: %w", err)
	}

	wrappedDEK, err := v.wrapKey(dek, path)
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
		Version:     envelopeVersion,
		CreatedUnix: created,
		UpdatedUnix: now,
		Recipients: map[string]string{
			v.RecipientID: hex.EncodeToString(wrappedDEK),
		},
		Payload: hex.EncodeToString(sealedPayload),
	}
	data, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding envelope: %w", err)
	}

	return AtomicWriteFile(dest, data)
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

// Get decrypts and returns the secret stored at path.
func (v *Vault) Get(path string) ([]byte, error) {
	env, err := v.readEnvelope(path)
	if err != nil {
		return nil, err
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
	case envelopeVersion:
		aad = envelopeAAD(path, env.Version, env.CreatedUnix, env.UpdatedUnix)
	default:
		return nil, fmt.Errorf("secret %s has envelope version %d, newer than this jit understands (max %d), upgrade jit to read it", path, env.Version, envelopeVersion)
	}

	wrappedHex, ok := env.Recipients[v.RecipientID]
	if !ok {
		// Exact match failed. A single-recipient envelope is still worth
		// attempting: every envelope this vault has ever written has exactly
		// one recipient (Set always writes one), so a mismatch here almost
		// always means the machine's IDENTIFIER changed, not the machine —
		// envelopes written before EnsureDeviceID existed are keyed by
		// os.Hostname(), which drifts with a Mac rename or even a DHCP-
		// supplied name. If the wrapped DEK genuinely came from a different
		// machine, UnwrapKey below fails at the KeyWrapper layer anyway (the
		// MEK won't match), so trying costs nothing and never decrypts
		// anything this device couldn't already decrypt.
		if len(env.Recipients) == 1 {
			for _, w := range env.Recipients {
				wrappedHex = w
			}
		} else {
			return nil, fmt.Errorf("no key for this device (%s) in %s, it was likely encrypted on a different machine", v.RecipientID, path)
		}
	}
	wrappedDEK, err := hex.DecodeString(wrappedHex)
	if err != nil {
		return nil, fmt.Errorf("corrupt envelope %s: invalid recipient encoding: %w", path, err)
	}
	// Payload decoded BEFORE unwrapKey: that call is where a Touch
	// ID/passcode prompt can fire, and a corrupt envelope should fail
	// without first costing the user an authentication they'll only
	// watch turn into an error.
	sealedPayload, err := hex.DecodeString(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("corrupt envelope %s: invalid payload encoding: %w", path, err)
	}

	dek, err := v.unwrapKey(wrappedDEK, path)
	if err != nil {
		return nil, fmt.Errorf("unwrapping data encryption key: %w", err)
	}
	defer wipe(dek)

	plaintext, err := open(dek, sealedPayload, aad)
	if err != nil {
		return nil, fmt.Errorf("decrypting %s: %w", path, err)
	}
	return plaintext, nil
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
		Path:        path,
		Version:     env.Version,
		CreatedUnix: env.CreatedUnix,
		UpdatedUnix: env.UpdatedUnix,
	}, nil
}

// wrapKey/unwrapKey route through the KeyWrapper, passing the secret's
// own vault path as the audit label when the wrapper supports it
// (LabeledKeyWrapper — the agent-backed wrapper does; keychainwrap
// doesn't). The label is the caller-reported "what was this key FOR"
// the agent's history is otherwise structurally blind to.
func (v *Vault) wrapKey(dek []byte, label string) ([]byte, error) {
	if lw, ok := v.KeyWrapper.(LabeledKeyWrapper); ok {
		return lw.WrapKeyLabeled(dek, label)
	}
	return v.KeyWrapper.WrapKey(dek)
}

func (v *Vault) unwrapKey(wrapped []byte, label string) ([]byte, error) {
	if lw, ok := v.KeyWrapper.(LabeledKeyWrapper); ok {
		return lw.UnwrapKeyLabeled(wrapped, label)
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
