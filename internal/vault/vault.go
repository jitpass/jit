// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: Apache-2.0

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
// directories as needed. An existing secret at path is overwritten.
func (v *Vault) Set(path string, value []byte) error {
	dest, err := sanitizeSecretPath(v.vaultDir(), path)
	if err != nil {
		return err
	}

	dek, err := generateDEK()
	if err != nil {
		return err
	}
	defer wipe(dek)

	sealedPayload, err := seal(dek, value)
	if err != nil {
		return fmt.Errorf("encrypting secret: %w", err)
	}

	wrappedDEK, err := v.KeyWrapper.WrapKey(dek)
	if err != nil {
		return fmt.Errorf("wrapping data encryption key: %w", err)
	}

	env := envelope{
		Version: envelopeVersion,
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

// Get decrypts and returns the secret stored at path.
func (v *Vault) Get(path string) ([]byte, error) {
	src, err := sanitizeSecretPath(v.vaultDir(), path)
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(src) // #nosec G304 -- src is derived and validated by sanitizeSecretPath, not a raw external path
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("reading %s: %w", src, err)
	}

	var env envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("parsing envelope %s: %w", src, err)
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
			return nil, fmt.Errorf("no key for this device (%s) in %s — it was likely encrypted on a different machine", v.RecipientID, src)
		}
	}
	wrappedDEK, err := hex.DecodeString(wrappedHex)
	if err != nil {
		return nil, fmt.Errorf("corrupt envelope %s: invalid recipient encoding: %w", src, err)
	}

	dek, err := v.KeyWrapper.UnwrapKey(wrappedDEK)
	if err != nil {
		return nil, fmt.Errorf("unwrapping data encryption key: %w", err)
	}
	defer wipe(dek)

	sealedPayload, err := hex.DecodeString(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("corrupt envelope %s: invalid payload encoding: %w", src, err)
	}

	plaintext, err := open(dek, sealedPayload)
	if err != nil {
		return nil, fmt.Errorf("decrypting %s: %w", src, err)
	}
	return plaintext, nil
}

// Remove deletes the secret stored at path.
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
	return nil
}

// List returns every secret path currently stored, sorted, e.g.
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
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".enc") {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		rel = strings.TrimSuffix(rel, ".enc")
		paths = append(paths, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("listing vault: %w", err)
	}
	sort.Strings(paths)
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
	if d, err := os.Open(dir); err == nil { // #nosec G304 -- dest's own parent directory, not external input
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
