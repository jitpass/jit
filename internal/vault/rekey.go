// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package vault

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// RewrapAll re-wraps every stored envelope's DEK(s) from oldKW to newKW —
// the vault half of `jit vault rekey`. Payloads are never decrypted and
// never change: only the Recipients values (DEK wrapped under the MEK)
// do, so the envelope's version, timestamps, and payload AAD all stay
// exactly as they were. Every .enc under the vault is covered — live
// secrets, _backups/ and _history/ included, since all of them must
// survive the old MEK's deletion.
//
// Idempotent and resumable by construction: an entry that already
// unwraps under newKW is counted as current and left untouched, so a
// re-run after a crash finishes exactly the remainder. oldKW may be nil
// — the resume state where an interrupted promote already consumed the
// old key — in which case every entry must already be current, and
// anything that isn't is a hard error naming the file (never a silent
// skip: an envelope neither key opens is a vault on its way to data
// loss, and the caller must keep the staged key alive until it's
// resolved).
//
// Each rewrapped DEK is verified to unwrap again under newKW before the
// envelope is rewritten (atomically). The one write failure mode this
// can't rule out — sealing under a corrupted in-memory key — is exactly
// the one the verify catches, and it's the difference between an error
// now and a vault that reports success until the day it can't decrypt.
func (v *Vault) RewrapAll(oldKW, newKW KeyWrapper) (rewrapped, current int, err error) {
	files, err := v.allEnvelopeFiles()
	if err != nil {
		return 0, 0, err
	}
	for _, file := range files {
		changed, err := v.rewrapFile(file, oldKW, newKW)
		if err != nil {
			return rewrapped, current, err
		}
		if changed {
			rewrapped++
		} else {
			current++
		}
	}
	return rewrapped, current, nil
}

// allEnvelopeFiles returns every .enc file under the vault directory —
// unlike List, nothing is excluded and paths are absolute: this is the
// rekey walk, and a file the walk misses is a file the old MEK's
// deletion orphans.
func (v *Vault) allEnvelopeFiles() ([]string, error) {
	root := v.vaultDir()
	var files []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) && p == root {
				return filepath.SkipDir
			}
			return err
		}
		if !d.IsDir() && strings.HasSuffix(d.Name(), ".enc") {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking vault: %w", err)
	}
	return files, nil
}

// rewrapFile rewraps one envelope file's recipient entries, reporting
// whether anything changed (and was therefore rewritten).
func (v *Vault) rewrapFile(file string, oldKW, newKW KeyWrapper) (changed bool, err error) {
	data, err := os.ReadFile(file) // #nosec G304 -- file comes from walking jit's own vault directory
	if err != nil {
		return false, fmt.Errorf("reading %s: %w", file, err)
	}
	var env envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return false, fmt.Errorf("parsing envelope %s: %w", file, err)
	}
	// An envelope with no recipient entries would fall straight through
	// the loop below and count as "current" — a silent skip of a file
	// neither key opens, the exact outcome the package comment promises
	// can never happen. Fail loudly instead, before the old MEK's
	// deletion turns a corrupt-but-diagnosable file into a lost one.
	if len(env.Recipients) == 0 {
		return false, fmt.Errorf("%s has no recipient entries (corrupt envelope?), rekey cannot proceed past it", file)
	}

	// The DEK-wrap now binds the secret's Class as AEAD (see keywrapper.go),
	// so rekey both rotates the MEK AND migrates a legacy empty-AAD wrap to a
	// class-bound one. unwrapWith/wrapWith carry env.Class; the old side also
	// falls back to a plain (empty-AAD) unwrap so a pre-binding wrap still
	// decrypts on its way to being re-wrapped class-bound.
	class := env.Class
	unwrapWith := func(kw KeyWrapper, w []byte) ([]byte, error) {
		if lw, ok := kw.(LabeledKeyWrapper); ok {
			return lw.UnwrapKeyLabeled(w, "", class)
		}
		return kw.UnwrapKey(w)
	}
	wrapWith := func(kw KeyWrapper, dek []byte) ([]byte, error) {
		if lw, ok := kw.(LabeledKeyWrapper); ok {
			return lw.WrapKeyLabeled(dek, "", class)
		}
		return kw.WrapKey(dek)
	}

	for id, wrappedHex := range env.Recipients {
		wrapped, err := hex.DecodeString(wrappedHex)
		if err != nil {
			return false, fmt.Errorf("corrupt envelope %s: invalid recipient encoding: %w", file, err)
		}

		if dek, err := unwrapWith(newKW, wrapped); err == nil {
			wipe(dek) // already current AND class-bound: a resumed run's own work
			continue
		}

		var dek []byte
		if oldKW != nil {
			// Class-bound under the old key first (a plain MEK rotation), then
			// a legacy empty-AAD unwrap (a pre-binding vault being migrated).
			dek, err = unwrapWith(oldKW, wrapped)
			if err != nil {
				dek, err = oldKW.UnwrapKey(wrapped)
			}
		}
		if oldKW == nil || err != nil {
			return false, fmt.Errorf("%s: cannot decrypt with the current or the staged master key, rekey cannot proceed past it (err: %v)", file, err)
		}

		rewrappedDEK, err := wrapWith(newKW, dek)
		if err != nil {
			wipe(dek)
			return false, fmt.Errorf("rewrapping key for %s: %w", file, err)
		}
		verify, err := unwrapWith(newKW, rewrappedDEK)
		if err != nil || !bytes.Equal(verify, dek) {
			wipe(dek)
			wipe(verify)
			return false, fmt.Errorf("verifying rewrapped key for %s failed (err: %v), envelope left untouched", file, err)
		}
		wipe(dek)
		wipe(verify)

		env.Recipients[id] = hex.EncodeToString(rewrappedDEK)
		changed = true
	}

	if !changed {
		return false, nil
	}
	out, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return false, fmt.Errorf("encoding envelope %s: %w", file, err)
	}
	if err := AtomicWriteFile(file, out); err != nil {
		return false, err
	}
	return true, nil
}
