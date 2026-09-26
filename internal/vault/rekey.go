// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package vault

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
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
	r, err := v.Rewrap(oldKW, newKW)
	return r.Rewrapped, r.Current, err
}

// RewrapResult is what Rewrap did.
type RewrapResult struct {
	Rewrapped, Current int
	// Kept lists the envelope files (slash paths relative to vault/) left
	// untouched because they are sealed to a lost Secure Enclave key: see
	// Rewrap.
	Kept []string
}

// Rewrap is RewrapAll, reporting the envelopes it kept: RewrapWith with no
// hooks.
//
// The one exception to "an envelope neither key opens is a hard error":
// an envelope PROVABLY sealed to a lost Secure Enclave key (lostkey.go):
// a lost key's readable record lists its bytes, or names it as unreadable
// when the key was set aside and it has not been written since. No key
// here ever opened it, so rotating cannot make it any less readable, and
// stopping on it would leave the marker behind and refuse every vault
// change, the import and rm that clear it included. It is left exactly as
// it is, never rewritten and never deleted, and reported in Kept. The old
// key is still tried first: an envelope it does open is rewrapped like any
// other, whatever a record says.
//
// Anything short of proof stops the rotation, as it always has: an
// envelope a record only presumes (an incomplete record, or one that is
// missing or unreadable) may be sealed to the key this rotation is about
// to destroy. The error says why jit could not prove it. Since the rewrap
// plans every envelope before writing any, it stops before the first
// write.
func (v *Vault) Rewrap(oldKW, newKW KeyWrapper) (RewrapResult, error) {
	return v.RewrapWith(oldKW, newKW, RewrapOptions{})
}

// WrapChange is one recipient's wrapped DEK before and after a rewrap. The
// plan pass proved both wrap the same DEK: New unwraps, under the new key,
// to the DEK Old unwrapped to under the old one.
type WrapChange struct {
	// File is the envelope's slash path relative to vault/ ("aws/key.enc").
	File string
	// Old and New are the wrapped DEK bytes, hex-decoded from the envelope
	// (what WrappedDEK returns for the path).
	Old, New []byte
}

// RewrapOptions are RewrapWith's hooks. Each is optional; an error from
// any of them stops the rewrap right there, with nothing undone, exactly
// as a crash at that point would (both keys still open every envelope).
type RewrapOptions struct {
	// BeforeWrite is called once, after every envelope has been read,
	// rewrapped and verified in memory and before the first is written,
	// with every change the writes will make (none for a run that finds
	// everything current). It is where the rotation writes its digest map
	// (internal/rekeymap): the new wrapped bytes are random, so they exist
	// only once planned, and the old ones are gone once written.
	BeforeWrite func(changes []WrapChange) error
	// AfterWrite is called after each envelope is written, with how many
	// have been so far: the crash hook's "written N".
	AfterWrite func(written int) error
	// AfterAll is called once every planned envelope is written and the
	// vault has been checked to hold exactly what the plan left in it,
	// with every recipient's wrapped DEK in the vault now (rekeymap.Prune's
	// onDisk).
	AfterAll func(onDisk [][]byte) error
}

// RewrapWith is Rewrap in two passes, with hooks between them.
//
// Pass 1 plans: it reads every envelope, rewraps each recipient's DEK under
// newKW and verifies it, all in memory (each DEK wiped as soon as it is
// verified; what is held is the new envelope bytes). It classifies every
// envelope neither key opens as Rewrap does. Any error stops it with
// nothing written, so an unproven lost-key copy stops the rotation before
// any envelope changes.
//
// Pass 2 calls BeforeWrite, then writes each planned envelope, atomically,
// after checking its bytes are still the ones planned from: a file changed
// under the marker stops the rewrap, left as it is, both keys intact.
// Envelopes found current, and kept lost-key copies, are never written.
//
// Last, it walks the vault again: every envelope file must be one it
// planned, holding the bytes it wrote or left. A file that appeared,
// changed or went during the rewrap stops it before the caller destroys
// the old key, which would orphan an envelope sealed under it.
func (v *Vault) RewrapWith(oldKW, newKW KeyWrapper, opts RewrapOptions) (RewrapResult, error) {
	var r RewrapResult
	lost, err := v.lostKeyCopies()
	if err != nil {
		return r, err
	}
	files, err := v.allEnvelopeFiles()
	if err != nil {
		return r, err
	}

	plan := make([]plannedEnvelope, 0, len(files))
	var changes []WrapChange
	var current int
	var kept []string
	for _, file := range files {
		p, fileChanges, err := v.planRewrap(file, oldKW, newKW)
		if err != nil {
			if errors.Is(err, errNoKeyOpens) && lost.any() {
				if lost.matchFile(v.vaultDir(), file) == provenLost {
					kept = append(kept, p.rel)
					plan = append(plan, p) // p.out is nil: left as it is
					continue
				}
				return r, fmt.Errorf("%w; %s", err, lost.unproven())
			}
			return r, err
		}
		if p.out == nil {
			current++
		}
		plan = append(plan, p)
		changes = append(changes, fileChanges...)
	}
	r.Current, r.Kept = current, kept

	if opts.BeforeWrite != nil {
		if err := opts.BeforeWrite(changes); err != nil {
			return r, err
		}
	}
	for _, p := range plan {
		if p.out == nil {
			continue
		}
		data, err := os.ReadFile(p.file) // #nosec G304 -- p.file comes from walking jit's own vault directory
		if errors.Is(err, fs.ErrNotExist) {
			return r, fmt.Errorf("%s went while the key was being rotated", p.rel)
		}
		if err != nil {
			return r, fmt.Errorf("reading %s again: %w", p.rel, err)
		}
		if digest(data) != p.from {
			return r, fmt.Errorf("%s changed while the key was being rotated, so it was left as it is", p.rel)
		}
		if err := AtomicWriteFile(p.file, p.out); err != nil {
			return r, err
		}
		r.Rewrapped++
		if opts.AfterWrite != nil {
			if err := opts.AfterWrite(r.Rewrapped); err != nil {
				return r, err
			}
		}
	}

	onDisk, err := v.checkRewrapped(plan)
	if err != nil {
		return r, err
	}
	if opts.AfterAll != nil {
		if err := opts.AfterAll(onDisk); err != nil {
			return r, err
		}
	}
	return r, nil
}

// plannedEnvelope is one envelope file in RewrapWith's plan.
type plannedEnvelope struct {
	file, rel string
	// from is the digest of the bytes the plan read; out the bytes to
	// write, nil when the file is left as it is (current, or a kept
	// lost-key copy); final the digest the file must hold at the end.
	from  string
	out   []byte
	final string
}

// errNoKeyOpens marks planRewrap's "neither key opens this" failure, the
// one Rewrap may turn into a kept lost-key copy.
var errNoKeyOpens = errors.New("cannot decrypt with the current or the staged master key")

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

// relSlash is file's slash path relative to vault/, or file itself.
func (v *Vault) relSlash(file string) string {
	rel, err := filepath.Rel(v.vaultDir(), file)
	if err != nil {
		return file
	}
	return filepath.ToSlash(rel)
}

// planRewrap rewraps one envelope file's recipient entries in memory,
// writing nothing. It returns the planned file (out nil when every entry is
// already current) and one change per entry it rewrapped. On an
// errNoKeyOpens failure the plan still names the file and the bytes read,
// for a kept lost-key copy.
func (v *Vault) planRewrap(file string, oldKW, newKW KeyWrapper) (plannedEnvelope, []WrapChange, error) {
	p := plannedEnvelope{file: file, rel: v.relSlash(file)}
	data, err := os.ReadFile(file) // #nosec G304 -- file comes from walking jit's own vault directory
	if err != nil {
		return p, nil, fmt.Errorf("reading %s: %w", file, err)
	}
	p.from, p.final = digest(data), digest(data)
	var env envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return p, nil, fmt.Errorf("parsing envelope %s: %w", file, err)
	}
	// An envelope with no recipient entries would fall straight through
	// the loop below and count as "current" — a silent skip of a file
	// neither key opens, the exact outcome the package comment promises
	// can never happen. Fail loudly instead, before the old MEK's
	// deletion turns a corrupt-but-diagnosable file into a lost one.
	if len(env.Recipients) == 0 {
		return p, nil, fmt.Errorf("%s has no recipient entries (corrupt envelope?), rekey cannot proceed past it", file)
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

	var changes []WrapChange
	for _, id := range slices.Sorted(maps.Keys(env.Recipients)) {
		wrapped, err := hex.DecodeString(env.Recipients[id])
		if err != nil {
			return p, nil, fmt.Errorf("corrupt envelope %s: invalid recipient encoding: %w", file, err)
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
			return p, nil, fmt.Errorf("%s: %w, rekey cannot proceed past it (err: %v)", file, errNoKeyOpens, err)
		}

		rewrappedDEK, err := wrapWith(newKW, dek)
		if err != nil {
			wipe(dek)
			return p, nil, fmt.Errorf("rewrapping key for %s: %w", file, err)
		}
		verify, err := unwrapWith(newKW, rewrappedDEK)
		if err != nil || !bytes.Equal(verify, dek) {
			wipe(dek)
			wipe(verify)
			return p, nil, fmt.Errorf("verifying rewrapped key for %s failed (err: %v), envelope left untouched", file, err)
		}
		wipe(dek)
		wipe(verify)

		env.Recipients[id] = hex.EncodeToString(rewrappedDEK)
		changes = append(changes, WrapChange{File: p.rel, Old: wrapped, New: rewrappedDEK})
	}

	if len(changes) == 0 {
		return p, nil, nil
	}
	out, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return p, nil, fmt.Errorf("encoding envelope %s: %w", file, err)
	}
	p.out, p.final = out, digest(out)
	return p, changes, nil
}

// checkRewrapped walks the vault once every write is done: the envelope
// files must be exactly the planned ones, each holding the bytes the plan
// wrote or left. It returns every recipient's wrapped DEK on disk.
func (v *Vault) checkRewrapped(plan []plannedEnvelope) ([][]byte, error) {
	files, err := v.allEnvelopeFiles()
	if err != nil {
		return nil, err
	}
	want := make(map[string]string, len(plan))
	for _, p := range plan {
		want[p.file] = p.final
	}
	var onDisk [][]byte
	for _, file := range files {
		sum, planned := want[file]
		if !planned {
			return nil, fmt.Errorf("%s appeared while the key was being rotated", v.relSlash(file))
		}
		delete(want, file)
		data, err := os.ReadFile(file) // #nosec G304 -- file comes from walking jit's own vault directory
		if err != nil {
			return nil, fmt.Errorf("reading %s again: %w", v.relSlash(file), err)
		}
		if digest(data) != sum {
			return nil, fmt.Errorf("%s changed while the key was being rotated", v.relSlash(file))
		}
		var env envelope
		if err := json.Unmarshal(data, &env); err != nil {
			return nil, fmt.Errorf("parsing envelope %s again: %w", v.relSlash(file), err)
		}
		for _, w := range env.Recipients {
			if b, err := hex.DecodeString(w); err == nil {
				onDisk = append(onDisk, b)
			}
		}
	}
	if len(want) > 0 {
		return nil, fmt.Errorf("%s went while the key was being rotated", v.relSlash(slices.Min(slices.Collect(maps.Keys(want)))))
	}
	return onDisk, nil
}
