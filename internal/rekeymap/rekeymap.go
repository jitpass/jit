// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package rekeymap

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/jitpass/jit/internal/atomicfile"
)

// FileName is the map's name in jit's own directory, beside jobs.json and
// grants.json.
const FileName = "rekey.digests"

// Version is the only map version this build reads or writes.
const Version = 1

// Path is where the map lives for the jit directory root.
func Path(root string) string {
	return filepath.Join(root, FileName)
}

// Digest is the one definition of a pin's hash: the lowercase hex SHA-256
// of a wrapped data key's bytes (the recipient value hex-decoded, as
// vault.WrappedDEK returns it). The agent's pins use it too.
func Digest(wrapped []byte) string {
	sum := sha256.Sum256(wrapped)
	return hex.EncodeToString(sum[:])
}

// Change is one link: the wrapped data key that hashed to Old was wrapped
// again, keeping the same data key, into bytes that hash to New.
type Change struct {
	Old string `json:"old"`
	New string `json:"new"`
	// File is the envelope's slash path under vault/, for people reading
	// the file. The rule never uses it.
	File string `json:"file,omitempty"`
}

// NewChange is the link for one recipient's rewrap of the envelope file
// (a slash path under vault/), from the wrapped bytes before to after.
func NewChange(file string, oldWrapped, newWrapped []byte) Change {
	return Change{Old: Digest(oldWrapped), New: Digest(newWrapped), File: file}
}

// ErrUnreadable marks a map that is there but cannot be used: not JSON, a
// version this build does not know, or an entry that is not two digests.
// Nothing is applied from it, and Write and Prune never write over it.
var ErrUnreadable = errors.New("the key rotation's digest map is unreadable")

// fileJSON is the file's shape.
type fileJSON struct {
	Version int      `json:"version"`
	Changes []Change `json:"changes"`
}

// Map is a read map.
type Map struct {
	changes []Change
	next    map[string][]string // Old -> every New it was wrapped into
}

func newMap(changes []Change) *Map {
	m := &Map{changes: changes, next: make(map[string][]string, len(changes))}
	for _, c := range changes {
		m.next[c.Old] = append(m.next[c.Old], c.New)
	}
	return m
}

// Changes returns the map's links, in file order.
func (m *Map) Changes() []Change {
	return append([]Change(nil), m.changes...)
}

// Reaches reports whether the map proves that the wrapped data key hashing
// to current holds the same data key as the one hashing to pinned: a chain
// of links pinned → … → current (current == pinned is the empty chain).
//
// It says nothing about paths. The caller must read current at the pin's
// own path, now: that is what keeps a pin from moving to another path's
// envelope, and a value changed since the approval (a new data key) from
// being re-pinned. Each hash is visited once, so a cycle ends the search.
func (m *Map) Reaches(pinned, current string) bool {
	seen := map[string]bool{pinned: true}
	queue := []string{pinned}
	for len(queue) > 0 {
		d := queue[0]
		queue = queue[1:]
		if d == current {
			return true
		}
		for _, n := range m.next[d] {
			if !seen[n] {
				seen[n] = true
				queue = append(queue, n)
			}
		}
	}
	return false
}

// Read reads the map at path. An absent map is an error satisfying
// errors.Is(err, fs.ErrNotExist); anything else that stops it being used
// wraps ErrUnreadable.
func Read(path string) (*Map, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- a fixed name under jit's own directory
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %v", ErrUnreadable, err)
	}
	var f fileJSON
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnreadable, err)
	}
	if f.Version != Version {
		return nil, fmt.Errorf("%w: version %d, this jit reads version %d", ErrUnreadable, f.Version, Version)
	}
	if f.Changes == nil {
		return nil, fmt.Errorf("%w: no list of changes", ErrUnreadable)
	}
	for i, c := range f.Changes {
		if err := c.valid(); err != nil {
			return nil, fmt.Errorf("%w: change %d: %v", ErrUnreadable, i+1, err)
		}
	}
	return newMap(f.Changes), nil
}

// readOrEmpty is Read with an absent map read as an empty one.
func readOrEmpty(path string) (*Map, error) {
	m, err := Read(path)
	if errors.Is(err, fs.ErrNotExist) {
		return newMap(nil), nil
	}
	return m, err
}

// Write adds changes to the map at path, keeping every link already there
// (an earlier run that stopped part way wrote them, and they may be all
// that chains a pin to an envelope it wrote), and writes it whole, durably
// (atomicfile). A link already present is not added twice. When nothing is
// new, nothing is written: no file is created for a run with no changes.
//
// A map that is there but unreadable is an error and is left as it is:
// writing over it could drop the only record of an earlier run's old
// hashes, which nothing can recompute.
func Write(path string, changes []Change) error {
	for i, c := range changes {
		if err := c.valid(); err != nil {
			return fmt.Errorf("digest map: change %d: %w", i+1, err)
		}
	}
	m, err := readOrEmpty(path)
	if err != nil {
		return fmt.Errorf("%w (%s), not writing over it", err, path)
	}
	have := make(map[[2]string]bool, len(m.changes)+len(changes))
	for _, c := range m.changes {
		have[[2]string{c.Old, c.New}] = true
	}
	merged := m.Changes()
	for _, c := range changes {
		if k := [2]string{c.Old, c.New}; !have[k] {
			have[k] = true
			merged = append(merged, c)
		}
	}
	if len(merged) == len(m.changes) {
		return nil
	}
	return write(path, merged)
}

// Prune drops the links that can never be part of a chain to an envelope:
// a link whose New no envelope has (onDisk is every recipient's wrapped
// data key in the vault now) and from which no link leads on, repeated
// until none is left. What such a link names was planned by a run that
// stopped before writing it, and the next run wrapped that data key again.
// Every chain that ends at a hash on disk is kept whole, links from earlier
// rotations included.
//
// Call it only once every envelope a run planned is written: a New not yet
// on disk may still be written. An absent map is nothing to prune; an
// unreadable one is an error and is left as it is. Nothing is written when
// nothing is dropped.
func Prune(path string, onDisk [][]byte) error {
	m, err := Read(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%w (%s), not writing over it", err, path)
	}
	present := make(map[string]bool, len(onDisk))
	for _, w := range onDisk {
		present[Digest(w)] = true
	}
	out := map[string]int{}
	for _, c := range m.changes {
		out[c.Old]++
	}
	keep := make([]bool, len(m.changes))
	for i := range keep {
		keep[i] = true
	}
	for dropped := true; dropped; {
		dropped = false
		for i, c := range m.changes {
			if keep[i] && !present[c.New] && out[c.New] == 0 {
				keep[i] = false
				out[c.Old]--
				dropped = true
			}
		}
	}
	var kept []Change
	for i, c := range m.changes {
		if keep[i] {
			kept = append(kept, c)
		}
	}
	if len(kept) == len(m.changes) {
		return nil
	}
	return write(path, kept)
}

// writeFile is the map's one write, a variable so a test can see that it
// is atomicfile's: nothing on disk tells an atomic write from a plain one.
var writeFile = atomicfile.WriteFile

func write(path string, changes []Change) error {
	if changes == nil {
		changes = []Change{}
	}
	data, err := json.MarshalIndent(fileJSON{Version: Version, Changes: changes}, "", "  ")
	if err != nil {
		return err
	}
	if err := writeFile(path, append(data, '\n')); err != nil {
		return fmt.Errorf("writing the key rotation's digest map: %w", err)
	}
	return nil
}

// valid: both sides are digests.
func (c Change) valid() error {
	for _, d := range []string{c.Old, c.New} {
		if !isDigest(d) {
			return fmt.Errorf("%q is not a lowercase hex SHA-256", d)
		}
	}
	return nil
}

func isDigest(s string) bool {
	if len(s) != 2*sha256.Size {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}
