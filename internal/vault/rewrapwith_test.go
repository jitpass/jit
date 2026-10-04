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
	"testing"

	"github.com/jitpass/jit/internal/rekeymap"
)

// errCrash is what the hooks return to stop a rewrap where a crash would.
var errCrash = errors.New("simulated crash")

// rotationHooks is the rotation's glue as `jit vault rekey` wires it
// (design/secure-enclave-rotation.md, part 2): the digest map written
// before the first envelope, pruned after the last. crashAt names the one
// step to stop after: "planned" (before the map write), "mapped",
// "written N", "rewritten" (every envelope written, before the prune).
func rotationHooks(root, crashAt string) RewrapOptions {
	mapPath := rekeymap.Path(root)
	crash := func(step string) error {
		if step == crashAt {
			return errCrash
		}
		return nil
	}
	return RewrapOptions{
		BeforeWrite: func(cs []WrapChange) error {
			if err := crash("planned"); err != nil {
				return err
			}
			changes := make([]rekeymap.Change, len(cs))
			for i, c := range cs {
				changes[i] = rekeymap.NewChange(c.File, c.Old, c.New)
			}
			if err := rekeymap.Write(mapPath, changes); err != nil {
				return err
			}
			return crash("mapped")
		},
		AfterWrite: func(n int) error { return crash(fmt.Sprintf("written %d", n)) },
		AfterAll: func(onDisk [][]byte) error {
			if err := crash("rewritten"); err != nil {
				return err
			}
			return rekeymap.Prune(mapPath, onDisk)
		},
	}
}

// rotationFixture is a vault about to be rotated, as it was before.
type rotationFixture struct {
	root         string
	oldKW, newKW *fakeKeyWrapper
	values       map[string]string            // live path -> value
	pins         map[string]string            // live path -> the pin an approval took
	before       map[string]map[string]string // envelope file -> recipient -> digest
	snapshot     string                       // a copy of root as it was before
}

// liveValues are the fixture's live secrets. aws/key is set twice (an
// archived copy under _history/), and db/pass carries a second recipient
// wrapping the same data key, so every envelope population is covered.
var liveValues = map[string]string{
	"aws/key":           "v2",
	"db/pass":           "hunter2",
	"_backups/some/env": "backup-bytes",
	"zz/last":           "last",
}

func newRotationFixture(t *testing.T) *rotationFixture {
	t.Helper()
	f := &rotationFixture{
		root:   t.TempDir(),
		oldKW:  newFakeKeyWrapper(),
		newKW:  &fakeKeyWrapper{key: bytes.Repeat([]byte{0x99}, dekSize)},
		values: liveValues,
	}
	v := &Vault{Root: f.root, KeyWrapper: f.oldKW, RecipientID: "test-device"}
	if err := v.Set("aws/key", []byte("v1")); err != nil {
		t.Fatal(err)
	}
	for p, val := range f.values {
		if err := v.Set(p, []byte(val)); err != nil {
			t.Fatal(err)
		}
	}
	addRecipient(t, filepath.Join(v.vaultDir(), "db/pass.enc"), f.oldKW, "other-device")
	f.pins = pinsOf(t, f.root)
	f.before = recipientDigests(t, f.root)
	if n := len(f.before); n != 5 {
		t.Fatalf("fixture has %d envelope files, want 5", n)
	}
	f.snapshot = t.TempDir()
	copyTree(t, f.root, f.snapshot)
	return f
}

// clone is a fixture holding f's starting vault byte for byte, so its old
// wrapped keys (a map's old sides) are f's.
func (f *rotationFixture) clone(t *testing.T) *rotationFixture {
	t.Helper()
	c := *f
	c.root = t.TempDir()
	copyTree(t, f.snapshot, c.root)
	return &c
}

// addRecipient wraps an envelope's data key a second time, under kw, for
// another recipient id.
func addRecipient(t *testing.T, file string, kw KeyWrapper, id string) {
	t.Helper()
	var env envelope
	if err := json.Unmarshal(fileBytes(t, file), &env); err != nil {
		t.Fatal(err)
	}
	for _, w := range env.Recipients {
		wrapped, _ := hex.DecodeString(w)
		dek, err := kw.UnwrapKey(wrapped)
		if err != nil {
			t.Fatal(err)
		}
		again, err := kw.WrapKey(dek)
		if err != nil {
			t.Fatal(err)
		}
		env.Recipients[id] = hex.EncodeToString(again)
		break
	}
	out, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := AtomicWriteFile(file, out); err != nil {
		t.Fatal(err)
	}
}

// pinsOf is each live secret's pin, as the agent takes it: the digest of
// the wrapped data key WrappedDEK reads at the path.
func pinsOf(t *testing.T, root string) map[string]string {
	t.Helper()
	v := &Vault{Root: root, RecipientID: "test-device"}
	pins := map[string]string{}
	for p := range liveValues {
		wrapped, _, err := v.WrappedDEK(p)
		if err != nil {
			t.Fatalf("WrappedDEK(%s): %v", p, err)
		}
		pins[p] = rekeymap.Digest(wrapped)
	}
	return pins
}

// recipientDigests is every envelope file's recipients, by id, as digests.
func recipientDigests(t *testing.T, root string) map[string]map[string]string {
	t.Helper()
	v := &Vault{Root: root}
	files, err := v.allEnvelopeFiles()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]map[string]string{}
	for _, file := range files {
		var env envelope
		if err := json.Unmarshal(fileBytes(t, file), &env); err != nil {
			t.Fatal(err)
		}
		out[v.relSlash(file)] = map[string]string{}
		for id, w := range env.Recipients {
			wrapped, err := hex.DecodeString(w)
			if err != nil {
				t.Fatal(err)
			}
			out[v.relSlash(file)][id] = rekeymap.Digest(wrapped)
		}
	}
	return out
}

// notOpeningUnder is the envelope files with a recipient that does not
// unwrap under kw.
func notOpeningUnder(t *testing.T, root string, kw KeyWrapper) []string {
	t.Helper()
	v := &Vault{Root: root}
	files, err := v.allEnvelopeFiles()
	if err != nil {
		t.Fatal(err)
	}
	var bad []string
	for _, file := range files {
		var env envelope
		if err := json.Unmarshal(fileBytes(t, file), &env); err != nil {
			t.Fatal(err)
		}
		for _, w := range env.Recipients {
			wrapped, _ := hex.DecodeString(w)
			if _, err := kw.UnwrapKey(wrapped); err != nil {
				bad = append(bad, v.relSlash(file))
				break
			}
		}
	}
	return bad
}

// readMap is the map at root, or an empty one when there is none.
func readMap(t *testing.T, root string) *rekeymap.Map {
	t.Helper()
	m, err := rekeymap.Read(rekeymap.Path(root))
	if errors.Is(err, fs.ErrNotExist) {
		m, err = rekeymap.Read(writeEmptyMap(t))
	}
	if err != nil {
		t.Fatalf("reading the map: %v", err)
	}
	return m
}

func writeEmptyMap(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(p, []byte(`{"version":1,"changes":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// checkMidRotation is what must hold at every instant of a rotation: every
// envelope opens under one of the two keys, and every recipient that no
// longer holds its old wrapped key is reached from it through the map (so
// a pin taken before the rotation can always be carried over).
func (f *rotationFixture) checkMidRotation(t *testing.T) {
	t.Helper()
	oldBad, newBad := notOpeningUnder(t, f.root, f.oldKW), notOpeningUnder(t, f.root, f.newKW)
	for _, file := range oldBad {
		if slices.Contains(newBad, file) {
			t.Errorf("%s opens under neither key", file)
		}
	}
	m := readMap(t, f.root)
	for file, recips := range recipientDigests(t, f.root) {
		for id, now := range recips {
			if was := f.before[file][id]; !m.Reaches(was, now) {
				t.Errorf("%s (%s) was rewritten with no chain in the map from its old wrapped key", file, id)
			}
		}
	}
}

// mapShape is a finished map as (file, old) pairs, sorted: what an
// interrupted and an uninterrupted run must agree on (the new sides are
// random).
func mapShape(m *rekeymap.Map) []string {
	var out []string
	for _, c := range m.Changes() {
		out = append(out, c.File+" "+c.Old)
	}
	slices.Sort(out)
	return out
}

// checkFinished is the state after a rotation's last run: every envelope
// opens under the new key and none under the old, every value is intact,
// the map holds one link per rewrapped recipient from its old wrapped key
// to the one on disk now, and names no digest that no envelope has, and
// every pin reaches its envelope's hash now.
func (f *rotationFixture) checkFinished(t *testing.T) {
	t.Helper()
	if bad := notOpeningUnder(t, f.root, f.newKW); len(bad) > 0 {
		t.Errorf("not open under the new key: %v", bad)
	}
	if good := notOpeningUnder(t, f.root, f.oldKW); len(good) != len(f.before) {
		t.Errorf("the old key still opens some envelopes (it fails on only %v)", good)
	}
	v := &Vault{Root: f.root, KeyWrapper: f.newKW, RecipientID: "test-device"}
	for p, want := range f.values {
		if got, err := v.Get(p); err != nil || string(got) != want {
			t.Errorf("Get(%s) under the new key = %q, %v; want %q", p, got, err, want)
		}
	}
	now := recipientDigests(t, f.root)
	onDisk := map[string]bool{}
	var wantShape []string
	for file, recips := range now {
		for id, d := range recips {
			onDisk[d] = true
			wantShape = append(wantShape, file+" "+f.before[file][id])
		}
	}
	slices.Sort(wantShape)
	m := readMap(t, f.root)
	if got := mapShape(m); !slices.Equal(got, wantShape) {
		t.Errorf("map links (file, old):\n%v\nwant one per rewrapped recipient:\n%v", got, wantShape)
	}
	for _, c := range m.Changes() {
		if !onDisk[c.New] {
			t.Errorf("the map names %s for %s, which no envelope has", c.New[:12], c.File)
		}
		if now[c.File] == nil || !slices.Contains(slices.Collect(maps.Values(now[c.File])), c.New) {
			t.Errorf("the map's link for %s ends at a hash that file does not hold", c.File)
		}
	}
	nowPins := pinsOf(t, f.root)
	for p, pin := range f.pins {
		if !m.Reaches(pin, nowPins[p]) {
			t.Errorf("the pin on %s does not reach its envelope now", p)
		}
	}
}

// runRotation is one `jit vault rekey` run from a fresh process's view.
func (f *rotationFixture) runRotation(crashAt string) (RewrapResult, error) {
	v := &Vault{Root: f.root, RecipientID: "test-device"}
	return v.RewrapWith(f.oldKW, f.newKW, rotationHooks(f.root, crashAt))
}

// A crash after every step of RewrapWith, and after two steps in a row,
// then re-runs until one finishes: at every stop the vault opens under one
// of the keys and every rewritten envelope is covered by the map; at the
// end the vault, the map and the pins are what one uninterrupted run
// leaves (the map's new sides aside, which are random).
func TestRewrapWithResumesAfterACrashAtEveryStep(t *testing.T) {
	ref := newRotationFixture(t)
	if _, err := ref.runRotation(""); err != nil {
		t.Fatalf("uninterrupted run: %v", err)
	}
	ref.checkFinished(t)
	refShape := mapShape(readMap(t, ref.root))
	if len(refShape) != 6 {
		t.Fatalf("an uninterrupted run's map has %d links, want 6 (five files, one with two recipients)", len(refShape))
	}

	for _, crashes := range [][]string{
		{"planned"},
		{"mapped"},
		{"written 1"},
		{"written 3"},
		{"rewritten"},
		{"mapped", "mapped"},
		{"mapped", "written 1"},
		{"written 1", "mapped"},
		{"written 2", "written 1", "rewritten"},
	} {
		t.Run(strings.Join(crashes, ", then "), func(t *testing.T) {
			f := ref.clone(t)

			for _, step := range crashes {
				if _, err := f.runRotation(step); !errors.Is(err, errCrash) {
					t.Fatalf("run crashing at %q: err = %v, want the crash", step, err)
				}
				f.checkMidRotation(t)
				if step == "planned" {
					if _, err := os.Stat(rekeymap.Path(f.root)); !errors.Is(err, fs.ErrNotExist) {
						t.Errorf("a crash before the map write left a map")
					}
				}
			}
			r, err := f.runRotation("")
			if err != nil {
				t.Fatalf("resumed run: %v", err)
			}
			if r.Rewrapped+r.Current != 5 {
				t.Errorf("resumed run = %+v, want five envelopes accounted for", r)
			}
			f.checkFinished(t)
			if got := mapShape(readMap(t, f.root)); !slices.Equal(got, refShape) {
				t.Errorf("resumed map (file, old):\n%v\nuninterrupted:\n%v", got, refShape)
			}
		})
	}
}

func copyTree(t *testing.T, from, to string) {
	t.Helper()
	err := filepath.WalkDir(from, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(from, p)
		dest := filepath.Join(to, rel)
		if d.IsDir() {
			return os.MkdirAll(dest, 0o700)
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(dest, data, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// BeforeWrite sees every change before the first envelope is written, and
// each change is a proven rewrap: New opens under the new key to the data
// key Old opens to under the old one.
func TestRewrapWithHandsEveryChangeToBeforeWriteBeforeAnyWrite(t *testing.T) {
	f := newRotationFixture(t)
	var got []WrapChange
	v := &Vault{Root: f.root, RecipientID: "test-device"}
	r, err := v.RewrapWith(f.oldKW, f.newKW, RewrapOptions{BeforeWrite: func(cs []WrapChange) error {
		if now := recipientDigests(t, f.root); !maps.EqualFunc(now, f.before, maps.Equal) {
			t.Error("an envelope was written before BeforeWrite ran")
		}
		got = cs
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 6 || r.Rewrapped != 5 {
		t.Fatalf("BeforeWrite got %d changes for %d envelopes written, want 6 for 5", len(got), r.Rewrapped)
	}
	for _, c := range got {
		want := f.before[c.File]
		if want == nil || !slices.Contains(slices.Collect(maps.Values(want)), rekeymap.Digest(c.Old)) {
			t.Errorf("change for %s: Old is not a wrapped key that file held", c.File)
		}
		was, err := f.oldKW.UnwrapKey(c.Old)
		if err != nil {
			t.Fatal(err)
		}
		now, err := f.newKW.UnwrapKey(c.New)
		if err != nil || !bytes.Equal(was, now) {
			t.Errorf("change for %s: New does not open to Old's data key (%v)", c.File, err)
		}
	}
	after := recipientDigests(t, f.root)
	for _, c := range got {
		if !slices.Contains(slices.Collect(maps.Values(after[c.File])), rekeymap.Digest(c.New)) {
			t.Errorf("%s was not written with the New BeforeWrite was given", c.File)
		}
	}
}

// An unproven envelope stops the rotation in the plan pass, before any
// envelope is written. The rewrap used to stop part way instead, with the
// files before it already under the new key.
func TestRewrapStopsOnAnUnprovenEnvelopeBeforeWritingAny(t *testing.T) {
	v, _, current := lostKeyVault(t, "a")
	setSecrets(t, v, "b") // after the set-aside, under the current key
	other := &Vault{Root: v.Root, KeyWrapper: &fakeKeyWrapper{key: bytes.Repeat([]byte{0x11}, dekSize)}, RecipientID: "test-device"}
	setSecrets(t, other, "stranger") // under neither key, and no record lists it
	bFile := filepath.Join(v.vaultDir(), "b.enc")
	before := fileBytes(t, bFile)

	staged := &fakeKeyWrapper{key: bytes.Repeat([]byte{0x55}, dekSize)}
	if _, err := v.Rewrap(current, staged); err == nil || !strings.Contains(err.Error(), "stranger") {
		t.Fatalf("Rewrap = %v, want it to stop naming stranger", err)
	}
	if !bytes.Equal(fileBytes(t, bFile), before) {
		t.Fatal("b.enc was rewritten before the rotation stopped on stranger.enc")
	}
}

// A file changed between the plan and its write stops the rewrap and is
// left as it is: the plan was made from other bytes, and writing it would
// throw the new value away. Both keys still open everything, and a re-run
// finishes with the new value.
func TestRewrapWithStopsOnAFileChangedAfterThePlan(t *testing.T) {
	f := newRotationFixture(t)
	opts := rotationHooks(f.root, "")
	before := opts.BeforeWrite
	opts.BeforeWrite = func(cs []WrapChange) error {
		if err := before(cs); err != nil {
			return err
		}
		// Another writer, under the old key (an older jit ignoring the marker).
		w := &Vault{Root: f.root, KeyWrapper: f.oldKW, RecipientID: "test-device"}
		return w.Set("zz/last", []byte("written mid-rotation"))
	}
	v := &Vault{Root: f.root, RecipientID: "test-device"}
	_, err := v.RewrapWith(f.oldKW, f.newKW, opts)
	old := &Vault{Root: f.root, KeyWrapper: f.oldKW, RecipientID: "test-device"}
	if got, err := old.Get("zz/last"); err != nil || string(got) != "written mid-rotation" {
		t.Errorf("zz/last = %q, %v; want the value written mid-rotation, under the old key", got, err)
	}
	if err == nil || !strings.Contains(err.Error(), "zz/last.enc changed") {
		t.Fatalf("RewrapWith = %v, want it to stop on zz/last.enc", err)
	}

	// The re-run plans the new bytes. zz/last's history copy is a sixth file.
	f.values = map[string]string{"zz/last": "written mid-rotation"}
	if _, err := f.runRotation(""); err != nil {
		t.Fatalf("re-run: %v", err)
	}
	nv := &Vault{Root: f.root, KeyWrapper: f.newKW, RecipientID: "test-device"}
	if got, err := nv.Get("zz/last"); err != nil || string(got) != "written mid-rotation" {
		t.Fatalf("after the re-run zz/last = %q, %v", got, err)
	}
	if bad := notOpeningUnder(t, f.root, f.newKW); len(bad) > 0 {
		t.Fatalf("not open under the new key after the re-run: %v", bad)
	}
}

// Once every envelope is written, the vault must hold exactly what the plan
// left: an envelope that appeared, or changed after it was written, under
// the old key would be orphaned when the caller destroys that key.
func TestRewrapWithStopsWhenTheVaultChangedUnderIt(t *testing.T) {
	for name, meddle := range map[string]func(w *Vault) error{
		"an envelope appeared": func(w *Vault) error { return w.Set("new/one", []byte("new")) },
		"a written envelope changed": func(w *Vault) error {
			// The first file written is _backups/some/env.enc (walk order);
			// a backup keeps no history, so this adds no file.
			return w.Set("_backups/some/env", []byte("changed"))
		},
		"a written envelope went": func(w *Vault) error {
			return os.Remove(filepath.Join(w.vaultDir(), "_backups/some/env.enc"))
		},
		"an envelope went before its write": func(w *Vault) error {
			return os.Remove(filepath.Join(w.vaultDir(), "zz/last.enc"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newRotationFixture(t)
			opts := rotationHooks(f.root, "")
			opts.AfterWrite = func(n int) error {
				if n != 1 {
					return nil
				}
				return meddle(&Vault{Root: f.root, KeyWrapper: f.oldKW, RecipientID: "test-device"})
			}
			afterAll := false
			prune := opts.AfterAll
			opts.AfterAll = func(onDisk [][]byte) error { afterAll = true; return prune(onDisk) }
			v := &Vault{Root: f.root, RecipientID: "test-device"}
			if _, err := v.RewrapWith(f.oldKW, f.newKW, opts); err == nil || !strings.Contains(err.Error(), "while the key was being rotated") {
				t.Fatalf("RewrapWith = %v, want it to stop on the vault changing under it", err)
			}
			if afterAll {
				t.Error("AfterAll ran over a vault that changed under the rewrap")
			}
		})
	}
}

// A proven lost-key copy is never rewritten, gets no link in the map, and
// does not stop the rotation.
func TestRewrapWithLeavesProvenLostKeyCopiesOutOfTheMap(t *testing.T) {
	v, _, current := lostKeyVault(t, "a", "b")
	setSecrets(t, v, "a", "c") // a restored (its lost-key copy archived), c new
	before := recipientDigests(t, v.Root)
	staged := &fakeKeyWrapper{key: bytes.Repeat([]byte{0x55}, dekSize)}
	fresh := &Vault{Root: v.Root, RecipientID: "test-device"}
	r, err := fresh.RewrapWith(current, staged, rotationHooks(v.Root, ""))
	if err != nil {
		t.Fatalf("RewrapWith stopped on a lost-key copy: %v", err)
	}
	if r.Rewrapped != 2 || len(r.Kept) != 2 {
		t.Fatalf("RewrapWith = %+v, want a and c rewrapped, b and a's archived copy kept", r)
	}
	m := readMap(t, v.Root)
	if len(m.Changes()) != 2 {
		t.Errorf("map has %d links, want 2 (a and c)", len(m.Changes()))
	}
	for _, kept := range r.Kept {
		for _, d := range before[kept] {
			for _, c := range m.Changes() {
				if c.File == kept || c.Old == d || c.New == d {
					t.Errorf("the map names the kept lost-key copy %s: %+v", kept, c)
				}
			}
		}
		if !maps.Equal(recipientDigests(t, v.Root)[kept], before[kept]) {
			t.Errorf("the kept lost-key copy %s was rewritten", kept)
		}
	}
}

// Two rotations, the first interrupted and resumed, and the service asleep
// throughout, so the map is never applied or removed between them. A pin
// follows its data key through both; a value set between them, an envelope
// restored from history (another data key) and a path now holding another
// path's envelope reach nothing.
func TestPinsFollowTwoRotationsTheFirstInterrupted(t *testing.T) {
	f := newRotationFixture(t)
	midKW := &fakeKeyWrapper{key: bytes.Repeat([]byte{0x66}, dekSize)}
	newKW := f.newKW

	f.newKW = midKW
	if _, err := f.runRotation("written 1"); !errors.Is(err, errCrash) {
		t.Fatalf("first run: %v, want the crash", err)
	}
	if _, err := f.runRotation(""); err != nil {
		t.Fatalf("first rotation, resumed: %v", err)
	}

	w := &Vault{Root: f.root, KeyWrapper: midKW, RecipientID: "test-device"}
	if err := w.Set("db/pass", []byte("a new value")); err != nil {
		t.Fatal(err)
	}
	if err := w.Restore("aws/key", 0); err != nil { // v1 back: another data key
		t.Fatal(err)
	}
	backup := fileBytes(t, filepath.Join(w.vaultDir(), "_backups/some/env.enc"))
	if err := AtomicWriteFile(filepath.Join(w.vaultDir(), "zz/last.enc"), backup); err != nil {
		t.Fatal(err)
	}

	// The second rotation stops after its last write, before the prune: the
	// service may read the map then (its lazy apply), so the rule must hold
	// on it as written, and again once pruned.
	f.oldKW, f.newKW = midKW, newKW
	if _, err := f.runRotation("rewritten"); !errors.Is(err, errCrash) {
		t.Fatalf("second rotation: %v, want the crash", err)
	}
	check := func(when string) {
		m := readMap(t, f.root)
		now := pinsOf(t, f.root)
		for p, want := range map[string]bool{
			"_backups/some/env": true,  // never changed
			"db/pass":           false, // a value set between the rotations
			"aws/key":           false, // restored from history: another data key
			"zz/last":           false, // holds _backups/some/env's envelope now
		} {
			if got := m.Reaches(f.pins[p], now[p]); got != want {
				t.Errorf("%s, %s: the pin reaches its envelope now = %v, want %v", when, p, got, want)
			}
		}
	}
	check("before the prune")
	if _, err := f.runRotation(""); err != nil {
		t.Fatalf("second rotation, resumed: %v", err)
	}
	check("pruned")
}
