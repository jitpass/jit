// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package rekeymap

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// d is a test digest: the Digest of a name standing for some wrapped bytes.
func d(name string) string { return Digest([]byte(name)) }

// link is the Change from wrapped bytes named a to wrapped bytes named b.
func link(a, b string) Change { return NewChange("x.enc", []byte(a), []byte(b)) }

func readChanges(t *testing.T, path string) []Change {
	t.Helper()
	m, err := Read(path)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	return m.Changes()
}

// Digest is the pin's hash, fixed by a known vector: the agent's pins and
// the map are compared by it, so any change to it strands every pin.
func TestDigestIsTheHexSHA256OfTheWrappedBytes(t *testing.T) {
	const want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" // SHA-256("abc")
	if got := Digest([]byte("abc")); got != want {
		t.Fatalf("Digest(abc) = %s, want %s", got, want)
	}
}

func TestWriteThenReadBack(t *testing.T) {
	path := Path(t.TempDir())
	want := []Change{
		NewChange("aws/key.enc", []byte("old-a"), []byte("new-a")),
		NewChange("_history/b/1.enc", []byte("old-b"), []byte("new-b")),
	}
	if err := Write(path, want); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got := readChanges(t, path); !slices.Equal(got, want) {
		t.Fatalf("read back %+v, want %+v", got, want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode %v, want 0600", info.Mode().Perm())
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != FileName {
		t.Errorf("directory holds %v, want only %s (no temp file left)", entries, FileName)
	}
}

// The map is the only record of the old hashes once the envelopes change,
// so its write must be the durable one (atomicfile: fsync, rename, fsync of
// the directory). Nothing on disk tells that from a plain write, hence the
// seam.
func TestWriteGoesThroughAtomicfile(t *testing.T) {
	path := Path(t.TempDir())
	var calls []string
	orig := writeFile
	writeFile = func(dest string, data []byte) error {
		calls = append(calls, dest)
		return orig(dest, data)
	}
	t.Cleanup(func() { writeFile = orig })

	if err := Write(path, []Change{link("a0", "a1")}); err != nil {
		t.Fatal(err)
	}
	if err := Prune(path, nil); err != nil { // a1 is not on disk: the link goes
		t.Fatal(err)
	}
	if !slices.Equal(calls, []string{path, path}) {
		t.Fatalf("writes through atomicfile: %v, want Write's and Prune's to %s", calls, path)
	}
}

// A failed write leaves the earlier map exactly as it was.
func TestAFailedWriteLeavesTheEarlierMap(t *testing.T) {
	path := Path(t.TempDir())
	if err := Write(path, []Change{link("a0", "a1")}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	orig := writeFile
	writeFile = func(string, []byte) error { return errors.New("disk full") }
	t.Cleanup(func() { writeFile = orig })
	if err := Write(path, []Change{link("b0", "b1")}); err == nil {
		t.Fatal("Write succeeded with a failing write")
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(after, before) {
		t.Fatalf("a failed write changed the map:\n%s\nwant\n%s", after, before)
	}
}

// An interrupted run's links stay: they may be all that chains a pin to an
// envelope that run wrote before it stopped.
func TestWriteKeepsWhatAnEarlierRunWrote(t *testing.T) {
	path := Path(t.TempDir())
	first := []Change{link("a0", "a1"), link("b0", "b1")}
	if err := Write(path, first); err != nil {
		t.Fatal(err)
	}
	// The re-run: b is current (no link), a is planned again (a fresh
	// wrap), c is new, and a0->a1 comes again (deduplicated).
	if err := Write(path, []Change{link("a0", "a2"), link("c0", "c1"), link("a0", "a1")}); err != nil {
		t.Fatal(err)
	}
	want := []Change{link("a0", "a1"), link("b0", "b1"), link("a0", "a2"), link("c0", "c1")}
	if got := readChanges(t, path); !slices.Equal(got, want) {
		t.Fatalf("merged map %+v, want %+v", got, want)
	}
}

// A run with no changes creates no map, and one that adds nothing new does
// not rewrite it.
func TestWriteWithNothingNewWritesNothing(t *testing.T) {
	path := Path(t.TempDir())
	if err := Write(path, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a run with no changes left a map (stat: %v)", err)
	}
	if err := Write(path, []Change{link("a0", "a1")}); err != nil {
		t.Fatal(err)
	}
	orig := writeFile
	writeFile = func(string, []byte) error { t.Error("rewrote a map with nothing new"); return nil }
	t.Cleanup(func() { writeFile = orig })
	if err := Write(path, []Change{link("a0", "a1")}); err != nil {
		t.Fatal(err)
	}
}

var unreadableMaps = map[string]string{
	"garbage":             `not json`,
	"a newer version":     `{"version": 2, "changes": []}`,
	"no version":          `{"changes": []}`,
	"no changes list":     `{"version": 1}`,
	"a digest too short":  `{"version": 1, "changes": [{"old": "abc", "new": "` + Digest(nil) + `"}]}`,
	"an uppercase digest": `{"version": 1, "changes": [{"old": "` + Digest(nil) + `", "new": "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"}]}`,
}

// A map this build can't read applies nothing and is never written over:
// it may hold the only record of an earlier run's old hashes.
func TestAnUnreadableMapIsAnErrorAndIsNeverWrittenOver(t *testing.T) {
	for name, content := range unreadableMaps {
		t.Run(name, func(t *testing.T) {
			path := Path(t.TempDir())
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Read(path); !errors.Is(err, ErrUnreadable) {
				t.Errorf("Read = %v, want ErrUnreadable", err)
			}
			if err := Write(path, []Change{link("a0", "a1")}); !errors.Is(err, ErrUnreadable) {
				t.Errorf("Write = %v, want ErrUnreadable", err)
			}
			if err := Prune(path, nil); !errors.Is(err, ErrUnreadable) {
				t.Errorf("Prune = %v, want ErrUnreadable", err)
			}
			if got, _ := os.ReadFile(path); string(got) != content {
				t.Errorf("the unreadable map was written over: %s", got)
			}
		})
	}
}

func TestReadOfNoMapIsNotExist(t *testing.T) {
	if _, err := Read(Path(t.TempDir())); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Read of no map = %v, want fs.ErrNotExist", err)
	}
}

func TestWriteRefusesAChangeThatIsNotTwoDigests(t *testing.T) {
	path := Path(t.TempDir())
	if err := Write(path, []Change{{Old: "a0", New: d("a1")}}); err == nil {
		t.Fatal("Write accepted a change whose old side is not a digest")
	}
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a refused Write left a map (stat: %v)", err)
	}
}

func TestReachesFollowsChainsForwardOnly(t *testing.T) {
	m := newMap([]Change{
		link("a0", "a1x"), // planned by a run that stopped, never written
		link("a0", "a1"),
		link("a1", "a2"),
		link("b0", "b1"),
	})
	for _, tc := range []struct {
		pinned, current string
		want            bool
	}{
		{"a0", "a0", true}, // the empty chain
		{"a0", "a1", true},
		{"a0", "a2", true}, // two rotations
		{"a1", "a2", true},
		{"a0", "a1x", true}, // harmless: no envelope has it
		{"a2", "a0", false}, // never backwards
		{"a0", "b1", false}, // never to another data key
		{"b0", "a2", false},
		{"c0", "c1", false}, // a hash the map does not know
	} {
		if got := m.Reaches(d(tc.pinned), d(tc.current)); got != tc.want {
			t.Errorf("Reaches(%s, %s) = %v, want %v", tc.pinned, tc.current, got, tc.want)
		}
	}
}

// A cycle can't be written by a rotation (new bytes are random), but a map
// is a file anyone at that tier can write: following one must end.
func TestReachesEndsOnACycle(t *testing.T) {
	m := newMap([]Change{link("a", "b"), link("b", "c"), link("c", "a")})
	done := make(chan bool, 1)
	go func() { done <- m.Reaches(d("a"), d("z")) }()
	select {
	case got := <-done:
		if got {
			t.Fatal("Reaches found a chain to a hash the map does not know")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Reaches did not end on a cycle")
	}
}

// Two rotations, the first interrupted and resumed, with the service asleep
// throughout (the map is never applied or removed between them). Every
// secret whose data key never changed reaches its envelope now; one whose
// value was set in between, and a path now holding another path's
// envelope, reach nothing: not on the map as rotation 2 writes it, and not
// once it is pruned.
func TestChainsSpanTwoRotationsTheFirstInterrupted(t *testing.T) {
	path := Path(t.TempDir())
	// Rotation 1, run 1: planned everything; wrote the map; wrote b; stopped.
	if err := Write(path, []Change{link("a0", "a1x"), link("b0", "b1"), link("c0", "c1x"), link("p0", "p1x"), link("q0", "q1x")}); err != nil {
		t.Fatal(err)
	}
	// Run 2: b is current; the rest are planned again, fresh wraps.
	if err := Write(path, []Change{link("a0", "a1"), link("c0", "c1"), link("p0", "p1"), link("q0", "q1")}); err != nil {
		t.Fatal(err)
	}
	if err := Prune(path, [][]byte{[]byte("a1"), []byte("b1"), []byte("c1"), []byte("p1"), []byte("q1")}); err != nil {
		t.Fatal(err)
	}
	// Between the rotations: c's value is set again (a new data key, cN),
	// and p's envelope is replaced by a copy of q's.
	// Rotation 2, one run: p's file (q's bytes) is rewrapped too, into q2p.
	if err := Write(path, []Change{link("a1", "a2"), link("b1", "b2"), link("cN", "cN2"), link("q1", "q2p"), link("q1", "q2")}); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, pinned, now string
		want              bool
	}{
		{"a, rewrapped twice", "a0", "a2", true},
		{"b, written before the stop", "b0", "b2", true},
		{"q, never changed", "q0", "q2", true},
		{"c, a value set between the rotations", "c0", "cN2", false},
		{"p, holding q's envelope now", "p0", "q2p", false},
	}
	check := func(when string) {
		m, err := Read(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, tc := range cases {
			if got := m.Reaches(d(tc.pinned), d(tc.now)); got != tc.want {
				t.Errorf("%s, %s: Reaches = %v, want %v", when, tc.name, got, tc.want)
			}
		}
	}
	check("before the prune")
	if err := Prune(path, [][]byte{[]byte("a2"), []byte("b2"), []byte("cN2"), []byte("q2p"), []byte("q2")}); err != nil {
		t.Fatal(err)
	}
	check("pruned")
}

// Prune drops only dead ends: a link to a hash no envelope has and that no
// link leads on from. A chain through a hash that is gone (an earlier
// rotation's) stays whole.
func TestPruneDropsOnlyDeadEnds(t *testing.T) {
	path := Path(t.TempDir())
	all := []Change{
		link("a0", "a1"),   // rotation 1; a1 is gone, but a1 -> a2 leads on
		link("a1", "a2x"),  // rotation 2, run 1, never written
		link("a1", "a2"),   // rotation 2, run 2, on disk
		link("b0", "b1x"),  // never written ...
		link("b1x", "b2x"), // ... nor this, from it: both go
		link("c0", "c1"),   // on disk
	}
	if err := Write(path, all); err != nil {
		t.Fatal(err)
	}
	if err := Prune(path, [][]byte{[]byte("a2"), []byte("c1"), []byte("unrelated")}); err != nil {
		t.Fatal(err)
	}
	want := []Change{link("a0", "a1"), link("a1", "a2"), link("c0", "c1")}
	if got := readChanges(t, path); !slices.Equal(got, want) {
		t.Fatalf("pruned map %+v, want %+v", got, want)
	}
	m, _ := Read(path)
	if !m.Reaches(d("a0"), d("a2")) {
		t.Error("pruning broke the chain a0 -> a1 -> a2")
	}
}

func TestPruneWithNothingToDropWritesNothing(t *testing.T) {
	path := Path(t.TempDir())
	if err := Prune(path, nil); err != nil {
		t.Fatalf("Prune of no map: %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Prune of no map made one (stat: %v)", err)
	}
	if err := Write(path, []Change{link("a0", "a1")}); err != nil {
		t.Fatal(err)
	}
	orig := writeFile
	writeFile = func(string, []byte) error { t.Error("Prune rewrote a map it dropped nothing from"); return nil }
	t.Cleanup(func() { writeFile = orig })
	if err := Prune(path, [][]byte{[]byte("a1")}); err != nil {
		t.Fatal(err)
	}
}
