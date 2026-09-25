// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package job

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/jitpass/jit/internal/atomicfile"
)

// storeVersion is bumped when a job's shape changes incompatibly. A newer
// file is refused, and never written back over, so a downgrade cannot
// silently drop a job it does not understand (grants.json's rule).
const storeVersion = 1

// StorePath is where the job list lives: jit's own directory, beside
// grants.json. docs/service/sandboxed-callers.md already says never to give a
// sandbox write access there; the list lives there for that reason.
func StorePath(root string) string {
	return filepath.Join(root, "jobs.json")
}

type storeFile struct {
	Version int   `json:"version"`
	Jobs    []Job `json:"jobs"`
}

// ErrNewerStore marks a file written by a newer jit. The caller must not save
// over it.
var ErrNewerStore = errors.New("written by a newer jit")

// rawStoreFile is storeFile with every record left as it was written.
type rawStoreFile struct {
	Version int               `json:"version"`
	Jobs    []json.RawMessage `json:"jobs"`
}

// Kept is a record Load could not accept (a name this build rejects, an ask
// value from a newer jit, a field a run needs missing), kept as the file
// held it. It is never run, listed or shown: it is not a Job. Encode writes
// it back unchanged, so the record, and the key id it names, outlive every
// save (the start-up key cleanup keeps any key the file names).
type Kept struct {
	// Name is the record's name as written, possibly invalid or empty. A
	// loaded job of the same name wins: Encode never writes both.
	Name string
	Raw  json.RawMessage
}

// Load reads the job list. A missing file is an empty list. A file that does
// not parse, or is newer than this build, is an error; the caller then runs
// with no jobs and must not Save over that path. Records it skips are
// dropped; a caller that saves the list back uses LoadKeeping.
func Load(path string) (map[string]*Job, error) {
	jobs, _, err := LoadKeeping(path)
	return jobs, err
}

// LoadKeeping is Load, plus the records it skipped, verbatim, for Encode to
// write back. A skipped record named like a loaded one is not kept: the
// loaded one wins, and writing both would put two jobs of one name in the
// file.
func LoadKeeping(path string) (map[string]*Job, []Kept, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- a fixed path under jit's own config directory
	if errors.Is(err, os.ErrNotExist) {
		return map[string]*Job{}, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	var f storeFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	if f.Version > storeVersion {
		return nil, nil, fmt.Errorf("%s: %w (version %d, this build reads %d)", path, ErrNewerStore, f.Version, storeVersion)
	}
	var raw rawStoreFile
	if err := json.Unmarshal(data, &raw); err != nil || len(raw.Jobs) != len(f.Jobs) {
		return nil, nil, fmt.Errorf("parsing %s: its records do not read the same twice", path)
	}
	out := make(map[string]*Job, len(f.Jobs))
	var skipped []Kept
	for i := range f.Jobs {
		j := f.Jobs[i]
		// A record missing what a run needs is skipped, not half-served.
		if ValidateName(j.Name) != nil || j.Dir == "" || j.Exe == "" || len(j.Argv) == 0 || !j.Ask.Valid() {
			skipped = append(skipped, Kept{Name: j.Name, Raw: raw.Jobs[i]})
			continue
		}
		out[j.Name] = &j
	}
	var kept []Kept
	for _, k := range skipped {
		if _, loaded := out[k.Name]; !loaded {
			kept = append(kept, k)
		}
	}
	return out, kept, nil
}

// Save writes the whole list atomically and durably (atomicfile.WriteFile:
// fsynced, renamed into place, mode 0600), sorted by name so the file diffs
// cleanly.
func Save(path string, jobs map[string]*Job) error {
	data, err := Encode(jobs, nil)
	if err != nil {
		return err
	}
	return atomicfile.WriteFile(path, data)
}

// Encode is the file Save writes, for a caller that writes it itself: jobs,
// then every kept record whose name no job in jobs has (the loaded one
// wins), unchanged but for indentation, all sorted by name.
func Encode(jobs map[string]*Job, kept []Kept) ([]byte, error) {
	type rec struct {
		name string
		raw  json.RawMessage
	}
	recs := make([]rec, 0, len(jobs)+len(kept))
	for _, j := range jobs {
		b, err := json.Marshal(j)
		if err != nil {
			return nil, err
		}
		recs = append(recs, rec{j.Name, b})
	}
	for _, k := range kept {
		if _, loaded := jobs[k.Name]; loaded {
			continue
		}
		recs = append(recs, rec{k.Name, k.Raw})
	}
	sort.SliceStable(recs, func(a, b int) bool { return recs[a].name < recs[b].name })
	f := rawStoreFile{Version: storeVersion, Jobs: make([]json.RawMessage, len(recs))}
	for i, r := range recs {
		f.Jobs[i] = r.raw
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}
