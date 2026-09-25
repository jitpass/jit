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

	"github.com/jitpass/jit/internal/jsonkeep"
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

// ErrNewerStore marks a file written by a newer jit. The caller must not save
// over it.
var ErrNewerStore = errors.New("written by a newer jit")

// rawStoreFile is jobs.json with every record left as it was written.
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
// with no jobs and must not write over that path. Records it skips are
// dropped; a caller that saves the list back uses Decode, and Encode.
func Load(path string) (map[string]*Job, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- a fixed path under jit's own config directory
	if errors.Is(err, os.ErrNotExist) {
		return map[string]*Job{}, nil
	}
	if err != nil {
		return nil, err
	}
	jobs, _, err := Decode(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return jobs, nil
}

// Decode reads a job list from the bytes of jobs.json, once: the jobs it
// accepts, and the records it skipped, verbatim, for Encode to write back.
// A file newer than this build is ErrNewerStore. A skipped record named
// like a loaded one is not kept (Unshadowed).
func Decode(data []byte) (map[string]*Job, []Kept, error) {
	var raw rawStoreFile
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, nil, fmt.Errorf("parsing: %w", err)
	}
	if raw.Version > storeVersion {
		return nil, nil, fmt.Errorf("%w (version %d, this build reads %d)", ErrNewerStore, raw.Version, storeVersion)
	}
	out := make(map[string]*Job, len(raw.Jobs))
	var skipped []Kept
	for _, r := range raw.Jobs {
		var j Job
		err := json.Unmarshal(r, &j)
		// A record missing what a run needs is skipped, not half-served; so
		// is one whose fields do not read as this build's (a type a newer
		// jit changed).
		if err != nil || ValidateName(j.Name) != nil || j.Dir == "" || j.Exe == "" || len(j.Argv) == 0 || !j.Ask.Valid() {
			skipped = append(skipped, Kept{Name: j.Name, Raw: r})
			continue
		}
		out[j.Name] = &j
	}
	return out, Unshadowed(skipped, out), nil
}

// Unshadowed is kept without every record a job in jobs has the name of:
// the loaded one wins, and the file never holds two jobs of one name. The
// one place that rule is applied, at load and at every save.
func Unshadowed(kept []Kept, jobs map[string]*Job) []Kept {
	var out []Kept
	for _, k := range kept {
		if _, loaded := jobs[k.Name]; !loaded {
			out = append(out, k)
		}
	}
	return out
}

// Encode is the file jobs.json holds: jobs, then every kept record whose
// name no job in jobs has (Unshadowed), unchanged but for indentation, all
// sorted by name. A job read from the file keeps the fields this build does
// not know, and so does each of its secrets (MarshalJSON). The caller
// writes it, durably (atomicfile.WriteFile).
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
	for _, k := range Unshadowed(kept, jobs) {
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

// MarshalJSON writes the job with every field of the record it was read
// from that this build does not know (jsonkeep), so a save by this jit
// never deletes what a newer one wrote.
func (j Job) MarshalJSON() ([]byte, error) {
	type plain Job
	return jsonkeep.Marshal(plain(j), j.raw)
}

// UnmarshalJSON reads the job and keeps the record it came from, for
// MarshalJSON.
func (j *Job) UnmarshalJSON(b []byte) error {
	type plain Job
	var p plain
	// A field of the wrong type still leaves the rest read (encoding/json
	// completes what it can), so a record Decode skips keeps its name.
	err := json.Unmarshal(b, &p)
	*j = Job(p)
	j.raw = append([]byte(nil), b...)
	return err
}

// MarshalJSON is Job's, for one secret.
func (s Secret) MarshalJSON() ([]byte, error) {
	type plain Secret
	return jsonkeep.Marshal(plain(s), s.raw)
}

// UnmarshalJSON is Job's, for one secret.
func (s *Secret) UnmarshalJSON(b []byte) error {
	type plain Secret
	var p plain
	// A field of the wrong type still leaves the rest read (encoding/json
	// completes what it can), so a record Decode skips keeps its name.
	err := json.Unmarshal(b, &p)
	*s = Secret(p)
	s.raw = append([]byte(nil), b...)
	return err
}
