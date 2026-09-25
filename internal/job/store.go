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

	"github.com/jitpass/jit/internal/vault"
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

// Load reads the job list. A missing file is an empty list. A file that does
// not parse, or is newer than this build, is an error; the caller then runs
// with no jobs and must not Save over that path.
func Load(path string) (map[string]*Job, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- a fixed path under jit's own config directory
	if errors.Is(err, os.ErrNotExist) {
		return map[string]*Job{}, nil
	}
	if err != nil {
		return nil, err
	}
	var f storeFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	if f.Version > storeVersion {
		return nil, fmt.Errorf("%s: %w (version %d, this build reads %d)", path, ErrNewerStore, f.Version, storeVersion)
	}
	out := make(map[string]*Job, len(f.Jobs))
	for i := range f.Jobs {
		j := f.Jobs[i]
		// A record missing what a run needs is skipped, not half-served.
		if ValidateName(j.Name) != nil || j.Dir == "" || j.Exe == "" || len(j.Argv) == 0 || !j.Ask.Valid() {
			continue
		}
		out[j.Name] = &j
	}
	return out, nil
}

// Save writes the whole list atomically, mode 0600, sorted by name so the
// file diffs cleanly.
func Save(path string, jobs map[string]*Job) error {
	f := storeFile{Version: storeVersion, Jobs: make([]Job, 0, len(jobs))}
	for _, j := range jobs {
		f.Jobs = append(f.Jobs, *j)
	}
	sort.Slice(f.Jobs, func(a, b int) bool { return f.Jobs[a].Name < f.Jobs[b].Name })
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return vault.AtomicWriteFile(path, append(data, '\n'))
}
