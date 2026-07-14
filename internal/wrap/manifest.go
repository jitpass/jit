// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package wrap

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Manifest is wrap's bookkeeping (~/.jit/wrap.json): which tools wrap
// manages and which profile serves each. Deliberately separate from
// migrate's undo index — a wrap add mutates no pre-existing file in M1, so
// there is nothing for migrate's backup machinery to track yet (plan open
// question #2; the M2 catalog flow revisits this when scrubbing starts).
// It holds names and paths only, never secret values.
type Manifest struct {
	Tools map[string]Entry `json:"tools"`
}

// Entry describes one wrapped tool.
type Entry struct {
	Profile string    `json:"profile"`
	Vars    []string  `json:"vars"` // env var names the profile injects, for `jit wrap list`
	AddedAt time.Time `json:"added_at"`
}

// ManifestPath returns the manifest's location under home.
func ManifestPath(home string) string {
	return filepath.Join(home, ".jit", "wrap.json")
}

// LoadManifest reads home's wrap manifest; a missing file is an empty,
// usable manifest, not an error.
func LoadManifest(home string) (Manifest, error) {
	m := Manifest{Tools: map[string]Entry{}}
	data, err := os.ReadFile(ManifestPath(home)) // #nosec G304 -- fixed name under the user's own home dir
	if err != nil {
		if os.IsNotExist(err) {
			return m, nil
		}
		return m, fmt.Errorf("reading %s: %w", ManifestPath(home), err)
	}
	if err := json.Unmarshal(data, &m); err != nil {
		return m, fmt.Errorf("parsing %s: %w", ManifestPath(home), err)
	}
	if m.Tools == nil {
		m.Tools = map[string]Entry{}
	}
	return m, nil
}

// Save writes the manifest back, creating ~/.jit if needed. 0600 like the
// vault's own metadata: the manifest holds no secrets, but nothing about it
// is anyone else's business either.
func (m Manifest) Save(home string) error {
	path := ManifestPath(home)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("creating %s: %w", filepath.Dir(path), err)
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}
