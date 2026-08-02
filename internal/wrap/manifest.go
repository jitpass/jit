// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

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

// Entry describes one wrapped tool. Exactly one of Profile (an env-wrap,
// the shim injects the profile's vars), With (a grant-wrap, the shim
// grants a global file-delivered mount by name — gcp/sops/npm — for tools
// that read a machine-wide credential FILE rather than an env var), or
// Capture (a capture-wrap, the shim routes through `jit <tool>-capture`
// so the tool's freshly minted credentials land in the vault instead of a
// plaintext file — see KindCapture) is set.
type Entry struct {
	Profile string `json:"profile,omitempty"`
	With    string `json:"with,omitempty"`
	Capture string `json:"capture,omitempty"`
	// RunGrant marks a run-grant-wrap: the shim re-execs through a bare
	// `jit run --grant-only` so the tool's whole process tree is
	// grant-authorized for the project's template mounts (a Kubernetes
	// Secret manifest served as a rejectable-decoy FIFO). No profile, no
	// env var, no global mount name: which mounts apply is decided per
	// invocation from the tool's working directory, exactly as if the user
	// had typed `jit run -- <tool> ...` themselves.
	RunGrant bool      `json:"run_grant,omitempty"`
	Vars     []string  `json:"vars,omitempty"` // env var names the profile injects, for `jit wrap list`
	AddedAt  time.Time `json:"added_at"`
}

// IsGrant reports whether e is a grant-wrap (runs `jit run --with`) rather
// than an env-wrap (runs `jit run --profile`).
func (e Entry) IsGrant() bool { return e.With != "" }

// IsCapture reports whether e is a capture-wrap (runs `jit <tool>-capture`).
func (e Entry) IsCapture() bool { return e.Capture != "" }

// IsRunGrant reports whether e is a run-grant-wrap (runs `jit run
// --grant-only`, no profile and no named mount).
func (e Entry) IsRunGrant() bool { return e.RunGrant }

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
