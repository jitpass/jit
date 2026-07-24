// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// projectConfig is the optional per-project .jit/config.yaml. Today it holds
// exactly one setting, read_as_file, which pins `jit run` to live mode for
// this project (keep the FIFO and grant the run real file reads, instead of
// the default compatibility swap). It exists for projects whose tools read
// values FROM the .env file rather than the environment — docker compose
// env_file being the canonical case — so the user declares that intent once
// instead of typing --live on every run. It is deliberately explicit intent,
// not a heuristic: guessing live wrong reintroduces the regular-file-guard
// trap the swap exists to fix, so live is only ever chosen when the user
// (or a recognized file-value command) actually asks for it.
type projectConfig struct {
	ReadAsFile bool `yaml:"read_as_file"`
}

// readAsFilePinned reports whether the nearest project at or above cwd
// declares read_as_file: true in its .jit/config.yaml. Walks up like git /
// the profile resolver, stopping at $HOME or the filesystem root. Any read
// or parse failure is treated as "not pinned" — this is an ergonomic
// convenience, never a correctness gate, so it fails toward the safe
// default (swap).
func readAsFilePinned(cwd string) bool {
	home, _ := os.UserHomeDir()
	for d := cwd; ; {
		data, err := os.ReadFile(filepath.Join(d, ".jit", "config.yaml")) // #nosec G304 -- a project-local jit config path, not external input
		if err == nil {
			var c projectConfig
			if yaml.Unmarshal(data, &c) == nil {
				return c.ReadAsFile
			}
			return false // a config that won't parse pins nothing
		}
		if d == home {
			return false
		}
		parent := filepath.Dir(d)
		if parent == d {
			return false
		}
		d = parent
	}
}
