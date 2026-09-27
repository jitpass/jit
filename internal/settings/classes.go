// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package settings

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/jitpass/jit/internal/atomicfile"
)

// ClassesFile is the class index's name under the vault root.
const ClassesFile = "classes.json"

// Classes records, per vault path, what audit.ClassifyEnvVar said of the
// value when it went into the vault: "secret" or "check". It lets the app
// warn before Touch ID that moving a value out would leave a counted secret
// in plain text, which it could not know without decrypting
// (design/secrets-only-vault.md). Names and classes only, never a value;
// kept outside the vault's envelopes so the envelope format is unchanged.
// A path with no entry was vaulted before the index existed: unknown.
type Classes struct {
	file   string
	m      map[string]string
	origin map[string]Provenance
}

// Provenance is a plain setting's birth record, which a vault envelope keeps
// in its header and a plain file cannot: the file it came from and its
// import group. It lets `jit migrate remove` find the settings a file's
// protection made, and `jit vault move-in` give the value back its origin.
type Provenance struct {
	Origin  string `json:"origin,omitempty"`
	GroupID string `json:"group_id,omitempty"`
}

type classesDoc struct {
	Version  int                   `json:"version"`
	Classes  map[string]string     `json:"classes"`
	Settings map[string]Provenance `json:"settings,omitempty"`
}

// LoadClasses reads the index under vaultRoot. A missing file is an empty
// index; an unreadable one is an error, since a caller writing it back would
// otherwise drop every entry.
func LoadClasses(vaultRoot string) (*Classes, error) {
	c := &Classes{file: filepath.Join(vaultRoot, ClassesFile), m: map[string]string{}, origin: map[string]Provenance{}}
	data, err := os.ReadFile(c.file) // #nosec G304 -- jit's own file under its own root
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", ClassesFile, err)
	}
	var doc classesDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", ClassesFile, err)
	}
	for k, v := range doc.Classes {
		c.m[k] = v
	}
	for k, v := range doc.Settings {
		c.origin[k] = v
	}
	return c, nil
}

// Get returns a path's class, "" when unknown.
func (c *Classes) Get(path string) string { return c.m[path] }

// Set records a path's class; "" forgets it.
func (c *Classes) Set(path, class string) {
	if class == "" {
		delete(c.m, path)
		return
	}
	c.m[path] = class
}

// SettingProvenance returns a setting's birth record, zero when none.
func (c *Classes) SettingProvenance(path string) Provenance { return c.origin[path] }

// SetSettingProvenance records a setting's birth record; zero forgets it.
func (c *Classes) SetSettingProvenance(path string, p Provenance) {
	if p == (Provenance{}) {
		delete(c.origin, path)
		return
	}
	c.origin[path] = p
}

// SettingsFrom returns the settings whose recorded origin is origin, as
// written (a "~/" path stays one; the caller compares like for like).
func (c *Classes) SettingsFrom(match func(origin string) bool) []string {
	var out []string
	for p, prov := range c.origin {
		if prov.Origin != "" && match(prov.Origin) {
			out = append(out, p)
		}
	}
	return out
}

// Save writes the index, 0600.
func (c *Classes) Save() error {
	doc := classesDoc{Version: 1, Classes: c.m, Settings: c.origin}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.WriteFile(c.file, append(data, '\n'))
}
