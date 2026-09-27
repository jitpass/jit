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
	file string
	m    map[string]string
}

type classesDoc struct {
	Version int               `json:"version"`
	Classes map[string]string `json:"classes"`
}

// LoadClasses reads the index under vaultRoot. A missing file is an empty
// index; an unreadable one is an error, since a caller writing it back would
// otherwise drop every entry.
func LoadClasses(vaultRoot string) (*Classes, error) {
	c := &Classes{file: filepath.Join(vaultRoot, ClassesFile), m: map[string]string{}}
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

// Save writes the index, 0600.
func (c *Classes) Save() error {
	doc := classesDoc{Version: 1, Classes: c.m}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.WriteFile(c.file, append(data, '\n'))
}
