// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: Apache-2.0

package mount

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Entry is one active mount jit migrate has created and jit agent should
// serve: the FIFO's path and the absolute path to the profile manifest
// whose secrets it should serve there.
//
// TemplatePath is empty for a plain dotenv-style mount (the FIFO's whole
// content is generated from the profile's resolved values via
// FormatDotenv — .env/shell-config's own convention). It's set for a
// template-based mount (npmrc's Tier 4 case, GAPS.md #8): a file with
// mixed secret and non-secret content, where only the profile's secret
// values are substituted into a template read from this path (see
// FormatTemplate) and everything else in the original file passes through
// untouched.
type Entry struct {
	MountPath    string `yaml:"mount_path"`
	ProfilePath  string `yaml:"profile_path"`
	TemplatePath string `yaml:"template_path,omitempty"`
}

type registryFile struct {
	Mounts []Entry `yaml:"mounts"`
}

// RegistryPath returns the registry file's location under root (jit's
// config directory, e.g. ~/Library/Application Support/jitpass) — bookkeeping
// metadata, not secret material, so it lives alongside (not inside) the
// vault tree.
func RegistryPath(root string) string {
	return filepath.Join(root, "mounts.yaml")
}

// AddMount records entry in the registry at registryPath, replacing any
// existing entry for the same MountPath (re-running jit migrate on an
// already-mounted file updates its record rather than duplicating it).
func AddMount(registryPath string, entry Entry) error {
	reg, err := loadRegistry(registryPath)
	if err != nil {
		return err
	}
	filtered := reg.Mounts[:0]
	for _, m := range reg.Mounts {
		if m.MountPath != entry.MountPath {
			filtered = append(filtered, m)
		}
	}
	reg.Mounts = append(filtered, entry)
	return saveRegistry(registryPath, reg)
}

// LoadRegistry returns every mount recorded at registryPath. A missing
// registry (no mounts created yet) returns an empty slice, not an error.
func LoadRegistry(registryPath string) ([]Entry, error) {
	reg, err := loadRegistry(registryPath)
	if err != nil {
		return nil, err
	}
	return reg.Mounts, nil
}

// FindMount looks up the entry for mountPath, if any.
func FindMount(registryPath, mountPath string) (Entry, bool, error) {
	reg, err := loadRegistry(registryPath)
	if err != nil {
		return Entry{}, false, err
	}
	for _, m := range reg.Mounts {
		if m.MountPath == mountPath {
			return m, true, nil
		}
	}
	return Entry{}, false, nil
}

// RemoveMount deletes the entry for mountPath from the registry at
// registryPath — the counterpart to AddMount, used by jit unmount to
// stop tracking a mount it's just reversed. Returns false (not an error)
// if no entry for mountPath existed.
func RemoveMount(registryPath, mountPath string) (bool, error) {
	reg, err := loadRegistry(registryPath)
	if err != nil {
		return false, err
	}
	filtered := reg.Mounts[:0]
	found := false
	for _, m := range reg.Mounts {
		if m.MountPath == mountPath {
			found = true
			continue
		}
		filtered = append(filtered, m)
	}
	if !found {
		return false, nil
	}
	reg.Mounts = filtered
	return true, saveRegistry(registryPath, reg)
}

func loadRegistry(path string) (registryFile, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- fixed, well-known path under jit's own config directory
	if err != nil {
		if os.IsNotExist(err) {
			return registryFile{}, nil
		}
		return registryFile{}, fmt.Errorf("reading %s: %w", path, err)
	}
	var reg registryFile
	if err := yaml.Unmarshal(data, &reg); err != nil {
		return registryFile{}, fmt.Errorf("parsing %s: %w", path, err)
	}
	return reg, nil
}

func saveRegistry(path string, reg registryFile) error {
	data, err := yaml.Marshal(reg)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}
