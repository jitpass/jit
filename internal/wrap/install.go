// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package wrap

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
)

// ShimDir returns the directory wrap installs its shims into. Fixed under
// home (like the global profile store) because a shim must resolve no
// matter what directory the wrapped tool is invoked from.
func ShimDir(home string) string {
	return filepath.Join(home, ".jit", "shims")
}

// ProfileName returns the profile a wrapped tool's shim injects —
// the wrap-<tool> naming both jit wrap and the shim exec path agree on.
func ProfileName(tool string) string {
	return "wrap-" + tool
}

// toolNamePattern mirrors internal/profile's namePattern: a tool name
// becomes both a filename in the shim dir and part of a profile name, so
// the same allowlist discipline applies.
var toolNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.\-]+$`)

// ValidateToolName rejects names that can't safely become a shim filename,
// and "jit" itself — a shim named jit would shadow the real binary with a
// symlink whose whole behavior depends on not being named jit.
func ValidateToolName(tool string) error {
	if !toolNamePattern.MatchString(tool) {
		return fmt.Errorf("tool name %q must contain only letters, digits, '.', '_', '-'", tool)
	}
	if tool == "jit" {
		return fmt.Errorf("refusing to wrap %q, a shim named jit would shadow jit itself", tool)
	}
	return nil
}

// InstallShim creates (or refreshes) the shim symlink for tool, pointing at
// jitBinary, and returns the symlink's path. The shim dir is created 0700
// (docs/internal/WRAP-PLAN.md §3.5). An existing entry is replaced only if it is
// itself a symlink — a regular file squatting on the name is somebody
// else's and an error, never silently deleted.
func InstallShim(home, jitBinary, tool string) (string, error) {
	if err := ValidateToolName(tool); err != nil {
		return "", err
	}
	if !filepath.IsAbs(jitBinary) {
		return "", fmt.Errorf("shim target %q must be an absolute path", jitBinary)
	}
	dir := ShimDir(home)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("creating shim directory: %w", err)
	}
	link := filepath.Join(dir, tool)
	if info, err := os.Lstat(link); err == nil {
		if info.Mode()&os.ModeSymlink == 0 {
			return "", fmt.Errorf("%s exists and is not a symlink, refusing to replace it", link)
		}
		if err := os.Remove(link); err != nil {
			return "", fmt.Errorf("replacing existing shim: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return "", err
	}
	if err := os.Symlink(jitBinary, link); err != nil {
		return "", fmt.Errorf("creating shim symlink: %w", err)
	}
	return link, nil
}

// RemoveShim deletes tool's shim symlink. Reports false without error when
// no shim exists (undo of a half-installed wrap must still succeed), and
// refuses to delete a non-symlink for the same reason InstallShim won't
// replace one.
func RemoveShim(home, tool string) (bool, error) {
	if err := ValidateToolName(tool); err != nil {
		return false, err
	}
	link := filepath.Join(ShimDir(home), tool)
	info, err := os.Lstat(link)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return false, fmt.Errorf("%s is not a symlink, refusing to delete it", link)
	}
	if err := os.Remove(link); err != nil {
		return false, err
	}
	return true, nil
}

// InstalledShims lists the symlink names present in home's shim dir,
// sorted. A missing dir is an empty list, not an error — a machine with no
// wraps yet is a valid state (same contract as profile.ListNames).
func InstalledShims(home string) ([]string, error) {
	entries, err := os.ReadDir(ShimDir(home))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.Type()&os.ModeSymlink != 0 {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}
