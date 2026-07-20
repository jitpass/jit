// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package wrap

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"

	"github.com/jitpass/jit/internal/profile"
)

// AddRequest describes one manual wrap (`jit wrap add`): the tool to shim
// and the env-var-to-vault-path mapping its profile should inject. Order
// preserves the user's --env flag order into the profile manifest, the same
// way migrate persists a source file's own variable order.
type AddRequest struct {
	Tool      string
	Env       map[string]string
	Order     []string
	JitBinary string // absolute path the shim symlink points at
}

// AddResult reports what Add created, for the CLI to print.
type AddResult struct {
	ProfileName string
	ProfilePath string
	ShimPath    string
}

// envNamePattern is the same shape audit/migrate accept for shell exports.
var envNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// Add performs the manual wrap flow: write the wrap-<tool> profile into the
// home-rooted global store (a shim can be invoked from any cwd — same
// reasoning as shell/MCP migrations), install the shim symlink, record the
// tool in the manifest. Re-running for an already-wrapped tool refreshes
// profile and shim in place; a wrap-<tool> profile that exists WITHOUT a
// manifest entry is somebody's hand-written profile and is never
// overwritten. Add never touches the vault: secret values are the user's to
// store (`jit vault set`), and never this package's to read.
func Add(home string, req AddRequest) (AddResult, error) {
	if err := ValidateToolName(req.Tool); err != nil {
		return AddResult{}, err
	}
	if len(req.Env) == 0 {
		return AddResult{}, fmt.Errorf("nothing to inject, pass at least one --env VAR=<vault-path>")
	}
	for name, vaultPath := range req.Env {
		if !envNamePattern.MatchString(name) {
			return AddResult{}, fmt.Errorf("%q is not a valid environment variable name", name)
		}
		if vaultPath == "" {
			return AddResult{}, fmt.Errorf("%s has no vault path", name)
		}
	}

	name := ProfileName(req.Tool)
	profilePath, err := profile.Path(home, name)
	if err != nil {
		return AddResult{}, err
	}

	manifest, err := LoadManifest(home)
	if err != nil {
		return AddResult{}, err
	}
	if _, managed := manifest.Tools[req.Tool]; !managed {
		if _, statErr := os.Stat(profilePath); statErr == nil {
			return AddResult{}, fmt.Errorf("profile %s already exists at %s but wasn't created by jit wrap, refusing to overwrite it", name, profilePath)
		}
	}

	data, err := profile.MarshalOrdered(profile.Profile(req.Env), req.Order)
	if err != nil {
		return AddResult{}, err
	}
	if err := os.MkdirAll(filepath.Dir(profilePath), 0o700); err != nil {
		return AddResult{}, fmt.Errorf("creating profile directory: %w", err)
	}
	if err := os.WriteFile(profilePath, data, 0o600); err != nil {
		return AddResult{}, fmt.Errorf("writing %s: %w", profilePath, err)
	}

	shimPath, err := InstallShim(home, req.JitBinary, req.Tool)
	if err != nil {
		return AddResult{}, err
	}

	manifest.Tools[req.Tool] = Entry{
		Profile: name,
		Vars:    orderedNames(req.Env, req.Order),
		AddedAt: time.Now().UTC(),
	}
	if err := manifest.Save(home); err != nil {
		return AddResult{}, err
	}

	return AddResult{ProfileName: name, ProfilePath: profilePath, ShimPath: shimPath}, nil
}

// AddGrant installs a GRANT-wrap: a shim that runs `jit run --with
// <mountName> -- <tool>` so a tool reading a global, file-delivered
// credential (gcloud reading the ADC file, sops reading its age key) works
// when typed by its native name, with the disclosed challenge still gating
// each grant. Unlike Add there is no profile — a grant-wrap injects no env
// var; it grants a mount. mountName is validated by `jit run --with` at use
// time (unknown/unmigrated names fail loudly there), so this only checks it
// is non-empty.
func AddGrant(home, tool, mountName, jitBinary string) (AddResult, error) {
	if err := ValidateToolName(tool); err != nil {
		return AddResult{}, err
	}
	if mountName == "" {
		return AddResult{}, fmt.Errorf("--grant needs a mount name (gcp, sops, npm, netrc)")
	}

	manifest, err := LoadManifest(home)
	if err != nil {
		return AddResult{}, err
	}
	// Refuse to clobber a hand-written env profile for this tool that jit
	// wrap doesn't manage — same guard Add applies.
	if _, managed := manifest.Tools[tool]; !managed {
		if profilePath, perr := profile.Path(home, ProfileName(tool)); perr == nil {
			if _, statErr := os.Stat(profilePath); statErr == nil {
				return AddResult{}, fmt.Errorf("profile %s already exists at %s but wasn't created by jit wrap, refusing to grant-wrap over it", ProfileName(tool), profilePath)
			}
		}
	}

	shimPath, err := InstallShim(home, jitBinary, tool)
	if err != nil {
		return AddResult{}, err
	}
	manifest.Tools[tool] = Entry{With: mountName, AddedAt: time.Now().UTC()}
	if err := manifest.Save(home); err != nil {
		return AddResult{}, err
	}
	return AddResult{ShimPath: shimPath}, nil
}

// orderedNames returns env's variable names in order (names order lists
// first, then any stragglers sorted) — mirroring profile.MarshalOrdered's
// own completion rule so the manifest lists vars the way the profile
// renders them.
func orderedNames(env map[string]string, order []string) []string {
	names := make([]string, 0, len(env))
	seen := make(map[string]bool, len(env))
	for _, n := range order {
		if _, ok := env[n]; ok && !seen[n] {
			seen[n] = true
			names = append(names, n)
		}
	}
	rest := make([]string, 0, len(env)-len(names))
	for n := range env {
		if !seen[n] {
			rest = append(rest, n)
		}
	}
	if len(rest) > 0 {
		sort.Strings(rest)
		names = append(names, rest...)
	}
	return names
}
