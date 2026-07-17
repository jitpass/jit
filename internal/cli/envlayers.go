// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/fatih/color"

	"github.com/jitpass/jit/internal/mount"
	"github.com/jitpass/jit/internal/profile"
)

// This file implements dotenv layer resolution for `jit run`/`jit export`:
// when --profile is omitted, the effective profile is the precedence-ordered
// overlay of the current project's mounted .env-family layers, found via the
// mount registry (which by construction holds exactly the mergeable layers —
// templates are never mounted, backup-suffixed files become pointer files,
// and npmrc mounts are excluded here by their non-empty TemplatePath).
//
// Precedence follows the Next.js/CRA convention, ascending:
//
//	.env  <  .env.<mode>  <  .env.local  <  .env.<mode>.local
//
// (.env.local beats .env.<mode>; only .env.<mode>.local beats .env.local.
// dotenv-flow orders these two the other way — we deliberately follow the
// more widely deployed convention and document the choice.) Without --mode
// the chain is just .env < .env.local: a mode-suffixed layer that exists but
// wasn't asked for is never merged, so production secrets can't ride into a
// dev run by default.

// envLayer is one mounted .env-family file participating in the merge.
type envLayer struct {
	rank        int    // ascending precedence (see envLayerRank)
	fileName    string // e.g. ".env.local", for announce lines
	profilePath string // the layer's manifest, from the registry entry
	profileName string // manifest basename minus extension, for announce lines
}

// envLayerRank maps an .env-family filename to its merge precedence under
// mode. ok is false for any file that does not participate: an unrelated
// variant (.env.development when mode is "" or "production"), or anything
// that isn't part of the four-layer chain.
func envLayerRank(fileName, mode string) (rank int, ok bool) {
	switch fileName {
	case ".env":
		return 0, true
	case ".env.local":
		return 2, true
	}
	if mode == "" {
		return 0, false
	}
	switch fileName {
	case ".env." + mode:
		return 1, true
	case ".env." + mode + ".local":
		return 3, true
	}
	return 0, false
}

// validateEnvMode rejects --mode values that can't name a real mode layer.
// "local" is reserved by the chain itself (.env.local is rank 2, not a
// mode), and a path separator can't appear in a filename suffix.
func validateEnvMode(mode string) error {
	if mode == "" {
		return nil
	}
	if mode == "local" {
		return fmt.Errorf("--mode local is not a mode, .env.local is always merged (it's the override layer)")
	}
	if strings.ContainsAny(mode, "/\\") || strings.Contains(mode, "..") {
		return fmt.Errorf("--mode %q must be a plain suffix like production or development", mode)
	}
	return nil
}

// dirEnvLayers returns dir's mergeable layers from the registry entries, in
// ascending precedence order. Template-based mounts (npmrc — non-empty
// TemplatePath) never participate: their variables belong in an .npmrc, not
// in a process environment.
func dirEnvLayers(entries []mount.Entry, dir, mode string) []envLayer {
	var layers []envLayer
	for _, e := range entries {
		if e.TemplatePath != "" {
			continue
		}
		if filepath.Dir(e.MountPath) != dir {
			continue
		}
		name := filepath.Base(e.MountPath)
		rank, ok := envLayerRank(name, mode)
		if !ok {
			continue
		}
		layers = append(layers, envLayer{
			rank:        rank,
			fileName:    name,
			profilePath: e.ProfilePath,
			profileName: strings.TrimSuffix(filepath.Base(e.ProfilePath), filepath.Ext(e.ProfilePath)),
		})
	}
	sort.Slice(layers, func(i, j int) bool { return layers[i].rank < layers[j].rank })
	return layers
}

// findEnvLayers walks from startDir up toward home (git/direnv style),
// returning the first directory with at least one mergeable layer. The walk
// checks home itself last, then stops — it never scans above $HOME (or above
// the filesystem root for a cwd outside $HOME).
func findEnvLayers(entries []mount.Entry, startDir, home, mode string) (dir string, layers []envLayer) {
	for d := startDir; ; {
		if l := dirEnvLayers(entries, d, mode); len(l) > 0 {
			return d, l
		}
		if d == home {
			return "", nil
		}
		parent := filepath.Dir(d)
		if parent == d {
			return "", nil
		}
		d = parent
	}
}

// unmigratedSiblingLayers reports chain member files that exist on disk in
// dir as regular files (i.e. still plaintext, not migrated FIFOs) but are
// not among the merged layers. They can't participate in the merge, and —
// worse — an override=false dotenv loader will IGNORE them at runtime for
// any variable jit already injected, so their absence deserves a heads-up
// rather than silence.
func unmigratedSiblingLayers(dir, mode string, merged []envLayer) []string {
	candidates := []string{".env", ".env.local"}
	if mode != "" {
		candidates = append(candidates, ".env."+mode, ".env."+mode+".local")
	}
	inMerge := make(map[string]bool, len(merged))
	for _, l := range merged {
		inMerge[l.fileName] = true
	}
	var missing []string
	for _, name := range candidates {
		if inMerge[name] {
			continue
		}
		info, err := os.Lstat(filepath.Join(dir, name))
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		missing = append(missing, name)
	}
	return missing
}

// resolveInjectionProfile decides what profile `jit run`/`jit export`
// inject when the user may not have named one, announcing any choice it
// makes on w (stderr — stdout belongs to the target command / the export
// lines). cmdName is "jit run" or "jit export", for error/announce voice.
//
// Resolution order:
//  1. explicit --profile: used verbatim (project-then-global via
//     profile.Load), no merge, silent. --mode is an error here — it only
//     means something for the layer merge.
//  2. the mount registry's .env layers for the nearest directory at or
//     above cwd (findEnvLayers): overlaid in precedence order.
//  3. no layers anywhere: fall back to the single project-local profile if
//     exactly one exists; zero or several stay a hard error that says how
//     to disambiguate. --mode without any layers is also a hard error.
func resolveInjectionProfile(cmdName, cwd, explicit, mode string, w io.Writer) (profile.Profile, error) {
	if explicit != "" {
		if mode != "" {
			return nil, fmt.Errorf("--mode only applies when jit merges a project's .env layers, with --profile %s, name the mode's profile directly instead", explicit)
		}
		return profile.Load(cwd, explicit)
	}
	if err := validateEnvMode(mode); err != nil {
		return nil, err
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	root, err := vaultRootDir()
	if err != nil {
		return nil, err
	}
	entries, err := mount.LoadRegistry(mount.RegistryPath(root))
	if err != nil {
		return nil, fmt.Errorf("reading mount registry: %w", err)
	}

	dir, layers := findEnvLayers(entries, cwd, home, mode)
	if len(layers) == 0 {
		if mode != "" {
			return nil, fmt.Errorf("--mode %s: no migrated .env layers found at or above this directory, mode selects among a project's migrated .env files", mode)
		}
		return resolveSingleProjectProfile(cmdName, cwd, w)
	}

	if mode != "" {
		hasModeLayer := false
		for _, l := range layers {
			if l.rank == 1 || l.rank == 3 {
				hasModeLayer = true
				break
			}
		}
		if !hasModeLayer {
			return nil, fmt.Errorf("--mode %s: no migrated .env.%s (or .env.%s.local) in %s", mode, mode, mode, displayPath(home, dir))
		}
	}

	merged := make([]profile.Profile, 0, len(layers))
	fileNames := make([]string, 0, len(layers))
	profileNames := make([]string, 0, len(layers))
	for _, l := range layers {
		p, err := profile.LoadFile(l.profilePath)
		if err != nil {
			return nil, fmt.Errorf("layer %s: %w", l.fileName, err)
		}
		merged = append(merged, p)
		fileNames = append(fileNames, l.fileName)
		profileNames = append(profileNames, l.profileName)
	}

	// Injecting real plaintext secrets should never be silent — say
	// exactly which layers (and whose directory) fed the environment.
	where := ""
	if dir != cwd {
		where = fmt.Sprintf(", in %s", displayPath(home, dir))
	}
	if len(layers) == 1 {
		fmt.Fprintf(w, "%s: using profile %q (%s)%s\n", cmdName, profileNames[0], fileNames[0], where)
	} else {
		fmt.Fprintf(w, "%s: merging %s (last wins), profiles %s%s\n",
			cmdName, strings.Join(fileNames, ", "), strings.Join(profileNames, ", "), where)
	}
	if missing := unmigratedSiblingLayers(dir, mode, layers); len(missing) > 0 {
		_, _ = color.New(color.FgYellow).Fprintf(w, "%s: note: %s in %s not migrated, not merged, and injected variables shadow it for most dotenv loaders (fix: jit migrate local)\n",
			cmdName, strings.Join(missing, ", "), displayPath(home, dir))
	}
	return profile.Overlay(merged...), nil
}

// resolveSingleProjectProfile is the pre-layer fallback: use the project's
// single profile when exactly one is defined in cwd's own .jit/profiles/;
// zero or several are genuine ambiguity jit refuses to guess through. Only
// project-local names are considered (profile.ListNames, not ListAll): a
// home-rooted global profile isn't tied to the directory you're standing
// in, so "the profile for here" must never silently resolve to one — that
// would inject a different project's (or a shell/MCP/AWS) secret-set just
// because it happens to be the only global one. Naming it explicitly with
// --profile still works, since profile.Load falls back to the global store.
func resolveSingleProjectProfile(cmdName, cwd string, w io.Writer) (profile.Profile, error) {
	names, err := profile.ListNames(cwd)
	if err != nil {
		return nil, err
	}
	switch len(names) {
	case 0:
		return nil, fmt.Errorf("no profile given and none defined in %s/, migrate this project with `jit migrate local`, or name one with --profile (see: jit profile list)", profile.ProfilesDir)
	case 1:
		fmt.Fprintf(w, "%s: using profile %q\n", cmdName, names[0])
		return profile.Load(cwd, names[0])
	default:
		return nil, fmt.Errorf("no profile given and this project defines several (%s), pick one with --profile", strings.Join(names, ", "))
	}
}
