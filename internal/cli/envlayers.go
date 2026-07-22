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
	"github.com/spf13/cobra"

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

// loadMountRegistry reads the mount registry together with $HOME — the two
// facts every registry consumer on the run path needs — so the
// home+root+LoadRegistry boilerplate lives in one place instead of being
// copied per call site (resolveInjectionProfile, projectTemplateMounts,
// withMountPaths, grantMountsForProfileName). Consumers that don't need home
// discard it. (Deliberately not memoized: each caller runs at most once per
// `jit run`, on the cold pre-exec path, reading a small cached file — sharing
// one load would mean threading state through several tested signatures for a
// negligible I/O saving.)
func loadMountRegistry() (entries []mount.Entry, home string, err error) {
	home, err = os.UserHomeDir()
	if err != nil {
		return nil, "", err
	}
	root, err := vaultRootDir()
	if err != nil {
		return nil, "", err
	}
	entries, err = mount.LoadRegistry(mount.RegistryPath(root))
	if err != nil {
		return nil, "", fmt.Errorf("reading mount registry: %w", err)
	}
	return entries, home, nil
}

// completeMountPaths offers the registered live-mount paths for the
// command whose argument must name one — `jit unmount`. Like
// completeVaultPaths it returns only real, known targets
// (NoFileComp): a path that isn't a registered mount is not a valid
// argument for either command, so offering arbitrary filesystem paths
// would only mislead.
func completeMountPaths(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	entries, _, err := loadMountRegistry()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	var out []string
	for _, e := range entries {
		if strings.HasPrefix(e.MountPath, toComplete) {
			out = append(out, e.MountPath+"\tlive mount")
		}
	}
	sort.Strings(out)
	return out, cobra.ShellCompDirectiveNoFileComp
}

// envLayer is one mounted .env-family file participating in the merge.
type envLayer struct {
	rank        int    // ascending precedence (see envLayerRank)
	fileName    string // e.g. ".env.local", for announce lines
	mountPath   string // the layer's live mount on disk, from the registry entry — what a run-scoped grant names
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
			mountPath:   e.MountPath,
			profilePath: e.ProfilePath,
			profileName: strings.TrimSuffix(filepath.Base(e.ProfilePath), filepath.Ext(e.ProfilePath)),
		})
	}
	sort.Slice(layers, func(i, j int) bool { return layers[i].rank < layers[j].rank })
	return layers
}

// projectTemplateMounts returns the PROJECT-local template mounts (npmrc
// and the like — non-empty TemplatePath) at or above cwd but strictly below
// $HOME, walking git/direnv style. These are file-delivered secrets a tool
// reads from the file itself, so a run grants them (never swaps — an inert
// file would starve the tool). Machine-global mounts are deliberately
// excluded: they are granted only by an explicit `--with`, never because a
// run walked into a directory. Exclusion is by KNOWN global path
// (globalMountPaths), not by directory position — a `~/.npmrc` sits directly
// at $HOME (so the walk's `d != home` bound already skips it), but the gcloud
// ADC and sops keys live in $HOME SUBDIRECTORIES the walk visits, so they
// must be filtered out explicitly or a run launched under ~/.config/gcloud
// would grant the global ADC with no disclosed challenge. Best-effort: a
// registry read failure yields nothing, and jit run proceeds without the grant.
func projectTemplateMounts(cwd string) []string {
	entries, home, err := loadMountRegistry()
	if err != nil {
		return nil
	}
	global := globalMountPaths(home)
	var out []string
	for d := cwd; d != home; {
		for _, e := range entries {
			if e.TemplatePath != "" && filepath.Dir(e.MountPath) == d && !global[e.MountPath] {
				out = append(out, e.MountPath)
			}
		}
		parent := filepath.Dir(d)
		if parent == d {
			break
		}
		d = parent
	}
	return out
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
// grantMounts is the second answer the same resolution produces: the live
// mount paths whose files serve exactly the values being injected — what
// `jit run` names in its run-scoped reveal grant so a script that re-reads
// the mounted file mid-run gets those same real values instead of decoys
// (the reported jit-hidden-* clobber incident). Best-effort by design:
// empty means "nothing to grant" (an unmounted profile, an unreadable
// registry), never an error — injection must not fail over grant lookup.
//
// Resolution order:
//  1. explicit --profile: used verbatim (project-then-global via
//     profile.Load), no merge, silent. --mode is an error here — it only
//     means something for the layer merge. grantMounts is whatever
//     registry entries reference that profile's manifest.
//  2. the mount registry's .env layers for the nearest directory at or
//     above cwd (findEnvLayers): overlaid in precedence order. grantMounts
//     is exactly the merged layers' mount paths.
//  3. no layers anywhere: fall back to the single project-local profile if
//     exactly one exists; zero or several stay a hard error that says how
//     to disambiguate. --mode without any layers is also a hard error.
//
// injectionProfileForRun wraps resolveInjectionProfile with jit run's one
// tolerance: a run that carries global --with grants and named neither
// --profile nor --mode may inject NOTHING and exist purely to grant a global
// mount (a grant-wrapped `gcloud` typed in a non-project directory is exactly
// this). For that case a missing project profile is not an error: the run
// proceeds with an empty injection profile. An explicit --profile or --mode
// that fails to resolve still errors, and a run with no --with still requires
// a profile as before.
func injectionProfileForRun(cwd, explicit, mode string, hasWith bool, w io.Writer) (profile.Profile, []string, error) {
	p, grantMounts, err := resolveInjectionProfile("jit run", cwd, explicit, mode, w)
	if err != nil && hasWith && explicit == "" && mode == "" {
		return profile.Profile{}, nil, nil
	}
	return p, grantMounts, err
}

func resolveInjectionProfile(cmdName, cwd, explicit, mode string, w io.Writer) (p profile.Profile, grantMounts []string, err error) {
	if explicit != "" {
		if mode != "" {
			return nil, nil, fmt.Errorf("--mode only applies when jit merges a project's .env layers, with --profile %s, name the mode's profile directly instead", explicit)
		}
		p, err := profile.Load(cwd, explicit)
		if err != nil {
			return nil, nil, err
		}
		return p, grantMountsForProfileName(cwd, explicit), nil
	}
	if err := validateEnvMode(mode); err != nil {
		return nil, nil, err
	}

	entries, home, err := loadMountRegistry()
	if err != nil {
		return nil, nil, err
	}

	dir, layers := findEnvLayers(entries, cwd, home, mode)
	if len(layers) == 0 {
		if mode != "" {
			return nil, nil, fmt.Errorf("--mode %s: no migrated .env layers found at or above this directory, mode selects among a project's migrated .env files", mode)
		}
		p, name, err := resolveSingleProjectProfile(cmdName, cwd, w)
		if err != nil {
			return nil, nil, err
		}
		return p, grantMountsForProfileName(cwd, name), nil
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
			return nil, nil, fmt.Errorf("--mode %s: no migrated .env.%s (or .env.%s.local) in %s", mode, mode, mode, displayPath(home, dir))
		}
	}

	merged := make([]profile.Profile, 0, len(layers))
	fileNames := make([]string, 0, len(layers))
	profileNames := make([]string, 0, len(layers))
	for _, l := range layers {
		p, err := profile.LoadFile(l.profilePath)
		if err != nil {
			return nil, nil, fmt.Errorf("layer %s: %w", l.fileName, err)
		}
		merged = append(merged, p)
		fileNames = append(fileNames, l.fileName)
		profileNames = append(profileNames, l.profileName)
		grantMounts = append(grantMounts, l.mountPath)
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
	return profile.Overlay(merged...), grantMounts, nil
}

// grantMountsForProfileName finds the live mounts (if any) whose registry
// entries reference the named profile's manifest — the grant targets for
// the --profile and single-project-profile paths, where no layer merge
// carries the mount paths along. Best-effort throughout: any lookup
// failure just means no grant, matching resolveInjectionProfile's
// grantMounts contract.
func grantMountsForProfileName(cwd, name string) []string {
	if name == "" {
		return nil
	}
	entries, _, err := loadMountRegistry()
	if err != nil {
		return nil
	}
	infos, err := profile.ListAll(cwd)
	if err != nil {
		return nil
	}
	// First name match wins — ListAll orders project-local before global,
	// the same precedence profile.Load itself resolves with.
	profilePath := ""
	for _, info := range infos {
		if info.Name == name {
			profilePath = info.Path
			break
		}
	}
	if profilePath == "" {
		return nil
	}
	var mounts []string
	for _, e := range entries {
		if e.TemplatePath == "" && e.ProfilePath == profilePath {
			mounts = append(mounts, e.MountPath)
		}
	}
	return mounts
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
// The chosen name is returned alongside so the caller can look up grant
// mounts for it ("" when erroring).
func resolveSingleProjectProfile(cmdName, cwd string, w io.Writer) (profile.Profile, string, error) {
	names, err := profile.ListNames(cwd)
	if err != nil {
		return nil, "", err
	}
	switch len(names) {
	case 0:
		return nil, "", fmt.Errorf("no profile given and none defined in %s/, migrate this project with `jit migrate local`, or name one with --profile (see: jit profile list)", profile.ProfilesDir)
	case 1:
		fmt.Fprintf(w, "%s: using profile %q\n", cmdName, names[0])
		p, err := profile.Load(cwd, names[0])
		return p, names[0], err
	default:
		return nil, "", fmt.Errorf("no profile given and this project defines several (%s), pick one with --profile", strings.Join(names, ", "))
	}
}
