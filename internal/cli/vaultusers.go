// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jitpass/jit/internal/audit"
	"github.com/jitpass/jit/internal/migrate"
	"github.com/jitpass/jit/internal/mount"
	"github.com/jitpass/jit/internal/pointerfile"
	"github.com/jitpass/jit/internal/profile"
)

// secretUse is one thing that uses a stored secret: a profile that names it
// (from any store jit can find, possibly served through a mount), or a
// pointer file holding a jit://vault reference to it. Exactly one of
// ProfilePath and PointerFile is set.
type secretUse struct {
	ProfileName string
	ProfilePath string        // the manifest file, the identity uses dedupe on
	Scope       profile.Scope // global or project
	Project     string        // the project root, for a project-scope profile
	MountPath   string        // a registered mount this profile feeds, "" when none
	OwnerConfig string        // the profile's recorded source config (.source sidecar)
	PointerFile string        // a pointer file naming the secret, for a pointer use
	// LaunchedBy lists the MCP configs whose entries start this profile, in
	// any wrapper layer. Display evidence only (attachLaunchers): an MCP
	// config that fails to parse is skipped there, so an empty list means
	// "no known launcher", never "unused".
	LaunchedBy []string
}

// scopeLabel renders the profile's store the way the rm warnings show it:
// "global", or "project ~/proj".
func (u secretUse) scopeLabel() string {
	if u.Scope == profile.ScopeProject && u.Project != "" {
		return "project " + shortPath(u.Project)
	}
	return string(u.Scope)
}

// vaultUsage is collectVaultUsers' answer: every vault path something uses,
// with each user, plus the registered mounts whose profile manifest is gone.
type vaultUsage struct {
	byPath      map[string][]secretUse
	staleMounts []mount.Entry
}

// usesOf returns the uses of the given paths only, keyed by path.
func (u vaultUsage) usesOf(paths []string) map[string][]secretUse {
	out := map[string][]secretUse{}
	for _, p := range paths {
		if list := u.byPath[p]; len(list) > 0 {
			out[p] = list
		}
	}
	return out
}

// collectVaultUsers is the one STRICT answer to "what uses this secret",
// for every caller that deletes on the answer (`jit vault rm`, `vault
// orphans --prune`, `vault duplicates`, `jit migrate remove`). It reads:
//
//   - profiles in cwd's store, the global store (always, even when cwd is
//     home) and every project store under home. A project store is found by
//     walking home for .jit directories, skipping the same noise directories
//     jit scan does, plus the Trash: a trashed project launches nothing.
//     The walk used to be missing, and every check ran from cwd alone, so a
//     project's secrets looked unused from anywhere else. That is how "Delete
//     All" in the app was one click from removing a project's secrets.
//   - the mount registry. A registered mount whose manifest is gone names
//     nothing and comes back as a stale mount instead (GAPS.md #67).
//   - pointer files: jit's own in-place pointer files (header-marked), found
//     through the undo index (every one was backed up before it was written)
//     and the home walk (.env-family names), plus ~/.clisso.yaml. Their
//     `.pointers` companions are not users: jit never reads them, and the
//     mount they sit beside is already counted through its profile.
//
// STRICT means an unreadable or unparseable manifest, registry, undo index
// or pointer file is an ERROR, never a skip: a skipped file would make its
// secrets look unused, which is exactly the verdict a deleting caller must
// never reach by accident. A directory the walk can't enter is skipped, as
// every home walk in jit does: a macOS privacy denial on one folder must
// not disable deletion everywhere.
func collectVaultUsers(root, cwd string) (vaultUsage, error) {
	usage := vaultUsage{byPath: map[string][]secretUse{}}
	home, err := profile.GlobalRoot()
	if err != nil {
		return usage, fmt.Errorf("finding the global profile store: %w", err)
	}
	home = filepath.Clean(home)
	cwd = filepath.Clean(cwd)

	// Keyed by the manifest's resolved path: cwd from os.Getwd and the
	// same directory reached by the home walk can differ by a symlink
	// (/var vs /private/var), and one profile must be one use.
	seen := map[string]int{} // canonical manifest path -> index into profiles
	var profiles []secretUse
	addStore := func(storeRoot string, scope profile.Scope) error {
		manifests, err := listProfileManifests(storeRoot)
		if err != nil {
			return err
		}
		for _, m := range manifests {
			key := canonicalPath(m)
			if _, ok := seen[key]; ok {
				continue
			}
			u := secretUse{
				ProfileName: manifestName(m),
				ProfilePath: m,
				Scope:       scope,
			}
			if scope == profile.ScopeProject {
				u.Project = storeRoot
			}
			seen[key] = len(profiles)
			profiles = append(profiles, u)
		}
		return nil
	}

	if canonicalPath(cwd) == canonicalPath(home) {
		if err := addStore(home, profile.ScopeGlobal); err != nil {
			return usage, err
		}
	} else {
		if err := addStore(cwd, profile.ScopeProject); err != nil {
			return usage, err
		}
		if err := addStore(home, profile.ScopeGlobal); err != nil {
			return usage, err
		}
	}

	projectRoots, envPointers := walkHomeForUsers(home)
	for _, pr := range projectRoots {
		if err := addStore(pr, profile.ScopeProject); err != nil {
			return usage, err
		}
	}

	entries, err := mount.LoadRegistry(mount.RegistryPath(root))
	if err != nil {
		return usage, fmt.Errorf("reading the mount registry: %w", err)
	}
	for _, e := range entries {
		m := filepath.Clean(e.ProfilePath)
		if _, statErr := os.Stat(m); errors.Is(statErr, fs.ErrNotExist) {
			usage.staleMounts = append(usage.staleMounts, e)
			continue
		}
		key := canonicalPath(m)
		if i, ok := seen[key]; ok {
			if profiles[i].MountPath == "" {
				profiles[i].MountPath = e.MountPath
			}
			continue
		}
		u := secretUse{ProfileName: manifestName(m), ProfilePath: m, MountPath: e.MountPath}
		u.Scope, u.Project = scopeOfManifest(home, m)
		seen[key] = len(profiles)
		profiles = append(profiles, u)
	}

	for _, u := range profiles {
		entries, err := profile.LoadFile(u.ProfilePath)
		if err != nil {
			return usage, fmt.Errorf("loading profile %s: %w", u.ProfilePath, err)
		}
		u.OwnerConfig = migrate.ProfileOwnerConfig(u.ProfilePath)
		for _, vaultPath := range uniqueValues(entries) {
			usage.byPath[vaultPath] = append(usage.byPath[vaultPath], u)
		}
	}

	pointers, err := pointerFileUses(root, home, envPointers)
	if err != nil {
		return usage, err
	}
	for _, pu := range pointers {
		usage.byPath[pu.path] = append(usage.byPath[pu.path], secretUse{PointerFile: pu.file})
	}

	for p, list := range usage.byPath {
		sort.SliceStable(list, func(i, j int) bool { return useSortKey(list[i]) < useSortKey(list[j]) })
		usage.byPath[p] = list
	}
	return usage, nil
}

// collectReferencedPaths is collectVaultUsers flattened to the set of used
// paths, for `jit vault orphans`, which only asks "is anything using it".
// Same strict contract, same stale-mount exception.
func collectReferencedPaths(root, cwd string) (map[string]bool, []mount.Entry, error) {
	usage, err := collectVaultUsers(root, cwd)
	if err != nil {
		return nil, nil, err
	}
	referenced := make(map[string]bool, len(usage.byPath))
	for p := range usage.byPath {
		referenced[p] = true
	}
	return referenced, usage.staleMounts, nil
}

func useSortKey(u secretUse) string {
	if u.PointerFile != "" {
		return "1\x00" + u.PointerFile
	}
	return "0\x00" + u.ProfileName + "\x00" + u.ProfilePath
}

// uniqueValues returns a profile's vault paths, each once: two variables
// naming one secret are one use of it.
func uniqueValues(p profile.Profile) []string {
	set := map[string]bool{}
	for _, v := range p {
		set[v] = true
	}
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// listProfileManifests returns the manifest files in storeRoot's profile
// directory. It reads the directory itself rather than rebuilding each path
// from a name, so a `.yml` manifest is listed under its real name.
func listProfileManifests(storeRoot string) ([]string, error) {
	dir := filepath.Join(storeRoot, profile.ProfilesDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading %s: %w", dir, err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if ext := filepath.Ext(e.Name()); ext == ".yaml" || ext == ".yml" {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	return out, nil
}

// canonicalPath resolves symlinks for comparison, falling back to the
// cleaned path when it can't (the file vanished mid-read).
func canonicalPath(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return filepath.Clean(p)
}

// manifestName is the profile name a manifest file carries.
func manifestName(path string) string {
	return strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
}

// scopeOfManifest labels a manifest reached only through the mount
// registry: global when it sits in home's store, else a project store,
// whose root is the directory holding .jit.
func scopeOfManifest(home, manifest string) (profile.Scope, string) {
	storeRoot := filepath.Dir(filepath.Dir(filepath.Dir(manifest)))
	if canonicalPath(storeRoot) == canonicalPath(home) {
		return profile.ScopeGlobal, ""
	}
	return profile.ScopeProject, storeRoot
}

// walkHomeForUsers walks home once for the two kinds of user a fixed path
// can't find: project roots (a directory holding .jit) and in-place pointer
// files with a .env-family name. Noise directories are skipped exactly as
// jit scan skips them, and so is the Trash. A .jit directory is never
// entered. Home's own .jit is the global store, already read.
func walkHomeForUsers(home string) (projectRoots, pointerFiles []string) {
	_ = filepath.WalkDir(home, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if path == home {
				return err
			}
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if path == home {
				return nil
			}
			name := d.Name()
			if name == ".jit" {
				if parent := filepath.Dir(path); parent != home {
					projectRoots = append(projectRoots, parent)
				}
				return fs.SkipDir
			}
			if name == ".Trash" || audit.SkipNoiseDir(home, path, name) {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || pointerfile.IsCompanion(d.Name()) || !migrate.IsEnvFileName(d.Name()) {
			return nil
		}
		if migrate.IsPointerFile(path) {
			pointerFiles = append(pointerFiles, path)
		}
		return nil
	})
	sort.Strings(projectRoots)
	return projectRoots, pointerFiles
}

// pointerUse is one jit://vault reference found in a pointer file.
type pointerUse struct {
	path string // the vault path
	file string // the pointer file
}

// pointerFileUses reads every pointer file jit can enumerate: in-place
// pointer files from the undo index and the home walk, and ~/.clisso.yaml.
func pointerFileUses(root, home string, walked []string) ([]pointerUse, error) {
	var uses []pointerUse
	done := map[string]bool{}
	read := func(file string, mustRead bool) error {
		file = filepath.Clean(file)
		if done[file] {
			return nil
		}
		done[file] = true
		paths, err := readPointerFile(file, mustRead)
		if err != nil {
			return err
		}
		for _, p := range paths {
			uses = append(uses, pointerUse{path: p, file: file})
		}
		return nil
	}

	recs, err := migrate.LoadBackupRecords(root)
	if err != nil {
		return nil, fmt.Errorf("reading the undo index: %w", err)
	}
	for _, rec := range recs {
		if rec.OriginalPath == "" || filepath.Clean(rec.OriginalPath) == migrate.ClissoConfigPath(home) {
			continue
		}
		if err := read(rec.OriginalPath, true); err != nil {
			return nil, err
		}
	}
	for _, f := range walked {
		if err := read(f, false); err != nil {
			return nil, err
		}
	}

	clisso, err := migrate.ClissoPointerPaths(home)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", migrate.ClissoConfigPath(home), err)
	}
	for _, p := range clisso {
		uses = append(uses, pointerUse{path: p, file: migrate.ClissoConfigPath(home)})
	}
	return uses, nil
}

// readPointerFile returns the vault paths a jit pointer file names, or
// nothing for a file that isn't one (or no longer exists). Only a regular
// file is ever opened: a path in the undo index may be a live mount's FIFO
// by now, and opening one for read blocks on a writer. mustRead is set for a
// file jit knows it rewrote (the undo index says so): failing to open that
// one is an error. A walk candidate that can't be opened can't be told
// apart from any other unreadable .env file, so it is skipped.
func readPointerFile(file string, mustRead bool) ([]string, error) {
	info, err := os.Lstat(file)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		if mustRead {
			return nil, fmt.Errorf("reading pointer file %s: %w", file, err)
		}
		return nil, nil
	}
	if !info.Mode().IsRegular() {
		return nil, nil
	}
	data, err := os.ReadFile(file) // #nosec G304 -- a path from jit's own undo index or its home walk, confirmed a regular file above
	if err != nil {
		if mustRead {
			return nil, fmt.Errorf("reading pointer file %s: %w", file, err)
		}
		return nil, nil
	}
	if !pointerfile.HasHeader(data) {
		return nil, nil
	}
	var paths []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		_, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		if p, ok := pointerfile.VaultPath(value); ok && p != "" {
			paths = append(paths, p)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading pointer file %s: %w", file, err)
	}
	return paths, nil
}

// attachLaunchers fills LaunchedBy on the given uses from every MCP config
// jit can discover from home: which configs start each profile, counting
// every wrapper layer of a nested entry. Display only, and lenient: a
// discovery error leaves the lists empty, which reads as "no known
// launcher", never as "unused". A launcher names a profile by NAME, which
// `jit run` resolves project-first: a global profile takes every launcher
// naming it, a project one only launchers inside its own project.
func attachLaunchers(uses map[string][]secretUse, home string) {
	if len(uses) == 0 {
		return
	}
	entries, err := migrate.DiscoverWrappedMCPEntries(home, home, true)
	if err != nil || len(entries) == 0 {
		return
	}
	byName := map[string][]string{}
	for _, e := range entries {
		for _, name := range e.Profiles {
			if !containsString(byName[name], e.ConfigPath) {
				byName[name] = append(byName[name], e.ConfigPath)
			}
		}
	}
	for p, list := range uses {
		for i := range list {
			u := &list[i]
			if u.ProfilePath == "" {
				continue
			}
			for _, cfg := range byName[u.ProfileName] {
				if u.Scope == profile.ScopeProject && !pathWithinDir(u.Project, cfg) {
					continue
				}
				if !containsString(u.LaunchedBy, cfg) {
					u.LaunchedBy = append(u.LaunchedBy, cfg)
				}
			}
			sort.Strings(u.LaunchedBy)
		}
		uses[p] = list
	}
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
