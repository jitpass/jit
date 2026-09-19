// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package launchers

import (
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
	"github.com/jitpass/jit/internal/profile"
	"github.com/jitpass/jit/internal/wrap"
)

// Kind is what sort of thing launches a profile (or, for KindPointerFile,
// points at a secret).
type Kind string

const (
	KindMCP          Kind = "mcp"           // an MCP server entry; Detail is the server name
	KindAWS          Kind = "aws"           // credential_process in ~/.aws/config; Detail is the "[profile x]" section
	KindKube         Kind = "kube"          // a kubeconfig exec plugin; Detail is "user <name>"
	KindWrap         Kind = "wrap"          // an env-wrap in ~/.jit/wrap.json; Detail is the tool
	KindMount        Kind = "mount"         // a registered mount; File is mounts.yaml, Detail the mount path
	KindHelper       Kind = "helper"        // a docker/git/terraform/cargo helper script; Detail is its category
	KindShellRC      Kind = "shell_rc"      // `jit export --profile` in a shell rc file; Detail is "line N"
	KindPointerFile  Kind = "pointer_file"  // a jit://vault pointer; VaultPath is set, Profile is not
	KindProjectStore Kind = "project_store" // a project profile, launched by `jit run` inside File (the project root)
)

// ByName reports whether a kind names its profile by NAME, resolved the way
// `jit run --profile` resolves it. Only these can be Broken: the others are
// tied to an existing manifest (mount, project store), derive their profile
// per request (helper), or name a vault path (pointer file).
func (k Kind) ByName() bool {
	switch k {
	case KindMCP, KindAWS, KindKube, KindWrap, KindShellRC:
		return true
	}
	return false
}

// Launcher is one thing that starts a profile, or one pointer at a secret.
type Launcher struct {
	Kind Kind `json:"kind"`
	// File is the config or artifact holding the launch: the MCP config,
	// ~/.aws/config, the helper script, the rc file, the pointer file. For
	// KindProjectStore it is the project root.
	File string `json:"file"`
	// Detail locates it inside File, as the user would name it (see Kind).
	Detail string `json:"detail,omitempty"`
	// Profile is the profile name launched. Empty for a pointer.
	Profile string `json:"profile,omitempty"`
	// VaultPath is the secret a pointer names. Pointers only.
	VaultPath string `json:"vault_path,omitempty"`
	// Layer is an MCP entry's wrapper layer: 0 for the outermost `jit run
	// --profile`, 1 for the one it wraps, and so on. A nested entry starts
	// every layer's profile.
	Layer int `json:"layer,omitempty"`
}

// Profile is one profile manifest jit can find, with what uses it.
type Profile struct {
	Name    string        `json:"name"`
	Scope   profile.Scope `json:"scope"`
	Project string        `json:"project,omitempty"` // the project root, for a project-scope profile
	Path    string        `json:"path"`              // the manifest file
	// Values is the loaded manifest (variable -> vault path). nil when it
	// failed to load; that failure is in Map.Errors under SourceProfiles.
	Values profile.Profile `json:"-"`
	// Owners is the .source owner list, verbatim (block-scoped entries,
	// see migrate.OwnerFile); LiveOwners the subset whose file exists.
	Owners     []string `json:"owners,omitempty"`
	LiveOwners []string `json:"live_owners,omitempty"`
	// Mounts lists every registered mount this profile feeds, in registry
	// order.
	Mounts []string `json:"mounts,omitempty"`
	// Launchers is everything known to start it, sorted by kind, file and
	// detail. Empty means "no known launcher", never "unused".
	Launchers []Launcher `json:"launchers,omitempty"`
}

// LaunchersOf returns the profile's launchers of the given kinds, in order.
func (p *Profile) LaunchersOf(kinds ...Kind) []Launcher {
	var out []Launcher
	for _, l := range p.Launchers {
		for _, k := range kinds {
			if l.Kind == k {
				out = append(out, l)
				break
			}
		}
	}
	return out
}

// Source is a class of input the map reads, for SourceError and Map.Err.
type Source string

const (
	SourceProfiles Source = "profiles" // profile store directories and manifests
	SourceOwners   Source = "owners"   // .source owner sidecars
	SourceMounts   Source = "mounts"   // the mount registry
	SourcePointers Source = "pointers" // the undo index, pointer files, ~/.clisso.yaml, and vault lookups of their targets
	SourceMCP      Source = "mcp"      // MCP config files
	SourceAWS      Source = "aws"      // ~/.aws/config
	SourceKube     Source = "kube"     // ~/.kube/config
	SourceWrap     Source = "wrap"     // ~/.jit/wrap.json
	SourceHelpers  Source = "helpers"  // credential helper scripts
	SourceShellRC  Source = "shell_rc" // shell rc files
)

// SourceError is one input that could not be read. Its message is complete
// on its own ("loading profile <path>: ..."): callers print it unchanged.
type SourceError struct {
	Source Source
	File   string
	Err    error
}

func (e SourceError) Error() string { return e.Err.Error() }
func (e SourceError) Unwrap() error { return e.Err }

// Coverage says how much of home the walk saw.
type Coverage struct {
	// Root is where the walk started: always home.
	Root string `json:"root"`
	// Walked is true when the walk read Root itself.
	Walked bool `json:"walked"`
	// Unreadable lists directories under Root the walk could not enter
	// (a macOS privacy denial, a permission). They were skipped.
	Unreadable []string `json:"unreadable,omitempty"`
}

// Complete reports whether the walk covered all of home: it read home and
// entered every directory it did not prune on purpose. Only then may a
// caller say "no known launcher" about a global profile with a straight face.
func (c Coverage) Complete() bool { return c.Walked && len(c.Unreadable) == 0 }

// Map is Discover's answer.
type Map struct {
	Home string
	// Profiles is every manifest found, each once (keyed by resolved path).
	Profiles []*Profile
	// Broken lists by-name launchers naming a profile no store holds, as
	// `jit run` would resolve it (see doc.go).
	Broken []Launcher
	// Pointers lists every jit://vault reference found in a pointer file, in
	// discovery order, one per reference (a file naming a path twice is two).
	Pointers []Launcher
	// Companions lists every jit://vault reference found in a `.pointers`
	// companion file. Deliberately NOT part of Pointers: a companion
	// launches nothing (readPointers says why), so counting it as a user
	// would make a secret only it names look referenced. Kept so its
	// targets can be checked.
	Companions []Launcher
	// MissingPointers is the subset of Pointers whose secret the vault does
	// not hold. Only computed when Options.SecretExists is set
	// (PointersChecked).
	MissingPointers []Launcher
	// MissingCompanions is the same for Companions. A companion naming a
	// secret the vault lacks is usually a leftover from a machine that had
	// it — and the only record left of what the mount beside it served.
	MissingCompanions []Launcher
	PointersChecked   bool
	// StaleMounts are registered mounts whose manifest is gone. They name
	// no profile, so they are not launchers (doctor's mount_stale).
	StaleMounts []mount.Entry
	// MCPEntries is every wrapped MCP server entry found from home, the raw
	// material the KindMCP launchers were built from: doctor's per-server
	// checks (jit path, nesting) want the entry, not just the profile.
	MCPEntries []migrate.WrappedMCPEntry
	Coverage   Coverage
	// Errors lists every source that failed to read, in discovery order.
	Errors []SourceError
}

// Err returns the first recorded error from any of the given sources (from
// every source when none are given), or nil.
func (m *Map) Err(sources ...Source) error {
	for _, e := range m.Errors {
		if len(sources) == 0 {
			return e
		}
		for _, s := range sources {
			if e.Source == s {
				return e
			}
		}
	}
	return nil
}

// ProfileAt returns the profile whose manifest is at path (symlinks
// resolved on both sides), or nil.
func (m *Map) ProfileAt(path string) *Profile {
	key := canonicalPath(path)
	for _, p := range m.Profiles {
		if canonicalPath(p.Path) == key {
			return p
		}
	}
	return nil
}

// ProfilesNamed returns every profile called name, in any store.
func (m *Map) ProfilesNamed(name string) []*Profile {
	var out []*Profile
	for _, p := range m.Profiles {
		if p.Name == name {
			out = append(out, p)
		}
	}
	return out
}

// PointersTo returns the pointers naming vaultPath.
func (m *Map) PointersTo(vaultPath string) []Launcher {
	var out []Launcher
	for _, l := range m.Pointers {
		if l.VaultPath == vaultPath {
			out = append(out, l)
		}
	}
	return out
}

// Options configures Discover.
type Options struct {
	// Home is the user's home: the walk root and the global store. Required,
	// absolute, and never "/".
	Home string
	// Root is jit's config directory (vaultRootDir: the mount registry and
	// the undo index live there). Empty skips both.
	Root string
	// Cwd, when set and not home, adds that directory's own store as a
	// project store, the one `jit run` would try first from there. It does
	// not move the walk.
	Cwd string
	// Strict makes any SourceError fail Discover.
	Strict bool
	// SecretExists, when set, is asked about every pointer's target to fill
	// MissingPointers. A read-only vault's Exists is enough.
	SecretExists func(vaultPath string) (bool, error)
}

// Discover builds the map. It only reads. In Strict mode any source that
// failed to read is returned as the error (the first one, in discovery
// order) and the map is nil; otherwise the failures are in Map.Errors.
// An invalid Home is always an error.
func Discover(opts Options) (*Map, error) {
	home, err := validHome(opts.Home)
	if err != nil {
		return nil, err
	}
	d := &discovery{
		m:    &Map{Home: home},
		home: home,
		seen: map[string]*Profile{},
	}
	cwd := ""
	if opts.Cwd != "" {
		cwd = filepath.Clean(opts.Cwd)
	}

	// Stores, in the order `jit run` consults them from cwd: cwd's own,
	// then the global one. Keyed by the manifest's resolved path: cwd from
	// os.Getwd and the same directory reached by the walk can differ by a
	// symlink (/var vs /private/var), and one profile must be one entry.
	if cwd != "" && canonicalPath(cwd) != canonicalPath(home) {
		d.addStore(cwd, profile.ScopeProject)
	}
	d.addStore(home, profile.ScopeGlobal)

	w := walkHome(home)
	d.m.Coverage = w.coverage
	for _, pr := range w.projectRoots {
		d.addStore(pr, profile.ScopeProject)
	}

	if opts.Root != "" {
		d.addMounts(opts.Root)
	}
	d.loadProfiles()
	d.readPointers(opts.Root, w.envPointers)
	d.readCompanions(w.companions)

	d.readMCP(w.mcpFiles)
	d.readProfileLaunches(SourceAWS, KindAWS, migrate.AWSConfigProfileLaunches)
	d.readProfileLaunches(SourceKube, KindKube, migrate.KubeconfigProfileLaunches)
	d.readWrap()
	d.readProfileLaunches(SourceShellRC, KindShellRC, migrate.ShellRCProfileLaunches)
	d.resolveByName()
	d.readHelpers()
	d.addProjectStores()
	if opts.SecretExists != nil {
		d.checkPointers(opts.SecretExists)
	}

	for _, p := range d.m.Profiles {
		sortLaunchers(p.Launchers)
	}
	if opts.Strict {
		if err := d.m.Err(); err != nil {
			return nil, err
		}
	}
	return d.m, nil
}

// validHome refuses a home the walk must not start from: empty, relative,
// or the filesystem root (the whole disk, every config twice).
func validHome(home string) (string, error) {
	if home == "" {
		return "", errors.New("launcher discovery needs a home directory")
	}
	home = filepath.Clean(home)
	if !filepath.IsAbs(home) {
		return "", fmt.Errorf("launcher discovery needs an absolute home directory, got %q", home)
	}
	if filepath.Dir(home) == home {
		return "", fmt.Errorf("refusing to discover launchers from %s: the walk starts at home, never at the filesystem root", home)
	}
	return home, nil
}

type discovery struct {
	m    *Map
	home string
	seen map[string]*Profile // canonical manifest path -> profile
	// byName holds the unresolved by-name launchers until resolveByName.
	byName []Launcher
}

func (d *discovery) fail(src Source, file string, err error) {
	d.m.Errors = append(d.m.Errors, SourceError{Source: src, File: file, Err: err})
}

// addStore lists storeRoot's manifests. The directory is read itself rather
// than each path rebuilt from a name, so a .yml manifest keeps its real name.
func (d *discovery) addStore(storeRoot string, scope profile.Scope) {
	dir := filepath.Join(storeRoot, profile.ProfilesDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			d.fail(SourceProfiles, dir, fmt.Errorf("reading %s: %w", dir, err))
		}
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if ext := filepath.Ext(e.Name()); ext != ".yaml" && ext != ".yml" {
			continue
		}
		m := filepath.Join(dir, e.Name())
		p := &Profile{Name: manifestName(m), Path: m, Scope: scope}
		if scope == profile.ScopeProject {
			p.Project = storeRoot
		}
		d.add(p)
	}
}

func (d *discovery) add(p *Profile) *Profile {
	key := canonicalPath(p.Path)
	if existing, ok := d.seen[key]; ok {
		return existing
	}
	d.seen[key] = p
	d.m.Profiles = append(d.m.Profiles, p)
	return p
}

// addMounts reads the mount registry. A mount whose manifest is gone names
// nothing and is a stale mount, not a launcher (GAPS.md #67).
func (d *discovery) addMounts(root string) {
	regPath := mount.RegistryPath(root)
	entries, err := mount.LoadRegistry(regPath)
	if err != nil {
		d.fail(SourceMounts, regPath, fmt.Errorf("reading the mount registry: %w", err))
		return
	}
	for _, e := range entries {
		m := filepath.Clean(e.ProfilePath)
		if _, statErr := os.Stat(m); errors.Is(statErr, fs.ErrNotExist) {
			d.m.StaleMounts = append(d.m.StaleMounts, e)
			continue
		}
		p, ok := d.seen[canonicalPath(m)]
		if !ok {
			p = &Profile{Name: manifestName(m), Path: m}
			p.Scope, p.Project = scopeOfManifest(d.home, m)
			p = d.add(p)
		}
		p.Mounts = append(p.Mounts, e.MountPath)
		p.Launchers = append(p.Launchers, Launcher{Kind: KindMount, File: regPath, Detail: e.MountPath, Profile: p.Name})
	}
}

// loadProfiles loads every manifest and its owner list.
func (d *discovery) loadProfiles() {
	for _, p := range d.m.Profiles {
		values, err := profile.LoadFile(p.Path)
		if err != nil {
			d.fail(SourceProfiles, p.Path, fmt.Errorf("loading profile %s: %w", p.Path, err))
		} else {
			p.Values = values
		}
		owners, err := migrate.ReadProfileOwners(p.Path)
		if err != nil {
			d.fail(SourceOwners, p.Path, fmt.Errorf("reading the record of profile %s: %w", p.Path, err))
			continue
		}
		p.Owners = owners
		for _, o := range owners {
			if _, err := os.Stat(migrate.OwnerFile(o)); errors.Is(err, fs.ErrNotExist) {
				continue
			}
			p.LiveOwners = append(p.LiveOwners, o)
		}
	}
}

// readMCP parses every MCP config: the fixed files, then what the walk
// found. Every wrapper layer of every entry is a launcher.
func (d *discovery) readMCP(walked []string) {
	done := map[string]bool{}
	var files []string
	for _, f := range FixedMCPConfigPaths(d.home) {
		if _, err := os.Stat(f); err == nil {
			files = append(files, f)
		}
	}
	files = append(files, walked...)
	for _, f := range files {
		if done[f] {
			continue
		}
		done[f] = true
		entries, err := migrate.WrappedMCPEntriesIn(f)
		if err != nil {
			d.fail(SourceMCP, f, fmt.Errorf("reading MCP config %s: %w", f, err))
			continue
		}
		d.m.MCPEntries = append(d.m.MCPEntries, entries...)
		for _, e := range entries {
			for layer, name := range e.Profiles {
				d.byName = append(d.byName, Launcher{Kind: KindMCP, File: e.ConfigPath, Detail: e.ServerName, Profile: name, Layer: layer})
			}
		}
	}
}

// readProfileLaunches adds one migrate reader's by-name launches.
func (d *discovery) readProfileLaunches(src Source, kind Kind, read func(home string) ([]migrate.ProfileLaunch, error)) {
	launches, err := read(d.home)
	if err != nil {
		d.fail(src, "", err)
	}
	for _, l := range launches {
		d.byName = append(d.byName, Launcher{Kind: kind, File: l.File, Detail: l.Detail, Profile: l.Profile})
	}
}

// readWrap adds every env-wrap: its shim runs `jit run --profile
// wrap-<tool>`. Grant, capture and run-grant wraps name no profile.
func (d *discovery) readWrap() {
	manifest, err := wrap.LoadManifest(d.home)
	if err != nil {
		d.fail(SourceWrap, wrap.ManifestPath(d.home), err)
		return
	}
	tools := make([]string, 0, len(manifest.Tools))
	for t := range manifest.Tools {
		tools = append(tools, t)
	}
	sort.Strings(tools)
	for _, t := range tools {
		e := manifest.Tools[t]
		if e.IsGrant() || e.IsCapture() || e.IsRunGrant() {
			continue
		}
		d.byName = append(d.byName, Launcher{Kind: KindWrap, File: wrap.ManifestPath(d.home), Detail: t, Profile: wrap.ProfileName(t)})
	}
}

// resolveByName attaches every by-name launcher to the profiles `jit run`
// would resolve it to: every global profile of that name, and a project one
// only when the launcher sits inside its project. One resolving to nothing
// is broken.
func (d *discovery) resolveByName() {
	for _, l := range d.byName {
		resolved := false
		for _, p := range d.m.Profiles {
			if p.Name != l.Profile {
				continue
			}
			if p.Scope == profile.ScopeProject && !pathWithinDir(p.Project, l.File) {
				continue
			}
			p.Launchers = append(p.Launchers, l)
			resolved = true
		}
		if !resolved {
			d.m.Broken = append(d.m.Broken, l)
		}
	}
	d.byName = nil
}

// readHelpers attaches each helper script that exists to every global
// profile under its prefix: the helper picks one per request, from the
// registry or host the tool asks about.
func (d *discovery) readHelpers() {
	for _, h := range migrate.CredentialHelpers(d.home) {
		info, err := os.Lstat(h.Path)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				d.fail(SourceHelpers, h.Path, fmt.Errorf("checking %s: %w", h.Path, err))
			}
			continue
		}
		if !info.Mode().IsRegular() {
			continue
		}
		for _, p := range d.m.Profiles {
			if p.Scope == profile.ScopeGlobal && strings.HasPrefix(p.Name, h.ProfilePrefix) {
				p.Launchers = append(p.Launchers, Launcher{Kind: KindHelper, File: h.Path, Detail: h.Category, Profile: p.Name})
			}
		}
	}
}

// addProjectStores records that a project profile is launched from its
// project, by whatever runs `jit run` there.
func (d *discovery) addProjectStores() {
	for _, p := range d.m.Profiles {
		if p.Scope == profile.ScopeProject && p.Project != "" {
			p.Launchers = append(p.Launchers, Launcher{Kind: KindProjectStore, File: p.Project, Profile: p.Name})
		}
	}
}

func (d *discovery) checkPointers(exists func(string) (bool, error)) {
	d.m.PointersChecked = true
	check := func(in []Launcher, out *[]Launcher) {
		for _, l := range in {
			ok, err := exists(l.VaultPath)
			if err != nil {
				d.fail(SourcePointers, l.File, fmt.Errorf("checking %s's target %s: %w", l.File, l.VaultPath, err))
				continue
			}
			if !ok {
				*out = append(*out, l)
			}
		}
	}
	check(d.m.Pointers, &d.m.MissingPointers)
	check(d.m.Companions, &d.m.MissingCompanions)
}

// FixedMCPConfigPaths lists the MCP configs no home walk reaches, whether
// or not each exists: audit's own fixed list (Claude Desktop, ~/.claude.json),
// VS Code's user mcp.json and each VS Code profile's copy (all under
// ~/Library, which every walk prunes), and Windsurf's mcp_config.json,
// whose name no walk recognizes. Both new shapes parse with migrate's
// reader: VS Code keys its servers "servers", Windsurf "mcpServers".
//
// Deliberately NOT audit.FixedMCPConfigPaths itself: that list decides what
// `jit scan` reports and `jit migrate` rewrites, and widening it changes
// both. This one only decides what counts as a launcher.
func FixedMCPConfigPaths(home string) []string {
	paths := audit.FixedMCPConfigPaths(home)
	vscodeUser := filepath.Join(home, "Library", "Application Support", "Code", "User")
	paths = append(paths, filepath.Join(vscodeUser, "mcp.json"))
	if profiles, err := filepath.Glob(filepath.Join(vscodeUser, "profiles", "*", "mcp.json")); err == nil {
		sort.Strings(profiles)
		paths = append(paths, profiles...)
	}
	paths = append(paths, filepath.Join(home, ".codeium", "windsurf", "mcp_config.json"))
	return paths
}

// kindOrder sorts launchers the way a report lists them: the configs a user
// edits first, then jit's own bookkeeping.
var kindOrder = map[Kind]int{
	KindMCP: 0, KindAWS: 1, KindKube: 2, KindShellRC: 3, KindWrap: 4,
	KindHelper: 5, KindMount: 6, KindProjectStore: 7, KindPointerFile: 8,
}

func sortLaunchers(l []Launcher) {
	sort.SliceStable(l, func(i, j int) bool {
		if l[i].Kind != l[j].Kind {
			return kindOrder[l[i].Kind] < kindOrder[l[j].Kind]
		}
		if l[i].File != l[j].File {
			return l[i].File < l[j].File
		}
		if l[i].Detail != l[j].Detail {
			return l[i].Detail < l[j].Detail
		}
		return l[i].Layer < l[j].Layer
	})
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

// pathWithinDir reports whether p is dir or lies under it.
func pathWithinDir(dir, p string) bool {
	rel, err := filepath.Rel(dir, p)
	if err != nil {
		return false
	}
	return rel == "." || (!strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != "..")
}
