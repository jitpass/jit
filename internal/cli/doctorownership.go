// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/fatih/color"

	"github.com/jitpass/jit/internal/launchers"
	"github.com/jitpass/jit/internal/migrate"
	"github.com/jitpass/jit/internal/profile"
	"github.com/jitpass/jit/internal/vault"
	"github.com/jitpass/jit/internal/wrap"
)

// Doctor's ownership sections (design/doctor-repair.md, Phase 2) read the
// launcher map (internal/launchers): what starts each profile, and what
// points at each secret, discovered from home. Five findings come of it:
//
//   - launcher_broken (problem): a launcher names a profile no store holds.
//   - pointer_missing (problem): a jit://vault pointer names a missing secret.
//   - owner_gone (warning): an MCP profile's recorded owners are all gone,
//     and a live config launches it.
//   - no_owner (warning): an MCP profile with no owner recorded at all.
//   - unlaunched (warning): a global profile nothing known launches.
//
// Discovery is lenient here: doctor reports, so a source it can't read is
// not a doctor failure. What an unread source costs is the one verdict that
// depends on having read everything, "no known launcher", which is then not
// issued at all (see unlaunchedFindings).

// doctorLauncherMap discovers the launcher map for doctor: always from home
// (F2), never from cwd and never from /, with cwd's own store added the way
// `jit run` would try it first. Existence of each pointer's target is asked
// of the vault, which reads no value. nil when there is no usable home.
func doctorLauncherMap(root, cwd string, v *vault.Vault) *launchers.Map {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	m, err := launchers.Discover(launchers.Options{
		Home:         home,
		Root:         root,
		Cwd:          cwd,
		SecretExists: v.Exists,
	})
	if err != nil {
		return nil
	}
	return m
}

// launcherFindings turns the map into doctor's ownership findings, and
// returns the global profiles reported as unlaunched, by name, so the
// profile check can leave their missing secrets and gone origins to that
// row (each profile is reported in one section).
func launcherFindings(m *launchers.Map, v *vault.Vault) ([]checkFinding, map[string]bool) {
	if m == nil {
		return nil, nil
	}
	var out []checkFinding
	out = append(out, brokenLauncherFindings(m)...)
	out = append(out, missingPointerFindings(m)...)
	out = append(out, ownerFindings(m)...)
	unlaunched, names := unlaunchedFindings(m, v)
	return append(out, unlaunched...), names
}

// brokenLauncherFindings reports every by-name launcher that resolves to no
// profile. Two are left to the section that already owns them, so one
// broken thing is one line: an env-wrap ([wrap] checks its profile), and an
// MCP entry's OUTER layer when [mcp] reported that entry (see
// dropCoveredLauncherFindings). An inner layer is nobody else's.
func brokenLauncherFindings(m *launchers.Map) []checkFinding {
	var out []checkFinding
	seen := map[string]bool{}
	for _, l := range m.Broken {
		if !l.Kind.ByName() || l.Kind == launchers.KindWrap {
			continue
		}
		// One row per place that names it: a nested entry whose layers
		// name the same gone profile is one entry to fix.
		key := strings.Join([]string{string(l.Kind), l.File, l.Detail, l.Profile}, "\x00")
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, checkFinding{
			Kind:      kindLauncherBroken,
			Profile:   l.Profile,
			File:      l.File,
			Launchers: []launchers.Launcher{l},
			Detail:    fmt.Sprintf("%s names profile %s, which no jit store holds", launcherWhere(l), l.Profile),
			Action:    strings.Join(brokenLauncherNote(l), "; "),
		})
	}
	return out
}

// launcherWhere names a launcher as the user would find it: the file, then
// the place inside it ("[profile dev]", "user docker-desktop", "line 12", an
// MCP server's name).
func launcherWhere(l launchers.Launcher) string {
	if l.Detail == "" {
		return shortPath(l.File)
	}
	return shortPath(l.File) + " " + l.Detail
}

// brokenLauncherNote closes a run of broken launchers of one kind: what
// fails, then what to do. Plain notes, not commands: the fix is an edit to
// a file jit doesn't own, or re-creating a profile only its source can.
func brokenLauncherNote(l launchers.Launcher) []string {
	switch l.Kind {
	case launchers.KindAWS:
		return []string{
			fmt.Sprintf("no such jit profile, so %s fails", awsProfileCommand(l.Detail)),
			"mint it again, or delete that [profile] block",
		}
	case launchers.KindMCP:
		return []string{
			"no such jit profile, so that MCP server fails to start",
			"undo that migration, or drop that jit run layer",
		}
	case launchers.KindKube:
		return []string{
			"no such jit profile, so kubectl fails as that user",
			"undo that migration, or delete that user entry",
		}
	case launchers.KindShellRC:
		return []string{
			"no such jit profile, so that line fails in every new shell",
			"undo that migration, or delete that line",
		}
	default:
		return []string{"no such jit profile, so it fails"}
	}
}

// awsProfileCommand is the aws invocation an ~/.aws/config section serves:
// "[profile dev]" is `aws --profile dev`, "[default]" is plain `aws`.
func awsProfileCommand(section string) string {
	name := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(section, "["), "]"))
	name = strings.TrimSpace(strings.TrimPrefix(name, "profile "))
	switch name {
	case "":
		return "that aws profile"
	case "default":
		return "aws"
	}
	return "aws --profile " + name
}

// dropCoveredLauncherFindings removes the launcher_broken rows [mcp] already
// reports: an MCP entry's outer layer, for an entry [mcp] flagged. [mcp]
// walks from cwd and launcher discovery from home, so an entry outside cwd
// keeps its row here rather than going unreported.
func dropCoveredLauncherFindings(findings []checkFinding) []checkFinding {
	covered := map[string]bool{}
	for _, f := range findings {
		if f.Kind == kindMCP {
			covered[resolvedPath(f.Path)+"\x00"+f.Profile] = true
		}
	}
	if len(covered) == 0 {
		return findings
	}
	out := make([]checkFinding, 0, len(findings))
	for _, f := range findings {
		if f.Kind == kindLauncherBroken && len(f.Launchers) == 1 {
			l := f.Launchers[0]
			if l.Kind == launchers.KindMCP && l.Layer == 0 && covered[resolvedPath(l.File)+"\x00"+l.Profile] {
				continue
			}
		}
		out = append(out, f)
	}
	return out
}

// resolvedPath resolves symlinks for comparing two spellings of one file:
// [mcp] walks from os.Getwd's cwd and discovery from $HOME, which can reach
// the same config as /var/... and /private/var/.... The cleaned path when
// it can't be resolved.
func resolvedPath(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return filepath.Clean(p)
}

// missingPointerFindings reports each pointer naming a secret the vault
// doesn't hold, once per file and path.
func missingPointerFindings(m *launchers.Map) []checkFinding {
	var out []checkFinding
	seen := map[string]bool{}
	for _, l := range m.MissingPointers {
		key := l.File + "\x00" + l.VaultPath
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, checkFinding{
			Kind:   kindPointerMissing,
			File:   l.File,
			Path:   l.VaultPath,
			Detail: fmt.Sprintf("%s points at %s, which isn't in the vault", shortPath(l.File), l.VaultPath),
			Action: fmt.Sprintf("`jit vault set %s`", l.VaultPath),
		})
	}
	return out
}

// ownerFindings reports the MCP profiles a live config launches but no live
// config owns: owner_gone when every recorded owner's file is gone, no_owner
// when none was ever recorded. Only global profiles an MCP entry launches
// qualify; a profile something else also launches (an AWS or rc line) is
// not an MCP profile unless its owner list says it was made by one.
//
// Sorted into the groups the report prints: owner_gone first, then by gone
// owners, launching configs and name.
func ownerFindings(m *launchers.Map) []checkFinding {
	var out []checkFinding
	for _, p := range m.Profiles {
		if p.Scope != profile.ScopeGlobal || ownersUnreadable(m, p) {
			continue
		}
		mcp := p.LaunchersOf(launchers.KindMCP)
		if len(mcp) == 0 {
			continue
		}
		configs := launcherFiles(mcp)
		adopt := fmt.Sprintf("`jit profile adopt %s`", shellQuoteArg(shortPath(configs[0])))
		switch {
		case len(p.Owners) > 0 && len(p.LiveOwners) == 0:
			gone := ownerFiles(p.Owners)
			out = append(out, checkFinding{
				Kind:      kindOwnerGone,
				Profile:   p.Name,
				Scope:     string(profile.ScopeGlobal),
				Path:      p.Path,
				Config:    configs[0],
				Configs:   configs,
				Owners:    p.Owners,
				Launchers: mcp,
				Detail: fmt.Sprintf("made by %s, now gone; launched by %s",
					pathsPhrase(gone), pathsPhrase(configs)),
				Action: adopt,
			})
		case len(p.Owners) == 0 && len(mcp) == len(p.Launchers):
			out = append(out, checkFinding{
				Kind:      kindNoOwner,
				Profile:   p.Name,
				Scope:     string(profile.ScopeGlobal),
				Path:      p.Path,
				Config:    configs[0],
				Configs:   configs,
				Launchers: mcp,
				Detail:    fmt.Sprintf("no owner recorded; launched by %s", pathsPhrase(configs)),
				Action:    adopt,
			})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind == kindOwnerGone
		}
		a, b := ownerGroupKey(out[i]), ownerGroupKey(out[j])
		if a != b {
			return a < b
		}
		return out[i].Profile < out[j].Profile
	})
	return out
}

// ownersUnreadable reports whether the profile's owner sidecar failed to
// read: its Owners are then unknown, not empty.
func ownersUnreadable(m *launchers.Map, p *launchers.Profile) bool {
	for _, e := range m.Errors {
		if e.Source == launchers.SourceOwners && e.File == p.Path {
			return true
		}
	}
	return false
}

// launcherFiles returns the distinct files of ls, sorted.
func launcherFiles(ls []launchers.Launcher) []string {
	seen := map[string]bool{}
	var files []string
	for _, l := range ls {
		if !seen[l.File] {
			seen[l.File] = true
			files = append(files, l.File)
		}
	}
	sort.Strings(files)
	return files
}

// ownerFiles returns the distinct config files an owner list names, in
// list order, block scopes stripped.
func ownerFiles(owners []string) []string {
	seen := map[string]bool{}
	var files []string
	for _, o := range owners {
		f := migrate.OwnerFile(o)
		if !seen[f] {
			seen[f] = true
			files = append(files, f)
		}
	}
	return files
}

// pathsPhrase names the first path and counts the rest: "~/a/.mcp.json",
// "~/a/.mcp.json and 2 more".
func pathsPhrase(paths []string) string {
	if len(paths) == 0 {
		return ""
	}
	s := shortPath(paths[0])
	if n := len(paths) - 1; n > 0 {
		s += fmt.Sprintf(" and %d more", n)
	}
	return s
}

// ownerGroupKey is the owner sub-group a finding prints under: the same gone
// owners and the same launching configs share one header.
func ownerGroupKey(f checkFinding) string {
	return strings.Join(ownerFiles(f.Owners), "\x00") + "\x01" + strings.Join(f.Configs, "\x00")
}

// launcherSources are the inputs a "no known launcher" verdict depends on.
// If any failed to read, a launcher may be sitting in it.
var launcherSources = []launchers.Source{
	launchers.SourceMounts, launchers.SourceMCP, launchers.SourceAWS,
	launchers.SourceKube, launchers.SourceWrap, launchers.SourceHelpers,
	launchers.SourceShellRC,
}

// unlaunchedFindings reports every global profile with no known launcher and
// no live owner, the one state `jit profile rm` will act on. It says
// nothing unless the walk covered all of home and every launcher source
// read: the verdict is only honest about places jit actually looked. A
// project profile never qualifies, since `jit run` inside its project
// launches it and nothing records that.
//
// The row counts the profile's secrets, and how many are missing (reads
// existence only, never a value). The └ line names the file it was made
// from when that file is gone.
func unlaunchedFindings(m *launchers.Map, v *vault.Vault) ([]checkFinding, map[string]bool) {
	if !m.Coverage.Complete() || m.Err(launcherSources...) != nil {
		return nil, nil
	}
	var out []checkFinding
	names := map[string]bool{}
	for _, p := range m.Profiles {
		if p.Scope != profile.ScopeGlobal || len(p.Launchers) > 0 || len(p.LiveOwners) > 0 ||
			p.Values == nil || ownersUnreadable(m, p) {
			continue
		}
		paths := profileVaultPaths(p.Values)
		missing, history := 0, 0
		origins := map[string]int{}
		for _, sp := range paths {
			ok, err := v.Exists(sp)
			if err != nil {
				continue
			}
			if !ok {
				missing++
				continue
			}
			if info, err := v.Info(sp); err == nil {
				if info.Origin != "" {
					origins[info.Origin]++
				}
				if info.Class == vault.ClassShellHistory {
					history++
				}
			}
		}
		// Credentials redacted out of a shell history file are an archive:
		// nothing is meant to launch them, and the vault holds the only
		// copy. Offering `jit profile rm` there would offer to destroy them.
		if history > 0 && history == len(paths)-missing {
			continue
		}
		origin := unlaunchedOrigin(m.Home, p, origins)
		f := checkFinding{
			Kind:           kindUnlaunched,
			Profile:        p.Name,
			Scope:          string(profile.ScopeGlobal),
			Path:           p.Path,
			Owners:         p.Owners,
			Secrets:        len(paths),
			SecretsMissing: missing,
			Origin:         origin,
			Detail:         fmt.Sprintf("no known launcher; %s", secretsPhrase(len(paths), missing)),
			Action:         fmt.Sprintf("`jit profile rm %s` if you no longer use it", p.Name),
		}
		out = append(out, f)
		names[p.Name] = true
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Profile < out[j].Profile })
	return out, names
}

// profileVaultPaths returns the distinct vault paths a profile names, sorted.
func profileVaultPaths(values profile.Profile) []string {
	seen := map[string]bool{}
	var paths []string
	for _, p := range values {
		if !seen[p] {
			seen[p] = true
			paths = append(paths, p)
		}
	}
	sort.Strings(paths)
	return paths
}

// unlaunchedOrigin is the file an unlaunched profile was made from, when
// that file is gone; "" when it still exists or can't be told. The evidence,
// best first: the origin most of its secrets' envelopes record; the owner
// its .source sidecar names (an MCP profile). Never a guess from the
// profile's name: a line that states where a profile came from has to rest
// on a record, so a profile whose secrets are all gone may have none.
func unlaunchedOrigin(home string, p *launchers.Profile, origins map[string]int) string {
	candidate := ""
	switch {
	case len(origins) > 0:
		best := ""
		for o, n := range origins {
			if best == "" || n > origins[best] || (n == origins[best] && o < best) {
				best = o
			}
		}
		candidate = wrap.ExpandHome(home, best)
	case len(p.Owners) > 0:
		candidate = migrate.OwnerFile(p.Owners[0])
	}
	if candidate == "" || !filepath.IsAbs(candidate) {
		return ""
	}
	if _, err := os.Stat(candidate); !errors.Is(err, fs.ErrNotExist) {
		return ""
	}
	return candidate
}

// secretsPhrase is an unlaunched row's count: "1 secret", "2 secrets, both
// missing", "5 secrets, 2 missing".
func secretsPhrase(n, missing int) string {
	switch {
	case n == 0:
		return "no secrets"
	case missing == 0:
		return countWord(n, "secret", "secrets")
	case missing < n:
		return fmt.Sprintf("%s, %d missing", countWord(n, "secret", "secrets"), missing)
	case n == 1:
		return "1 secret, missing"
	case n == 2:
		return "2 secrets, both missing"
	default:
		return fmt.Sprintf("%d secrets, all missing", n)
	}
}

// unlaunchedTemplate closes a [no known launcher] group of more than one:
// the placeholder stands for the names listed above it.
const unlaunchedTemplate = "`jit profile rm <name>` for any you no longer use"

// writeOwnershipGroup renders the ownership kinds, whose groups carry shared
// lines a plain finding list has no place for: launcher_broken's closing
// notes per launcher kind, the owner kinds' "made by"/"launched by" headers,
// unlaunched's └ origin line and closing note. false for any other kind.
func writeOwnershipGroup(out io.Writer, glyph string, c *color.Color, kind checkKind, group []checkFinding) bool {
	switch kind {
	case kindLauncherBroken:
		writeLauncherBrokenGroup(out, glyph, c, group)
	case kindOwnerGone, kindNoOwner:
		writeOwnerGroup(out, glyph, c, kind, group)
	case kindUnlaunched:
		writeUnlaunchedGroup(out, glyph, c, group)
	default:
		return false
	}
	return true
}

// writeGroupRow prints one glyph row under a group header.
func writeGroupRow(out io.Writer, glyph string, c *color.Color, body string) {
	_, _ = c.Fprintf(out, "  %s ", glyph)
	wrapBody(out, findingIndent, strings.Repeat(" ", findingIndent), body)
}

// writeGroupNote prints one plain line at the arrow column: a sub-group's
// header, or a closing note.
func writeGroupNote(out io.Writer, note string) {
	fmt.Fprint(out, strings.Repeat(" ", findingArrow))
	wrapBody(out, findingArrow, strings.Repeat(" ", findingIndent), note)
}

func writeLauncherBrokenGroup(out io.Writer, glyph string, c *color.Color, group []checkFinding) {
	var kinds []launchers.Kind
	byKind := map[launchers.Kind][]checkFinding{}
	for _, f := range group {
		var k launchers.Kind
		if len(f.Launchers) > 0 {
			k = f.Launchers[0].Kind
		}
		if _, ok := byKind[k]; !ok {
			kinds = append(kinds, k)
		}
		byKind[k] = append(byKind[k], f)
	}
	for _, k := range kinds {
		rows := byKind[k]
		for _, f := range rows {
			writeGroupRow(out, glyph, c, formatFinding(f))
		}
		if len(rows[0].Launchers) > 0 {
			for _, note := range brokenLauncherNote(rows[0].Launchers[0]) {
				writeGroupNote(out, note)
			}
		}
	}
}

func writeOwnerGroup(out io.Writer, glyph string, c *color.Color, kind checkKind, group []checkFinding) {
	var keys []string
	subs := map[string][]checkFinding{}
	for _, f := range group {
		k := ownerGroupKey(f)
		if _, ok := subs[k]; !ok {
			keys = append(keys, k)
		}
		subs[k] = append(subs[k], f)
	}
	arrow := strings.Repeat(" ", findingArrow)
	for _, k := range keys {
		rows := subs[k]
		first := rows[0]
		if kind == kindOwnerGone {
			writeGroupNote(out, fmt.Sprintf("made by %s, now gone", pathsPhrase(ownerFiles(first.Owners))))
		}
		writeGroupNote(out, "launched by "+pathsPhrase(first.Configs))
		for _, f := range rows {
			writeGroupRow(out, glyph, c, formatFinding(f))
		}
		writeActionLine(out, arrow, kind, first.Action)
	}
}

func writeUnlaunchedGroup(out io.Writer, glyph string, c *color.Color, group []checkFinding) {
	evidence := strings.Repeat(" ", findingIndent)
	for _, f := range group {
		writeGroupRow(out, glyph, c, formatFinding(f))
		if f.Origin != "" {
			fmt.Fprint(out, evidence+glyphBranch+" ")
			wrapBody(out, findingIndent+2, evidence+"  ", fmt.Sprintf("made from %s, now gone", shortPath(f.Origin)))
		}
	}
	writeGroupNote(out, fmt.Sprintf("a script or alias may still run %s; jit can't see those",
		pluralWord(len(group), "it", "them")))
	action := group[0].Action
	if len(group) > 1 {
		action = unlaunchedTemplate
	}
	writeActionLine(out, strings.Repeat(" ", findingArrow), kindUnlaunched, action)
}
