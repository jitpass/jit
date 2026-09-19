// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jitpass/jit/internal/launchers"
	"github.com/jitpass/jit/internal/mount"
	"github.com/jitpass/jit/internal/projectrecord"
	"github.com/jitpass/jit/internal/vault"
)

// Reconciling the two halves of what jit knows about a mount: the registry,
// which is this Mac's list of what it serves and holds absolute paths, and
// the project records, which travel with a project and hold relative ones
// (design/project-relocation.md).
//
// Three states come out of the comparison, and only the third is what doctor
// used to report for all of them:
//
//   - RELOCATED: a registry entry whose paths are gone, and a project found
//     elsewhere that carries the record for it. Repairable — one registry
//     line.
//   - UNREGISTERED: a project carrying a record whose mount exists on disk
//     and that this Mac's registry does not list. This is the duplicated
//     folder, and it is the quietest failure jit had: the copy looks like a
//     working project, and reading its .env blocks forever because nothing
//     writes to a FIFO nobody serves.
//   - STALE: gone, and nothing found. kindMountStale, which now says so
//     honestly rather than asserting the project was deleted.

// relocationFindings compares the registry against every project record the
// home walk found. Returns its findings plus the mount paths it explained,
// so the caller can drop the kindMountStale findings they supersede.
func relocationFindings(m *launchers.Map, root, home string, v *vault.Vault) ([]checkFinding, map[string]bool) {
	if m == nil || root == "" {
		return nil, nil
	}
	entries, err := mount.LoadRegistry(mount.RegistryPath(root))
	if err != nil {
		return nil, nil
	}
	records := loadProjectRecords(m)
	if len(records) == 0 && len(entries) == 0 {
		return nil, nil
	}

	registered := map[string]bool{}
	for _, e := range entries {
		registered[canonicalPath(e.MountPath)] = true
	}

	var findings []checkFinding
	explained := map[string]bool{}

	// Relocated: a dead registry entry whose project turned up elsewhere.
	origins := newOriginGroups(v)
	for _, e := range entries {
		if _, err := os.Stat(e.ProfilePath); !os.IsNotExist(err) {
			continue
		}
		matches := matchRelocated(records, e, origins)
		switch len(matches) {
		case 0:
			// Left to kindMountStale, which says it could not find it.
		case 1:
			explained[canonicalPath(e.MountPath)] = true
			findings = append(findings, relocatedFinding(e, matches[0], home))
		default:
			explained[canonicalPath(e.MountPath)] = true
			findings = append(findings, ambiguousFinding(e, matches, home))
		}
	}

	// Unregistered: a project's own record naming a mount this Mac does not
	// serve. Only ever reported for a file that IS there — a record naming a
	// mount nobody created describes nothing, and saying so would fire on
	// every clone of a repo whose .env was never migrated here.
	for _, r := range records {
		for _, mountPath := range r.mounts {
			if registered[canonicalPath(mountPath)] {
				continue
			}
			info, err := os.Lstat(mountPath)
			if err != nil || info.Mode()&os.ModeNamedPipe == 0 {
				continue
			}
			findings = append(findings, unregisteredFinding(mountPath, r, home))
		}
	}
	sort.SliceStable(findings, func(i, j int) bool { return findings[i].Path < findings[j].Path })
	return findings, explained
}

// projectRecord is one record, resolved against its own project.
type projectRecord struct {
	manifest string   // the manifest it sits beside
	root     string   // the project root
	name     string   // the manifest's name, which is the profile's name
	group    string   // the vault group it recorded, "" when unknown
	mounts   []string // absolute, every one validated by projectrecord.Resolve
}

// loadProjectRecords reads the record beside every manifest the home walk
// found. A record that will not parse, or whose paths do not validate, is
// skipped in silence: it describes a project jit can simply fail to
// recognise, which is the state without any record at all.
func loadProjectRecords(m *launchers.Map) []projectRecord {
	var out []projectRecord
	for _, p := range m.Profiles {
		recordPath := projectrecord.Path(p.Path)
		r, ok, err := projectrecord.Read(recordPath)
		if err != nil || !ok {
			continue
		}
		root := projectrecord.ProjectRoot(recordPath)
		pr := projectRecord{manifest: p.Path, root: root, name: p.Name, group: r.Group}
		for _, rel := range r.Mounts {
			abs, rerr := projectrecord.Resolve(root, rel)
			if rerr != nil {
				continue
			}
			pr.mounts = append(pr.mounts, abs)
		}
		if len(pr.mounts) > 0 {
			out = append(out, pr)
		}
	}
	return out
}

// originGroups answers "which vault group was born at this path", from the
// provenance already on every secret.
//
// vault.Meta.Origin is frozen at birth and explicitly allowed to go stale,
// which every other consumer treats as a limitation — and which is exactly
// what makes it right here: the path it still names is the OLD one, which is
// the path the dead registry entry also names. GroupID beside it is 128 bits
// that survive any rename, so the two together identify a moved project
// without a single filename comparison.
type originGroups struct{ byOrigin map[string]string }

func newOriginGroups(v *vault.Vault) *originGroups {
	g := &originGroups{byOrigin: map[string]string{}}
	if v == nil {
		return g
	}
	paths, err := v.List()
	if err != nil {
		return g
	}
	secrets, _ := splitBackupPaths(paths)
	for _, p := range secrets {
		info, err := v.Info(p) // auth-free: never touches the KeyWrapper
		if err != nil || info.Origin == "" || info.GroupID == "" {
			continue
		}
		if seen, ok := g.byOrigin[info.Origin]; ok && seen != info.GroupID {
			g.byOrigin[info.Origin] = "" // two groups claim it: no answer
			continue
		}
		g.byOrigin[info.Origin] = info.GroupID
	}
	return g
}

func (g *originGroups) groupAt(mountPath string) string {
	return g.byOrigin[shortPath(mountPath)]
}

// matchRelocated finds the projects that could be where this dead entry went.
//
// The group is tried first and alone when it answers, because it is the only
// evidence that does not involve guessing from a name: the secrets born at
// this mount path still record the group they were minted in, and the project
// that carries that group in its record is that project, wherever it now
// sits. Names are the fallback, and two projects owning an `api` profile is
// not exotic — which is why several matches refuse rather than pick.
func matchRelocated(records []projectRecord, e mount.Entry, origins *originGroups) []projectRecord {
	if group := origins.groupAt(e.MountPath); group != "" {
		var byGroup []projectRecord
		for _, r := range records {
			if r.group != "" && r.group == group {
				byGroup = append(byGroup, r)
			}
		}
		if len(byGroup) > 0 {
			return byGroup
		}
	}
	wantName := strings.TrimSuffix(filepath.Base(e.ProfilePath), filepath.Ext(e.ProfilePath))
	wantMount := filepath.Base(e.MountPath)
	var byName []projectRecord
	for _, r := range records {
		if r.name != wantName {
			continue
		}
		for _, mp := range r.mounts {
			if filepath.Base(mp) == wantMount {
				byName = append(byName, r)
				break
			}
		}
	}
	return byName
}

func relocatedFinding(e mount.Entry, to projectRecord, home string) checkFinding {
	return checkFinding{
		Kind:   kindMountMoved,
		Scope:  scopeMount,
		Path:   e.MountPath,
		Detail: fmt.Sprintf("%s moved to %s: the mount registered at the old path serves nothing, and anything reading the file there gets nothing", displayPath(home, filepath.Dir(e.MountPath)), displayPath(home, to.root)),
		Action: "`jit mount relocate " + shortPath(to.root) + "` re-points the registration; no secret is touched",
	}
}

func ambiguousFinding(e mount.Entry, matches []projectRecord, home string) checkFinding {
	roots := make([]string, 0, len(matches))
	for _, r := range matches {
		roots = append(roots, displayPath(home, r.root))
	}
	sort.Strings(roots)
	return checkFinding{
		Kind:  kindMountMoved,
		Scope: scopeMount,
		Path:  e.MountPath,
		Detail: fmt.Sprintf("%s is gone and %s look like where it went (%s), so jit will not choose",
			displayPath(home, filepath.Dir(e.MountPath)), countWord(len(roots), "project", "projects"), strings.Join(roots, ", ")),
		Action: "`jit mount relocate <project>` with the one you mean",
	}
}

func unregisteredFinding(mountPath string, r projectRecord, home string) checkFinding {
	return checkFinding{
		Kind:   kindMountUnregistered,
		Scope:  scopeMount,
		Path:   mountPath,
		Detail: fmt.Sprintf("%s is a jit mount this Mac does not serve, so reading it blocks forever: a copied or cloned project brings the file with it, never the registration", displayPath(home, mountPath)),
		Action: "`jit mount register " + shortPath(r.root) + "` serves it here, or delete the file if the copy does not need it",
	}
}

// dropSupersededStaleMounts removes the kindMountStale findings that
// relocationFindings explained: one event must not produce two rows, and the
// relocated one is strictly more informative.
func dropSupersededStaleMounts(findings []checkFinding, explained map[string]bool) []checkFinding {
	if len(explained) == 0 {
		return findings
	}
	out := findings[:0]
	for _, f := range findings {
		if f.Kind == kindMountStale && explained[canonicalPath(f.Path)] {
			continue
		}
		out = append(out, f)
	}
	return out
}
