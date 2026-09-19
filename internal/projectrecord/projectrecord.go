// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

// Package projectrecord owns the file that lets jit recognise a project
// after it has been renamed, moved or copied: `<name>.mount`, written beside
// the profile manifest it belongs to.
//
// The problem it exists for is in design/project-relocation.md. In short: the
// mount registry records ABSOLUTE paths and nothing reconciles them, so a
// folder that travels leaves an entry pointing at nothing, its FIFO serving
// nobody, and a doctor finding that cannot tell a deleted project from a
// renamed one. The registry is right to be machine-local — it is the list of
// what this Mac's service actually serves — so the missing half is a record
// that travels WITH the project and says what the project is.
//
// Two rules give this file its shape, and neither is negotiable.
//
// RELATIVE PATHS ONLY. The record is committed, so it crosses machines, and
// an absolute path is true on exactly one. The cautionary case is already
// in-tree: internal/migrate's `.source` sidecar records absolute config paths
// and stats them, so on a second machine every owner silently drops to zero,
// which flips claimMCPNamespace into its adopt-and-overwrite branch. A path
// here is relative to the project root, which is the record's own store's
// grandparent — `scopeOfManifest`'s existing answer, adopted rather than
// invented.
//
// IT AUTHORIZES NOTHING. The record names no vault path, no grant and no
// command: it says "this manifest backs a mount at this relative path", and
// nothing more. That is what keeps it in the same class as
// `<project>/.jit/config.yaml`, which jit already reads from a project with
// no confirmation — repo content may choose among behaviours the user already
// authorized, never enlarge the set (docs/getting-started/how-it-fits.md,
// "The rule that never bends"). The service never reads this file; only
// `jit doctor` and the commands a human runs do.
package projectrecord

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Suffix names the record written beside a manifest: `app.yaml` ->
// `app.mount`. A sibling, like `.source` and the `.tmpl` templates, because
// one project can hold several manifests and one manifest can back several
// mounts — a single file at the project root had to answer both and could
// answer neither.
const Suffix = ".mount"

const header = "jit project record — no secret values, no vault paths, no absolute paths.\n" +
	"Lets jit recognise this project after it is renamed, moved or copied.\n" +
	"Paths are relative to the project root (this file's store's parent)."

// Record is one manifest's mounts, as they sit inside the project.
type Record struct {
	// Mounts are the mount paths this manifest backs, relative to the
	// project root, in registry order.
	Mounts []string `yaml:"mounts"`
	// Group is the vault group id the manifest's secrets were born under
	// (vault.Meta.GroupID): 128 bits that survive any rename of the source or
	// of the secrets' vault paths, because nothing about it is derived from a
	// path. It is a TIE-BREAKER and never an authority — it decides which
	// candidate is offered when several match, and a human still sees both
	// paths before anything is written. Empty when unknown, which is not an
	// error: matching falls back to the manifest's own name and contents.
	Group string `yaml:"group,omitempty"`
}

// Path returns the record belonging to the manifest at manifestPath.
func Path(manifestPath string) string {
	return strings.TrimSuffix(manifestPath, filepath.Ext(manifestPath)) + Suffix
}

// ProjectRoot returns the project a record at recordPath describes: its
// store's grandparent, since a record lives at
// `<root>/.jit/profiles/<name>.mount`. Matches launchers.scopeOfManifest, so
// the tree keeps one answer to "which directory is the project" rather than
// gaining a third.
func ProjectRoot(recordPath string) string {
	return filepath.Dir(filepath.Dir(filepath.Dir(recordPath)))
}

// Read loads the record at path. A missing file is (Record{}, false, nil):
// most projects have no record yet, and that is not a failure.
func Read(path string) (Record, bool, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- a jit-written sibling of a manifest; every path it CONTAINS is validated by Resolve
	if os.IsNotExist(err) {
		return Record{}, false, nil
	}
	if err != nil {
		return Record{}, false, err
	}
	var r Record
	if err := yaml.Unmarshal(data, &r); err != nil {
		return Record{}, false, fmt.Errorf("reading %s: %w", path, err)
	}
	return r, true, nil
}

// Write stores r at path, atomically enough for a file nothing serves from:
// a torn record is re-derivable from the registry, unlike a torn manifest.
func Write(path string, r Record) error {
	node := &yaml.Node{Kind: yaml.MappingNode, HeadComment: header}
	mounts := &yaml.Node{Kind: yaml.SequenceNode}
	for _, m := range r.Mounts {
		mounts.Content = append(mounts.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: m})
	}
	node.Content = append(node.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: "mounts"}, mounts)
	if r.Group != "" {
		node.Content = append(node.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Value: "group"},
			&yaml.Node{Kind: yaml.ScalarNode, Value: r.Group})
	}
	data, err := yaml.Marshal(node)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// Add upserts one mount into the record beside manifestPath, converting it to
// a project-relative path. A mount already recorded is left alone, so
// re-running migrate rewrites nothing.
func Add(manifestPath, mountPath, group string) error {
	recordPath := Path(manifestPath)
	root := ProjectRoot(recordPath)
	rel, err := relativeTo(root, mountPath)
	if err != nil {
		// A mount outside its own manifest's project is not a shape this
		// record can describe, and inventing a `../..` path to reach it is
		// exactly what the no-absolute-paths rule exists to prevent. The
		// registry still has it; only the record skips it.
		return err
	}
	r, _, err := Read(recordPath)
	if err != nil {
		return err
	}
	for _, m := range r.Mounts {
		if m == rel {
			if group != "" && r.Group == "" {
				r.Group = group
				return Write(recordPath, r)
			}
			return nil
		}
	}
	r.Mounts = append(r.Mounts, rel)
	if r.Group == "" {
		r.Group = group
	}
	return Write(recordPath, r)
}

// Resolve turns one recorded relative path into an absolute one under root,
// refusing anything that could name a file outside the project.
//
// This is the gate, and it is deliberately the same shape `jit migrate undo`
// was given after the 2026-07 self-review found that an unauthenticated index
// could "redirect a decrypted secret to an arbitrary destination, using the
// user's own authenticated undo", and that the restore followed symlinks. A
// mount path is a serve destination, so it gets the same treatment: no
// absolute path, no `..` segment, canonicalised, still under the project
// root afterwards, and never a symlink.
func Resolve(root, rel string) (string, error) {
	if rel == "" {
		return "", fmt.Errorf("empty mount path")
	}
	if filepath.IsAbs(rel) {
		return "", fmt.Errorf("%q is absolute; a project record holds relative paths only", rel)
	}
	for _, seg := range strings.Split(filepath.ToSlash(rel), "/") {
		if seg == ".." {
			return "", fmt.Errorf("%q leaves the project", rel)
		}
	}
	abs := filepath.Join(root, rel)
	// Re-checked AFTER Join and Clean rather than trusting the segment scan:
	// a filesystem path derived from file content is exactly where a single
	// missed edge case becomes a traversal bug.
	if !within(root, abs) {
		return "", fmt.Errorf("%q leaves the project", rel)
	}
	if info, err := os.Lstat(abs); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("%s is a symlink; a mount is never followed through one", rel)
	}
	return abs, nil
}

// relativeTo is Resolve's inverse for writing: the project-relative form of
// an absolute mount path, refused when it is not inside the project.
func relativeTo(root, abs string) (string, error) {
	rel, err := filepath.Rel(root, abs)
	if err != nil {
		return "", err
	}
	if !within(root, filepath.Join(root, rel)) || strings.HasPrefix(rel, "..") {
		return "", fmt.Errorf("%s is not inside %s", abs, root)
	}
	return filepath.ToSlash(rel), nil
}

func within(dir, p string) bool {
	rel, err := filepath.Rel(dir, p)
	if err != nil {
		return false
	}
	return rel == "." || (!strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != "..")
}
