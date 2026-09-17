// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"os"
	"sort"
	"strings"

	"github.com/jitpass/jit/internal/profile"
	"github.com/jitpass/jit/internal/vault"
	"github.com/jitpass/jit/internal/wrap"
)

// `jit wrap list --format json` — the machine shape of the text table, plus
// what the table leaves to `jit doctor` and to the catalog: each tool's shim
// verdict, the real binary it fronts, the vault paths it injects and whether
// each is stored, and the catalog's own description of the tool. With --all,
// the catalog entries that are NOT wrapped join the list, with the same
// installed-path lookup, so a consumer (the JitPass app's Tools window) can
// say "installed, not wrapped" without guessing at PATH itself.
//
// Everything here is prompt-free: manifest, profile files, symlinks, PATH
// and envelope headers. The vault is opened bare and read-only for `stored`
// and the per-class counts — one os.Stat per path, never a decrypt, the same
// never-mutate-on-read discipline `jit vault list` documents.

type wrapListResult struct {
	// ShimDir is where the shims live; ShimDirOnPath says whether THIS
	// process's PATH carries it (a fact about the caller's shell, which is
	// why doctor calls the same check environmental), RcHasPathLine whether
	// future shells will.
	ShimDir       string         `json:"shim_dir"`
	ShimDirOnPath bool           `json:"shim_dir_on_path"`
	RcFile        string         `json:"rc_file"`
	RcHasPathLine bool           `json:"rc_has_path_line"`
	Tools         []wrapToolJSON `json:"tools"`
}

// wrapToolJSON is one tool. Kind is the catalog's word for wrapped catalog
// tools and for --all entries ("shim", "native", "capture", "rungrant"), and
// the manifest's for a hand-wrapped tool ("shim" for --env, "grant" for
// --with). Fields that do not apply to a kind are omitted rather than
// zeroed, so a consumer can tell "no profile" from "profile unknown".
type wrapToolJSON struct {
	Tool    string `json:"tool"`
	Kind    string `json:"kind"`
	Catalog bool   `json:"catalog"`
	Doc     string `json:"doc,omitempty"`
	// InstalledPath is the real binary beyond the shim dir on this PATH,
	// absent when the tool is not installed here (or not on this PATH).
	InstalledPath string `json:"installed_path,omitempty"`
	Wrapped       bool   `json:"wrapped"`
	AddedUnix     int64  `json:"added_unix,omitempty"`
	// Shim is "ok", "missing" or "broken" for a wrapped tool, with Detail
	// carrying doctor's sentence when it is not ok. Absent when not wrapped.
	Shim       string           `json:"shim,omitempty"`
	ShimDetail string           `json:"shim_detail,omitempty"`
	Profile    string           `json:"profile,omitempty"`
	Injects    []wrapInjectJSON `json:"injects,omitempty"`
	With       string           `json:"with,omitempty"`
	Capture    string           `json:"capture,omitempty"`
	VerifyHint string           `json:"verify_hint,omitempty"`
	// Sources are the catalog's plaintext locations for the token, "~"-rooted,
	// and TokenCommand the tool's own export command — where `jit wrap
	// <tool>` will look, for a consumer that wants to say so before running
	// it. Paths only, never contents.
	Sources      []string `json:"sources,omitempty"`
	TokenCommand string   `json:"token_command,omitempty"`
	// NativeCategory is the migrate category a native-kind tool delegates
	// to, and VaultSecrets how many secrets of that class the vault holds —
	// the prompt-free proxy for "has this tool's credential been migrated",
	// since the migration is what stamps that class. A grant-kind tool
	// carries the same count for its mount's class, under With.
	NativeCategory string `json:"native_category,omitempty"`
	VaultSecrets   int    `json:"vault_secrets,omitempty"`
	// KeyFound and KeySource answer "is there anything to wrap" for an
	// unwrapped shim tool, with --discover: the same discovery `jit wrap
	// <tool>` runs (its config files, then its own export command such as
	// `gh auth token`), with the value discarded here. KeySource is the
	// "~"-rooted file or the command. Absent without --discover, so a
	// consumer can tell "not looked" from "looked and found nothing".
	KeyFound  *bool  `json:"key_found,omitempty"`
	KeySource string `json:"key_source,omitempty"`
}

// wrapInjectJSON is one env var an env-wrap fills: from which vault path,
// and whether that path currently holds a secret. A wrapped tool whose path
// is not stored runs, but with an empty variable — the state the docs'
// "`jit vault set` first" instruction exists for.
type wrapInjectJSON struct {
	Var       string `json:"var"`
	VaultPath string `json:"vault_path,omitempty"`
	Stored    bool   `json:"stored"`
}

// gatherWrapListing builds the JSON listing. Errors are reserved for an
// unreadable manifest; everything else degrades per field, because a
// listing that fails outright over one unreadable profile answers nothing.
func gatherWrapListing(home string, all, discover bool) (wrapListResult, error) {
	manifest, err := wrap.LoadManifest(home)
	if err != nil {
		return wrapListResult{}, err
	}
	pathEnv := os.Getenv("PATH")
	shell := os.Getenv("SHELL")
	res := wrapListResult{
		ShimDir:       wrap.ShimDir(home),
		ShimDirOnPath: wrap.ShimDirOnPath(home, pathEnv),
		RcFile:        wrap.RcFile(home, shell),
		RcHasPathLine: wrap.RcHasPathLine(home, shell),
		Tools:         []wrapToolJSON{},
	}
	store := newWrapVaultLookup()

	for _, tool := range sortedTools(manifest) {
		entry := manifest.Tools[tool]
		st := wrap.CheckTool(home, pathEnv, tool, entry)
		row := wrapToolJSON{
			Tool:          tool,
			Kind:          "shim",
			InstalledPath: st.InstalledPath,
			Wrapped:       true,
			AddedUnix:     entry.AddedAt.Unix(),
			Shim:          st.Shim,
			ShimDetail:    st.Detail,
		}
		if entry.AddedAt.IsZero() {
			row.AddedUnix = 0
		}
		if st.Shim == wrap.ShimOK && st.ProfileDetail != "" {
			row.Shim, row.ShimDetail = wrap.ShimBroken, st.ProfileDetail
		}
		switch {
		case entry.IsGrant():
			row.Kind, row.With = "grant", entry.With
		case entry.IsCapture():
			row.Kind, row.Capture = "capture", entry.Capture
		case entry.IsRunGrant():
			row.Kind = "rungrant"
		default:
			row.Profile = entry.Profile
			row.Injects = wrapInjectsFromProfile(home, entry, store)
		}
		if ce, ok := wrap.Lookup(tool); ok {
			applyCatalog(&row, ce)
		}
		res.Tools = append(res.Tools, row)
	}

	if all {
		for _, tool := range wrap.CatalogTools() {
			if _, wrapped := manifest.Tools[tool]; wrapped {
				continue
			}
			ce, _ := wrap.Lookup(tool)
			row := wrapToolJSON{
				Tool:          tool,
				Kind:          string(ce.Kind),
				InstalledPath: wrap.RealBinary(home, pathEnv, tool),
			}
			applyCatalog(&row, ce)
			if ce.Kind == wrap.KindShim {
				for _, v := range ce.Order {
					p := ce.VaultPath(v)
					row.Injects = append(row.Injects, wrapInjectJSON{Var: v, VaultPath: p, Stored: store.exists(p)})
				}
				// Only for a tool that is installed: the export command
				// needs the binary, and a key for a tool that is not here
				// is not this listing's question.
				if discover && row.InstalledPath != "" {
					found, source := discoverKey(home, ce)
					row.KeyFound, row.KeySource = &found, source
				}
			}
			if ce.Kind == wrap.KindNative {
				row.VaultSecrets = store.classCount(ce.NativeCategory)
			}
			// The migrate category behind a grant wrap stamps its mount
			// name as the class, so the same count says whether the file
			// is vaulted yet.
			if ce.Kind == wrap.KindGrant {
				row.With = ce.Grant
				row.VaultSecrets = store.classCount(ce.Grant)
			}
			res.Tools = append(res.Tools, row)
		}
	}
	return res, nil
}

// discoverKey runs the catalog's discovery for a tool and reports only
// whether it found a key and where. The value DiscoverToken returns is
// dropped on the floor here and never serialized: a listing answers
// "is there anything to wrap", and `jit wrap <tool>` is what moves it.
// An error reads as not found; the wrap flow reports it properly.
func discoverKey(home string, ce wrap.CatalogEntry) (bool, string) {
	d, found, err := wrap.DiscoverToken(home, ce)
	if err != nil || !found {
		return false, ""
	}
	if d.Source != nil {
		return true, d.Source.Path
	}
	return true, strings.Join(ce.TokenCommand, " ")
}

// applyCatalog copies the catalog's description onto a row. Kind is left
// alone for a wrapped tool: the manifest knows how it was actually wrapped
// (a catalog shim tool hand-wrapped with --grant is a grant).
func applyCatalog(row *wrapToolJSON, ce wrap.CatalogEntry) {
	row.Catalog = true
	row.Doc = ce.Doc
	row.VerifyHint = ce.VerifyHint
	row.NativeCategory = ce.NativeCategory
	for _, s := range ce.Sources {
		row.Sources = append(row.Sources, s.Path)
	}
	if len(ce.TokenCommand) > 0 {
		row.TokenCommand = strings.Join(ce.TokenCommand, " ")
	}
}

// wrapInjectsFromProfile reads an env-wrap's profile manifest for its
// var→path map, in the manifest's own order. When the profile cannot be
// read (CheckTool has already said so in ProfileDetail), the manifest's
// recorded var names stand in with no path, so the row still says what the
// tool expects to receive.
func wrapInjectsFromProfile(home string, entry wrap.Entry, store *wrapVaultLookup) []wrapInjectJSON {
	var out []wrapInjectJSON
	if path, err := profile.Path(home, entry.Profile); err == nil {
		if p, order, err := profile.LoadFileOrdered(path); err == nil {
			for _, v := range order {
				out = append(out, wrapInjectJSON{Var: v, VaultPath: p[v], Stored: store.exists(p[v])})
			}
			return out
		}
	}
	for _, v := range entry.Vars {
		out = append(out, wrapInjectJSON{Var: v})
	}
	return out
}

// wrapVaultLookup answers "is this path stored" and "how many secrets carry
// this class" on a bare read-only vault: Exists is one os.Stat and Info reads
// an envelope header, so neither dials the agent, prompts, or writes. A vault
// that cannot be opened answers false and 0 — the honest reading for a
// listing that promises to always run.
type wrapVaultLookup struct {
	v      *vault.Vault
	counts map[string]int
}

func newWrapVaultLookup() *wrapVaultLookup {
	root, err := vaultRootDir()
	if err != nil {
		return &wrapVaultLookup{}
	}
	return &wrapVaultLookup{v: &vault.Vault{Root: root}}
}

func (l *wrapVaultLookup) exists(path string) bool {
	if l.v == nil || path == "" {
		return false
	}
	ok, err := l.v.Exists(path)
	return err == nil && ok
}

func (l *wrapVaultLookup) classCount(class string) int {
	if l.v == nil || class == "" {
		return 0
	}
	if l.counts == nil {
		l.counts = map[string]int{}
		paths, err := l.v.List()
		if err != nil {
			return 0
		}
		sort.Strings(paths)
		for _, p := range paths {
			if info, err := l.v.Info(p); err == nil && info.Class != "" {
				l.counts[info.Class]++
			}
		}
	}
	return l.counts[class]
}
