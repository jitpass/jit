// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package wrap

import (
	"path/filepath"
	"sort"
	"strings"
)

// Kind says which mechanism serves a catalog entry (docs/internal/WRAP-PLAN.md §3.2).
type Kind string

const (
	// KindShim: the tool reads its credential from an env var; wrap
	// installs a PATH shim and injects via jit run.
	KindShim Kind = "shim"
	// KindNative: jit already hooks this tool's own pluggable credential
	// mechanism (aws credential_process, terraform credentials_helper) —
	// stronger than a shim because the tool's whole ecosystem (SDKs,
	// login/logout) consults it. `jit wrap <tool>` delegates to the
	// existing migrate flow instead of installing a shim.
	KindNative Kind = "native"
)

// TokenSource names one place a tool's plaintext credential lives today and
// how to pull it out. Selector segments are separated by "/" (not "."):
// YAML keys like "github.com" contain dots themselves.
type TokenSource struct {
	Path     string // "~"-rooted file path; expand with ExpandHome
	Format   string // "yaml", "toml", "json", or "raw" — must have an extractor registered
	Selector string // format-specific, e.g. "github.com/oauth_token"; empty for "raw", where the whole file is the value
}

// CatalogEntry is one supported CLI. Pure data — behavior lives in the
// extractors, scrub, and the wrap flow; entries live in catalog_data.go.
type CatalogEntry struct {
	Tool string
	Kind Kind
	Doc  string // one line: what token this is, shown in audit evidence and wrap output

	// KindShim fields. EnvVars maps env var name -> vault subpath under
	// wrap-<tool>/; Order is the profile's variable order. Discovery
	// (Sources/TokenCommand) fills Order[0]'s secret; entries with no
	// Sources and no TokenCommand are wrappable but need `jit vault set`
	// first (e.g. a key that only ever lived in the user's head).
	EnvVars map[string]string
	Order   []string
	// Sources are tried in order; the first file+selector that yields a
	// value wins and becomes the scrub target.
	Sources []TokenSource
	// TokenCommand is a fallback when no Source matches: the tool's own
	// documented way to print its active token (e.g. `gh auth token` for
	// keyring-stored logins). Nothing is scrubbed in this case — the
	// keyring copy is already encrypted at rest.
	TokenCommand []string
	VerifyHint   string // suggested check after wrapping, e.g. "gh auth status"

	// KindNative fields.
	NativeCategory string // the `jit migrate home --only <category>` token
}

// Lookup returns the catalog entry for tool.
func Lookup(tool string) (CatalogEntry, bool) {
	e, ok := catalog[tool]
	return e, ok
}

// CatalogTools returns every cataloged tool name, sorted, for help text and
// error messages.
func CatalogTools() []string {
	names := make([]string, 0, len(catalog))
	for t := range catalog {
		names = append(names, t)
	}
	sort.Strings(names)
	return names
}

// VaultPath returns the vault path a catalog entry stores varName's value
// at: wrap-<tool>/<subpath>.
func (e CatalogEntry) VaultPath(varName string) string {
	return ProfileName(e.Tool) + "/" + e.EnvVars[varName]
}

// PrimaryVar is the env var discovery fills — Order[0]. Every current shim
// entry has exactly one variable; the slice exists so a future multi-var
// tool doesn't need a schema change.
func (e CatalogEntry) PrimaryVar() string {
	if len(e.Order) == 0 {
		return ""
	}
	return e.Order[0]
}

// ExpandHome resolves a catalog "~"-rooted path against home.
func ExpandHome(home, path string) string {
	if path == "~" {
		return home
	}
	if strings.HasPrefix(path, "~/") {
		return filepath.Join(home, path[2:])
	}
	return path
}
