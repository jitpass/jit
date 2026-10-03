// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/wrap"
)

// wrapReport is `jit wrap <tool> --format json`: what the wrap did, in the
// terms the JitPass app's Wrapped sheet draws as rows, instead of parsing
// the text. Paths, names and vault paths, never a value.
type wrapReport struct {
	Tool string `json:"tool"`
	// Kind is the catalog's: "shim", "native", "grant", "capture",
	// "rungrant" or "store".
	Kind string `json:"kind"`
	// Wrapped is whether the wrap finished: the shim and profile are in
	// place, or for a native tool the migration ran.
	Wrapped bool `json:"wrapped"`
	// Key is a shim tool's credential: where it came from and where it is.
	Key *wrapKeyReport `json:"key,omitempty"`
	// Shim is the ~-path of the installed shim, Profile the jit profile it
	// runs under (shim kind only).
	Shim    string `json:"shim,omitempty"`
	Profile string `json:"profile,omitempty"`
	// Grant is the global mount a grant wrap runs the tool with, and
	// GrantMigrated whether that mount's file is in the vault yet; until it
	// is, the shim has nothing to serve.
	Grant         string `json:"grant,omitempty"`
	GrantMigrated *bool  `json:"grant_migrated,omitempty"`
	// Store is the login store a store wrap sealed (gcloud), and Shims the
	// ~-paths of every shim in its family that was installed: one wrap
	// shims gcloud, bq, gsutil and the two credential helpers together.
	// StoreLoggedOut says the store holds no login yet; the next login
	// through the shim is captured into it.
	Store          string   `json:"store,omitempty"`
	Shims          []string `json:"shims,omitempty"`
	StoreLoggedOut bool     `json:"store_logged_out,omitempty"`
	// Vaulted are other secrets the wrap moved into the vault (clisso's
	// client secrets), by vault path.
	Vaulted []string `json:"vaulted"`
	// Injects are a hand wrap's variables (`jit wrap add --env`), each with
	// its vault path and whether that path holds a secret yet.
	Injects []wrapInjectJSON `json:"injects,omitempty"`
	// PathAddedTo is the ~-path of the shell config the shim's PATH line
	// was added to, when this wrap added it.
	PathAddedTo string `json:"path_added_to,omitempty"`
	// Migrate is a native tool's migration: the same document as
	// `jit migrate <file> --format json`.
	Migrate *migrateReport `json:"migrate,omitempty"`
	Errors  []string       `json:"errors"`
	// Report is the text the wrap would have printed, stderr included.
	Report string `json:"report"`
}

// wrapKeyReport is a shim tool's key. From is "file" (Source is the
// ~-path it was read from), "keyring" (Source is the tool's own export
// command), "vault" (it was already stored) or "none" (nothing found;
// the tool runs with an empty variable until `jit vault set`). Scrubbed
// says the plaintext was removed from Source, after an encrypted backup.
type wrapKeyReport struct {
	Var       string `json:"var"`
	VaultPath string `json:"vault_path"`
	From      string `json:"from"`
	Source    string `json:"source,omitempty"`
	Scrubbed  bool   `json:"scrubbed"`
}

// shim and key record their part; both are no-ops on a nil report, so the
// text flow calls them unconditionally.
func (r *wrapReport) shim(home, path string) {
	if r != nil {
		r.Shim = displayPath(home, path)
	}
}

func (r *wrapReport) key(name, vaultPath, from, source string) {
	if r != nil {
		r.Key = &wrapKeyReport{Var: name, VaultPath: vaultPath, From: from, Source: source}
	}
}

// runCatalogWrapJSON runs the wrap with its text captured and writes one
// wrapReport, after a failure too: the steps that finished are real.
func runCatalogWrapJSON(cmd *cobra.Command, tool string) error {
	if wrapDryRun {
		return errors.New("jit wrap: --format json is for a real run; drop --dry-run")
	}
	entry, ok := wrap.Lookup(tool)
	if !ok {
		return runCatalogWrap(cmd, tool, nil) // the not-in-catalog error, as text
	}
	if entry.Kind == wrap.KindNative && !wrapYes {
		return fmt.Errorf("jit wrap: --format json needs --yes for %s, whose migration asks to confirm", tool)
	}
	stdout := cmd.OutOrStdout()
	var text bytes.Buffer
	cmd.SetOut(&text)
	cmd.SetErr(&text)
	defer func() { cmd.SetOut(nil); cmd.SetErr(nil) }()

	rep := &wrapReport{Tool: tool, Kind: string(entry.Kind), Vaulted: []string{}, Errors: []string{}}
	runErr := runCatalogWrap(cmd, tool, rep)
	if runErr != nil {
		rep.Errors = append(rep.Errors, runErr.Error())
	} else if rep.Kind != string(wrap.KindNative) {
		rep.Wrapped = true
	}
	rep.Report = text.String()
	if err := writeJSON(stdout, rep); err != nil {
		return fmt.Errorf("jit wrap: writing report: %w", err)
	}
	if runErr != nil {
		cmd.SilenceErrors = true
		defer func() { cmd.SilenceErrors = false }()
	}
	return runErr
}

// runNativeWrapJSON runs a native tool's delegated migration as
// `jit migrate <file> --only <category> --yes --format json` and embeds its
// document. Wrapped follows the migration's own Applied.
func runNativeWrapJSON(cmd *cobra.Command, self string, d wrap.NativeDelegation, rep *wrapReport) error {
	args := append(append([]string{}, d.Command...), "--yes", "--format", "json")
	var doc bytes.Buffer
	sub := exec.Command(self, args...) // #nosec G204 -- self + compiled-in catalog args
	sub.Stdin, sub.Stdout, sub.Stderr = cmd.InOrStdin(), &doc, cmd.ErrOrStderr()
	runErr := sub.Run()
	var mr migrateReport
	if err := json.Unmarshal(doc.Bytes(), &mr); err != nil {
		if runErr != nil {
			return runErr
		}
		return fmt.Errorf("reading the migration's report: %w", err)
	}
	rep.Migrate = &mr
	rep.Wrapped = mr.Applied && len(mr.Errors) == 0
	return runErr
}

// runWrapAddJSON is `jit wrap add --format json`, the same document as a
// catalog wrap's, with Injects for --env.
func runWrapAddJSON(cmd *cobra.Command, tool string) error {
	stdout := cmd.OutOrStdout()
	var text bytes.Buffer
	cmd.SetOut(&text)
	cmd.SetErr(&text)
	defer func() { cmd.SetOut(nil); cmd.SetErr(nil) }()

	rep := &wrapReport{Tool: tool, Vaulted: []string{}, Errors: []string{}}
	runErr := runWrapAdd(cmd, tool, rep)
	if runErr != nil {
		rep.Errors = append(rep.Errors, runErr.Error())
	} else {
		rep.Wrapped = true
	}
	rep.Report = text.String()
	if err := writeJSON(stdout, rep); err != nil {
		return fmt.Errorf("jit wrap add: writing report: %w", err)
	}
	if runErr != nil {
		cmd.SilenceErrors = true
		defer func() { cmd.SilenceErrors = false }()
	}
	return runErr
}
