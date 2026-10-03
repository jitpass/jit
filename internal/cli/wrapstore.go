// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/migrate"
	"github.com/jitpass/jit/internal/sealstore"
	"github.com/jitpass/jit/internal/selfpath"
	"github.com/jitpass/jit/internal/wrap"
)

// runStoreWrap is `jit wrap gcloud`, `jit wrap az` (or any tool of a
// store family): shim every installed member of the family, then seal the
// store (design/gcloud-sealed-store.md). Shims first: if the seal then
// fails, the plaintext store is still where the tool looks, and the run
// passes straight through to it with a note — never a tool that lost its
// login.
func runStoreWrap(cmd *cobra.Command, home string, entry wrap.CatalogEntry, openV vaultOpener, rep *wrapReport) error {
	out := cmd.OutOrStdout()
	store, ok := migrate.ToolStoreNamed(entry.Store)
	if !ok {
		// The kind is general; the sealing is per store. A catalog entry
		// naming a store this flow cannot seal is a build mistake, caught
		// here rather than by shimming tools at a store nobody fills.
		return fmt.Errorf("jit wrap: no sealing flow for the %q store", entry.Store)
	}
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("jit wrap: %w", err)
	}
	jitBinary, err := selfpath.Stable(exe)
	if err != nil {
		return fmt.Errorf("jit wrap: %w", err)
	}

	pathEnv := os.Getenv("PATH")
	var wrapped []string
	for _, tool := range wrap.StoreFamily(entry.Store) {
		if wrap.RealBinary(home, pathEnv, tool) == "" {
			continue // not installed: nothing to shim, and nothing reads the store through it
		}
		res, err := wrap.AddStore(home, tool, entry.Store, jitBinary)
		if err != nil {
			return fmt.Errorf("jit wrap: %w", err)
		}
		wrapped = append(wrapped, tool)
		if rep != nil {
			rep.Shims = append(rep.Shims, displayPath(home, res.ShimPath))
			if tool == entry.Tool {
				rep.shim(home, res.ShimPath)
			}
		}
	}

	v, err := openV()
	if err != nil {
		return fmt.Errorf("jit wrap: %w", err)
	}
	sealed, err := store.Seal(v, home)
	if err != nil {
		return fmt.Errorf("jit wrap: %w", err)
	}
	if rep != nil {
		rep.Store = entry.Store
		rep.StoreLoggedOut = sealed.LoggedOut
		if len(sealed.Files) > 0 {
			rep.Vaulted = append(rep.Vaulted, store.VaultPath)
		}
	}

	dir := displayPath(home, store.ConfigDir(home))
	fmt.Fprintf(out, "Wrapped %s (%s):\n", strings.Join(wrapped, ", "), entry.Doc)
	switch {
	case sealed.AlreadySealed:
		fmt.Fprintf(out, "  store  already in the vault; nothing in plaintext in %s\n", dir)
	case sealed.LoggedOut:
		fmt.Fprintf(out, "  store  not logged in yet; the next login goes straight to the vault\n")
	default:
		fmt.Fprintf(out, "  store  %s moved to the vault from %s\n", countWord(len(sealed.Files), "file", "files"), dir)
	}
	wrapBody(out, 0, "", hlCmds(fmt.Sprintf("From now on each `%s` run unseals the login for that run only; "+
		"your settings stay in %s. `jit wrap undo %s` puts it back.", entry.Store, dir, entry.Store)))

	if err := ensureShimOnPath(cmd, home, entry.Tool, rep); err != nil {
		return fmt.Errorf("jit wrap: %w", err)
	}
	if hint := wrapVerifyHint(entry); hint != "" {
		fmt.Fprint(out, hlCmds(fmt.Sprintf("Check it: open a new shell and run `%s`.\n", hint)))
	}
	return nil
}

// wrapVerifyHint is the check to suggest after a store wrap: the entry's
// own, or the family namesake's when a helper (which has none) was named.
func wrapVerifyHint(entry wrap.CatalogEntry) string {
	if entry.VerifyHint != "" {
		return entry.VerifyHint
	}
	if lead, ok := wrap.Lookup(entry.Store); ok {
		return lead.VerifyHint
	}
	return ""
}

// runStoreUndo is `jit wrap undo <tool>` for a store family: the login goes
// back to its plaintext files (a fresh Touch ID first, as for every action
// that writes a secret back to disk), then every shim of the family comes
// out. In that order: a declined Touch ID changes nothing, and shims never
// outlive a store they would unseal. The vault copy is kept, like every
// other unwrap keeps its secrets.
func runStoreUndo(cmd *cobra.Command, home, store string, m wrap.Manifest) error {
	out := cmd.OutOrStdout()
	s, ok := migrate.ToolStoreNamed(store)
	if !ok {
		return fmt.Errorf("jit wrap undo: no unsealing flow for the %q store", store)
	}
	var family []string
	for _, tool := range wrap.StoreFamily(store) {
		if m.Tools[tool].Store == store {
			family = append(family, tool)
		}
	}
	dir := displayPath(home, s.ConfigDir(home))

	if wrapDryRun {
		printDryRunBanner(out)
		fmt.Fprintf(out, "Unwrap %s:\n", strings.Join(family, ", "))
		fmt.Fprintf(out, "  "+glyphBullet+" login written back in plaintext to %s\n", dir)
		fmt.Fprintf(out, "  "+glyphBullet+" %s removed; the vault copy is kept\n", countWord(len(family), "shim", "shims"))
		printDryRunTrailer(out, "jit wrap undo "+store, false)
		return nil
	}

	ro, err := openVaultReadOnly()
	if err != nil {
		return fmt.Errorf("jit wrap undo: %w", err)
	}
	sealed, err := s.Sealed(ro)
	if err != nil {
		return fmt.Errorf("jit wrap undo: %w", err)
	}
	var restored []string
	if sealed {
		v, err := openVaultFreshAuth()
		if err != nil {
			return fmt.Errorf("jit wrap undo: %w", err)
		}
		if err := requireFreshUserPresence(v, "write "+s.Label+" back to disk in plaintext"); err != nil {
			return fmt.Errorf("jit wrap undo: %w", err)
		}
		if restored, err = s.Unseal(v, home); err != nil {
			return fmt.Errorf("jit wrap undo: %w", err)
		}
	}

	var last wrap.UndoResult
	for _, tool := range family {
		if last, err = wrap.Undo(home, tool); err != nil {
			return fmt.Errorf("jit wrap undo: %w", err)
		}
	}
	fmt.Fprintf(out, "Unwrapped %s.\n", strings.Join(family, ", "))
	if len(restored) > 0 {
		fmt.Fprintf(out, "  login  %s written back to %s\n", countWord(len(restored), "file", "files"), dir)
		fmt.Fprint(out, hlCmds(fmt.Sprintf("The vault copy was kept: `jit vault rm %s` removes it for good.\n", s.VaultPath)))
	}
	return finishUnwrapPath(out, home, last)
}

// storeWrapFindings is doctor's view of a sealed store beyond its shims
// (wrap.Doctor checks those): the two states in which the login sits in
// plaintext although the wrap is installed. Read-only, like every doctor
// probe: it names the fix and changes nothing.
//
//   - Folders a store run left behind when it was killed before cleaning
//     up, each holding the unsealed login. The next run of the tool removes
//     them, and so does a service start (D1); until then they are on disk.
//   - A plaintext store back in the tool's config dir: something logged in
//     without the shim. The run passes through to it (D7).
func storeWrapFindings(home, root string) []checkFinding {
	wrapped := map[string]bool{}
	if m, err := wrap.LoadManifest(home); err == nil {
		for _, e := range m.Tools {
			if e.Store != "" {
				wrapped[e.Store] = true
			}
		}
	}
	var out []checkFinding
	// A killed `jit aws-sso` leaves the same kind of folder (design/
	// aws-sso-sealed.md); no wrap is involved, so it is checked first.
	if left := staleRuns(awsSSORunBase(root)); len(left) > 0 {
		out = append(out, checkFinding{
			Kind: kindWrapStore,
			Path: awsSSORunBase(root),
			Detail: fmt.Sprintf("aws-sso: %s an interrupted run left the AWS login unsealed in %s",
				countWord(len(left), "folder where", "folders where"), displayPath(home, awsSSORunBase(root))),
			Action: "`jit service restart` removes it now; the next AWS call would too",
		})
	}
	for _, s := range migrate.ToolStores() {
		base := storeRunBase(root, s)
		if left := staleRuns(base); len(left) > 0 {
			out = append(out, checkFinding{
				Kind: kindWrapStore,
				Path: base,
				Detail: fmt.Sprintf("%s: %s an interrupted run left the login unsealed in %s",
					s.Name, countWord(len(left), "folder where", "folders where"), displayPath(home, base)),
				Action: "`jit service restart` removes it now; the next " + s.Name + " run would too",
			})
		}
		if !wrapped[s.Name] {
			continue
		}
		if secrets, _, err := splitPlaintext(s, s.ConfigDir(home)); err == nil && len(secrets) > 0 {
			out = append(out, checkFinding{
				Kind:   kindWrapStore,
				Path:   s.ConfigDir(home),
				Detail: fmt.Sprintf("%s: the login is back in plaintext in %s (something logged in without the shim)", s.Name, displayPath(home, s.ConfigDir(home))),
				Action: "`jit wrap " + s.Name + "` seals it again",
			})
		}
	}
	return out
}

// staleRuns lists the run folders whose owner is gone: what Sweep would
// remove, found without removing it.
func staleRuns(base string) []string {
	entries, err := os.ReadDir(base)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if pid, start, ok := sealstore.Owner(e.Name()); ok && !runOwnerAlive(pid, start) {
			out = append(out, filepath.Join(base, e.Name()))
		}
	}
	return out
}
