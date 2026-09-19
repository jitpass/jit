// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/profile"
	"github.com/jitpass/jit/internal/vault"
)

// `jit vault rm` refuses a secret something still uses. It used to warn and
// delete anyway, and `--yes` skipped everything but Touch ID. The menu bar
// app runs it with `--yes`, and that is how two MCP servers stopped
// starting: their profiles still named secrets rm had just deleted, history
// and all (design/doctor-repair.md, "The incident"). The engine refuses, not
// only the app, because every script passes --yes too.

var (
	vaultRmBreakProfiles bool
	vaultRmDryRun        bool
	vaultRmFormat        string
)

// invocationDeleted and invocationBroke are what a successful rm hands the
// audit record (auditlog.Record.Deleted/Broke): the expanded paths it
// removed and the profiles and pointer files that lost a secret. Package
// vars for the reason invocationAuth is one: the audit hook runs around
// Execute and has no other channel to the command.
var (
	invocationDeleted []string
	invocationBroke   []string
)

// rmInUseJSON is one (path, user) pair in the --dry-run --format json
// output: a profile (with its store, project, mount and known launchers)
// or a pointer file.
type rmInUseJSON struct {
	Path        string   `json:"path"`
	Profile     string   `json:"profile,omitempty"`
	Scope       string   `json:"scope,omitempty"`
	Project     string   `json:"project,omitempty"`
	Mount       string   `json:"mount,omitempty"`
	PointerFile string   `json:"pointer_file,omitempty"`
	LaunchedBy  []string `json:"launched_by,omitempty"`
}

// rmDryRunJSON is `jit vault rm --dry-run --format json`: what the app
// shows before its own confirmation. paths are the expanded secrets that
// exist; refused says whether the real run would stop without
// --break-profiles; error is set when jit couldn't tell what uses them.
type rmDryRunJSON struct {
	Paths   []string      `json:"paths"`
	Missing []string      `json:"missing,omitempty"`
	InUse   []rmInUseJSON `json:"in_use,omitempty"`
	Refused bool          `json:"refused"`
	Error   string        `json:"error,omitempty"`
}

func runVaultRm(cmd *cobra.Command, args []string) error {
	// Validate BEFORE the confirmation and the biometric gate. Remove
	// validates each path itself, but that runs after both, so a
	// malformed path made jit demand a fingerprint to delete something it
	// was always going to refuse. Hit for real by a shell-quoting slip
	// that passed seventeen paths as one argument: the prompt appeared,
	// asked for a password, and the command then failed on the argument
	// it had just been authorized to act on. Needless prompts are how
	// users learn to approve without reading.
	for _, path := range args {
		if err := vault.ValidatePath(path); err != nil {
			return fmt.Errorf("jit vault rm: %w", err)
		}
	}
	if err := validateOutputFormat(vaultRmFormat); err != nil {
		return fmt.Errorf("jit vault rm: %w", err)
	}
	if vaultRmFormat == "json" && !vaultRmDryRun {
		return fmt.Errorf("jit vault rm: --format json needs --dry-run")
	}
	out := cmd.OutOrStdout()
	given := args

	// Before the confirmation, so the [y/N] prompt below lists exactly
	// what a group argument is about to delete. A dry run lists the
	// expanded paths itself, so the announcement would only repeat them.
	announce := out
	if vaultRmDryRun {
		announce = io.Discard
	}
	args, stored := expandRmGroups(announce, args)
	existing, missing := args, []string(nil)
	if stored != nil {
		existing = nil
		for _, p := range args {
			if stored[p] {
				existing = append(existing, p)
			} else {
				missing = append(missing, p)
			}
		}
	}

	// Who uses each doomed path, from every store, mount and pointer file
	// jit can find. Strict: a file it can't read is an error, and an error
	// is a refusal, because "can't tell" must never read as "unused".
	var uses map[string][]secretUse
	root, err := vaultRootDir()
	if err == nil {
		var cwd string
		if cwd, err = os.Getwd(); err == nil {
			var usage vaultUsage
			if usage, err = collectVaultUsers(root, cwd); err == nil {
				uses = usage.usesOf(existing)
			}
		}
	}
	collectErr := err
	if len(uses) > 0 {
		if home, herr := profile.GlobalRoot(); herr == nil {
			attachLaunchers(uses, home)
		}
	}
	refused := !vaultRmBreakProfiles && (collectErr != nil || len(uses) > 0)

	if vaultRmDryRun {
		if vaultRmFormat == "json" {
			return writeJSON(out, rmDryRunResult(existing, missing, uses, refused, collectErr))
		}
		printRmDryRun(out, existing, missing, uses, refused, collectErr)
		return nil
	}

	printRmUseWarnings(out, existing, uses, true)
	remedy := "jit vault rm --break-profiles " + strings.Join(given, " ")
	if collectErr != nil {
		if !vaultRmBreakProfiles {
			return &hintedError{
				msg:  fmt.Sprintf("jit vault rm: nothing deleted, can't tell whether %s in use: %v", rmSubject(existing), collectErr),
				cmd:  remedy,
				note: "to delete anyway",
			}
		}
		_, _ = cWarnBold.Fprintf(out, "%s ", glyphMark)
		fmt.Fprintf(out, "can't tell whether %s in use: %v\n", rmSubject(existing), collectErr)
	}
	if len(uses) > 0 && !vaultRmBreakProfiles {
		n := len(uses)
		e := &hintedError{
			msg: fmt.Sprintf("jit vault rm: nothing deleted, %s %s in use",
				countWord(n, "secret", "secrets"), pluralWord(n, "is", "are")),
			cmd: remedy,
		}
		if n > 1 {
			e.note = "to delete them anyway"
		}
		return e
	}

	var confirmQ, presence string
	if len(args) == 1 {
		confirmQ = fmt.Sprintf("Permanently delete %s from the vault? This can't be undone. [y/N] ", args[0])
		// Bounded: this string is rendered verbatim into a macOS
		// authentication dialog, which neither wraps nor scrolls
		// usefully. A long path pushed the actual question off the
		// visible area, leaving a wall of text over an OK button --
		// the exact shape of a prompt people approve without reading.
		presence = fmt.Sprintf("delete the secret %q from the vault", promptEllipsis(args[0], 60))
	} else {
		confirmQ = fmt.Sprintf("Permanently delete these %d secrets from the vault? This can't be undone:\n  %s\n[y/N] ",
			len(args), strings.Join(args, "\n  "))
		presence = fmt.Sprintf("delete %d secrets from the vault", len(args))
	}
	// The dialog names what breaks: the one fact a person approving a
	// delete most needs, and the one the incident's dialog left out.
	if broken := rmBrokenLabel(uses); broken != "" {
		presence += ", breaking " + broken
	}
	if !vaultRmYes && !vaultRmForce && !confirmPrompt(cmd, confirmQ) {
		fmt.Fprintln(out, "Aborted.")
		return nil
	}

	// Fresh biometric gate, same idiom as restore/delete: Remove only
	// deletes envelope files (never touches the KeyWrapper), so an
	// explicit user-presence check is what forces a fingerprint/passcode
	// here, whether the agent is locked or not. The [y/N] above is a
	// footgun guard (bypassable with --yes); this is the real gate. One
	// gesture covers the whole batch: user-presence proves a human is here
	// for THIS command, and deleting N of their own secrets needs no finer
	// per-secret proof than deleting one.
	if err := requireUserPresence(presence); err != nil {
		return fmt.Errorf("jit vault rm: %w", err)
	}

	v, err := openVaultReadOnly()
	if err != nil {
		return fmt.Errorf("jit vault rm: %w", err)
	}
	var failed int
	var removed []string
	for _, path := range args {
		if err := v.Remove(path); err != nil {
			failed++
			if errors.Is(err, vault.ErrNotFound) {
				fmt.Fprintf(cmd.ErrOrStderr(), "jit vault rm: no secret stored at %q\n", path)
			} else {
				fmt.Fprintf(cmd.ErrOrStderr(), "jit vault rm: %s: %v\n", path, err)
			}
			continue
		}
		removed = append(removed, path)
		fmt.Fprintf(out, "Removed %s\n", path)
	}
	invocationDeleted = removed
	invocationBroke = rmBrokenUsers(uses, removed)
	if failed > 0 {
		return fmt.Errorf("jit vault rm: %d of %d %s could not be removed", failed, len(args), pluralWord(len(args), "secret", "secrets"))
	}
	return nil
}

// rmSubject names what a "can't tell whether ... in use" line is about.
func rmSubject(paths []string) string {
	if len(paths) == 1 {
		return paths[0] + " is"
	}
	return fmt.Sprintf("these %d secrets are", len(paths))
}

// rmUser is one thing using some of the doomed paths, aggregated across
// them: a profile (keyed by manifest) or a pointer file.
type rmUser struct {
	use   secretUse
	paths []string
}

func (u rmUser) key() string {
	if u.use.PointerFile != "" {
		return "1\x00" + u.use.PointerFile
	}
	return "0\x00" + u.use.ProfileName + "\x00" + u.use.ProfilePath
}

// rmUsers flattens per-path uses into one entry per user, sorted:
// profiles by name first, then pointer files by path.
func rmUsers(doomed []string, uses map[string][]secretUse) []rmUser {
	byKey := map[string]*rmUser{}
	var keys []string
	for _, p := range doomed {
		for _, use := range uses[p] {
			u := rmUser{use: use}
			k := u.key()
			if byKey[k] == nil {
				byKey[k] = &u
				keys = append(keys, k)
			}
			byKey[k].paths = append(byKey[k].paths, p)
		}
	}
	sort.Strings(keys)
	out := make([]rmUser, 0, len(keys))
	for _, k := range keys {
		out = append(out, *byKey[k])
	}
	return out
}

// rmUsesWhat says how much of the doomed set one user holds: "it" when rm
// names one secret, "both" or "all N" when it holds every one, else the
// single path it holds, or a count.
func rmUsesWhat(count, total int, paths []string) string {
	switch {
	case total == 1:
		return "it"
	case count == total && total == 2:
		return "both"
	case count == total:
		return fmt.Sprintf("all %d", total)
	case count == 1:
		return paths[0]
	default:
		return fmt.Sprintf("%d of them", count)
	}
}

// printRmUseWarnings names everything that uses a doomed path, one row per
// user: the profile and its store, what launches it and which mount it
// feeds, or the pointer file. explain adds the line saying why that
// matters, for the refusal and the --break-profiles run; the dry run leaves
// it to its caller. Nothing is printed when nothing uses any of them.
func printRmUseWarnings(out io.Writer, doomed []string, uses map[string][]secretUse, explain bool) {
	users := rmUsers(doomed, uses)
	if len(users) == 0 {
		return
	}
	total := len(doomed)
	launched := false
	mounts := map[string]bool{}
	var mountOrder []string
	for _, u := range users {
		what := rmUsesWhat(len(u.paths), total, u.paths)
		_, _ = cWarnBold.Fprintf(out, "%s ", glyphMark)
		if u.use.PointerFile != "" {
			wrapBody(out, 2, "    ", fmt.Sprintf("%s points at %s (jit://)", shortPath(u.use.PointerFile), what))
			continue
		}
		wrapBody(out, 2, "    ", fmt.Sprintf("profile %s (%s) uses %s",
			cBold.Sprint(u.use.ProfileName), u.use.scopeLabel(), what))
		for _, cfg := range u.use.LaunchedBy {
			launched = true
			fmt.Fprintf(out, "  %s launched by %s\n", glyphBranch, shortPath(cfg))
		}
		if m := u.use.MountPath; m != "" {
			fmt.Fprintf(out, "  %s served by the mount at %s\n", glyphBranch, shortPath(m))
			if !mounts[m] {
				mounts[m] = true
				mountOrder = append(mountOrder, m)
			}
		}
	}
	if explain && launched {
		fmt.Fprintln(out, "  a profile missing a secret can't start its tool")
	}
	if len(mountOrder) > 0 {
		// rm deletes only the envelope files: the mount would keep serving
		// a FIFO nothing can fill. `jit migrate remove` takes the file,
		// the profile and the secrets down together.
		which := "that mount"
		if len(mountOrder) > 1 {
			which = "those mounts"
		}
		fmt.Fprintf(out, "  deleting only the secret leaves %s broken; to remove file,\n", which)
		fmt.Fprintln(out, "  profile and secret together:")
		for _, m := range mountOrder {
			_, _ = cPath.Fprintf(out, "  %s jit migrate remove %s\n", glyphAction, shortPath(m))
		}
	}
}

// printRmDryRun is --dry-run's text: the paths that would go, the ones
// that aren't stored, what uses them, and whether the real run would stop.
func printRmDryRun(out io.Writer, existing, missing []string, uses map[string][]secretUse, refused bool, collectErr error) {
	if len(existing) == 0 {
		fmt.Fprintln(out, "nothing to delete")
	} else {
		fmt.Fprintf(out, "would delete %s:\n", countWord(len(existing), "secret", "secrets"))
		for _, p := range existing {
			fmt.Fprintf(out, "  %s\n", p)
		}
	}
	for _, p := range missing {
		fmt.Fprintf(out, "no secret stored at %q\n", p)
	}
	printRmUseWarnings(out, existing, uses, false)
	if collectErr != nil {
		_, _ = cWarnBold.Fprintf(out, "%s ", glyphMark)
		wrapBody(out, 2, "    ", fmt.Sprintf("can't tell whether %s in use: %v", rmSubject(existing), collectErr))
	}
	if refused {
		fmt.Fprintln(out, "refused without --break-profiles")
	}
}

// rmDryRunResult builds the --format json dry run: one in_use row per
// (path, user), in the order the text view names them.
func rmDryRunResult(existing, missing []string, uses map[string][]secretUse, refused bool, collectErr error) rmDryRunJSON {
	res := rmDryRunJSON{Paths: existing, Missing: missing, Refused: refused}
	if res.Paths == nil {
		res.Paths = []string{}
	}
	if collectErr != nil {
		res.Error = collectErr.Error()
	}
	for _, p := range existing {
		for _, u := range uses[p] {
			row := rmInUseJSON{Path: p, PointerFile: u.PointerFile}
			if u.PointerFile == "" {
				row.Profile = u.ProfileName
				row.Scope = string(u.Scope)
				row.Project = u.Project
				row.Mount = u.MountPath
				row.LaunchedBy = u.LaunchedBy
			}
			res.InUse = append(res.InUse, row)
		}
	}
	return res
}

// rmBrokenLabel names, for the Touch ID dialog, what a --break-profiles
// delete leaves unable to start: "profile X", "~/.clisso.yaml", or a count.
// Bounded like the rest of the reason, since the dialog neither wraps nor
// scrolls usefully.
func rmBrokenLabel(uses map[string][]secretUse) string {
	var profiles, pointers []string
	for _, list := range uses {
		for _, u := range list {
			if u.PointerFile != "" {
				if !containsString(pointers, u.PointerFile) {
					pointers = append(pointers, u.PointerFile)
				}
			} else if !containsString(profiles, u.ProfileName) {
				profiles = append(profiles, u.ProfileName)
			}
		}
	}
	switch {
	case len(profiles) == 0 && len(pointers) == 0:
		return ""
	case len(profiles) == 1 && len(pointers) == 0:
		return "profile " + promptEllipsis(profiles[0], 40)
	case len(profiles) == 0 && len(pointers) == 1:
		return promptEllipsis(shortPath(pointers[0]), 40)
	case len(pointers) == 0:
		return countWord(len(profiles), "profile", "profiles")
	case len(profiles) == 0:
		return countWord(len(pointers), "pointer file", "pointer files")
	default:
		return countWord(len(profiles), "profile", "profiles") + " and " +
			countWord(len(pointers), "pointer file", "pointer files")
	}
}

// rmBrokenUsers lists, for the audit record, every profile (by name) and
// pointer file (by path) that used one of the removed paths.
func rmBrokenUsers(uses map[string][]secretUse, removed []string) []string {
	var out []string
	for _, p := range removed {
		for _, u := range uses[p] {
			name := u.ProfileName
			if u.PointerFile != "" {
				name = shortPath(u.PointerFile)
			}
			if !containsString(out, name) {
				out = append(out, name)
			}
		}
	}
	sort.Strings(out)
	return out
}
