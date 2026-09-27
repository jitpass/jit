// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/audit"
	"github.com/jitpass/jit/internal/profile"
	"github.com/jitpass/jit/internal/settings"
	"github.com/jitpass/jit/internal/vault"
)

// jit vault move-out / move-in: one value between the vault and the plain
// settings beside it (design/secrets-only-vault.md). Neither changes a value,
// only where it is kept, so every file that reads it keeps working and the
// live mount's next read is already right. Both are their own Touch ID every
// time: move-out decrypts, move-in writes the vault, and neither rides the
// service session.

var (
	settingMoveYes    bool
	settingMoveFormat string
)

var vaultMoveOutCmd = &cobra.Command{
	Use:   "move-out <path>...",
	Short: "Keep vault entries as plain settings beside the vault instead",
	Long: "Move each named vault entry out of the vault into a plain setting beside it, and point\n" +
		"every profile that names it at the setting. The value does not change and files that read\n" +
		"it keep working, but any program on this Mac can then read it without Touch ID.\n\n" +
		"For a value the scan counts as a secret, that leaves a secret in plain text, and jit scan\n" +
		"reports it again. Undo with jit vault move-in.",
	Example: "  jit vault move-out billing-sync/EXPORT_SECRETS_FILE",
	Args:    cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSettingMove(cmd, args, true)
	},
}

var vaultMoveInCmd = &cobra.Command{
	Use:   "move-in <path>...",
	Short: "Move plain settings into the vault",
	Long: "Move each named plain setting into the vault, and point every profile that names it at the\n" +
		"vault entry. The value does not change and files that read it keep working; reading it\n" +
		"then needs Touch ID or a grant, like any secret.",
	Example: "  jit vault move-in billing-sync/BILLING_URL",
	Args:    cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSettingMove(cmd, args, false)
	},
}

// settingMoveResult is --format json's document: what moved, and for a move
// out, what the scan says of each value now that it has been read.
type settingMoveResult struct {
	Moved []settingMovedEntry `json:"moved"`
}

type settingMovedEntry struct {
	Path     string   `json:"path"`
	Scan     string   `json:"scan,omitempty"`
	Profiles []string `json:"profiles"`
}

// settingMoveTarget is one path and the manifests that name it.
type settingMoveTarget struct {
	path      string
	from, to  string // the manifest value now, and after the move
	manifests []string
	profiles  []string
}

func runSettingMove(cmd *cobra.Command, args []string, out bool) error {
	verb := "move-in"
	if out {
		verb = "move-out"
	}
	if err := validateOutputFormat(settingMoveFormat); err != nil {
		return fmt.Errorf("jit vault %s: %w", verb, err)
	}
	if settingMoveFormat == "json" && !settingMoveYes {
		return fmt.Errorf("jit vault %s: --format json needs --yes; a confirmation cannot be answered on a JSON stream", verb)
	}
	root, err := vaultRootDir()
	if err != nil {
		return err
	}
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	store := settings.New(root)
	seen := map[string]bool{}
	var paths []string
	for _, p := range args {
		if err := vault.ValidatePath(p); err != nil {
			return fmt.Errorf("jit vault %s: %w", verb, err)
		}
		if vault.IsBackupPath(p) {
			return fmt.Errorf("jit vault %s: %s is one of jit's file backups, not a value a profile reads", verb, p)
		}
		if !seen[p] {
			seen[p] = true
			paths = append(paths, p)
		}
	}

	// Every manifest that names each path, from every store jit knows. Strict,
	// like vault rm: a manifest jit cannot read could be left naming a value
	// that is no longer where it says.
	usage, err := collectVaultUsers(root, cwd)
	if err != nil {
		return fmt.Errorf("jit vault %s: nothing moved, can't tell which profiles name these: %w", verb, err)
	}
	readVault := &vault.Vault{Root: root}
	targets := make([]settingMoveTarget, 0, len(paths))
	for _, p := range paths {
		t := settingMoveTarget{path: p, from: p, to: settings.Pointer(p)}
		if !out {
			t.from, t.to = settings.Pointer(p), p
		}
		var exists bool
		if out {
			exists, err = readVault.Exists(p)
		} else {
			exists, err = store.Exists(p)
		}
		if err != nil {
			return fmt.Errorf("jit vault %s: %w", verb, err)
		}
		// A 1Password link is a reference, not a value: moving it out would
		// write the item's current value to disk and cut the link, so later
		// changes in 1Password stop reaching the file. Refused, as the app
		// hides Move Out for one.
		if out && exists {
			if info, ierr := readVault.Info(p); ierr == nil && info.Storage == vault.StorageOpRef {
				return fmt.Errorf("jit vault %s: nothing moved, %s is a 1Password link; a plain copy would cut the link", verb, p)
			}
		}
		if !exists {
			where := "the vault"
			if !out {
				where = "the settings"
			}
			return fmt.Errorf("jit vault %s: nothing moved, %s is not in %s", verb, p, where)
		}
		for _, u := range usage.byPath[t.from] {
			if u.PointerFile != "" {
				return fmt.Errorf("jit vault %s: nothing moved, %s names %s; jit migrate remove that file first", verb, shortPath(u.PointerFile), p)
			}
			if u.ProfilePath != "" && !containsString(t.manifests, u.ProfilePath) {
				t.manifests = append(t.manifests, u.ProfilePath)
				t.profiles = append(t.profiles, u.ProfileName)
			}
		}
		if len(t.manifests) == 0 {
			// A value no profile names reaches no program; moving it would
			// only move where it is forgotten.
			return fmt.Errorf("jit vault %s: nothing moved, no profile names %s", verb, p)
		}
		targets = append(targets, t)
	}

	w := cmd.OutOrStdout()
	if !settingMoveYes {
		if !confirmPrompt(cmd, settingMoveQuestion(paths, out)) {
			fmt.Fprintln(w, "Nothing moved.")
			return nil
		}
	}

	// Before the Touch ID: an index that cannot be read refuses the run
	// without spending a fingerprint on it.
	classes, cerr := settings.LoadClasses(root)
	if cerr != nil {
		if out {
			// Moving out keeps each value's origin only in this index.
			return fmt.Errorf("jit vault %s: nothing moved: %w", verb, cerr)
		}
		classes = nil
	}

	v, err := openVaultFreshAuth()
	if err != nil {
		return fmt.Errorf("jit vault %s: %w", verb, err)
	}
	if err := requireFreshUserPresence(v, settingMoveReason(targets, out)); err != nil {
		return fmt.Errorf("jit vault %s: nothing moved: %w", verb, err)
	}

	result := settingMoveResult{Moved: []settingMovedEntry{}}
	for _, t := range targets {
		scan, err := settingMoveOne(v, store, classes, t, out)
		if err != nil {
			return fmt.Errorf("jit vault %s: %w", verb, err)
		}
		if classes != nil {
			if out {
				classes.Set(t.path, "")
			} else {
				classes.Set(t.path, scan)
				classes.SetSettingProvenance(t.path, settings.Provenance{})
			}
		}
		result.Moved = append(result.Moved, settingMovedEntry{Path: t.path, Scan: scan, Profiles: t.profiles})
	}
	if classes != nil {
		_ = classes.Save()
	}

	if settingMoveFormat == "json" {
		return writeJSON(w, result)
	}
	printSettingMove(w, result, out)
	return nil
}

// settingMoveOne moves one value. The order keeps it whole whatever fails: the
// value is written to its new place first, then every manifest is pointed
// at it, and only then is the old copy removed. A failure part way leaves
// the value in both places, never in neither.
func settingMoveOne(v *vault.Vault, store *settings.Store, classes *settings.Classes, t settingMoveTarget, out bool) (string, error) {
	var value []byte
	var err error
	if out {
		value, err = v.Get(t.path)
	} else {
		value, err = store.Get(t.path)
	}
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", t.path, err)
	}
	scan := string(audit.ClassifyEnvVar(path.Base(t.path), string(value)))
	if out {
		// The envelope's origin and group go with the value, into the index
		// beside the vault: a plain file has no header to keep them in.
		// Saved now, before the vault copy (the only other place they are
		// kept) is removed below: a run that fails on a later value must not
		// have lost this one's origin (review of #183).
		if classes == nil {
			return "", fmt.Errorf("moving %s out: the index beside the vault could not be read, so its origin would be lost", t.path)
		}
		info, ierr := v.Info(t.path)
		if ierr != nil {
			return "", fmt.Errorf("moving %s out: reading its origin: %w", t.path, ierr)
		}
		classes.SetSettingProvenance(t.path, settings.Provenance{Origin: info.Origin, GroupID: info.GroupID})
		if serr := classes.Save(); serr != nil {
			return "", fmt.Errorf("moving %s out: saving its origin: %w", t.path, serr)
		}
		err = store.Set(t.path, value)
	} else {
		meta := vault.Meta{Class: vault.ClassDotenv}
		if classes != nil {
			prov := classes.SettingProvenance(t.path)
			meta.Origin, meta.GroupID = prov.Origin, prov.GroupID
		}
		err = v.SetWithMeta(t.path, value, meta)
	}
	if err != nil {
		return "", fmt.Errorf("writing %s: %w", t.path, err)
	}
	for _, m := range t.manifests {
		if err := repointManifest(m, t.from, t.to); err != nil {
			return "", err
		}
	}
	if out {
		err = v.Remove(t.path)
		if errors.Is(err, vault.ErrNotFound) {
			err = nil
		}
	} else {
		err = store.Remove(t.path)
	}
	if err != nil {
		return "", fmt.Errorf("removing the old copy of %s: %w", t.path, err)
	}
	return scan, nil
}

// repointManifest rewrites every entry of the manifest at file that names
// from to name to instead, keeping its order, atomically.
func repointManifest(file, from, to string) error {
	p, order, err := profile.LoadFileOrdered(file)
	if err != nil {
		return fmt.Errorf("loading %s: %w", shortPath(file), err)
	}
	for name, entry := range p {
		if entry == from {
			p[name] = to
		}
	}
	data, err := profile.MarshalOrdered(p, order)
	if err != nil {
		return err
	}
	if err := vault.AtomicWriteFile(file, data); err != nil {
		return fmt.Errorf("writing %s: %w", shortPath(file), err)
	}
	return nil
}

// settingMoveQuestion leads with the risk for a move out, as a confirmation must.
func settingMoveQuestion(paths []string, out bool) string {
	subject := paths[0]
	if len(paths) > 1 {
		subject = countWord(len(paths), "value", "values")
	}
	if out {
		return fmt.Sprintf("Move %s out of the vault? Any program on this Mac can then read it, with no Touch ID. [y/N] ", subject)
	}
	return fmt.Sprintf("Move %s into the vault? Reading it will then need Touch ID or a grant. [y/N] ", subject)
}

// settingMoveReason is the Touch ID dialog's sentence. It names what the
// fingerprint approves: the value and its profile for one, the count for
// several. Bounded, as vault rm's is: the dialog neither wraps nor scrolls.
func settingMoveReason(targets []settingMoveTarget, out bool) string {
	dir := "into"
	if out {
		dir = "out of"
	}
	if len(targets) == 1 {
		t := targets[0]
		name, group := path.Base(t.path), path.Dir(t.path)
		return fmt.Sprintf("move %s %s the vault (%s)", promptEllipsis(name, 50), dir, promptEllipsis(group, 30))
	}
	return fmt.Sprintf("move %d values %s the vault", len(targets), dir)
}

func printSettingMove(w io.Writer, r settingMoveResult, out bool) {
	for _, m := range r.Moved {
		_, _ = cOK.Fprint(w, glyphOK+" ")
		where := "is in the vault"
		if out {
			where = "is a plain setting now"
		}
		fmt.Fprintf(w, "%s %s (%s)\n", m.Path, where, strings.Join(sortedNames(m.Profiles), ", "))
		if out && m.Scan == string(audit.EnvVarSecret) {
			_, _ = cWarn.Fprintf(w, "    note: the scan counts this value as a secret, so jit scan reports it again\n")
			wrapBody(w, 0, "    ", hlCmds("    to put it back: `jit vault move-in "+m.Path+"`"))
		}
	}
}

func sortedNames(s []string) []string {
	out := append([]string(nil), s...)
	sort.Strings(out)
	return out
}

func init() {
	for _, c := range []*cobra.Command{vaultMoveOutCmd, vaultMoveInCmd} {
		c.Flags().BoolVarP(&settingMoveYes, "yes", "y", false, "skip the confirmation question; Touch ID is still asked")
		c.Flags().StringVar(&settingMoveFormat, "format", "text", `output format: "text" (default) or "json"; json needs --yes`)
		c.ValidArgsFunction = completeVaultPaths
	}
	vaultCmd.AddCommand(vaultMoveOutCmd, vaultMoveInCmd)
}
