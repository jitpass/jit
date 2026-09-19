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

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/launchers"
	"github.com/jitpass/jit/internal/migrate"
	"github.com/jitpass/jit/internal/profile"
	"github.com/jitpass/jit/internal/vault"
	"github.com/jitpass/jit/internal/wrap"
)

// `jit profile rm` deletes a profile whole: its manifest, its .source
// sidecar and every secret nothing else uses (design/doctor-repair.md,
// "Deleting a profile removes its manifest, its sidecar and every secret no
// other profile or pointer references"). Deleting only the secrets breaks
// the profile; deleting only the manifest leaves orphans.
//
// It refuses a profile any known tool uses, with no flag to override: the
// fix is to remove that use (a launcher, in the code), which is a hand edit
// or another jit command, never a reason to break a tool. It reads the
// launcher map STRICTLY: a file it can't read might be the one launching
// this profile, so "can't tell" refuses too. Global profiles only: a
// project profile is launched by `jit run` from its project, which nothing
// records, and goes with its project (`jit migrate remove`).

var (
	profileRmYes    bool
	profileRmDryRun bool
	profileRmFormat string
)

var profileRmCmd = &cobra.Command{
	Use:   "rm <profile>",
	Short: "Delete a global profile and the secrets nothing else uses",
	Long: "Deletes a global profile: its manifest, its record of the configs\n" +
		"that use it, and each of its secrets no other profile or pointer file\n" +
		"uses. Secrets another profile uses are kept.\n\n" +
		"A profile a tool still uses is refused, and nothing is deleted: an MCP\n" +
		"server entry (any wrapper layer), an AWS or kubeconfig entry, a wrapped\n" +
		"tool, a mount, a shell rc export or a credential helper, found anywhere\n" +
		"under your home folder. Remove that first. If jit can't read one of\n" +
		"those files, it can't tell, and refuses the same way. Scripts and\n" +
		"aliases can't be seen, so \"no known tool\" is never proof the profile\n" +
		"is unused.\n\n" +
		"A project profile goes with its project: `jit migrate remove <project>`.\n\n" +
		"Beyond the [y/N] confirmation, deleting secrets needs a fresh Touch ID;\n" +
		"-y/--yes skips only the confirmation. --dry-run shows the plan and\n" +
		"stops. With --format json it prints profile, scope, launchers,\n" +
		"delete_secrets, keep_secrets, missing_secrets, coverage_complete,\n" +
		"refused and error.",
	Example: "  jit profile rm k8s-docker-desktop\n" +
		"  jit profile rm --dry-run --format json token",
	Args:              requireArgs(1, 1, "a profile name (see `jit status`)"),
	ValidArgsFunction: completeProfileNames,
	// A refusal is a result, not a usage mistake; and a --format json dry
	// run must never have usage text appended.
	SilenceUsage: true,
	RunE:         runProfileRm,
}

// profileRmPlan is everything rm decided before asking.
type profileRmPlan struct {
	name     string
	manifest string
	// blocking is every known launcher, one per (kind, file, detail): an
	// MCP entry's layers are one entry.
	blocking []launchers.Launcher
	// deletePaths exist and nothing else uses them; keepPaths exist and
	// another profile or pointer file uses them; missingPaths are gone.
	deletePaths, keepPaths, missingPaths []string
	// originGone is the most common recorded Origin among the profile's
	// stored secrets whose file no longer exists, "" when none.
	originGone string
	complete   bool // the launcher walk covered all of home
}

// profileRmJSON is `jit profile rm --dry-run --format json`.
type profileRmJSON struct {
	Profile          string               `json:"profile"`
	Scope            string               `json:"scope"`
	Launchers        []launchers.Launcher `json:"launchers"`
	DeleteSecrets    []string             `json:"delete_secrets"`
	KeepSecrets      []string             `json:"keep_secrets"`
	MissingSecrets   []string             `json:"missing_secrets"`
	CoverageComplete bool                 `json:"coverage_complete"`
	Refused          bool                 `json:"refused"`
	Error            string               `json:"error,omitempty"`
}

func runProfileRm(cmd *cobra.Command, args []string) error {
	name := args[0]
	if err := validateOutputFormat(profileRmFormat); err != nil {
		return fmt.Errorf("jit profile rm: %w", err)
	}
	if profileRmFormat == "json" && !profileRmDryRun {
		return errors.New("jit profile rm: --format json needs --dry-run")
	}
	if _, err := profile.Path("", name); err != nil {
		return fmt.Errorf("jit profile rm: %w", err)
	}
	home, err := profile.GlobalRoot()
	if err != nil {
		return fmt.Errorf("jit profile rm: finding the global profile store: %w", err)
	}
	root, err := vaultRootDir()
	if err != nil {
		return fmt.Errorf("jit profile rm: %w", err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("jit profile rm: %w", err)
	}
	out := cmd.OutOrStdout()

	manifest := globalManifestPath(home, name)
	if manifest == "" {
		return profileRmNotGlobal(home, root, cwd, name)
	}

	// Strict: any file jit can't read might be the one launching this
	// profile, or the other user of one of its secrets.
	m, discErr := launchers.Discover(launchers.Options{Home: home, Root: root, Cwd: cwd, Strict: true})
	var plan profileRmPlan
	if discErr == nil {
		plan, discErr = planProfileRm(m, home, name, manifest)
	}
	if discErr != nil {
		if profileRmDryRun {
			if profileRmFormat == "json" {
				return writeJSON(out, profileRmResult(name, profileRmPlan{}, true, discErr))
			}
			_, _ = cWarnBold.Fprintf(out, "%s ", glyphMark)
			wrapBody(out, 2, "    ", fmt.Sprintf("can't tell whether %s is in use: %s", name, shortHome(discErr.Error())))
			fmt.Fprintln(out, "refused: nothing would be deleted")
			return nil
		}
		return fmt.Errorf("jit profile rm: nothing deleted, can't tell whether %s is in use: %s", name, shortHome(discErr.Error()))
	}

	refused := len(plan.blocking) > 0
	if profileRmDryRun && profileRmFormat == "json" {
		return writeJSON(out, profileRmResult(name, plan, refused, nil))
	}
	if refused {
		printProfileRmLaunchers(out, plan.blocking)
		refusal := profileRmRefusal(name, plan.blocking)
		if profileRmDryRun {
			fmt.Fprintln(out, "refused: nothing would be deleted")
			fmt.Fprintln(out, refusal.hint())
			return nil
		}
		return refusal
	}

	printProfileRmPlan(out, home, plan)
	if profileRmDryRun {
		return nil
	}

	q := "Delete it? [y/N] "
	if len(plan.deletePaths) > 0 {
		q = "Delete both? [y/N] "
	}
	if !profileRmYes && !confirmPromptTight(cmd, q) {
		fmt.Fprintln(out, "Aborted.")
		return nil
	}

	// A fresh gesture only when secrets go: deleting a manifest destroys
	// nothing a `jit vault` command couldn't rebuild, deleting a secret
	// destroys its history too. The same gate `jit vault rm` uses.
	var removed []string
	if len(plan.deletePaths) > 0 {
		reason := fmt.Sprintf("delete profile %s and %s", promptEllipsis(name, 40),
			countWord(len(plan.deletePaths), "secret", "secrets"))
		announceTouchIDWait()
		if err := requireUserPresence(reason); err != nil {
			return fmt.Errorf("jit profile rm: %w", err)
		}
		invocationAuth = freshUserPresenceMethod
		v, err := openVaultReadOnly()
		if err != nil {
			return fmt.Errorf("jit profile rm: %w", err)
		}
		for _, p := range plan.deletePaths {
			if err := v.Remove(p); err != nil && !errors.Is(err, vault.ErrNotFound) {
				invocationDeleted = removed
				return fmt.Errorf("jit profile rm: deleting %s: %w", p, err)
			}
			removed = append(removed, p)
		}
	}
	// Secrets first, then the manifest and its sidecar: an interrupted run
	// leaves a profile naming a missing secret, which doctor reports and a
	// re-run finishes, never secrets nothing names.
	if err := migrate.RemoveOwnedProfile(plan.manifest); err != nil {
		invocationDeleted = removed
		return fmt.Errorf("jit profile rm: removing %s: %w", shortPath(plan.manifest), err)
	}
	invocationDeleted = append(removed, "profile:"+name)
	invocationBroke = nil

	_, _ = cOK.Fprint(out, glyphDone)
	if len(removed) > 0 {
		fmt.Fprintf(out, " deleted profile %s and %s\n", name, countWord(len(removed), "secret", "secrets"))
	} else {
		fmt.Fprintf(out, " deleted profile %s\n", name)
	}
	return nil
}

// profileRmNotGlobal is the error for a name with no global manifest: a
// project profile goes with its project, and anything else doesn't exist.
func profileRmNotGlobal(home, root, cwd, name string) error {
	// Lenient: this only chooses which error to show.
	m, err := launchers.Discover(launchers.Options{Home: home, Root: root, Cwd: cwd})
	if err == nil {
		for _, p := range m.ProfilesNamed(name) {
			if p.Scope == profile.ScopeProject && p.Project != "" {
				return &hintedError{
					msg:  fmt.Sprintf("jit profile rm: %s is a project profile in %s; it goes with its project", name, displayPath(home, p.Project)),
					cmd:  "jit migrate remove " + displayPath(home, p.Project),
					note: "removes the project's profiles and secrets together",
				}
			}
		}
	}
	return fmt.Errorf("jit profile rm: no global profile named %s", name)
}

// planProfileRm reads what launches the profile and sorts its secrets
// into delete, keep and missing, from the strict map m.
func planProfileRm(m *launchers.Map, home, name, manifest string) (profileRmPlan, error) {
	plan := profileRmPlan{name: name, manifest: manifest, complete: m.Coverage.Complete()}
	p := m.ProfileAt(manifest)
	if p == nil {
		return plan, fmt.Errorf("profile %s was not found looking for its tools", shortPath(manifest))
	}
	seen := map[string]bool{}
	for _, l := range p.Launchers {
		if l.Kind == launchers.KindProjectStore {
			continue
		}
		key := string(l.Kind) + "\x00" + l.File + "\x00" + l.Detail
		if seen[key] {
			continue
		}
		seen[key] = true
		plan.blocking = append(plan.blocking, l)
	}

	v, err := openVaultReadOnly()
	if err != nil {
		return plan, err
	}
	usage := vaultUsageFromMap(m)
	self := canonicalPath(manifest)
	origins := map[string]int{}
	for _, path := range uniqueValues(p.Values) {
		ok, err := v.Exists(path)
		if err != nil {
			return plan, fmt.Errorf("checking %s: %w", path, err)
		}
		if !ok {
			plan.missingPaths = append(plan.missingPaths, path)
			continue
		}
		other := false
		for _, u := range usage.byPath[path] {
			if u.PointerFile != "" || canonicalPath(u.ProfilePath) != self {
				other = true
				break
			}
		}
		if other {
			plan.keepPaths = append(plan.keepPaths, path)
		} else {
			plan.deletePaths = append(plan.deletePaths, path)
		}
		// Evidence only: an unreadable header just adds no origin.
		if info, err := v.Info(path); err == nil && info.Origin != "" {
			origins[info.Origin]++
		}
	}
	plan.originGone = mostCommonGoneOrigin(home, origins)
	return plan, nil
}

// mostCommonGoneOrigin picks, among recorded origins whose file is gone,
// the one the most secrets name (ties by path). Only a definite "does not
// exist" counts as gone.
func mostCommonGoneOrigin(home string, origins map[string]int) string {
	var gone []string
	for o := range origins {
		if _, err := os.Stat(wrap.ExpandHome(home, o)); os.IsNotExist(err) {
			gone = append(gone, o)
		}
	}
	sort.Slice(gone, func(i, j int) bool {
		if origins[gone[i]] != origins[gone[j]] {
			return origins[gone[i]] > origins[gone[j]]
		}
		return gone[i] < gone[j]
	})
	if len(gone) == 0 {
		return ""
	}
	return gone[0]
}

// printProfileRmPlan is what rm shows before its question: the profile,
// the evidence it rests on, and what goes.
func printProfileRmPlan(out io.Writer, home string, plan profileRmPlan) {
	fmt.Fprintf(out, "profile %s (global)\n", cBold.Sprint(plan.name))
	if plan.originGone != "" {
		fmt.Fprintf(out, "  %s made from %s, now gone\n", glyphBranch,
			displayPath(home, wrap.ExpandHome(home, plan.originGone)))
	}
	if plan.complete {
		fmt.Fprintf(out, "  %s no known tool\n", glyphBranch)
	} else {
		fmt.Fprintf(out, "  %s jit could not see all of ~\n", glyphBranch)
	}

	del, keep, missing := len(plan.deletePaths), len(plan.keepPaths), len(plan.missingPaths)
	switch {
	case del > 0:
		fmt.Fprintf(out, "deletes the profile and %s nothing else uses:\n", countWord(del, "secret", "secrets"))
		for _, p := range plan.deletePaths {
			fmt.Fprintf(out, "  %s\n", p)
		}
	case missing > 0 && keep == 0:
		if missing == 1 {
			fmt.Fprintln(out, "deletes the profile; its secret is already gone")
		} else {
			fmt.Fprintf(out, "deletes the profile; its %d secrets are already gone\n", missing)
		}
		return
	default:
		fmt.Fprintln(out, "deletes the profile")
	}
	if keep > 0 {
		fmt.Fprintf(out, "keeps %s something else uses:\n", countWord(keep, "secret", "secrets"))
		for _, p := range plan.keepPaths {
			fmt.Fprintf(out, "  %s\n", p)
		}
	}
	if missing > 0 {
		fmt.Fprintf(out, "%s already gone\n", countWord(missing, "secret is", "secrets are"))
	}
}

// printProfileRmLaunchers names each known tool that uses the profile, one
// `!` line each.
func printProfileRmLaunchers(out io.Writer, blocking []launchers.Launcher) {
	for _, l := range blocking {
		_, _ = cWarnBold.Fprintf(out, "%s ", glyphMark)
		wrapBody(out, 2, "    ", profileRmLauncherLine(l))
	}
}

// profileRmLauncherLine says, in the user's terms, which tool uses the
// profile and the config that starts it: "tool okta-mcp-server uses it
// (~/Security-Ops/.mcp.json)".
func profileRmLauncherLine(l launchers.Launcher) string {
	file := shortPath(l.File)
	switch l.Kind {
	case launchers.KindMCP:
		return fmt.Sprintf("tool %s uses it (%s)", l.Detail, file)
	case launchers.KindAWS:
		return fmt.Sprintf("tool aws uses it (%s %s)", file, l.Detail)
	case launchers.KindKube:
		return fmt.Sprintf("tool kubectl uses it (%s %s)", file, l.Detail)
	case launchers.KindWrap:
		return fmt.Sprintf("tool %s uses it (wrapped)", l.Detail)
	case launchers.KindMount:
		return fmt.Sprintf("the mount at %s uses it", shortPath(l.Detail))
	case launchers.KindShellRC:
		return fmt.Sprintf("your shell uses it (%s %s)", file, l.Detail)
	case launchers.KindHelper:
		return fmt.Sprintf("tool %s uses it (credential helper)", l.Detail)
	}
	return fmt.Sprintf("%s uses it", file)
}

// profileRmRefusal is the in-use error, with the one step that clears it:
// a command when jit has one (unwrap, migrate remove), else a note naming
// the hand edit.
func profileRmRefusal(name string, blocking []launchers.Launcher) *hintedError {
	e := &hintedError{msg: fmt.Sprintf("jit profile rm: nothing deleted, %s is in use", name)}
	kind := blocking[0].Kind
	for _, l := range blocking[1:] {
		if l.Kind != kind {
			e.note = "remove each of those first"
			return e
		}
	}
	one := len(blocking) == 1
	l := blocking[0]
	switch kind {
	case launchers.KindMCP:
		e.note = "remove those entries first"
		if one {
			e.note = fmt.Sprintf("remove %s from that file first", l.Detail)
		}
	case launchers.KindAWS:
		e.note = "remove those sections first"
		if one {
			e.note = fmt.Sprintf("remove the %s section from that file first", l.Detail)
		}
	case launchers.KindKube:
		e.note = "remove those users first"
		if one {
			e.note = fmt.Sprintf("remove %s from that file first", l.Detail)
		}
	case launchers.KindShellRC:
		e.note = "remove those jit export lines first"
		if one {
			e.note = fmt.Sprintf("remove its jit export line (%s) first", l.Detail)
		}
	case launchers.KindWrap:
		// One profile per wrapped tool (wrap-<tool>), so one launcher.
		e.cmd = "jit wrap undo " + l.Detail
		e.note = "unwraps the tool and removes this profile with it"
	case launchers.KindMount:
		e.note = "remove those mounts first"
		if one {
			e.cmd = "jit migrate remove " + shortPath(l.Detail)
			e.note = "restores the file and removes the profile with it"
		}
	case launchers.KindHelper:
		e.note = fmt.Sprintf("the %s helper may ask for it; undo that migration first", l.Detail)
	default:
		e.note = "remove that first"
	}
	return e
}

// profileRmResult builds the --format json dry run.
func profileRmResult(name string, plan profileRmPlan, refused bool, err error) profileRmJSON {
	res := profileRmJSON{
		Profile:          name,
		Scope:            string(profile.ScopeGlobal),
		Launchers:        nonNil(plan.blocking),
		DeleteSecrets:    nonNil(plan.deletePaths),
		KeepSecrets:      nonNil(plan.keepPaths),
		MissingSecrets:   nonNil(plan.missingPaths),
		CoverageComplete: plan.complete,
		Refused:          refused,
	}
	if err != nil {
		res.Error = err.Error()
	}
	return res
}

// nonNil turns a nil slice into an empty one, so JSON says [] not null.
func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
