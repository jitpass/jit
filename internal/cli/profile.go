// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

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

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/migrate"
	"github.com/jitpass/jit/internal/profile"
)

// `jit profile` is the explicit half of design/doctor-repair.md's Phase 2
// ("ownership"): commands doctor can name and the app can run, instead of
// ownership changing only as a side effect of `jit migrate`.
//
//   - attach records an MCP config on the global profiles its tools use but
//     that don't record it (in the owner list, the .source sidecar): the
//     case where the config that made a profile was deleted or copied, and
//     another one starts its tool now. Bookkeeping only, so no Touch ID and
//     no vault access. It was `adopt` until the vocabulary settled
//     (design/doctor-repair.md, "Vocabulary"); nothing shipped with it.
//   - rm (profilerm.go) deletes a global profile, its .source sidecar and
//     every secret nothing else uses, and refuses a profile any known tool
//     still uses.

var profileCmd = &cobra.Command{
	Use:     "profile",
	GroupID: groupSecrets,
	// See runCommandGroup: a mistyped subcommand must fail, not print help
	// and exit 0.
	RunE:        runCommandGroup,
	Annotations: commandGroupAnnotations(),
	Short:       "Write, edit, and delete profile manifests",
	Long: "A profile maps variables to vault secrets; `jit run --profile` resolves\n" +
		"it. A profile made from an MCP config records that config, which is\n" +
		"what `jit migrate remove` goes by.\n\n" +
		"`jit profile create` writes a manifest: every secret in a vault group of\n" +
		"the same name, or the variable=path pairs you name. It is how a manifest\n" +
		"lost with its project comes back beside a vault that survived.\n" +
		"`jit profile drop` removes variables from a manifest, leaving the\n" +
		"secrets they named in the vault.\n" +
		"`jit profile attach` records a config on the profiles its tools use but\n" +
		"that don't record it (the recorded config was deleted, or the config\n" +
		"was copied).\n" +
		"`jit profile rm` deletes a global profile no known tool uses, with the\n" +
		"secrets nothing else uses.",
}

var (
	profileAttachYes    bool
	profileAttachDryRun bool
	profileAttachFormat string
)

var profileAttachCmd = &cobra.Command{
	Use:   "attach <config> [profile]...",
	Short: "Record an MCP config on the profiles its tools use",
	Long: "Records <config> on every global profile its tools use that doesn't\n" +
		"record it yet: one whose recorded config is deleted, one that records\n" +
		"no config, or one that records another live config (it then records\n" +
		"both). Deleted configs are dropped from the record. Name profiles to\n" +
		"attach only those.\n\n" +
		"A profile that records a config goes with it: `jit migrate remove` of\n" +
		"that config's project deletes it too, so the list is shown and\n" +
		"confirmed first. Nothing is read from the vault and no Touch ID is\n" +
		"needed.\n\n" +
		"--dry-run shows the list and stops. With --format json it prints\n" +
		"config and profiles (name, status, owners, adds).",
	Example: "  jit profile attach ~/Security-Ops/.mcp.json\n" +
		"  jit profile attach ~/Security-Ops/.mcp.json mcp-okta\n" +
		"  jit profile attach --dry-run --format json ~/Security-Ops/.mcp.json",
	Args:              requireArgs(1, -1, "an MCP config file (see `jit doctor`)"),
	ValidArgsFunction: completeProfileAttachArgs,
	SilenceUsage:      true,
	RunE:              runProfileAttach,
}

// completeProfileAttachArgs completes the config as a file, then profile
// names.
func completeProfileAttachArgs(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) == 0 {
		return nil, cobra.ShellCompDirectiveDefault
	}
	return completeProfileNames(cmd, args, toComplete)
}

// Attach statuses, as --format json spells them.
const (
	attachConfigDeleted     = "config_deleted"     // records configs, none of their files exist
	attachNoConfig          = "no_config"          // no .source sidecar at all
	attachRecordedElsewhere = "recorded_elsewhere" // records a live config that isn't this one
)

// attachCandidate is one global profile the config's tools use that
// doesn't record the config.
type attachCandidate struct {
	name     string
	manifest string
	status   string
	owners   []string // the sidecar, verbatim
	live     []string // owners whose file exists
	adds     []string // this config's owner strings the live list lacks
}

// label is the status column: "records a deleted config", "records no
// config", "records <file>".
func (c attachCandidate) label(config string) string {
	switch c.status {
	case attachConfigDeleted:
		return "records a deleted config"
	case attachNoConfig:
		return "records no config"
	}
	for _, o := range c.live {
		if !sameOwnerFile(o, config) {
			return "records " + ownerLabel(o)
		}
	}
	// Only another block of this same file is recorded (~/.claude.json).
	return "records " + ownerLabel(c.live[0])
}

type attachProfileJSON struct {
	Name   string   `json:"name"`
	Status string   `json:"status"`
	Owners []string `json:"owners"`
	Adds   []string `json:"adds"`
}

type attachDryRunJSON struct {
	Config   string              `json:"config"`
	Profiles []attachProfileJSON `json:"profiles"`
}

func runProfileAttach(cmd *cobra.Command, args []string) error {
	if err := validateOutputFormat(profileAttachFormat); err != nil {
		return fmt.Errorf("jit profile attach: %w", err)
	}
	if profileAttachFormat == "json" && !profileAttachDryRun {
		return errors.New("jit profile attach: --format json needs --dry-run")
	}
	for _, name := range args[1:] {
		if _, err := profile.Path("", name); err != nil {
			return fmt.Errorf("jit profile attach: %w", err)
		}
	}
	home, err := profile.GlobalRoot()
	if err != nil {
		return fmt.Errorf("jit profile attach: finding the global profile store: %w", err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("jit profile attach: %w", err)
	}
	config := expandTilde(args[0], home)
	if !filepath.IsAbs(config) {
		config = filepath.Join(cwd, config)
	}
	config = filepath.Clean(config)
	shown := displayPath(home, config)

	info, err := os.Stat(config)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("jit profile attach: %s does not exist", shown)
	case err != nil:
		return fmt.Errorf("jit profile attach: %w", err)
	case info.IsDir():
		return fmt.Errorf("jit profile attach: %s is a directory; name the MCP config file", shown)
	}

	candidates, err := planAttach(home, config, args[1:])
	if err != nil {
		return fmt.Errorf("jit profile attach: %w", err)
	}
	out := cmd.OutOrStdout()

	if profileAttachFormat == "json" {
		res := attachDryRunJSON{Config: config, Profiles: []attachProfileJSON{}}
		for _, c := range candidates {
			owners := c.owners
			if owners == nil {
				owners = []string{}
			}
			res.Profiles = append(res.Profiles, attachProfileJSON{Name: c.name, Status: c.status, Owners: owners, Adds: c.adds})
		}
		return writeJSON(out, res)
	}
	if len(candidates) == 0 {
		fmt.Fprintf(out, "%s uses no profile that doesn't record it\n", shown)
		return nil
	}
	printAttachPlan(out, home, config, candidates)
	if profileAttachDryRun {
		return nil
	}

	q := fmt.Sprintf("Record it on all %d? [y/N] ", len(candidates))
	if len(candidates) == 1 {
		q = fmt.Sprintf("Record it on %s? [y/N] ", candidates[0].name)
	}
	if !profileAttachYes && !confirmPromptTight(cmd, q) {
		fmt.Fprintln(out, "Aborted.")
		return nil
	}
	for i, c := range candidates {
		if err := migrate.WriteProfileOwners(c.manifest, append(append([]string{}, c.live...), c.adds...)); err != nil {
			return fmt.Errorf("jit profile attach: %d of %d recorded, then: %w", i, len(candidates), err)
		}
	}
	_, _ = cOK.Fprint(out, glyphDone)
	fmt.Fprintf(out, " %s now %s %s\n", countWord(len(candidates), "profile", "profiles"),
		pluralWord(len(candidates), "records", "record"), shown)
	return nil
}

// planAttach reads config's wrapped servers and every global profile they
// launch, and returns the profiles that don't record config yet, sorted by
// status (config deleted, no config, recorded elsewhere), then name.
// names, when given, restricts the set; naming a profile config doesn't
// use is an error.
//
// It reads the config itself rather than the launcher map: the question is
// only "what does this file launch", and the answer must carry each
// server's BLOCK, because a ~/.claude.json project block owns its profile
// as "path#projectDir" (mcpSourceScope), the string migrate compares.
func planAttach(home, config string, names []string) ([]attachCandidate, error) {
	launched, err := migrate.MCPProfileOwners(config)
	if err != nil {
		return nil, err
	}
	if len(launched) == 0 {
		return nil, fmt.Errorf("no jit-wrapped MCP server in %s", displayPath(home, config))
	}
	scopes := map[string][]string{} // profile -> this config's owner strings for it
	var order []string
	for _, l := range launched {
		if _, ok := scopes[l.Profile]; !ok {
			order = append(order, l.Profile)
		}
		if !containsString(scopes[l.Profile], l.Owner) {
			scopes[l.Profile] = append(scopes[l.Profile], l.Owner)
		}
	}
	want := order
	if len(names) > 0 {
		want = nil
		for _, n := range names {
			if _, ok := scopes[n]; !ok {
				return nil, fmt.Errorf("no tool in %s uses %s", displayPath(home, config), n)
			}
			if !containsString(want, n) {
				want = append(want, n)
			}
		}
	}

	var out []attachCandidate
	for _, name := range want {
		manifest := globalManifestPath(home, name)
		if manifest == "" {
			if len(names) > 0 {
				return nil, fmt.Errorf("%s is not a global profile", name)
			}
			continue // a project profile, or one no store holds
		}
		owners, err := migrate.ReadProfileOwners(manifest)
		if err != nil {
			// Attach rewrites this list: one it can't read must not be
			// replaced with a guess.
			return nil, fmt.Errorf("reading the record of profile %s: %w", name, err)
		}
		c := attachCandidate{name: name, manifest: manifest, owners: owners}
		for _, o := range owners {
			if _, err := os.Stat(migrate.OwnerFile(o)); errors.Is(err, fs.ErrNotExist) {
				continue
			}
			c.live = append(c.live, o)
		}
		for _, s := range scopes[name] {
			if !ownersHave(c.live, s) {
				c.adds = append(c.adds, s)
			}
		}
		if len(c.adds) == 0 {
			continue
		}
		switch {
		case len(owners) == 0:
			c.status = attachNoConfig
		case len(c.live) == 0:
			c.status = attachConfigDeleted
		default:
			c.status = attachRecordedElsewhere
		}
		out = append(out, c)
	}
	rank := map[string]int{attachConfigDeleted: 0, attachNoConfig: 1, attachRecordedElsewhere: 2}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].status != out[j].status {
			return rank[out[i].status] < rank[out[j].status]
		}
		return out[i].name < out[j].name
	})
	return out, nil
}

// printAttachPlan is the list attach confirms: one row per profile, its
// status in a column, and what a later `jit migrate remove` takes.
func printAttachPlan(out io.Writer, home, config string, candidates []attachCandidate) {
	shown := displayPath(home, config)
	fmt.Fprintf(out, "%s uses %s that %s record it:\n", shown,
		countWord(len(candidates), "profile", "profiles"),
		pluralWord(len(candidates), "doesn't", "don't"))
	width := 0
	for _, c := range candidates {
		width = max(width, len(c.name))
	}
	unowned := false
	for _, c := range candidates {
		fmt.Fprintf(out, "  %-*s   %s\n", width, c.name, c.label(config))
		unowned = unowned || c.status != attachRecordedElsewhere
	}
	// Only a profile left with this config as its sole owner is one
	// `jit migrate remove` then takes (it goes by the first owner).
	if dir, ok := migrateRemoveTargetFor(home, config); ok && unowned {
		fmt.Fprintf(out, "jit migrate remove %s will then take them too.\n", displayPath(home, dir))
	}
}

// migrateRemoveTargetFor returns the directory `jit migrate remove` would
// be pointed at to take config's profiles: config's own directory, when
// that is a project. Not home (migrate remove refuses it: ~/.jit is the
// global store) and not an application's config directory under home
// (~/Library/..., ~/.cursor, ~/.codeium/windsurf), which no one removes as
// a project.
func migrateRemoveTargetFor(home, config string) (string, bool) {
	dir := filepath.Dir(config)
	if canonicalPath(dir) == canonicalPath(home) {
		return "", false
	}
	if rel, err := filepath.Rel(home, dir); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		first := strings.SplitN(rel, string(filepath.Separator), 2)[0]
		if first == "Library" || strings.HasPrefix(first, ".") {
			return "", false
		}
	}
	return dir, true
}

// globalManifestPath is name's manifest in the global store, .yaml or
// .yml, or "" when there is none.
func globalManifestPath(home, name string) string {
	p, err := profile.Path(home, name)
	if err != nil {
		return ""
	}
	for _, candidate := range []string{p, strings.TrimSuffix(p, ".yaml") + ".yml"} {
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
			return candidate
		}
	}
	return ""
}

// ownersHave reports whether owners lists owner, comparing the file part
// with symlinks resolved and the block scope exactly.
func ownersHave(owners []string, owner string) bool {
	for _, o := range owners {
		if sameOwnerFile(o, owner) && ownerScope(o) == ownerScope(owner) {
			return true
		}
	}
	return false
}

// sameOwnerFile reports whether two owners name the same config file.
func sameOwnerFile(a, b string) bool {
	return canonicalPath(migrate.OwnerFile(a)) == canonicalPath(migrate.OwnerFile(b))
}

// ownerScope is an owner's block scope: the project directory after '#',
// or "" for a whole file.
func ownerScope(owner string) string {
	if i := strings.IndexByte(owner, '#'); i >= 0 {
		return owner[i+1:]
	}
	return ""
}

// ownerLabel renders an owner for a status column: the file, and the
// ~/.claude.json project block when there is one.
func ownerLabel(owner string) string {
	s := shortPath(migrate.OwnerFile(owner))
	if scope := ownerScope(owner); scope != "" {
		s += " (" + shortPath(scope) + ")"
	}
	return s
}

func init() {
	profileAttachCmd.Flags().BoolVarP(&profileAttachYes, "yes", "y", false, "skip the confirmation prompt")
	profileAttachCmd.Flags().BoolVar(&profileAttachDryRun, "dry-run", false, "show what would be recorded; change nothing")
	profileAttachCmd.Flags().StringVar(&profileAttachFormat, "format", "text", `dry-run output format: "text" (default) or "json"`)
	_ = profileAttachCmd.RegisterFlagCompletionFunc("format", completeOutputFormat)

	profileRmCmd.Flags().BoolVarP(&profileRmYes, "yes", "y", false, "skip the confirmation prompt (never Touch ID)")
	profileRmCmd.Flags().BoolVar(&profileRmDryRun, "dry-run", false, "show what would be deleted and what uses it; change nothing")
	profileRmCmd.Flags().StringVar(&profileRmFormat, "format", "text", `dry-run output format: "text" (default) or "json"`)
	_ = profileRmCmd.RegisterFlagCompletionFunc("format", completeOutputFormat)

	profileCmd.AddCommand(profileAttachCmd, profileRmCmd)
	rootCmd.AddCommand(profileCmd)
}
