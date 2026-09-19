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
//   - adopt makes an MCP config an owner of the global profiles it launches
//     but doesn't own: the case where the config that made a profile was
//     deleted or copied, and another one launches it now. Bookkeeping only,
//     so no Touch ID and no vault access.
//   - rm (profilerm.go) deletes a global profile, its .source sidecar and
//     every secret nothing else uses, and refuses a profile anything known
//     still launches.

var profileCmd = &cobra.Command{
	Use:     "profile",
	GroupID: groupSecrets,
	// See runCommandGroup: a mistyped subcommand must fail, not print help
	// and exit 0.
	RunE:        runCommandGroup,
	Annotations: commandGroupAnnotations(),
	Short:       "Manage which configs own a profile, and delete one",
	Long: "A profile maps variables to vault secrets; `jit run --profile` resolves\n" +
		"it. A profile made from an MCP config records that config as its owner,\n" +
		"which is what `jit migrate remove` goes by.\n\n" +
		"`jit profile adopt` makes a config the owner of profiles it launches but\n" +
		"doesn't own (its owner was deleted, or the config was copied).\n" +
		"`jit profile rm` deletes a global profile nothing known launches, with\n" +
		"the secrets nothing else uses.",
}

var (
	profileAdoptYes    bool
	profileAdoptDryRun bool
	profileAdoptFormat string
)

var profileAdoptCmd = &cobra.Command{
	Use:   "adopt <config> [profile]...",
	Short: "Make an MCP config the owner of the profiles it launches",
	Long: "Records <config> as an owner of every global profile it launches but\n" +
		"doesn't own: one whose owner file is gone, one with no owner at all, or\n" +
		"one another live config owns (both then own it). Owners whose file is\n" +
		"gone are dropped. Name profiles to adopt only those.\n\n" +
		"Owning a profile means `jit migrate remove` of that config's project\n" +
		"deletes it too, so the list is shown and confirmed first. Nothing is\n" +
		"read from the vault and no Touch ID is needed.\n\n" +
		"--dry-run shows the list and stops. With --format json it prints\n" +
		"config and profiles (name, status, owners, adds).",
	Example: "  jit profile adopt ~/Security-Ops/.mcp.json\n" +
		"  jit profile adopt ~/Security-Ops/.mcp.json mcp-okta\n" +
		"  jit profile adopt --dry-run --format json ~/Security-Ops/.mcp.json",
	Args:              requireArgs(1, -1, "an MCP config file (see `jit doctor`)"),
	ValidArgsFunction: completeProfileAdoptArgs,
	SilenceUsage:      true,
	RunE:              runProfileAdopt,
}

// completeProfileAdoptArgs completes the config as a file, then profile
// names.
func completeProfileAdoptArgs(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) == 0 {
		return nil, cobra.ShellCompDirectiveDefault
	}
	return completeProfileNames(cmd, args, toComplete)
}

// Adopt statuses, as --format json spells them.
const (
	adoptOwnerGone      = "owner_gone"      // has owners, none of their files exist
	adoptNoOwner        = "no_owner"        // no .source sidecar at all
	adoptOwnedElsewhere = "owned_elsewhere" // a live owner that isn't this config
)

// adoptCandidate is one global profile the config launches but doesn't own.
type adoptCandidate struct {
	name     string
	manifest string
	status   string
	owners   []string // the sidecar, verbatim
	live     []string // owners whose file exists
	adds     []string // this config's owner strings the live list lacks
}

// label is the status column: "owner gone", "no owner", "owned by <file>".
func (c adoptCandidate) label(config string) string {
	switch c.status {
	case adoptOwnerGone:
		return "owner gone"
	case adoptNoOwner:
		return "no owner"
	}
	for _, o := range c.live {
		if !sameOwnerFile(o, config) {
			return "owned by " + ownerLabel(o)
		}
	}
	// Only another block of this same file owns it (~/.claude.json).
	return "owned by " + ownerLabel(c.live[0])
}

type adoptProfileJSON struct {
	Name   string   `json:"name"`
	Status string   `json:"status"`
	Owners []string `json:"owners"`
	Adds   []string `json:"adds"`
}

type adoptDryRunJSON struct {
	Config   string             `json:"config"`
	Profiles []adoptProfileJSON `json:"profiles"`
}

func runProfileAdopt(cmd *cobra.Command, args []string) error {
	if err := validateOutputFormat(profileAdoptFormat); err != nil {
		return fmt.Errorf("jit profile adopt: %w", err)
	}
	if profileAdoptFormat == "json" && !profileAdoptDryRun {
		return errors.New("jit profile adopt: --format json needs --dry-run")
	}
	for _, name := range args[1:] {
		if _, err := profile.Path("", name); err != nil {
			return fmt.Errorf("jit profile adopt: %w", err)
		}
	}
	home, err := profile.GlobalRoot()
	if err != nil {
		return fmt.Errorf("jit profile adopt: finding the global profile store: %w", err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("jit profile adopt: %w", err)
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
		return fmt.Errorf("jit profile adopt: %s does not exist", shown)
	case err != nil:
		return fmt.Errorf("jit profile adopt: %w", err)
	case info.IsDir():
		return fmt.Errorf("jit profile adopt: %s is a directory; name the MCP config file", shown)
	}

	candidates, err := planAdopt(home, config, args[1:])
	if err != nil {
		return fmt.Errorf("jit profile adopt: %w", err)
	}
	out := cmd.OutOrStdout()

	if profileAdoptFormat == "json" {
		res := adoptDryRunJSON{Config: config, Profiles: []adoptProfileJSON{}}
		for _, c := range candidates {
			owners := c.owners
			if owners == nil {
				owners = []string{}
			}
			res.Profiles = append(res.Profiles, adoptProfileJSON{Name: c.name, Status: c.status, Owners: owners, Adds: c.adds})
		}
		return writeJSON(out, res)
	}
	if len(candidates) == 0 {
		fmt.Fprintf(out, "%s launches no profile it doesn't own\n", shown)
		return nil
	}
	printAdoptPlan(out, home, config, candidates)
	if profileAdoptDryRun {
		return nil
	}

	q := fmt.Sprintf("Adopt all %d? [y/N] ", len(candidates))
	if len(candidates) == 1 {
		q = "Adopt it? [y/N] "
	}
	if !profileAdoptYes && !confirmPromptTight(cmd, q) {
		fmt.Fprintln(out, "Aborted.")
		return nil
	}
	for i, c := range candidates {
		if err := migrate.WriteProfileOwners(c.manifest, append(append([]string{}, c.live...), c.adds...)); err != nil {
			return fmt.Errorf("jit profile adopt: %d of %d adopted, then: %w", i, len(candidates), err)
		}
	}
	_, _ = cOK.Fprint(out, glyphDone)
	fmt.Fprintf(out, " %s owns %s\n", shown, countWord(len(candidates), "profile", "profiles"))
	return nil
}

// planAdopt reads config's wrapped servers and every global profile they
// launch, and returns the profiles config doesn't own yet, sorted by
// status (owner gone, no owner, owned elsewhere), then name. names, when
// given, restricts the set; naming a profile config doesn't launch is an
// error.
//
// It reads the config itself rather than the launcher map: the question is
// only "what does this file launch", and the answer must carry each
// server's BLOCK, because a ~/.claude.json project block owns its profile
// as "path#projectDir" (mcpSourceScope), the string migrate compares.
func planAdopt(home, config string, names []string) ([]adoptCandidate, error) {
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
				return nil, fmt.Errorf("%s doesn't launch %s", displayPath(home, config), n)
			}
			if !containsString(want, n) {
				want = append(want, n)
			}
		}
	}

	var out []adoptCandidate
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
			// Adopt rewrites this list: one it can't read must not be
			// replaced with a guess.
			return nil, fmt.Errorf("reading the owners of profile %s: %w", name, err)
		}
		c := adoptCandidate{name: name, manifest: manifest, owners: owners}
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
			c.status = adoptNoOwner
		case len(c.live) == 0:
			c.status = adoptOwnerGone
		default:
			c.status = adoptOwnedElsewhere
		}
		out = append(out, c)
	}
	rank := map[string]int{adoptOwnerGone: 0, adoptNoOwner: 1, adoptOwnedElsewhere: 2}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].status != out[j].status {
			return rank[out[i].status] < rank[out[j].status]
		}
		return out[i].name < out[j].name
	})
	return out, nil
}

// printAdoptPlan is the list adopt confirms: one row per profile, its
// status in a column, and what a later `jit migrate remove` takes.
func printAdoptPlan(out io.Writer, home, config string, candidates []adoptCandidate) {
	shown := displayPath(home, config)
	fmt.Fprintf(out, "%s launches %s it doesn't own:\n", shown,
		countWord(len(candidates), "profile", "profiles"))
	width := 0
	for _, c := range candidates {
		width = max(width, len(c.name))
	}
	unowned := false
	for _, c := range candidates {
		fmt.Fprintf(out, "  %-*s   %s\n", width, c.name, c.label(config))
		unowned = unowned || c.status != adoptOwnedElsewhere
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
	profileAdoptCmd.Flags().BoolVarP(&profileAdoptYes, "yes", "y", false, "skip the confirmation prompt")
	profileAdoptCmd.Flags().BoolVar(&profileAdoptDryRun, "dry-run", false, "show what would be adopted; change nothing")
	profileAdoptCmd.Flags().StringVar(&profileAdoptFormat, "format", "text", `dry-run output format: "text" (default) or "json"`)
	_ = profileAdoptCmd.RegisterFlagCompletionFunc("format", completeOutputFormat)

	profileRmCmd.Flags().BoolVarP(&profileRmYes, "yes", "y", false, "skip the confirmation prompt (never Touch ID)")
	profileRmCmd.Flags().BoolVar(&profileRmDryRun, "dry-run", false, "show what would be deleted and what launches it; change nothing")
	profileRmCmd.Flags().StringVar(&profileRmFormat, "format", "text", `dry-run output format: "text" (default) or "json"`)
	_ = profileRmCmd.RegisterFlagCompletionFunc("format", completeOutputFormat)

	profileCmd.AddCommand(profileAdoptCmd, profileRmCmd)
	rootCmd.AddCommand(profileCmd)
}
