// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/vault"
	"github.com/jitpass/jit/internal/wrap"
)

// jit vault duplicates is the answer to "which of these look-alike groups
// can I safely delete?" — the question `jit vault list`'s nudge raises but
// cannot answer, because answering takes evidence no listing may gather:
// whether the VALUES actually match, which only exists behind an unlock.
//
// It decrypts every stored secret in memory, compares hashes, and prints a
// verdict per finding with the exact remedy command. Reporting is the
// default; --prune acts on ONE shape only, the stale copy whose origin file
// is gone and which nothing references — pure vault garbage, the same
// object class `jit vault orphans --prune` already deletes, reached here by
// duplicate evidence rather than by reference-counting.
//
// Every other shape keeps a printed command instead, because the correct
// cleanup is not "delete these secrets":
//
//   - origin file still on disk -> `jit migrate remove <file>`. Retiring
//     that copy means un-migrating it (restore its plaintext, deregister
//     its mount, drop its profile). Deleting only the secrets would leave a
//     registered mount serving a FIFO no writer can fill.
//   - origin gone but a profile still names the paths -> `jit vault rm`,
//     per path, since deleting them leaves that manifest pointing at holes.
//   - values diverged, or the groups are a shared credential -> no removal
//     at all; neither is jit's call.
//
// --prune always reports what it left behind and why. A cleanup that
// silently skips most of what it listed reads as "cleaned everything".

// dupGroup is one top-level vault group with everything the verdicts need:
// its sorted key names, its uniform recorded origin (empty when absent or
// mixed), whether that origin still exists on disk, what references it, and
// a per-key digest of its decrypted values.
type dupGroup struct {
	name         string
	keys         []string // sorted key names
	origin       string   // uniform recorded origin, "" when absent/mixed
	originExists bool     // stat of origin, false when origin == ""
	profiles     []string // referencing profile names (deduped)
	mountPath    string   // a mount serving this group's profile, "" when none
	// ownerConfig is the source file the referencing PROFILE records, the
	// fallback provenance for a pre-provenance secret whose envelope has no
	// Origin. See sourceFile.
	ownerConfig string
	hashes      map[string]string // key -> value digest
}

// sourceFile is the group's best evidence of which file it came from: the
// envelope's recorded Origin, or — for a PRE-PROVENANCE secret, whose
// envelope has no Origin field at all — the source config the referencing
// profile records. Without the fallback every secret migrated before
// provenance shipped is invisible to duplicate detection, which is exactly
// how a real vault's clearest duplicate went unreported: the older copy
// (`mcp-caido`) predated provenance and was skipped, so its newer twin
// (`mcp-caido-2`) had nothing to pair with and both landed in the
// shared-credentials bucket as "keep all".
func (g *dupGroup) sourceFile() string {
	if g.origin != "" {
		return g.origin
	}
	return g.ownerConfig
}

// dupFinding is one same-file verdict: two or more groups holding the same
// key set from the same file (or two copies of it), with the value
// comparison's result and the routed remedy.
type dupFinding struct {
	Groups      []string `json:"groups"`
	Keys        []string `json:"keys"`
	Origins     []string `json:"origins"` // parallel to Groups
	SameOrigin  bool     `json:"same_origin"`
	ValuesMatch bool     `json:"values_match"`
	// RemoveGroup/RemoveCommand: the copy the report suggests retiring and
	// the command that retires it correctly. Empty when values differ —
	// diverged copies are the user's call, not a heuristic's.
	RemoveGroup   string `json:"remove_group,omitempty"`
	RemoveCommand string `json:"remove_command,omitempty"`
	// Prunable marks the findings `--prune` may delete itself: the stale
	// copy's origin file is GONE and no profile jit can see references it,
	// so its secrets are vault garbage with nothing live behind them. See
	// vaultDuplicatesCmd's Long for why the other shapes are deliberately
	// out of --prune's reach.
	Prunable bool `json:"prunable"`
	// RemovePaths are the stale copy's vault paths, what --prune deletes.
	RemovePaths []string `json:"remove_paths,omitempty"`
	// ExtraKeys are keys present in some copies but not all: the same file
	// migrated twice and edited since. Their presence blocks any removal
	// pick, because retiring a copy holding a key the others lack would
	// silently drop that secret.
	ExtraKeys []string `json:"extra_keys,omitempty"`
}

// sharedFinding is one shared-credential verdict: the same value stored
// under the same key names by independent files. Not a problem — the point
// of reporting it is to STOP these being mistaken for stale copies, and to
// name every place a rotation has to reach.
type sharedFinding struct {
	Keys   []string `json:"keys"`
	Groups []string `json:"groups"`
}

var (
	vaultDuplicatesFormat string
	vaultDuplicatesPrune  bool
	vaultDuplicatesYes    bool
)

var vaultDuplicatesCmd = &cobra.Command{
	Use:   "duplicates",
	Short: "Report groups that hold the same secrets, and which are safe to retire",
	Long: "Compares every stored secret's decrypted value in memory (no value is ever\n" +
		"printed or written) and reports two things `jit vault list` cannot know\n" +
		"from names alone:\n\n" +
		"  " + "Duplicated groups: the same key names migrated from the same file, or\n" +
		"  from two copies of it (a re-migrated project, a copied workspace tree).\n" +
		"  When the values still match, the report names the copy that looks stale\n" +
		"  and the command that retires it cleanly: `jit migrate remove <file>`\n" +
		"  while the file still exists (it restores that file's plaintext, then\n" +
		"  deletes its profile and secrets), otherwise --prune or `jit vault rm`.\n" +
		"  Diverged copies (same file ancestry, different values now) are reported\n" +
		"  without a removal pick.\n\n" +
		"  Shared credentials: the same value stored by independent files, e.g.\n" +
		"  one API client used by five export scripts. These are NOT stale copies,\n" +
		"  removing any breaks its tool, and the report lists every place a\n" +
		"  rotation has to reach.\n\n" +
		"Reporting only by default. --prune deletes the ONE shape that is pure\n" +
		"vault garbage: a stale copy whose origin file is already gone AND that no\n" +
		"profile jit can see references, after a [y/N] confirmation and a fresh\n" +
		"Touch ID/passcode. Everything else keeps its printed command instead, on\n" +
		"purpose: a copy whose file still exists has to be un-migrated by\n" +
		"`jit migrate remove` (which restores its plaintext, deregisters its mount\n" +
		"and drops its profile — deleting just the secrets would leave a mount\n" +
		"serving a file nothing can fill), a copy a profile still names is a\n" +
		"per-path `jit vault rm` decision, and diverged or shared copies are never\n" +
		"jit's call at all. --prune always reports what it left behind and why.\n\n" +
		"Reading every value means unlocking the vault and, for each credential\n" +
		"CLASS the per-process consent gate covers (aws, kube, git, shell_history,\n" +
		"...), approving that class once. A vault holding two gated classes\n" +
		"therefore asks about three times, not once: the unlock plus one per class.\n" +
		"`jit service consent off` removes the per-class half.",
	Example: "  jit vault duplicates\n" +
		"  jit vault duplicates --prune\n" +
		"  jit vault duplicates --format json",
	Args:         cobra.NoArgs,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateOutputFormat(vaultDuplicatesFormat); err != nil {
			return fmt.Errorf("jit vault duplicates: %w", err)
		}
		out := cmd.OutOrStdout()
		root, err := vaultRootDir()
		if err != nil {
			return fmt.Errorf("jit vault duplicates: %w", err)
		}
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("jit vault duplicates: %w", err)
		}

		v, err := openVault()
		if err != nil {
			return fmt.Errorf("jit vault duplicates: %w", err)
		}
		paths, err := v.List()
		if err != nil {
			return fmt.Errorf("jit vault duplicates: %w", err)
		}
		secrets, _ := splitBackupPaths(paths)

		groups, compared, err := gatherDupGroups(v, root, cwd, secrets)
		if err != nil {
			return fmt.Errorf("jit vault duplicates: %w", err)
		}
		findings := sameFileFindings(groups)
		shared := sharedCredentialFindings(groups, findings)

		if vaultDuplicatesFormat == "json" {
			if err := writeJSON(out, struct {
				Findings          []dupFinding    `json:"findings"`
				SharedCredentials []sharedFinding `json:"shared_credentials"`
				SecretsCompared   int             `json:"secrets_compared"`
			}{findings, shared, compared}); err != nil {
				return fmt.Errorf("jit vault duplicates: %w", err)
			}
			if !vaultDuplicatesPrune {
				return nil
			}
		} else {
			printDuplicatesReport(out, findings, shared, compared)
		}
		if !vaultDuplicatesPrune {
			return nil
		}
		if err := pruneDuplicates(cmd, v, findings); err != nil {
			return fmt.Errorf("jit vault duplicates: %w", err)
		}
		return nil
	},
}

// pruneDuplicates deletes the prunable findings' stale copies: origin file
// gone, referenced by nothing. Everything else is reported as left behind
// with the command that would retire it — a silent skip would read as
// "cleaned everything" when it hadn't.
func pruneDuplicates(cmd *cobra.Command, v *vault.Vault, findings []dupFinding) error {
	out := cmd.OutOrStdout()
	if vaultDuplicatesFormat == "json" {
		out = cmd.ErrOrStderr() // stdout already carries the machine output
	}
	var paths []string
	var left []dupFinding
	prunableGroups := 0
	for _, f := range findings {
		if f.Prunable {
			paths = append(paths, f.RemovePaths...)
			prunableGroups++
			continue
		}
		if f.RemoveCommand != "" || !f.ValuesMatch {
			left = append(left, f)
		}
	}
	reportLeft := func() {
		if len(left) == 0 {
			return
		}
		fmt.Fprintf(out, "\nLeft alone, %s %s a command only you should run:\n",
			countWord(len(left), "finding", "findings"),
			pluralWord(len(left), "needs", "need"))
		for _, f := range left {
			if !f.ValuesMatch {
				fmt.Fprintf(out, "  %s %s: copies have diverged, compare them first\n",
					glyphBranch, strings.Join(f.Groups, ", "))
				continue
			}
			fmt.Fprintf(out, "  %s %s: ", glyphBranch, f.RemoveGroup)
			_, _ = cPath.Fprintln(out, f.RemoveCommand)
		}
	}
	if len(paths) == 0 {
		fmt.Fprintln(out, "\nNothing to prune: no duplicate's stale copy is both file-less and unreferenced.")
		reportLeft()
		return nil
	}
	fmt.Fprintf(out, "\nPruning %s from %s whose origin file is gone and which nothing references:\n",
		countWord(len(paths), "secret", "secrets"),
		countWord(prunableGroups, "duplicate group", "duplicate groups"))
	for _, p := range paths {
		fmt.Fprintf(out, "  %s %s\n", glyphBullet, p)
	}
	// Names its own object class and disclaims the neighbouring prunes' —
	// see the matching comment in `jit vault prune`: three commands in this
	// namespace delete different things under the same word.
	if !vaultDuplicatesYes && !confirmPrompt(cmd, fmt.Sprintf(
		"Permanently delete %s? This removes duplicated secret values, not `jit migrate`'s file backups. This can't be undone. [y/N] ",
		countWord(len(paths), "duplicated secret", "duplicated secrets"))) {
		fmt.Fprintln(out, "Aborted. Nothing was deleted.")
		reportLeft()
		return nil
	}
	// Fresh biometric gate, same idiom as rm/orphans/prune: Remove only
	// unlinks envelope files, so this explicit user-presence check is what
	// forces a fingerprint here, locked or not.
	if err := requireUserPresence(fmt.Sprintf("delete %s from the vault",
		countWord(len(paths), "duplicated secret", "duplicated secrets"))); err != nil {
		return err
	}
	for _, p := range paths {
		if err := v.Remove(p); err != nil && !errors.Is(err, vault.ErrNotFound) {
			return fmt.Errorf("deleting %s: %w", p, err)
		}
	}
	fmt.Fprintf(out, "Deleted %s.\n", countWord(len(paths), "duplicated secret", "duplicated secrets"))
	reportLeft()
	return nil
}

// gatherDupGroups decrypts and digests every stored secret, grouped by top
// path segment. Values are hashed the moment they are read and never kept;
// the digest map is all any later stage sees. compared counts the secrets
// actually decrypted (an envelope that fails to read is skipped — one
// unreadable secret must not take down the whole report).
func gatherDupGroups(v *vault.Vault, root, cwd string, secrets []string) (map[string]*dupGroup, int, error) {
	refs := referencesForPaths(root, cwd, secrets)
	groups := map[string]*dupGroup{}
	compared := 0
	for _, p := range secrets {
		name := groupPrefix(p)
		key := strings.TrimPrefix(p, name+"/")
		if key == p {
			continue // a group-less top-level path joins no comparison
		}
		g := groups[name]
		if g == nil {
			g = &dupGroup{name: name, originExists: false, hashes: map[string]string{}}
			groups[name] = g
		}
		g.keys = append(g.keys, key)

		if info, err := v.Info(p); err == nil {
			switch {
			case len(g.hashes) == 0 && g.origin == "" && len(g.keys) == 1:
				g.origin = info.Origin
			case g.origin != info.Origin:
				g.origin = "" // mixed origins claim nothing
			}
		}
		for _, r := range refs[p] {
			if !slices.Contains(g.profiles, r.ProfileName) {
				g.profiles = append(g.profiles, r.ProfileName)
			}
			if r.MountPath != "" && g.mountPath == "" {
				g.mountPath = r.MountPath
			}
			if r.OwnerConfig != "" && g.ownerConfig == "" {
				g.ownerConfig = r.OwnerConfig
			}
		}

		value, err := v.Get(p)
		if err != nil {
			continue
		}
		sum := sha256.Sum256(value)
		g.hashes[key] = fmt.Sprintf("%x", sum)
		compared++
	}
	home, _ := os.UserHomeDir()
	for _, g := range groups {
		sort.Strings(g.keys)
		sort.Strings(g.profiles)
		if g.sourceFile() != "" {
			// Origin is stored ALREADY tilde-shortened ("~/proj/.env", see
			// newProvenance), so it must be expanded before it can be
			// stat'ed. Statting it raw always failed, which made
			// originExists permanently false: the `jit migrate remove`
			// branch below became dead code and every live duplicate was
			// routed to `jit vault rm` instead — the precise advice this
			// command exists to stop giving. Caught end to end on a real
			// vault, not by a unit test, because the tests supplied
			// absolute origins that no real migration ever writes.
			_, statErr := os.Stat(wrap.ExpandHome(home, g.sourceFile()))
			g.originExists = statErr == nil
		}
	}
	return groups, compared, nil
}

// sameFileFindings clusters groups on (key set, origin tail) — the same
// evidence rule the listing's nudge uses — and settles each cluster with
// the value comparison the nudge can't run. The removal pick prefers, in
// order: a copy whose origin file is gone (nothing can still read it), a
// copy nothing references, then the lexicographically-later name (the
// claimNamespace "-2" fork is the later arrival). No pick at all when
// values differ.
func sameFileFindings(groups map[string]*dupGroup) []dupFinding {
	// Cluster on the origin TAIL only. Requiring an identical key set as
	// well was too strict for the most ordinary real shape: copy a
	// workspace, then edit one copy. A real vault had
	// .../okta-mcp-server/.env migrated from two trees where one copy had
	// since gained OKTA_PRIVATE_KEY — same file, four identical values, and
	// the exact-set rule paired neither.
	byTail := map[string][]*dupGroup{}
	var tails []string
	for _, g := range groups {
		if g.sourceFile() == "" || len(g.keys) == 0 {
			continue
		}
		t := originTail(g.sourceFile())
		if _, ok := byTail[t]; !ok {
			tails = append(tails, t)
		}
		byTail[t] = append(byTail[t], g)
	}
	sort.Strings(tails)

	var findings []dupFinding
	for _, tail := range tails {
		cluster := byTail[tail]
		if len(cluster) < 2 {
			continue
		}
		// One .mcp.json yields one profile PER SERVER, so a shared tail
		// alone is not duplication: mcp-caido-2 and mcp-okta-mcp-server
		// both come from ai_security_workspace/.mcp.json and share no key
		// at all. Groups pair only when their keys actually overlap and
		// every shared value matches (relatedGroups).
		//
		// Widest first, so a subset attaches to its superset rather than
		// seeding its own finding.
		sort.Slice(cluster, func(i, j int) bool {
			if len(cluster[i].keys) != len(cluster[j].keys) {
				return len(cluster[i].keys) > len(cluster[j].keys)
			}
			return cluster[i].name < cluster[j].name
		})
		var buckets [][]*dupGroup
		for _, g := range cluster {
			placed := false
			for i := range buckets {
				if relatedGroups(buckets[i][0], g) {
					buckets[i] = append(buckets[i], g)
					placed = true
					break
				}
			}
			if !placed {
				buckets = append(buckets, []*dupGroup{g})
			}
		}
		for _, bucket := range buckets {
			if len(bucket) < 2 {
				continue
			}
			findings = append(findings, buildDupFinding(bucket))
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Groups[0] < findings[j].Groups[0] })
	return findings
}

// relatedGroups reports whether b looks like a descendant of the same file
// as a: their keys overlap substantially (b's keys are a subset of a's, or
// they share at least half of the wider set). Sharing an origin tail alone
// is not enough — one .mcp.json produces one profile PER SERVER, and those
// siblings share the tail while holding disjoint keys.
//
// Value equality is deliberately NOT a gate here. It is the VERDICT
// (ValuesMatch), not the evidence of common ancestry: two copies of one
// file whose values have since diverged are still copies, and are exactly
// what the user most needs told about. Gating on it made diverged copies
// vanish from the report entirely.
func relatedGroups(a, b *dupGroup) bool {
	shared := 0
	for _, k := range b.keys {
		if _, ok := a.hashes[k]; ok {
			shared++
		}
	}
	if shared == 0 {
		return false
	}
	wider := len(a.keys)
	if len(b.keys) > wider {
		wider = len(b.keys)
	}
	return shared == len(b.keys) || shared == len(a.keys) || shared*2 >= wider
}

// buildDupFinding turns one bucket of related groups into a finding. Keys
// are the SHARED set; a copy that has since gained or lost a key is still
// the same file's descendant, but it gets no removal pick, because retiring
// a copy holding a key the survivor lacks would silently drop that secret.
func buildDupFinding(bucket []*dupGroup) dupFinding {
	sort.Slice(bucket, func(i, j int) bool { return bucket[i].name < bucket[j].name })
	sharedKeys := append([]string(nil), bucket[0].keys...)
	for _, g := range bucket[1:] {
		var keep []string
		for _, k := range sharedKeys {
			if _, ok := g.hashes[k]; ok {
				keep = append(keep, k)
			}
		}
		sharedKeys = keep
	}
	sort.Strings(sharedKeys)

	f := dupFinding{Keys: sharedKeys, SameOrigin: true, ValuesMatch: true}
	sameKeySet := true
	for _, g := range bucket {
		f.Groups = append(f.Groups, g.name)
		f.Origins = append(f.Origins, g.sourceFile())
		if g.sourceFile() != bucket[0].sourceFile() {
			f.SameOrigin = false
		}
		if len(g.keys) != len(sharedKeys) {
			sameKeySet = false
			f.ExtraKeys = append(f.ExtraKeys, extraKeys(g, sharedKeys)...)
		}
		for _, k := range sharedKeys {
			if g.hashes[k] == "" || g.hashes[k] != bucket[0].hashes[k] {
				f.ValuesMatch = false
			}
		}
	}
	sort.Strings(f.ExtraKeys)
	f.ExtraKeys = slices.Compact(f.ExtraKeys)
	if !f.ValuesMatch || !sameKeySet {
		// Diverged in value, or one copy carries a key the others don't:
		// either way jit must not nominate a copy to delete.
		return f
	}
	pick := pickRemoval(bucket)
	f.RemoveGroup = pick.name
	f.RemovePaths = groupSecretPaths(pick)
	switch {
	case pick.sourceFile() != "" && pick.originExists:
		f.RemoveCommand = "jit migrate remove " + shortPath(pick.sourceFile())
	case len(pick.profiles) == 0:
		f.RemoveCommand = "jit vault duplicates --prune"
		f.Prunable = true
	default:
		f.RemoveCommand = "jit vault rm " + strings.Join(f.RemovePaths, " ")
	}
	return f
}

// extraKeys are g's keys outside the shared set.
func extraKeys(g *dupGroup, shared []string) []string {
	var extra []string
	for _, k := range g.keys {
		if !slices.Contains(shared, k) {
			extra = append(extra, k)
		}
	}
	return extra
}

// pickRemoval chooses which copy of a matching cluster the report suggests
// retiring. It is a suggestion, printed under a caveat — never acted on.
func pickRemoval(cluster []*dupGroup) *dupGroup {
	for _, g := range cluster {
		if g.sourceFile() != "" && !g.originExists {
			return g
		}
	}
	for _, g := range cluster {
		if len(g.profiles) == 0 {
			return g
		}
	}
	return cluster[len(cluster)-1]
}

func groupSecretPaths(g *dupGroup) []string {
	paths := make([]string, 0, len(g.keys))
	for _, k := range g.keys {
		paths = append(paths, g.name+"/"+k)
	}
	return paths
}

// sharedCredentialFindings reports the same VALUE stored under the same key
// by groups that same-file evidence did not pair — independent tools
// holding one credential. Key names that look like plain configuration
// (looksLikeConfig: OUTPUT_FILE, DEBUG, ...) don't count: two scripts
// writing to the same output path is not a shared credential, and
// reporting it would bury the ones that are.
func sharedCredentialFindings(groups map[string]*dupGroup, consumed []dupFinding) []sharedFinding {
	inFinding := map[string]bool{}
	for _, f := range consumed {
		for _, g := range f.Groups {
			inFinding[g] = true
		}
	}
	// (key, digest) -> group names sharing it.
	sharing := map[string][]string{}
	for _, g := range groups {
		if inFinding[g.name] {
			continue
		}
		for k, h := range g.hashes {
			if h == "" || looksLikeConfig(k) {
				continue
			}
			id := k + "\x00" + h
			sharing[id] = append(sharing[id], g.name)
		}
	}
	// Merge per-key clusters that cover the identical set of groups into
	// one finding (the five-export-scripts case is one credential, three
	// keys — three lines would triple-report one fact).
	byGroupSet := map[string]*sharedFinding{}
	var order []string
	ids := make([]string, 0, len(sharing))
	for id := range sharing {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		names := sharing[id]
		if len(names) < 2 {
			continue
		}
		sort.Strings(names)
		setKey := strings.Join(names, "\x00")
		f := byGroupSet[setKey]
		if f == nil {
			f = &sharedFinding{Groups: names}
			byGroupSet[setKey] = f
			order = append(order, setKey)
		}
		f.Keys = append(f.Keys, strings.SplitN(id, "\x00", 2)[0])
	}
	findings := make([]sharedFinding, 0, len(order))
	sort.Strings(order)
	for _, setKey := range order {
		f := byGroupSet[setKey]
		sort.Strings(f.Keys)
		findings = append(findings, *f)
	}
	return findings
}

// printDuplicatesReport renders the text report: a findings section in the
// house report shape, a shared-credentials section, and the one-line
// footer stating what was compared and how.
func printDuplicatesReport(out io.Writer, findings []dupFinding, shared []sharedFinding, compared int) {
	if len(findings) == 0 && len(shared) == 0 {
		fmt.Fprintf(out, "No duplicates: every group's keys, origins and values are distinct.\n")
		fmt.Fprintf(out, "%d %s compared in memory; no value was printed or written.\n",
			compared, pluralWord(compared, "secret", "secrets"))
		return
	}
	// The zero-findings header still prints when there ARE shared
	// credentials: without it the report opens on "[shared credentials]"
	// and there is no way to tell whether duplicates were checked and none
	// found, or the check never ran.
	if len(findings) == 0 {
		_, _ = cBold.Fprintf(out, "[duplicates]")
		fmt.Fprintf(out, " none across %d stored %s\n", compared, pluralWord(compared, "secret", "secrets"))
	}
	if len(findings) > 0 {
		_, _ = cBold.Fprintf(out, "[duplicates]")
		fmt.Fprintf(out, " %s across %d stored %s\n", countWord(len(findings), "finding", "findings"),
			compared, pluralWord(compared, "secret", "secrets"))
		for _, f := range findings {
			fmt.Fprintln(out)
			printDupFinding(out, f)
		}
	}
	if len(shared) > 0 {
		if len(findings) > 0 {
			fmt.Fprintln(out)
		}
		_, _ = cBold.Fprintf(out, "[shared credentials]")
		fmt.Fprintf(out, " %d · same value in independent tools, keep all\n", len(shared))
		for _, f := range shared {
			fmt.Fprintln(out)
			_, _ = cOK.Fprintf(out, "%s ", glyphOK)
			_, _ = cBold.Fprint(out, strings.Join(f.Keys, ", "))
			fmt.Fprintf(out, " shared by %d profiles\n", len(f.Groups))
			fmt.Fprintf(out, "  %s %s\n", glyphBranch, strings.Join(f.Groups, ", "))
		}
		fmt.Fprintln(out, "  removing any copy breaks its tool; when rotating, update every copy")
	}
	prunable := 0
	for _, f := range findings {
		if f.Prunable {
			prunable++
		}
	}
	fmt.Fprintln(out)
	if prunable > 0 && !vaultDuplicatesPrune {
		fmt.Fprint(out, hlCmds(fmt.Sprintf("%s can be deleted here (origin file gone, referenced by nothing): `jit vault duplicates --prune`\n",
			countWord(prunable, "finding", "findings"))))
	}
	fmt.Fprintf(out, "%d %s compared in memory; no value was printed or written.\n",
		compared, pluralWord(compared, "secret", "secrets"))
}

func printDupFinding(out io.Writer, f dupFinding) {
	_, _ = cWarn.Fprintf(out, "%s ", glyphWarn)
	_, _ = cBold.Fprint(out, strings.Join(f.Groups, ", "))
	switch {
	case f.SameOrigin:
		fmt.Fprintln(out, ": one file, migrated more than once")
	case len(f.ExtraKeys) > 0:
		fmt.Fprintln(out, ": one file, migrated twice and edited since")
	case f.ValuesMatch:
		fmt.Fprintln(out, ": one file, migrated from two copies")
	default:
		fmt.Fprintln(out, ": copies that have diverged")
	}
	keysLabel := "keys"
	if len(f.Keys) == 1 {
		keysLabel = "key"
	}
	match := "identical values"
	if !f.ValuesMatch {
		match = "values DIFFER"
	}
	fmt.Fprintf(out, "  %s %d shared %s (%s), %s\n", glyphBranch, len(f.Keys), keysLabel,
		truncateList(f.Keys, 3), match)
	if len(f.ExtraKeys) > 0 {
		fmt.Fprintf(out, "  %s not in every copy: %s\n", glyphBranch, truncateList(f.ExtraKeys, 3))
	}
	wide := 0
	for _, g := range f.Groups {
		if len(g) > wide {
			wide = len(g)
		}
	}
	for i, g := range f.Groups {
		fmt.Fprintf(out, "  %s %-*s  from %s\n", glyphBranch, wide, g, shortPath(f.Origins[i]))
	}
	switch {
	case !f.ValuesMatch:
		fmt.Fprintln(out, "  the copies no longer agree; compare the files before retiring either")
	case len(f.ExtraKeys) > 0:
		fmt.Fprintln(out, "  one copy holds keys the other doesn't; retiring either would lose them")
	case f.RemoveCommand != "":
		fmt.Fprintf(out, "  keep the copy your tools read; %s looks stale, retire it with:\n", f.RemoveGroup)
		_, _ = cPath.Fprintf(out, "  %s %s\n", glyphAction, f.RemoveCommand)
	}
}

// truncateList joins up to max names, summarizing the rest — variable
// content is truncated rather than wrapped (house rule).
func truncateList(names []string, max int) string {
	if len(names) <= max {
		return strings.Join(names, ", ")
	}
	return fmt.Sprintf("%s + %d more", strings.Join(names[:max], ", "), len(names)-max)
}

func init() {
	vaultDuplicatesCmd.Flags().StringVar(&vaultDuplicatesFormat, "format", "text", `output format: "text" (default) or "json"`)
	vaultDuplicatesCmd.Flags().BoolVar(&vaultDuplicatesPrune, "prune", false, "delete stale copies whose origin file is gone and which nothing references")
	vaultDuplicatesCmd.Flags().BoolVarP(&vaultDuplicatesYes, "yes", "y", false, "skip the confirmation prompt (never the fingerprint)")
	vaultCmd.AddCommand(vaultDuplicatesCmd)
}
