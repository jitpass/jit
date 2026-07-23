// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

//go:build darwin

package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/jitpass/jit/internal/agent"
	"github.com/jitpass/jit/internal/keychainwrap"
	"github.com/jitpass/jit/internal/migrate"
	"github.com/jitpass/jit/internal/mount"
	"github.com/jitpass/jit/internal/pasteboard"
	"github.com/jitpass/jit/internal/profile"
	"github.com/jitpass/jit/internal/vault"
)

var (
	vaultSetStdin      bool
	vaultSetForce      bool
	vaultGetCopy       bool
	vaultGetJSON       bool
	vaultRmForce       bool
	vaultListFormat    string
	vaultListAll       bool
	vaultListLong      bool
	vaultListBy        string
	vaultExportStdin   bool
	vaultImportStdin   bool
	vaultImportYes     bool
	vaultHistoryFormat string
	vaultRestoreStamp  int64
)

// requireUserPresence gates a destructive vault command (rm/clean/prune/
// delete) behind a real LocalAuthentication challenge (Touch ID/passcode),
// independent of the cached service session. These commands only move or delete
// envelope files and never exercise the KeyWrapper, so without this explicit
// gate they would ride an unlocked session silently. It's a package var so
// tests can replace it with a no-op — an automated test must never touch the
// real production keychain (see internal/keychainwrap's TEST-ONLY rule).
var requireUserPresence = func(reason string) error {
	return keychainwrap.New().RequireUserPresence(reason)
}

// vaultListResult is jit vault list's --format json shape (GAPS.md #22).
// Neither field is ever nil in JSON output even when the vault is empty —
// an empty array, not a null field, so a script doesn't need a special
// case for "nothing stored yet" vs. "field missing." Backups (the
// encrypted pre-rewrite file backups jit migrate stores under _backups/,
// which `jit migrate undo` restores from) are split out of Secrets rather
// than mixed in (GAPS.md #55): they're jit's own bookkeeping, not secrets
// the user stored, and listing them as peers made a three-project vault
// listing open with three unreadable absolute-path entries.
//
// Each secret is an object carrying its provenance (class/group/origin) and
// timestamps, not a bare path string: the point of --format json is a
// snapshot a script can group by source or age without a second `get` per
// secret (`jq '.secrets[] | select(.class=="mcp")'`). The path lives at
// `.path`. Empty provenance fields are omitted (a v1/v2 secret).
type vaultListResult struct {
	Secrets []vaultSecretJSON `json:"secrets"`
	Backups []string          `json:"backups"`
}

// vaultSecretJSON is one secret in a --format json listing: its path plus the
// same header metadata Info exposes, never a value (list never decrypts).
type vaultSecretJSON struct {
	Path           string `json:"path"`
	Version        int    `json:"version,omitempty"`
	Class          string `json:"class,omitempty"`
	GroupID        string `json:"group_id,omitempty"`
	Origin         string `json:"origin,omitempty"`
	OriginSeenUnix int64  `json:"origin_seen_unix,omitempty"`
	CreatedUnix    int64  `json:"created_unix,omitempty"`
	UpdatedUnix    int64  `json:"updated_unix,omitempty"`
}

// vaultGetResult is `jit vault get --json`'s object: the decrypted value plus
// the envelope's plaintext provenance (class/group/origin) and timestamps —
// the structured form of the faint footer, so a script gets the source kind
// as a first-class field instead of parsing decoration or joining to the
// prunable backup ledger. Empty provenance fields are omitted (a v1/v2 secret
// written before provenance existed), never rendered as a guess.
type vaultGetResult struct {
	Path           string `json:"path"`
	Version        int    `json:"version"`
	Class          string `json:"class,omitempty"`
	GroupID        string `json:"group_id,omitempty"`
	Origin         string `json:"origin,omitempty"`
	OriginSeenUnix int64  `json:"origin_seen_unix,omitempty"`
	CreatedUnix    int64  `json:"created_unix,omitempty"`
	UpdatedUnix    int64  `json:"updated_unix,omitempty"`
	Value          string `json:"value"`
}

// splitBackupPaths separates a vault listing into user secrets and jit
// migrate's own _backups/ entries, preserving order within each.
func splitBackupPaths(paths []string) (secrets, backups []string) {
	secrets, backups = []string{}, []string{}
	for _, p := range paths {
		if strings.HasPrefix(p, "_backups/") {
			backups = append(backups, p)
			continue
		}
		secrets = append(secrets, p)
	}
	return secrets, backups
}

// printVaultList renders jit vault list's text output. Piped (grouped
// false), secrets stay one full path per line, grep/pipe-friendly with no
// decoration; on a terminal (grouped true) they collapse under a faint
// per-group header — first path segment plus a count — with the remainder
// indented, which is what keeps a 50-secret listing scannable. Backups are
// collapsed into the closing count line unless showBackups (--all) lists
// them too (always flat: they're deep bookkeeping paths, grouping adds
// nothing), and exactly one closing count line so nobody has to count rows
// themselves.
// meta, when non-nil (`-l` on a terminal), carries each secret's header
// info so the grouped view can annotate every line with its class and
// last-updated age; nil keeps the plain, unannotated listing.
func printVaultList(out io.Writer, secrets, backups []string, showBackups, grouped bool, meta map[string]vault.SecretInfo, axis string) {
	if len(secrets) == 0 && len(backups) == 0 {
		fmt.Fprintln(out, hlCmds("No secrets stored yet. Run `jit vault set <path>` to add one, or `jit migrate .` to move existing secrets in."))
		return
	}
	switch {
	case grouped && (axis == "origin" || axis == "group"):
		printSecretsByProvenance(out, secrets, meta, axis)
	case grouped:
		printGroupedSecrets(out, secrets, meta)
	default:
		for _, p := range secrets {
			fmt.Fprintln(out, p)
		}
	}
	if showBackups {
		for _, p := range backups {
			fmt.Fprintln(out, p)
		}
	}
	secretsWord := pluralWord(len(secrets), "secret", "secrets")
	backupsWord := pluralWord(len(backups), "backup", "backups")
	switch {
	case len(backups) == 0:
		fmt.Fprintf(out, "\n%d %s stored.\n", len(secrets), secretsWord)
	case len(secrets) == 0 && showBackups:
		fmt.Fprintf(out, "\nNo secrets stored yet, %d encrypted file %s kept for `jit migrate undo`.\n", len(backups), backupsWord)
	case len(secrets) == 0:
		fmt.Fprintf(out, "No secrets stored yet, %d encrypted file %s kept for `jit migrate undo` (list with --all).\n", len(backups), backupsWord)
	case showBackups:
		fmt.Fprintf(out, "\n%d %s stored, plus %d encrypted file %s kept for `jit migrate undo`.\n", len(secrets), secretsWord, len(backups), backupsWord)
	default:
		fmt.Fprintf(out, "\n%d %s stored, plus %d encrypted file %s kept for `jit migrate undo` (list with --all).\n", len(secrets), secretsWord, len(backups), backupsWord)
	}
	// Duplicate-group nudge only decorates the default terminal view — a
	// piped/grep listing (grouped == false) and the provenance axes stay
	// uncluttered.
	if grouped && axis == "path" {
		printDuplicateGroupNudge(out, secrets)
	}
}

// printDuplicateGroupNudge emits one faint hint when two or more top-level
// groups hold an identical set of key names — the "wiz/ and
// custom_scripts-wiz/ are the same five WIZ_ keys" case, a common sign of an
// accidentally re-migrated file. Conservative on purpose: it fires only for
// sets of at least three keys, so intentional small look-alikes (a couple of
// sandboxes each holding DATABASE_URL + STRIPE_KEY) don't trip it.
func printDuplicateGroupNudge(out io.Writer, secrets []string) {
	const minKeys = 3
	members := map[string][]string{} // top-level group -> its sub-paths
	var order []string
	for _, p := range secrets {
		slash := strings.Index(p, "/")
		if slash < 0 {
			continue
		}
		g := p[:slash]
		if _, ok := members[g]; !ok {
			order = append(order, g)
		}
		members[g] = append(members[g], p[slash+1:])
	}
	bySignature := map[string][]string{} // key-set signature -> group names
	for _, g := range order {
		keys := members[g]
		if len(keys) < minKeys {
			continue
		}
		sorted := append([]string(nil), keys...)
		sort.Strings(sorted)
		sig := strings.Join(sorted, "\x00")
		bySignature[sig] = append(bySignature[sig], g)
	}
	var dupes [][]string
	for _, g := range order {
		keys := members[g]
		if len(keys) < minKeys {
			continue
		}
		sorted := append([]string(nil), keys...)
		sort.Strings(sorted)
		sig := strings.Join(sorted, "\x00")
		if groups := bySignature[sig]; len(groups) > 1 && groups[0] == g {
			dupes = append(dupes, groups) // report once, at the first group
		}
	}
	if len(dupes) == 0 {
		return
	}
	faint := color.New(color.Faint)
	for _, groups := range dupes {
		_, _ = faint.Fprintf(out, "note: %s hold the same keys — a re-migrated file? `jit vault rm` the stale copy.\n", strings.Join(groups, ", "))
	}
}

// printGroupedSecrets renders secrets as an indented tree, nesting on every
// path segment rather than only the first: `a/b/KEY` and `a/c/KEY` collapse
// under one `a/` header with `b/` and `c/` subtrees, instead of two flat
// `a/b` and `a/c` groups. A single-level path (`descope/KEY`) renders exactly
// as before — one `descope/ (n)` header with its keys indented — so the common
// case is unchanged. Relies on List's naturally-sorted input keeping every
// path that shares a prefix contiguous.
func printGroupedSecrets(out io.Writer, secrets []string, meta map[string]vault.SecretInfo) {
	printSecretTree(out, secrets, "", 0, meta)
}

// printSecretTree renders one level of the tree: paths are already stripped of
// the ancestor prefix, ancestorPath (the full vault prefix consumed so far)
// rebuilds each leaf's real path for the -l metadata lookup, and depth drives
// the indent. A segment with children becomes a faint "seg/ (n)" header whose
// subtree recurses one level deeper; a leaf prints at the current indent,
// -l-annotated when meta is set. Direct leaves at this level align their
// metadata column to the widest of them.
func printSecretTree(out io.Writer, paths []string, ancestorPath string, depth int, meta map[string]vault.SecretInfo) {
	indent := strings.Repeat("  ", depth)

	// Plain listing (no -l): this level's own keys flow into aligned columns
	// (house style — a 12-key group is three tidy rows, not a twelve-line
	// stack), then each child segment recurses under a bold name + dim count.
	if meta == nil {
		var leaves []string
		for _, p := range paths {
			if !strings.Contains(p, "/") {
				leaves = append(leaves, p)
			}
		}
		wrote := len(leaves) > 0
		flowNames(out, leaves, indent+"  ")
		for i := 0; i < len(paths); {
			slash := strings.Index(paths[i], "/")
			if slash < 0 {
				i++
				continue
			}
			seg := paths[i][:slash+1]
			j := i
			for j < len(paths) && strings.HasPrefix(paths[j], seg) {
				j++
			}
			// A blank line between top-level groups gives the listing room to
			// breathe (house style — whitespace separates sections); it goes
			// before each group but the first, so there's no trailing blank,
			// and nested subgroups stay tight so a deep tree doesn't sprawl.
			if depth == 0 && wrote {
				fmt.Fprintln(out)
			}
			printSecretGroupHeader(out, indent, paths[i][:slash], j-i)
			sub := make([]string, j-i)
			for k := i; k < j; k++ {
				sub[k-i] = paths[k][len(seg):]
			}
			printSecretTree(out, sub, ancestorPath+seg, depth+1, meta)
			wrote = true
			i = j
		}
		return
	}

	// -l listing: every leaf carries a metadata column, so it keeps its own
	// line; the group headers still get the bold-name/dim-count treatment.
	faint := color.New(color.Faint)
	leafWidth := 0
	for _, p := range paths {
		if !strings.Contains(p, "/") && len(p) > leafWidth {
			leafWidth = len(p)
		}
	}
	wrote := false
	for i := 0; i < len(paths); {
		slash := strings.Index(paths[i], "/")
		if slash < 0 {
			key := paths[i]
			fmt.Fprintf(out, "%s  %-*s  ", indent, leafWidth, key)
			_, _ = faint.Fprintln(out, secretMetaSuffix(meta[ancestorPath+key]))
			wrote = true
			i++
			continue
		}
		seg := paths[i][:slash+1]
		j := i
		for j < len(paths) && strings.HasPrefix(paths[j], seg) {
			j++
		}
		if depth == 0 && wrote {
			fmt.Fprintln(out)
		}
		printSecretGroupHeader(out, indent, paths[i][:slash], j-i)
		sub := make([]string, j-i)
		for k := i; k < j; k++ {
			sub[k-i] = paths[k][len(seg):]
		}
		printSecretTree(out, sub, ancestorPath+seg, depth+1, meta)
		wrote = true
		i = j
	}
}

// printSecretGroupHeader renders a vault-tree segment header in the one house
// header shape every jit section/group uses: a `[segment]` name (default
// weight — the brackets delimit it, no bold) and a dim count, at the given
// indent. The tree's indentation shows the nesting.
func printSecretGroupHeader(out io.Writer, indent, name string, n int) {
	fmt.Fprintf(out, "%s[%s]", indent, name)
	_, _ = cDim.Fprintf(out, " %d\n", n)
}

// validateListBy guards the --by axis. "path" is the default first-segment
// grouping; "origin"/"group" bucket by provenance instead.
func validateListBy(by string) error {
	switch by {
	case "", "path", "origin", "group":
		return nil
	default:
		return fmt.Errorf(`unknown --by %q (want "path", "origin", or "group")`, by)
	}
}

// printSecretsByProvenance renders secrets bucketed by where they came from
// rather than by vault path: axis "origin" groups on the source file (so
// "everything from ~/.mcp.json" reads as one block), axis "group" on the
// durable group id (finer — one bucket per import batch, e.g. per MCP server,
// even when several share a file). Each bucket is headed by its human label
// (the origin path) and class; secrets with no recorded provenance collect
// under a faint "(no recorded source)" so a pre-provenance vault still lists
// cleanly. Buckets sort by label, the unknown bucket always last.
func printSecretsByProvenance(out io.Writer, secrets []string, meta map[string]vault.SecretInfo, axis string) {
	type bucket struct {
		label string // origin path shown in the header ("" -> unknown)
		class string
		paths []string
	}
	order := []string{}
	buckets := map[string]*bucket{}
	for _, p := range secrets {
		info := meta[p]
		var key string
		switch axis {
		case "group":
			key = info.GroupID
		default: // origin
			key = info.Origin
		}
		b, ok := buckets[key]
		if !ok {
			b = &bucket{label: info.Origin, class: info.Class}
			buckets[key] = b
			order = append(order, key)
		}
		b.paths = append(b.paths, p)
	}

	// Label sort, empty (unknown) last. For --by group, the key differs but
	// the label (origin) is what a human orders by, so sort on that.
	sort.SliceStable(order, func(i, j int) bool {
		li, lj := buckets[order[i]].label, buckets[order[j]].label
		if (li == "") != (lj == "") {
			return lj == "" // non-empty labels first
		}
		if li != lj {
			return li < lj
		}
		return order[i] < order[j] // stable tiebreak within one origin (distinct groups)
	})

	faint := color.New(color.Faint)
	for _, key := range order {
		b := buckets[key]
		label := b.label
		if label == "" {
			label = "(no recorded source)"
		}
		header := fmt.Sprintf("%s (%d)", label, len(b.paths))
		if b.class != "" {
			header = fmt.Sprintf("%s  %s (%d)", label, b.class, len(b.paths))
		}
		_, _ = faint.Fprintln(out, header)
		for _, p := range b.paths {
			fmt.Fprintf(out, "  %s\n", p)
		}
	}
}

// secretMetaSuffix is the faint `-l` annotation for one secret: its class
// (or "unknown" for a v1/v2 secret written before provenance existed), how
// long ago the value was last updated when the envelope records it, and a
// gentle "likely config" when the key name looks non-secret (OUTPUT_FILE,
// DEBUG). The config note is a hint about the NAME, never a claim about the
// value — jit treats every value as opaque — so it errs toward silence.
func secretMetaSuffix(info vault.SecretInfo) string {
	class := info.Class
	if class == "" {
		class = "unknown"
	}
	parts := []string{class}
	if info.UpdatedUnix > 0 {
		parts = append(parts, "updated "+humanAgo(time.Since(time.Unix(info.UpdatedUnix, 0)))+" ago")
	}
	if looksLikeConfig(leafKeyName(info.Path)) {
		parts = append(parts, "likely config")
	}
	return strings.Join(parts, " · ")
}

// leafKeyName is the final path segment — the environment-variable-style key
// name a secret is stored under (jamf/API_KEY -> API_KEY).
func leafKeyName(path string) string {
	if i := strings.LastIndex(path, "/"); i >= 0 {
		return path[i+1:]
	}
	return path
}

// looksLikeConfig guesses, from the KEY NAME alone, whether a stored value is
// ordinary configuration rather than a credential — deliberately conservative
// so it never dims a real secret: anything with a secret-shaped token in its
// name (KEY, TOKEN, SECRET, PASSWORD, CREDENTIAL, PRIVATE, CERT) is never
// called config, and only names carrying an unambiguous config word (FILE,
// PATH, DEBUG, PORT, REGION, …) are. URL/HOST/ENDPOINT are intentionally left
// out: a DATABASE_URL routinely embeds a password, so flagging it config would
// be exactly the wrong nudge.
func looksLikeConfig(name string) bool {
	up := strings.ToUpper(name)
	for _, s := range []string{"KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "CREDENTIAL", "PRIVATE", "CERT", "SIGNING"} {
		if strings.Contains(up, s) {
			return false
		}
	}
	for _, c := range []string{"FILE", "PATH", "DIR", "DEBUG", "OUTPUT", "INPUT", "PORT", "REGION", "ZONE", "TIMEOUT", "RETRIES", "VERSION", "MODE", "LEVEL", "FORMAT", "SHOW", "FIELDS", "TIMEZONE", "LOCALE", "VERBOSE", "ENABLED", "DISABLED"} {
		if strings.Contains(up, c) {
			return true
		}
	}
	return false
}

var vaultCmd = &cobra.Command{
	Use:     "vault",
	GroupID: groupSecrets,
	Short:   "Manage the local encrypted secret vault",
	Long: "jit vault stores each secret as its own encrypted file under jit's data\n" +
		"directory, no monolithic database.\n\n" +
		"Every command that reads, writes, or destroys a secret (get, set, rm,\n" +
		"import, restore, clean, prune, delete, export) requires a fresh Touch\n" +
		"ID/passcode on EACH invocation, whether or not the background service's\n" +
		"session is unlocked - these commands never ride the cached session, so a\n" +
		"process running as you on an unlocked machine still can't read or destroy\n" +
		"the vault without a live human gesture. Only `list` and `history` are\n" +
		"prompt-free: they show secret names and version timestamps, never a value.",
}

var vaultInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Set up the local vault (generates the master encryption key)",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := keychainwrap.New().EnsureMEK(); err != nil {
			return fmt.Errorf("jit vault init: %w", err)
		}
		root, err := vaultRootDir()
		if err != nil {
			return fmt.Errorf("jit vault init: %w", err)
		}
		// Pin this machine's envelope-recipient identifier now, at init,
		// rather than lazily on first Set — same reasoning as generating
		// the MEK here: everything identity-shaped exists before the first
		// secret ever depends on it.
		if _, err := vault.EnsureDeviceID(root); err != nil {
			return fmt.Errorf("jit vault init: %w", err)
		}
		fmt.Fprint(cmd.OutOrStdout(), hlCmds(fmt.Sprintf("Vault initialized at %s.\nRun `jit vault set <path>` to add a secret, or `jit migrate .` to move existing secrets in.\n", root)))
		return nil
	},
}

var vaultSetCmd = &cobra.Command{
	Use:   "set <path> [value]",
	Short: "Encrypt and store a secret",
	Long: "Stores a secret at <path> (e.g. \"stripe/dev-key\"). If [value] is omitted,\n" +
		"prompts for it with hidden input. Use --stdin for scripts. Passing the value\n" +
		"as a bare argument works but lands in shell history, prefer the prompt or --stdin.\n\n" +
		"Requires a fresh Touch ID/passcode on every run, never the cached service\n" +
		"session, so writing a secret always takes a live human gesture.",
	Args:              cobra.RangeArgs(1, 2),
	ValidArgsFunction: completeVaultPaths,
	RunE: func(cmd *cobra.Command, args []string) error {
		path := args[0]

		value, err := readSecretValue(cmd, args)
		if err != nil {
			return fmt.Errorf("jit vault set: %w", err)
		}
		if len(value) == 0 {
			return fmt.Errorf("jit vault set: value must not be empty")
		}

		// Fresh auth on every sensitive vault command, never the cached
		// agent session: a fingerprint/passcode is required to write a
		// secret whether the agent is locked or not (a same-user process on
		// an unlocked session must not be able to store silently).
		v, err := openVaultFreshAuth()
		if err != nil {
			return fmt.Errorf("jit vault set: %w", err)
		}

		if !vaultSetForce {
			exists, err := v.Exists(path)
			if err != nil {
				return fmt.Errorf("jit vault set: %w", err)
			}
			if exists && !confirmOverwrite(cmd, path) {
				fmt.Fprintln(cmd.OutOrStdout(), "Aborted.")
				return nil
			}
		}

		// A hand-entered secret is provenance ClassManual — but only when
		// it's new: SetWithMeta preserves the existing class on a rotation,
		// so editing a migrated (e.g. dotenv) secret through `vault set`
		// keeps its real origin rather than relabeling it manual.
		if err := v.SetWithMeta(path, value, vault.Meta{Class: vault.ClassManual}); err != nil {
			return fmt.Errorf("jit vault set: %w", err)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Stored %s\n", path)
		return nil
	},
}

var vaultGetCmd = &cobra.Command{
	Use:   "get <path>",
	Short: "Decrypt and print a secret",
	Long: "Prints the decrypted value to stdout, where it lands in your terminal\n" +
		"scrollback and any output capture (tmux, script, CI logs). Prefer\n" +
		"--copy to send it straight to the clipboard instead.\n\n" +
		"On a terminal, one faint metadata line follows on stderr: when the\n" +
		"secret was last updated, which profiles reference it, and the config\n" +
		"file its migration recorded as the source. Piped or redirected output\n" +
		"receives the value only, never the footer.\n\n" +
		"--json prints an object with the value and the envelope's provenance\n" +
		"(class, group, origin) and timestamps instead of the bare value.\n\n" +
		"Requires a fresh Touch ID/passcode on every run, never the cached service\n" +
		"session, so a decrypted secret can never be read silently, even on an\n" +
		"already-unlocked machine.",
	Args:              cobra.ExactArgs(1),
	ValidArgsFunction: completeVaultPaths,
	// A --json error must not be buried under cobra usage text — same
	// reasoning as vault list's SilenceUsage.
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if vaultGetCopy && vaultGetJSON {
			return fmt.Errorf("jit vault get: --copy and --json are mutually exclusive (one hides the value, the other prints it)")
		}
		// Fresh auth on every read, never the cached service session: printing
		// a decrypted secret always costs a fingerprint/passcode, locked or
		// not, so an unlocked session can't be looped to exfiltrate secrets.
		v, err := openVaultFreshAuth()
		if err != nil {
			return fmt.Errorf("jit vault get: %w", err)
		}
		value, err := v.Get(args[0])
		if err != nil {
			if errors.Is(err, vault.ErrNotFound) {
				return fmt.Errorf("jit vault get: no secret stored at %q", args[0])
			}
			return fmt.Errorf("jit vault get: %w", err)
		}

		if vaultGetJSON {
			// Info reads only the envelope header — no decryption, no second
			// prompt (the one Get already cost is enough). Best-effort: the
			// value is in hand, so a header hiccup drops metadata, never the
			// whole get.
			info, _ := v.Info(args[0])
			return writeJSON(cmd.OutOrStdout(), vaultGetResult{
				Path:           args[0],
				Version:        info.Version,
				Class:          info.Class,
				GroupID:        info.GroupID,
				Origin:         info.Origin,
				OriginSeenUnix: info.OriginSeenUnix,
				CreatedUnix:    info.CreatedUnix,
				UpdatedUnix:    info.UpdatedUnix,
				Value:          string(value),
			})
		}

		if vaultGetCopy {
			autoClear, err := copyToClipboard(value)
			if err != nil {
				return fmt.Errorf("jit vault get: %w", err)
			}
			if autoClear {
				fmt.Fprintf(cmd.OutOrStdout(), "Copied to clipboard, clears in %s unless something else is copied first.\n", clipboardClearDelay)
			} else {
				fmt.Fprintln(cmd.OutOrStdout(), "Copied to clipboard (auto-clear unavailable, it stays until you copy over it).")
			}
			printVaultGetFooter(cmd, v, args[0])
			return nil
		}
		fmt.Fprintln(cmd.OutOrStdout(), string(value))
		printVaultGetFooter(cmd, v, args[0])
		return nil
	},
}

// printVaultGetFooter follows a successful `jit vault get` with one faint
// metadata line: last-updated age, the profile(s) whose manifests
// reference the secret, and the config file recorded as its source (the
// .source sidecar MCP migrations write — other migrations don't record
// one yet, so that part is simply omitted, never guessed). Written to
// stderr and only when stderr is a terminal: stdout must stay byte-clean
// for pipes and capture, and scripts never see decoration at all.
// Best-effort throughout — the value already printed, so no metadata
// hiccup may turn a successful get into a failure.
func printVaultGetFooter(cmd *cobra.Command, v *vault.Vault, path string) {
	if !term.IsTerminal(int(os.Stderr.Fd())) {
		return
	}
	var parts []string
	// Info reads only the envelope header, no decryption and no second
	// prompt. Version-1 envelopes predate timestamps; omit rather than lie.
	if info, err := v.Info(path); err == nil && info.UpdatedUnix > 0 {
		when := time.Unix(info.UpdatedUnix, 0)
		parts = append(parts, fmt.Sprintf("updated %s ago (%s)", humanAgo(time.Since(when)), when.Format("2006-01-02")))
	}
	if names, source := secretProfileReferences(path); len(names) > 0 {
		parts = append(parts, fmt.Sprintf("used by %s %s", pluralWord(len(names), "profile", "profiles"), strings.Join(names, ", ")))
		if source != "" {
			if home, err := os.UserHomeDir(); err == nil {
				source = displayPath(home, source)
			}
			parts = append(parts, "migrated from "+source)
		}
	}
	if len(parts) == 0 {
		return
	}
	_, _ = color.New(color.Faint).Fprintln(cmd.ErrOrStderr(), strings.Join(parts, " · "))
}

// secretProfileReferences returns the names of every profile manifest
// visible from the current directory (project-local plus the home-rooted
// global store, profile.ListAll) with at least one variable resolving to
// secretPath, and the first recorded source config file among them.
// Best-effort: an unreadable store or manifest yields fewer names, never
// an error — provenance is garnish on the footer, not something `jit
// vault get` may fail over.
func secretProfileReferences(secretPath string) (names []string, source string) {
	cwd, err := os.Getwd()
	if err != nil {
		return nil, ""
	}
	infos, err := profile.ListAll(cwd)
	if err != nil {
		return nil, ""
	}
	seen := map[string]bool{}
	for _, info := range infos {
		entries, err := profile.LoadFile(info.Path)
		if err != nil {
			continue
		}
		for _, p := range entries {
			if p != secretPath {
				continue
			}
			if !seen[info.Name] {
				seen[info.Name] = true
				names = append(names, info.Name)
			}
			if source == "" {
				source = migrate.ProfileOwnerConfig(info.Path)
			}
			break
		}
	}
	return names, source
}

var vaultListCmd = &cobra.Command{
	Use:   "list",
	Short: "List stored secret paths (names only, never values)",
	Long: "Lists every secret path currently stored, never a value. On a terminal,\n" +
		"secrets are grouped under a faint header per first path segment with a\n" +
		"count; piped or redirected, output stays one full path per line, so it\n" +
		"feeds grep and scripts unchanged. The encrypted file backups jit migrate\n" +
		"keeps for `jit migrate undo` are summarized in the count line rather than\n" +
		"listed; --all lists them too.\n\n" +
		"--by origin groups secrets by the source file they were migrated from\n" +
		"(--by group by the finer import-batch id); -l annotates each with its\n" +
		"class and age. --format json prints an object per secret carrying that\n" +
		"provenance, for grouping in a script without a `get` per secret.",
	Args: cobra.NoArgs,
	// See doctor.go's SilenceUsage comment — the same "don't corrupt a
	// --format json snapshot with usage text on a RunE error" reasoning
	// applies to every command in this file that gained --format json.
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateOutputFormat(vaultListFormat); err != nil {
			return fmt.Errorf("jit vault list: %w", err)
		}
		if err := validateListBy(vaultListBy); err != nil {
			return fmt.Errorf("jit vault list: %w", err)
		}

		// A bare read-only Vault, never openVault(): List only walks
		// filenames, so a names-only listing must not dial the agent (or
		// sit through its restart-gap retries), refuse mid-rekey (reading
		// filenames is exactly the triage you want available then), or
		// write the device-id file as a side effect on a machine that
		// never ran `jit vault init` — the same never-mutate-on-read
		// reasoning completeVaultPaths documents for tab completion.
		root, err := vaultRootDir()
		if err != nil {
			return fmt.Errorf("jit vault list: %w", err)
		}
		readVault := &vault.Vault{Root: root}
		paths, err := readVault.List()
		if err != nil {
			return fmt.Errorf("jit vault list: %w", err)
		}
		secrets, backups := splitBackupPaths(paths)

		grouped := term.IsTerminal(int(os.Stdout.Fd()))
		axis := vaultListBy
		if axis == "" {
			axis = "path"
		}
		// Read each secret's envelope header (Info: no key material, no
		// prompt, same read-only contract as List) when the output needs
		// provenance — a JSON snapshot always, -l or --by only when grouped
		// (a piped listing stays byte-clean for grep, so annotation there
		// would just be noise no one asked to parse).
		needMeta := vaultListFormat == "json" || (grouped && (vaultListLong || axis != "path"))
		var meta map[string]vault.SecretInfo
		if needMeta {
			meta = make(map[string]vault.SecretInfo, len(secrets))
			for _, p := range secrets {
				if info, err := readVault.Info(p); err == nil {
					meta[p] = info
				}
			}
		}

		if vaultListFormat == "json" {
			// --all is text-display-only: JSON always carries both
			// arrays, since a script parsing the snapshot shouldn't
			// need a flag to see the whole picture.
			out := vaultListResult{Secrets: make([]vaultSecretJSON, 0, len(secrets)), Backups: backups}
			for _, p := range secrets {
				info := meta[p]
				out.Secrets = append(out.Secrets, vaultSecretJSON{
					Path:           p,
					Version:        info.Version,
					Class:          info.Class,
					GroupID:        info.GroupID,
					Origin:         info.Origin,
					OriginSeenUnix: info.OriginSeenUnix,
					CreatedUnix:    info.CreatedUnix,
					UpdatedUnix:    info.UpdatedUnix,
				})
			}
			return writeJSON(cmd.OutOrStdout(), out)
		}

		printVaultList(cmd.OutOrStdout(), secrets, backups, vaultListAll, grouped, meta, axis)
		return nil
	},
}

var vaultRmCmd = &cobra.Command{
	Use:   "rm <path>",
	Short: "Delete a secret",
	Long: "Permanently deletes the secret at <path>. Beyond the [y/N] confirmation,\n" +
		"a fresh Touch ID/passcode is required (never the cached service session),\n" +
		"so a process running as you can't delete a secret without a live human\n" +
		"gesture even while the vault is unlocked.",
	Args:              cobra.ExactArgs(1),
	ValidArgsFunction: completeVaultPaths,
	RunE: func(cmd *cobra.Command, args []string) error {
		if !vaultRmForce && !confirmPrompt(cmd, fmt.Sprintf("Permanently delete %s from the vault? This can't be undone. [y/N] ", args[0])) {
			fmt.Fprintln(cmd.OutOrStdout(), "Aborted.")
			return nil
		}

		// Fresh biometric gate, same idiom as restore/delete: Remove only
		// deletes envelope files (never touches the KeyWrapper), so an
		// explicit user-presence check is what forces a fingerprint/passcode
		// here, whether the agent is locked or not. The [y/N] above is a
		// footgun guard (bypassable with --force); this is the real gate.
		if err := requireUserPresence(fmt.Sprintf("delete the secret %q from the vault", args[0])); err != nil {
			return fmt.Errorf("jit vault rm: %w", err)
		}

		v, err := openVaultReadOnly()
		if err != nil {
			return fmt.Errorf("jit vault rm: %w", err)
		}
		if err := v.Remove(args[0]); err != nil {
			if errors.Is(err, vault.ErrNotFound) {
				return fmt.Errorf("jit vault rm: no secret stored at %q", args[0])
			}
			return fmt.Errorf("jit vault rm: %w", err)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Removed %s\n", args[0])
		return nil
	},
}

// vaultHistoryResult is jit vault history's --format json shape: one row
// per archived version, newest first, matching the text output's order.
type vaultHistoryResult struct {
	Path     string                `json:"path"`
	Versions []vaultHistoryVersion `json:"versions"`
}

type vaultHistoryVersion struct {
	// Stamp is the opaque handle `jit vault restore --version` takes.
	Stamp       int64 `json:"stamp"`
	CreatedUnix int64 `json:"created_unix,omitempty"`
	UpdatedUnix int64 `json:"updated_unix,omitempty"`
}

var vaultHistoryCmd = &cobra.Command{
	Use:   "history <path>",
	Short: "List a secret's archived previous versions",
	Long: "Every overwrite of a stored secret keeps the outgoing value as an encrypted\n" +
		"archived version (the newest " + fmt.Sprint(vault.HistoryKeep) + " are kept). This lists them, never\n" +
		"decrypting anything, so it never prompts. `jit vault restore` brings one\n" +
		"back; `jit vault rm` deletes them along with the secret.",
	Args:              cobra.ExactArgs(1),
	ValidArgsFunction: completeVaultPaths,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateOutputFormat(vaultHistoryFormat); err != nil {
			return fmt.Errorf("jit vault history: %w", err)
		}
		v, err := openVaultReadOnly()
		if err != nil {
			return fmt.Errorf("jit vault history: %w", err)
		}
		versions, err := v.HistoryVersions(args[0])
		if err != nil {
			return fmt.Errorf("jit vault history: %w", err)
		}

		if vaultHistoryFormat == "json" {
			rows := make([]vaultHistoryVersion, 0, len(versions))
			for _, hv := range versions {
				rows = append(rows, vaultHistoryVersion{Stamp: hv.ArchiveStamp, CreatedUnix: hv.CreatedUnix, UpdatedUnix: hv.UpdatedUnix})
			}
			return writeJSON(cmd.OutOrStdout(), vaultHistoryResult{Path: args[0], Versions: rows})
		}

		if len(versions) == 0 {
			fmt.Fprintf(cmd.OutOrStdout(), "No archived versions for %s, history is kept from the first overwrite on.\n", args[0])
			return nil
		}
		for _, hv := range versions {
			when := time.Unix(0, hv.ArchiveStamp)
			line := fmt.Sprintf("archived %s ago (%s)", humanAgo(time.Since(when)), when.Format("2006-01-02 15:04:05"))
			if hv.UpdatedUnix > 0 {
				line += fmt.Sprintf(", value from %s", time.Unix(hv.UpdatedUnix, 0).Format("2006-01-02"))
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%d  %s\n", hv.ArchiveStamp, line)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "\n%d archived %s. Restore the newest with `jit vault restore %s`, an older one with --version <stamp>.\n",
			len(versions), pluralWord(len(versions), "version", "versions"), args[0])
		return nil
	},
}

var vaultRestoreCmd = &cobra.Command{
	Use:   "restore <path>",
	Short: "Bring back an archived previous version of a secret",
	Long: "Replaces the secret's current value with an archived one from `jit vault\n" +
		"history`, the newest by default, or the one named by --version <stamp>.\n" +
		"The displaced current value is archived first, so a restore is itself\n" +
		"restorable and flipping between two versions can never lose either.\n\n" +
		"Restoring moves the archived encrypted file back into place byte-for-byte;\n" +
		"nothing is decrypted, but a fresh Touch ID/passcode approval is required,\n" +
		"changing what a secret resolves to must never happen silently.",
	Args:              cobra.ExactArgs(1),
	ValidArgsFunction: completeVaultPaths,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Fresh auth, same reasoning as `jit migrate remove` (GAPS.md #60):
		// Restore never touches the KeyWrapper (it moves envelope files),
		// so without an explicit challenge the promised approval would
		// silently never happen — and riding a cached agent session would
		// let any same-user process quietly repoint a secret's value.
		wrapper := keychainwrap.New()
		if err := wrapper.RequireUserPresence(fmt.Sprintf("restore a previous version of %q", args[0])); err != nil {
			return fmt.Errorf("jit vault restore: %w", err)
		}
		v, err := openVaultReadOnly()
		if err != nil {
			return fmt.Errorf("jit vault restore: %w", err)
		}
		if err := v.Restore(args[0], vaultRestoreStamp); err != nil {
			return fmt.Errorf("jit vault restore: %w", err)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Restored %s. The value it replaced is archived, `jit vault history %s`.\n", args[0], args[0])
		return nil
	},
}

var vaultExportCmd = &cobra.Command{
	Use:   "export <file>",
	Short: "Export every secret to a passphrase-encrypted local backup file",
	Long: "Decrypts every secret currently in the vault and re-encrypts the whole set\n" +
		"under a passphrase you supply, NOT the vault's own per-secret encryption,\n" +
		"which is bound to this device and useless on a different machine. A\n" +
		"passphrase-derived key is what actually makes this file restorable after\n" +
		"laptop loss or a reformat, `jit vault import <file>` reverses it, on this\n" +
		"machine or any other. Remembering the passphrase is entirely on you: jit\n" +
		"never stores it anywhere. This is a local file, moved around by whatever\n" +
		"means you choose, jit never uploads it.\n\n" +
		"--stdin reads the passphrase from stdin (one line, no confirmation\n" +
		"double-entry) instead of the default hidden prompt, for scripting, e.g.\n" +
		"piping one in from a password manager's own CLI.",
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		destPath := args[0]

		passphrase, err := readPassphrase(cmd, vaultExportStdin, !vaultExportStdin, "Enter a passphrase to encrypt this export: ")
		if err != nil {
			return fmt.Errorf("jit vault export: %w", err)
		}
		defer wipeBytes(passphrase)

		// Fresh challenge on purpose, even mid-session — see
		// openVaultFreshAuth: one command that decrypts EVERY secret into
		// a single portable file should never run silently on a cached
		// session someone else's process could be riding.
		v, err := openVaultFreshAuth()
		if err != nil {
			return fmt.Errorf("jit vault export: %w", err)
		}
		// Counted BEFORE exporting (List is read-only and cheap): a List
		// failure after the export already succeeded used to make a fully
		// successful export report as an error, just to print the count.
		paths, err := v.List()
		if err != nil {
			return fmt.Errorf("jit vault export: %w", err)
		}
		env, err := v.Export(passphrase)
		if err != nil {
			return fmt.Errorf("jit vault export: %w", err)
		}

		data, err := json.MarshalIndent(env, "", "  ")
		if err != nil {
			return fmt.Errorf("jit vault export: %w", err)
		}
		// destPath is a path the user typed themselves via the command's own
		// required argument (like `curl -o`), not attacker-controlled input.
		if err := os.WriteFile(destPath, data, 0o600); err != nil { // #nosec G304 -- see comment above
			return fmt.Errorf("jit vault export: %w", err)
		}

		// Best-effort: the export itself already succeeded, and the marker
		// only feeds `jit status`'s backup nudge — a failure here must
		// not make a successful export report as failed.
		if err := vault.RecordExport(v.Root); err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "warning: recording export time for `jit status`: %v\n", err)
		}

		fmt.Fprintf(cmd.OutOrStdout(), "Exported %d secret(s) to %s.\n", len(paths), destPath)
		return nil
	},
}

var vaultImportCmd = &cobra.Command{
	Use:   "import <file>",
	Short: "Restore secrets from a jit vault export file",
	Long: "Decrypts <file> (written by `jit vault export`) with the passphrase you\n" +
		"supply and writes every secret it contains into this vault, overwriting\n" +
		"any existing secret at the same path. Confirms first unless --yes, the\n" +
		"passphrase prompt only comes after that, so declining never costs a\n" +
		"wasted attempt at typing it.",
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		srcPath := args[0]

		data, err := os.ReadFile(srcPath) // #nosec G304 -- user-specified input file, the command's entire purpose
		if err != nil {
			return fmt.Errorf("jit vault import: %w", err)
		}
		var env vault.ExportEnvelope
		if err := json.Unmarshal(data, &env); err != nil {
			return fmt.Errorf("jit vault import: parsing %s: %w", srcPath, err)
		}

		if !vaultImportYes && !confirmPrompt(cmd, fmt.Sprintf("Import secrets from %s, overwriting any existing secret at the same path? [y/N] ", srcPath)) {
			fmt.Fprintln(cmd.OutOrStdout(), "Aborted.")
			return nil
		}

		passphrase, err := readPassphrase(cmd, vaultImportStdin, false, "Enter the export's passphrase: ")
		if err != nil {
			return fmt.Errorf("jit vault import: %w", err)
		}
		defer wipeBytes(passphrase)

		// Fail fast on a wrong passphrase or a corrupted file BEFORE
		// openVault() below, which may trigger a Touch ID/passcode
		// challenge — see VerifyExportPassphrase's own doc comment for why
		// wasting that prompt on a typo matters enough to pay for a second
		// (deliberately slow) KDF run.
		if err := vault.VerifyExportPassphrase(&env, passphrase); err != nil {
			return fmt.Errorf("jit vault import: %w", err)
		}

		// Fresh auth, never the cached session: Import re-wraps every secret
		// under this device's master key, so a fingerprint/passcode is
		// required (on top of the export passphrase above) whether the agent
		// is locked or not.
		v, err := openVaultFreshAuth()
		if err != nil {
			return fmt.Errorf("jit vault import: %w", err)
		}
		n, err := v.Import(&env, passphrase)
		if err != nil {
			return fmt.Errorf("jit vault import: %w", err)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Restored %d secret(s) from %s.\n", n, srcPath)
		return nil
	},
}

// readPassphrase reads a passphrase for jit vault export/import — hidden
// input via term.ReadPassword by default, or a single line from stdin
// when stdinFlag is set (scripting/automation, matching vault set's own
// --stdin convention). confirm, when true (export only), re-prompts and
// requires an exact match: a typo'd export passphrase produces an
// unrecoverable backup, unlike a typo'd vault secret value (just re-run
// vault set), so catching it at entry time matters here in a way it
// doesn't for readSecretValue. Import never confirms — decryption itself
// is the check, and getting it wrong just means retrying.
func readPassphrase(cmd *cobra.Command, stdinFlag, confirm bool, prompt string) ([]byte, error) {
	if stdinFlag {
		data, err := io.ReadAll(cmd.InOrStdin())
		if err != nil {
			return nil, fmt.Errorf("reading stdin: %w", err)
		}
		return bytes.TrimRight(data, "\n"), nil
	}

	first, err := readHidden(cmd, prompt)
	if err != nil {
		return nil, fmt.Errorf("reading passphrase: %w", err)
	}
	if len(first) == 0 {
		return nil, fmt.Errorf("passphrase must not be empty")
	}
	if !confirm {
		return first, nil
	}

	second, err := readHidden(cmd, "Confirm passphrase: ")
	if err != nil {
		wipeBytes(first)
		return nil, fmt.Errorf("reading passphrase confirmation: %w", err)
	}
	if !bytes.Equal(first, second) {
		wipeBytes(first)
		wipeBytes(second)
		return nil, fmt.Errorf("passphrases did not match")
	}
	wipeBytes(second)
	return first, nil
}

// readHidden shows prompt and reads one line of hidden (no-echo) input.
// The single place the prompt stream is decided: prompts go to stderr,
// not stdout — standard interactive-prompt convention (ssh, sudo, gh):
// with stdout redirected to a file or a pipe, a stdout prompt is
// invisible and the command looks hung while silently waiting on stdin.
// Every hidden prompt must route through here rather than hand-rolling
// the sequence, so no future prompt can quietly regress to stdout.
func readHidden(cmd *cobra.Command, prompt string) ([]byte, error) {
	fmt.Fprint(cmd.ErrOrStderr(), prompt)
	data, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(cmd.ErrOrStderr())
	return data, err
}

// wipeBytes zeroes b in place — this package's own copy of the same
// best-effort hygiene internal/vault's crypto.go keeps for key/plaintext
// material (not exported from there, so a small local copy instead of
// exporting an internal primitive just for this).
func wipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func readSecretValue(cmd *cobra.Command, args []string) ([]byte, error) {
	switch {
	case vaultSetStdin:
		data, err := io.ReadAll(cmd.InOrStdin())
		if err != nil {
			return nil, fmt.Errorf("reading stdin: %w", err)
		}
		return bytes.TrimRight(data, "\n"), nil
	case len(args) == 2:
		return []byte(args[1]), nil
	default:
		data, err := readHidden(cmd, fmt.Sprintf("Enter value for %s: ", args[0]))
		if err != nil {
			return nil, fmt.Errorf("reading value: %w", err)
		}
		return data, nil
	}
}

func confirmOverwrite(cmd *cobra.Command, path string) bool {
	return confirmPrompt(cmd, fmt.Sprintf("%s already exists in the vault. Overwrite it? The current value is kept as an archived version (`jit vault history %s`). [y/N] ", path, path))
}

var vaultCleanYes bool

// vaultCleanCmd deletes every secret while leaving the vault itself set
// up (encryption key, device identity). Remove never decrypts, so — like
// `jit terraform-credentials forget` — this uses the read-only vault
// construction and can never trigger a Touch ID prompt: deletion isn't
// exposure, and the files are plain user-writable files an attacker could
// rm(1) regardless, so an auth gate here would be friction pretending to
// be a boundary. The confirmation is the real gate.
var vaultCleanCmd = &cobra.Command{
	Use:   "clean",
	Short: "Delete every secret in the vault (the vault itself stays set up)",
	Long: "Permanently deletes every secret stored in the vault, including the\n" +
		"encrypted file backups jit migrate keeps for `jit migrate undo`, after\n" +
		"this, undo has nothing left to restore from. The vault itself stays\n" +
		"initialized (its encryption key and device identity are kept), so\n" +
		"`jit vault set`/`jit migrate` keep working immediately afterward.\n" +
		"Refuses while any file is still live-mounted, unmount first, or the\n" +
		"mounted file's real content would be gone for good.\n" +
		"To destroy the vault entirely, key included, use `jit vault delete`.",
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Same refusal as `jit vault delete`, for the same reason: wiping
		// the secrets out from under a registered mount permanently strands
		// the file as decoys — and unmounting AFTER a clean is impossible
		// (unmount needs the vault to write the plaintext back), so the
		// only recoverable order is unmount first. A real incident: a
		// test vault cleaned with 4 mounts registered left all four
		// unrecoverable and every profile broken.
		root, err := vaultRootDir()
		if err != nil {
			return fmt.Errorf("jit vault clean: %w", err)
		}
		entries, err := mount.LoadRegistry(mount.RegistryPath(root))
		if err != nil {
			return fmt.Errorf("jit vault clean: reading the mount registry: %w", err)
		}
		if len(entries) > 0 {
			return fmt.Errorf("jit vault clean: %d file(s) are still live-mounted, run `jit unmount <path>` on each first, or their real content is gone for good", len(entries))
		}

		v, err := openVaultReadOnly()
		if err != nil {
			return fmt.Errorf("jit vault clean: %w", err)
		}
		paths, err := v.List()
		if err != nil {
			return fmt.Errorf("jit vault clean: %w", err)
		}
		if len(paths) == 0 {
			fmt.Fprintln(cmd.OutOrStdout(), "The vault is already empty, nothing to clean.")
			return nil
		}
		backups := 0
		for _, p := range paths {
			if strings.HasPrefix(p, "_backups/") {
				backups++
			}
		}
		warning := ""
		if backups > 0 {
			warning = fmt.Sprintf(", including %d encrypted file backup(s), so `jit migrate undo` will have nothing left to restore from", backups)
		}
		if !vaultCleanYes && !confirmPrompt(cmd, fmt.Sprintf(
			"Permanently delete ALL %d secret(s) from the vault%s? This can't be undone. [y/N] ", len(paths), warning)) {
			fmt.Fprintln(cmd.OutOrStdout(), "Aborted. Nothing was deleted.")
			return nil
		}
		// Fresh biometric gate before mass deletion: the [y/N] above is a
		// footgun guard (bypassable with --yes); this fingerprint/passcode is
		// the real gate, required whether the agent is locked or not.
		if err := requireUserPresence(fmt.Sprintf("delete all %d secret(s) from the vault", len(paths))); err != nil {
			return fmt.Errorf("jit vault clean: %w", err)
		}

		for _, p := range paths {
			if err := v.Remove(p); err != nil {
				return fmt.Errorf("jit vault clean: removing %s: %w", p, err)
			}
		}
		// The undo index now points at nothing — leaving it behind would
		// make `jit migrate undo` half-fail confusingly instead of saying
		// there's nothing to restore.
		if err := os.Remove(migrate.BackupIndexPath(root)); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("jit vault clean: removing the undo index: %w", err)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Deleted %d secret(s). The vault itself is still set up, `jit vault set` works immediately.\n", len(paths))
		return nil
	},
}

var vaultPruneYes bool

// vaultPruneCmd is the answer to the backups-accumulation question (issue
// #5): every migrate→undo cycle adds fresh `_backups/…` entries (undo
// snapshots the pre-undo state so it's itself undoable), nothing ever
// removes the older ones, and there is deliberately no automatic TTL/cap —
// silently expiring a recovery snapshot is worse than letting the user
// decide when history is disposable. Pruning keeps exactly what
// `jit migrate undo` would use (the newest backup per file) and deletes
// the rest.
var vaultPruneCmd = &cobra.Command{
	Use:   "prune",
	Short: "Delete stale encrypted file backups, keeping each file's newest",
	Long: "jit migrate backs a file up into the vault (under _backups/...) every time\n" +
		"it rewrites one, and `jit migrate undo` snapshots the pre-undo state too, so\n" +
		"repeated migrate/undo cycles accumulate backups indefinitely, nothing\n" +
		"expires them automatically, on purpose (a recovery snapshot silently aging\n" +
		"out is worse than a big vault). This prunes the accumulation: for every\n" +
		"file, the NEWEST backup, the one `jit migrate undo` would restore, is\n" +
		"kept, and every older one is permanently deleted.\n\n" +
		"Backups taken by jit builds before the undo index existed aren't touched\n" +
		"(they're invisible to undo but may be your only copy), see them with\n" +
		"`jit vault list --all` and delete by hand with `jit vault rm` if wanted.",
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		out := cmd.OutOrStdout()
		root, err := vaultRootDir()
		if err != nil {
			return fmt.Errorf("jit vault prune: %w", err)
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("jit vault prune: %w", err)
		}
		recs, err := migrate.LoadBackupRecords(root)
		if err != nil {
			return fmt.Errorf("jit vault prune: %w", err)
		}

		// Keep the newest record per file — exactly the set undo restores
		// from. RemoveOnRestore records have no vault entry at all
		// (VaultPath is empty); they cost nothing and must never land in
		// the drop set, where an empty VaultPath would match every one of
		// them in DropBackupRecords.
		keep := map[string]bool{}
		for _, r := range migrate.LatestBackups(recs) {
			if r.VaultPath != "" {
				keep[r.VaultPath] = true
			}
		}
		var stale []migrate.BackupRecord
		for _, r := range recs {
			if r.VaultPath != "" && !keep[r.VaultPath] {
				stale = append(stale, r)
			}
		}
		if len(stale) == 0 {
			fmt.Fprintln(out, "Nothing to prune, each backed-up file already has only its newest backup.")
			return nil
		}

		fmt.Fprintf(out, "Pruning %d stale backup(s), each file's newest backup is kept, so `jit migrate undo` still works:\n", len(stale))
		for _, r := range stale {
			fmt.Fprintf(out, "  • %s (%s, backed up %s ago)\n", r.VaultPath, displayPath(home, r.OriginalPath), humanAgo(time.Since(time.Unix(r.UnixTS, 0))))
		}
		if !vaultPruneYes && !confirmPrompt(cmd, fmt.Sprintf("Permanently delete %d stale backup(s)? This can't be undone. [y/N] ", len(stale))) {
			fmt.Fprintln(out, "Aborted. Nothing was deleted.")
			return nil
		}
		// Fresh biometric gate before deleting backups (bypassable [y/N]
		// above is only a footgun guard), required locked or not.
		if err := requireUserPresence(fmt.Sprintf("delete %d stale backup(s) from the vault", len(stale))); err != nil {
			return fmt.Errorf("jit vault prune: %w", err)
		}

		v, err := openVaultReadOnly()
		if err != nil {
			return fmt.Errorf("jit vault prune: %w", err)
		}
		for _, r := range stale {
			if err := v.Remove(r.VaultPath); err != nil && !errors.Is(err, vault.ErrNotFound) {
				return fmt.Errorf("jit vault prune: deleting %s: %w", r.VaultPath, err)
			}
		}
		if err := migrate.DropBackupRecords(root, stale); err != nil {
			return fmt.Errorf("jit vault prune: %w", err)
		}
		fmt.Fprintf(out, "Pruned %d stale backup(s). %d file(s) keep their newest backup for `jit migrate undo`.\n", len(stale), len(keep))
		return nil
	},
}

var (
	vaultOrphansPrune bool
	vaultOrphansYes   bool
)

// collectReferencedPaths gathers every vault path referenced by a profile jit
// can currently see: every profile in the project-local (cwd) and global
// stores, plus the profile behind every registered mount (which may live in
// another project's tree). It is deliberately STRICT — a profile it can't
// parse aborts with an error rather than returning a short set — because its
// only deleting caller (`jit vault orphans --prune`) must never treat a secret
// as unreferenced just because the manifest that names it failed to load.
func collectReferencedPaths(root, cwd string) (map[string]bool, error) {
	referenced := map[string]bool{}
	add := func(path string) error {
		p, err := profile.LoadFile(path)
		if err != nil {
			return fmt.Errorf("loading profile %s: %w", path, err)
		}
		for _, vaultPath := range p {
			referenced[vaultPath] = true
		}
		return nil
	}
	infos, err := profile.ListAll(cwd)
	if err != nil {
		return nil, err
	}
	for _, info := range infos {
		if err := add(info.Path); err != nil {
			return nil, err
		}
	}
	entries, err := mount.LoadRegistry(mount.RegistryPath(root))
	if err != nil {
		return nil, fmt.Errorf("reading the mount registry: %w", err)
	}
	for _, e := range entries {
		if err := add(e.ProfilePath); err != nil {
			return nil, err
		}
	}
	return referenced, nil
}

// printOrphanGroups renders orphaned secret paths grouped by their first path
// segment (the same grouping `jit vault list` shows), annotating each with its
// recorded Origin and age so a secret that actually belongs to another project
// is recognizable before it's deleted.
func printOrphanGroups(out io.Writer, v *vault.Vault, orphans []string) {
	groups := map[string][]string{}
	var order []string
	for _, p := range orphans {
		prefix := p
		if i := strings.IndexByte(p, '/'); i >= 0 {
			prefix = p[:i]
		}
		if _, ok := groups[prefix]; !ok {
			order = append(order, prefix)
		}
		groups[prefix] = append(groups[prefix], p)
	}
	sort.Strings(order)
	for _, prefix := range order {
		members := groups[prefix]
		names := make([]string, len(members))
		origins := make([]string, len(members))
		uniform := true
		for i, p := range members {
			names[i] = strings.TrimPrefix(p, prefix+"/")
			origins[i] = orphanOrigin(v, p)
			if origins[i] != origins[0] {
				uniform = false
			}
		}
		// Header: bold group name, dim count. When every secret shares the
		// same origin (the common pre-provenance case — all "no recorded
		// origin"), state it ONCE on the header instead of tacking the same
		// parenthetical onto all N lines, and flow the names into columns.
		// When origins genuinely differ, that per-secret provenance is worth
		// keeping, so fall back to one name-plus-origin line each.
		fmt.Fprintf(out, "  [%s]", prefix)
		if uniform {
			_, _ = cDim.Fprintf(out, " %d · %s\n", len(members), origins[0])
			flowNames(out, names, "      ")
			continue
		}
		_, _ = cDim.Fprintf(out, " %d\n", len(members))
		for i, name := range names {
			fmt.Fprintf(out, "      %s", name)
			_, _ = cDim.Fprintf(out, "  %s\n", origins[i])
		}
	}
}

// orphanOrigin renders one secret's provenance for the orphan/unreferenced
// listing: its recorded Origin and how long ago it was seen, or the
// pre-provenance fallback when the vault never recorded one.
func orphanOrigin(v *vault.Vault, path string) string {
	if info, err := v.Info(path); err == nil && info.Origin != "" {
		s := "from " + info.Origin
		if info.OriginSeenUnix > 0 {
			s += fmt.Sprintf(", seen %s ago", humanAgo(time.Since(time.Unix(info.OriginSeenUnix, 0))))
		}
		return s
	}
	return "no recorded origin (pre-provenance, or set directly)"
}

// vaultOrphansCmd is the actionable half of `jit doctor --orphans` (which only
// warns): it lists the vault secrets no profile jit can see references, and
// with --prune deletes them. This is what drains the secrets a path-only
// `jit migrate undo`/`remove` stranded before `migrate remove` learned to
// sweep them by Origin — and unlike that sweep, it catches pre-provenance
// (v1/v2) orphans too, since it keys on "referenced by nothing", not on Origin.
var vaultOrphansCmd = &cobra.Command{
	Use:   "orphans",
	Short: "List (and with --prune delete) secrets no profile references",
	Long: "Lists every stored secret that no profile jit can currently see points at,\n" +
		"grouped by path with each secret's recorded origin: the leftovers a\n" +
		"path-only `jit migrate undo`/`remove` leaves in the vault once the profile\n" +
		"that named them is gone. With --prune, they are permanently deleted after a\n" +
		"[y/N] confirmation and a fresh Touch ID/passcode.\n\n" +
		"\"Referenced\" is judged against every profile jit can see: the project-local\n" +
		"(current directory) and global profile stores, plus the profile behind every\n" +
		"registered mount. A secret used ONLY by a different project you're not in and\n" +
		"haven't mounted would look orphaned here, so check each secret's origin\n" +
		"before pruning, and delete a single one with `jit vault rm <path>` if unsure.",
	Args:         cobra.NoArgs,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		out := cmd.OutOrStdout()
		root, err := vaultRootDir()
		if err != nil {
			return fmt.Errorf("jit vault orphans: %w", err)
		}
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("jit vault orphans: %w", err)
		}

		referenced, err := collectReferencedPaths(root, cwd)
		if err != nil {
			return fmt.Errorf("jit vault orphans: %w", err)
		}

		readVault := &vault.Vault{Root: root}
		paths, err := readVault.List()
		if err != nil {
			return fmt.Errorf("jit vault orphans: %w", err)
		}
		secrets, _ := splitBackupPaths(paths)
		var orphans []string
		for _, p := range secrets {
			if !referenced[p] {
				orphans = append(orphans, p)
			}
		}
		if len(orphans) == 0 {
			fmt.Fprintln(out, "No orphaned secrets: every stored secret is referenced by a profile jit can see.")
			return nil
		}
		sort.Strings(orphans)

		printOrphanGroups(out, readVault, orphans)

		if !vaultOrphansPrune {
			fmt.Fprintf(out, "\n%d orphaned secret(s), referenced by no profile jit can currently see.\n"+
				"Run `jit vault orphans --prune` to delete them, or `jit vault rm <path>` one at a time.\n", len(orphans))
			return nil
		}

		if !vaultOrphansYes && !confirmPrompt(cmd, fmt.Sprintf(
			"Permanently delete %d orphaned secret(s)? This can't be undone. [y/N] ", len(orphans))) {
			fmt.Fprintln(out, "Aborted. Nothing was deleted.")
			return nil
		}
		// Fresh biometric gate before deleting, same idiom as rm/clean/prune:
		// Remove only unlinks envelope files (never touches the KeyWrapper), so
		// this explicit user-presence check is what forces a fingerprint here,
		// locked or not. The [y/N] above is only a footgun guard (--yes skips it).
		if err := requireUserPresence(fmt.Sprintf("delete %d orphaned secret(s) from the vault", len(orphans))); err != nil {
			return fmt.Errorf("jit vault orphans: %w", err)
		}
		for _, p := range orphans {
			if err := readVault.Remove(p); err != nil && !errors.Is(err, vault.ErrNotFound) {
				return fmt.Errorf("jit vault orphans: deleting %s: %w", p, err)
			}
		}
		fmt.Fprintf(out, "Deleted %d orphaned secret(s).\n", len(orphans))
		return nil
	},
}

var vaultDeleteYes bool

// vaultDeleteCmd destroys the entire vault: every secret, the undo index,
// the device identity, the last-export marker, AND the keychain-stored
// MEK — after which nothing short of a passphrase-encrypted `jit vault
// export` file can bring the secrets back. Refuses while any live mount
// is still registered: deleting the vault out from under a served mount
// would permanently strand the file as decoys with the real values gone.
var vaultDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Permanently destroy the whole vault, including its encryption key",
	Long: "Destroys the entire vault: every secret, the encrypted file backups and\n" +
		"their undo index, the device identity, and the vault's encryption key in\n" +
		"the macOS keychain. Nothing on this machine can decrypt anything\n" +
		"afterward, only a passphrase-encrypted `jit vault export` file survives\n" +
		"(restorable later via `jit vault init` + `jit vault import`).\n\n" +
		"Refuses to run while any file is still live-mounted: unmount first\n" +
		"(`jit unmount <path>`), or the mounted file would be permanently stuck\n" +
		"serving placeholder values with its real content gone.",
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		root, err := vaultRootDir()
		if err != nil {
			return fmt.Errorf("jit vault delete: %w", err)
		}
		entries, err := mount.LoadRegistry(mount.RegistryPath(root))
		if err != nil {
			return fmt.Errorf("jit vault delete: reading the mount registry: %w", err)
		}
		if len(entries) > 0 {
			return fmt.Errorf("jit vault delete: %d file(s) are still live-mounted, run `jit unmount <path>` on each first, or their real content is gone for good", len(entries))
		}

		v, err := openVaultReadOnly()
		if err != nil {
			return fmt.Errorf("jit vault delete: %w", err)
		}
		paths, err := v.List()
		if err != nil {
			return fmt.Errorf("jit vault delete: %w", err)
		}
		noBackup := ""
		if len(paths) > 0 {
			if _, exported, err := vault.LastExport(root); err == nil && !exported {
				noBackup = " No vault export exists, every secret will be unrecoverable."
			}
		}
		if !vaultDeleteYes && !confirmPrompt(cmd, fmt.Sprintf(
			"Permanently destroy the ENTIRE vault, %d secret(s), the undo backups, and the encryption key in the macOS keychain?%s [y/N] ", len(paths), noBackup)) {
			fmt.Fprintln(cmd.OutOrStdout(), "Aborted. Nothing was deleted.")
			return nil
		}
		// Fresh biometric gate before destroying the whole vault: the [y/N]
		// above is bypassable with --yes, so this fingerprint/passcode is the
		// real barrier against a same-user process wiping everything, and it
		// is required whether the agent is locked or not.
		if err := requireUserPresence("permanently destroy the entire vault and its encryption key"); err != nil {
			return fmt.Errorf("jit vault delete: %w", err)
		}

		removed, err := vault.DeleteLocalState(root)
		if err != nil {
			return fmt.Errorf("jit vault delete: %w", err)
		}
		if err := os.Remove(migrate.BackupIndexPath(root)); err == nil {
			removed = append(removed, migrate.BackupIndexPath(root))
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("jit vault delete: removing the undo index: %w", err)
		}
		// Best-effort on purpose: with every encrypted file already gone
		// above, a keychain entry that couldn't be removed (or was already
		// gone) protects nothing — warn rather than leave the command
		// half-failed over the least consequential step.
		if err := keychainwrap.New().DeleteMEK(); err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "warning: couldn't remove the vault's keychain entry (it may already be gone): %v\n", err)
		} else {
			removed = append(removed, "the vault's macOS keychain entry")
		}
		if locked := lockAgentAfterMEKDeletion(root, cmd.ErrOrStderr()); locked != "" {
			removed = append(removed, locked)
		}
		for _, r := range removed {
			fmt.Fprintf(cmd.OutOrStdout(), "Removed %s\n", r)
		}
		fmt.Fprintln(cmd.OutOrStdout(), hlCmds("The vault is gone. Run `jit vault init` to start fresh."))
		return nil
	},
}

// lockAgentAfterMEKDeletion locks a reachable agent's cached session right
// after the vault's keychain MEK is destroyed, returning a human-readable
// description of what it locked ("" if no agent was reachable or the lock
// failed). A running agent may still hold the just-deleted MEK decrypted
// in memory; left unlocked, the NEXT vault's first writes would ride that
// cached session and get wrapped with the old, orphaned key — unreadable
// the moment the agent locks and re-fetches the new MEK from the keychain.
// A real hazard observed on real hardware: `jit status` showed "unlocked,
// locks in 14m" immediately after a successful `jit vault delete`.
// Best-effort like the keychain step itself: a lock failure can't make the
// deletion any less complete, so it warns on w rather than failing.
// Split out of the delete RunE because the RunE's own path is the one
// flow the TEST-ONLY keychain rule forbids automating (it deletes the real
// MEK); this helper is the part a test can safely exercise.
func lockAgentAfterMEKDeletion(root string, w io.Writer) string {
	agentClient := agent.NewClient(agent.SocketPath(root))
	if !agentClient.Reachable() {
		return ""
	}
	if err := agentClient.Lock(); err != nil {
		fmt.Fprintf(w, "warning: couldn't lock the running service's cached session, run `jit lock` before using a new vault: %v\n", err)
		return ""
	}
	return "the running service's cached session (locked)"
}

// confirmPrompt is the one confirmation gate every mutating command in
// this package shares (migrate, vault set/rm/import, agent install,
// unmount). A blank line plus bold text is deliberate: this is the last
// thing printed before a command like `jit migrate` — which can produce
// a long, multi-section plan — actually mutates anything, and a plain,
// unstyled "Proceed? [y/N]" butted right up against the summary line
// above it was a real, reported case of the prompt being easy to miss
// entirely (mistaken for more body text, or scrolled past). Bold, not a
// severity color — this isn't a warning, it's the one line every other
// line in the report was leading up to. Written to stderr like every
// other interactive prompt here, so it stays visible (and the wait on
// stdin stays explicable) when stdout is redirected.
func confirmPrompt(cmd *cobra.Command, prompt string) bool {
	out := cmd.ErrOrStderr()
	fmt.Fprintln(out)
	_, _ = color.New(color.Bold).Fprint(out, prompt)
	line, err := readLineUnbuffered(cmd.InOrStdin())
	if err != nil && line == "" {
		return false
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes"
}

// readLineUnbuffered reads exactly one line, one byte at a time — never
// past the newline. confirmPrompt must not consume more of stdin than its
// own answer: a scripted `printf 'y\npass\n' | jit vault import --stdin`
// feeds the confirmation AND the passphrase on one pipe, and the
// bufio.Reader this used to wrap buffered both lines, so readPassphrase's
// io.ReadAll saw an empty stream and import always failed with "wrong
// passphrase" (a real bug found driving import from a script). One read(2)
// per byte is irrelevant here — the line is a human's "y".
func readLineUnbuffered(r io.Reader) (string, error) {
	var line []byte
	buf := make([]byte, 1)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if buf[0] == '\n' {
				return string(line), nil
			}
			line = append(line, buf[0])
		}
		if err != nil {
			return string(line), err
		}
	}
}

// copyToClipboard puts value on the pasteboard — concealed from clipboard
// managers (org.nspasteboard.ConcealedType) — and schedules a detached
// helper to clear it after clipboardClearDelay, unless something else has
// been copied by then. autoClear reports whether that helper actually got
// scheduled: a copy that will sit on the pasteboard forever should be
// SAID, not silently different.
func copyToClipboard(value []byte) (autoClear bool, err error) {
	count, err := pasteboard.WriteConcealed(value)
	if errors.Is(err, pasteboard.ErrNotUTF8) {
		// A non-UTF-8 secret can't ride NSString; pbcopy handles raw
		// bytes. No concealment on this path, but the auto-clear still
		// works — the changeCount contract doesn't care who wrote.
		if err := pbcopy(value); err != nil {
			return false, err
		}
		count = pasteboard.ChangeCount()
	} else if err != nil {
		return false, err
	}
	if err := spawnClipboardClear(count); err != nil {
		return false, nil // copied fine; only the auto-clear is missing
	}
	return true, nil
}

func pbcopy(value []byte) error {
	c := exec.Command("pbcopy") // #nosec G204 -- fixed macOS system binary, no user input in argv
	stdin, err := c.StdinPipe()
	if err != nil {
		return fmt.Errorf("opening pbcopy stdin: %w", err)
	}
	if err := c.Start(); err != nil {
		return fmt.Errorf("starting pbcopy: %w", err)
	}
	if _, err := stdin.Write(value); err != nil {
		return fmt.Errorf("writing to pbcopy: %w", err)
	}
	if err := stdin.Close(); err != nil {
		return fmt.Errorf("closing pbcopy stdin: %w", err)
	}
	return c.Wait()
}

// openVault returns a Vault backed by whichever KeyWrapper is actually
// available: a running jit-agent's already-unlocked shared session if
// reachable (so this command doesn't prompt Touch ID independently when
// the agent already has one cached), falling back to an independent
// keychainwrap.Wrapper — this command's own Touch ID challenge — when no
// agent is running. Either way the caller gets a real vault.KeyWrapper;
// which one is transparent beyond which prompts (if any) show up.
// openVaultFreshAuth is openVault WITHOUT the agent-session shortcut:
// always an independent keychainwrap challenge, even while a reachable
// agent holds an unlocked session. Used by exactly the commands that put
// plaintext back on disk or bundle every secret into one portable file
// (unmount, migrate undo, vault export): riding the cached session meant
// any same-user process could run those silently during the TTL window;
// forcing a fresh Touch ID/passcode turns that into a visible prompt the
// human at the keyboard has to approve. A speed bump against quiet misuse
// of jit's own commands, not a guarantee against an attacker who bypasses
// jit entirely — the challenge is still application-enforced until the
// Secure Enclave work lands (GAPS.md #1) — but "a prompt the user didn't
// initiate just appeared" is precisely the signal that boundary can add.
// completeVaultPaths powers tab completion for `jit vault get/set/rm
// <path>` (via `jit completion <shell>`). It lists stored secret paths
// with a bare Vault{Root} — List only walks filenames, so completion
// never decrypts anything and never triggers a Touch ID/passcode prompt
// mid-keystroke. Deliberately not openVaultReadOnly: that constructor
// calls EnsureDeviceID, which writes the device-id file when missing,
// and tab completion must never mutate vault state as a side effect.
// _backups/ entries are filtered out for the same reason vault list
// hides them by default: they're jit's own bookkeeping, and completing
// them into a get/rm invocation is never what the user is reaching for.
func completeVaultPaths(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) != 0 {
		// Only the first positional is a secret path (set's second is
		// the value) — never offer path or file completions past it.
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	root, err := vaultRootDir()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	paths, err := (&vault.Vault{Root: root}).List()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	secrets, _ := splitBackupPaths(paths)
	matches := []string{}
	for _, p := range secrets {
		if strings.HasPrefix(p, toComplete) {
			matches = append(matches, p)
		}
	}
	return matches, cobra.ShellCompDirectiveNoFileComp
}

// invocationAuth records the authentication a command forced for itself,
// read by recordAuditEvent when the invocation finishes so the audit trail
// shows a fresh fingerprint gated the action. Set only by
// requireFreshUserPresence; a package-level var (not threaded through every
// signature) because the audit hook runs generically around Execute and has
// no other channel to the command that ran. Single-invocation process, so
// there's no cross-run contamination to guard against.
var invocationAuth string

// freshUserPresenceMethod is the label requireFreshUserPresence stamps into
// the audit record. "local" = a Touch ID/passcode challenge answered by this
// very process (keychainwrap), never the agent's cached session.
const freshUserPresenceMethod = "local-userpresence"

// requireFreshUserPresence forces v's key wrapper to run its own local
// Touch ID/passcode challenge NOW, with reason shown in the dialog, and
// records that a fresh user-presence auth happened for this invocation. Use
// it for every plaintext-restoring or destructive action (jit migrate
// undo/remove, vault rekey/restore): openVaultFreshAuth already hands back a
// wrapper that talks to the keychain directly rather than a possibly-unlocked
// agent session, and this makes the challenge explicit and mandatory even on
// a code path that would otherwise not touch the key (a deletion-only remove,
// GAPS.md #60), so an attacker riding an unlocked agent can never drive one
// of these without a fresh fingerprint.
func requireFreshUserPresence(v *vault.Vault, reason string) error {
	presence, ok := v.KeyWrapper.(interface{ RequireUserPresence(string) error })
	if !ok {
		return fmt.Errorf("internal error: fresh-auth vault has no explicit user-presence challenge")
	}
	if err := presence.RequireUserPresence(reason); err != nil {
		return err
	}
	invocationAuth = freshUserPresenceMethod
	return nil
}

func openVaultFreshAuth() (*vault.Vault, error) {
	root, err := vaultRootDir()
	if err != nil {
		return nil, err
	}
	if rekeyInProgress(root) {
		return nil, errRekeyInProgress
	}
	deviceID, err := vault.EnsureDeviceID(root)
	if err != nil {
		return nil, fmt.Errorf("determining device recipient ID: %w", err)
	}
	return &vault.Vault{
		Root:        root,
		KeyWrapper:  keychainwrap.New(),
		RecipientID: deviceID,
	}, nil
}

func openVault() (*vault.Vault, error) {
	root, err := vaultRootDir()
	if err != nil {
		return nil, err
	}
	// Mid-rekey, envelopes are split between two master keys and neither
	// this process's KeyWrapper nor an agent's cached session is
	// guaranteed to hold the right one — refuse rather than risk sealing
	// anything under a key that's about to be destroyed.
	if rekeyInProgress(root) {
		return nil, errRekeyInProgress
	}
	// A persisted random ID, never os.Hostname() — a Mac rename or a
	// DHCP-supplied hostname used to change the recipient key out from
	// under every stored envelope, making the whole vault error with
	// "encrypted on a different machine" on a machine that never moved.
	deviceID, err := vault.EnsureDeviceID(root)
	if err != nil {
		return nil, fmt.Errorf("determining device recipient ID: %w", err)
	}

	var kw vault.KeyWrapper = keychainwrap.New()
	// The retry-configured client (agentClient): when the agent is
	// installed, a dial failure is usually its own restart gap (`jit service
	// restart`, stale-binary self-retirement) — without the retry, a
	// command landing in that gap silently fell back to an independent
	// Touch ID prompt caused by nothing the user did.
	if c, err := agentClient(); err == nil && c.Reachable() {
		kw = c
	}

	return &vault.Vault{
		Root:        root,
		KeyWrapper:  kw,
		RecipientID: deviceID,
	}, nil
}

func init() {
	vaultSetCmd.Flags().BoolVar(&vaultSetStdin, "stdin", false, "read the secret value from stdin instead of prompting")
	vaultSetCmd.Flags().BoolVarP(&vaultSetForce, "force", "f", false, "overwrite an existing secret without confirmation")
	vaultGetCmd.Flags().BoolVarP(&vaultGetCopy, "copy", "c", false, "copy the value to the clipboard instead of printing it")
	vaultGetCmd.Flags().BoolVar(&vaultGetJSON, "json", false, "print an object with the value plus provenance (class/group/origin) and timestamps")
	vaultRmCmd.Flags().BoolVarP(&vaultRmForce, "force", "f", false, "delete without confirmation")
	vaultListCmd.Flags().StringVar(&vaultListFormat, "format", "text", `output format: "text" (default) or "json"`)
	vaultListCmd.Flags().BoolVar(&vaultListAll, "all", false, "also list jit migrate's encrypted file backups (_backups/...)")
	vaultListCmd.Flags().BoolVarP(&vaultListLong, "long", "l", false, "show each secret's class and last-updated age (terminal output only)")
	vaultListCmd.Flags().StringVar(&vaultListBy, "by", "path", `group secrets by: "path" (default), "origin" (source file), or "group" (import batch)`)
	vaultExportCmd.Flags().BoolVar(&vaultExportStdin, "stdin", false, "read the passphrase from stdin instead of prompting (no confirmation double-entry)")
	vaultImportCmd.Flags().BoolVar(&vaultImportStdin, "stdin", false, "read the passphrase from stdin instead of prompting")
	vaultImportCmd.Flags().BoolVarP(&vaultImportYes, "yes", "y", false, "skip the confirmation prompt and import immediately")

	vaultCleanCmd.Flags().BoolVarP(&vaultCleanYes, "yes", "y", false, "skip the confirmation prompt")
	vaultPruneCmd.Flags().BoolVarP(&vaultPruneYes, "yes", "y", false, "skip the confirmation prompt")
	vaultOrphansCmd.Flags().BoolVar(&vaultOrphansPrune, "prune", false, "delete the orphaned secrets (default: only list them)")
	vaultOrphansCmd.Flags().BoolVarP(&vaultOrphansYes, "yes", "y", false, "with --prune, skip the confirmation prompt")
	vaultDeleteCmd.Flags().BoolVarP(&vaultDeleteYes, "yes", "y", false, "skip the confirmation prompt")
	vaultHistoryCmd.Flags().StringVar(&vaultHistoryFormat, "format", "text", `output format: "text" (default) or "json"`)
	vaultRestoreCmd.Flags().Int64Var(&vaultRestoreStamp, "version", 0, "which archived version to restore, by its stamp from jit vault history (default: the newest)")
	vaultCmd.AddCommand(vaultInitCmd, vaultSetCmd, vaultGetCmd, vaultListCmd, vaultHistoryCmd, vaultRestoreCmd, vaultRmCmd, vaultCleanCmd, vaultPruneCmd, vaultOrphansCmd, vaultDeleteCmd, vaultExportCmd, vaultImportCmd)
	rootCmd.AddCommand(vaultCmd)
}
