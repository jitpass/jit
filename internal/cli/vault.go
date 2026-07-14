// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: Apache-2.0

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
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/jitpass/jit/internal/agent"
	"github.com/jitpass/jit/internal/keychainwrap"
	"github.com/jitpass/jit/internal/migrate"
	"github.com/jitpass/jit/internal/mount"
	"github.com/jitpass/jit/internal/vault"
)

var (
	vaultSetStdin    bool
	vaultSetForce    bool
	vaultGetCopy     bool
	vaultRmForce     bool
	vaultListFormat  string
	vaultListAll     bool
	vaultExportStdin bool
	vaultImportStdin bool
	vaultImportYes   bool
)

// vaultListResult is jit vault list's --format json shape (GAPS.md #22).
// Neither field is ever nil in JSON output even when the vault is empty —
// an empty array, not a null field, so a script doesn't need a special
// case for "nothing stored yet" vs. "field missing." Backups (the
// encrypted pre-rewrite file backups jit migrate stores under _backups/,
// which `jit migrate undo` restores from) are split out of Secrets rather
// than mixed in (GAPS.md #55): they're jit's own bookkeeping, not secrets
// the user stored, and listing them as peers made a three-project vault
// listing open with three unreadable absolute-path entries.
type vaultListResult struct {
	Secrets []string `json:"secrets"`
	Backups []string `json:"backups"`
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

// printVaultList renders jit vault list's text output: secrets one per
// line (grep/pipe-friendly, no decoration), backups collapsed into the
// closing count line unless showBackups (--all) lists them too, and
// exactly one closing count line so nobody has to count rows themselves.
func printVaultList(out io.Writer, secrets, backups []string, showBackups bool) {
	if len(secrets) == 0 && len(backups) == 0 {
		fmt.Fprintln(out, "No secrets stored yet. Run `jit vault set <path>` to add one, or `jit migrate local` to move existing secrets in.")
		return
	}
	for _, p := range secrets {
		fmt.Fprintln(out, p)
	}
	if showBackups {
		for _, p := range backups {
			fmt.Fprintln(out, p)
		}
	}
	switch {
	case len(backups) == 0:
		fmt.Fprintf(out, "\n%d secret(s) stored.\n", len(secrets))
	case showBackups:
		fmt.Fprintf(out, "\n%d secret(s) stored, plus %d encrypted file backup(s) kept for `jit migrate undo`.\n", len(secrets), len(backups))
	case len(secrets) == 0:
		fmt.Fprintf(out, "No secrets stored yet — %d encrypted file backup(s) kept for `jit migrate undo` (list with --all).\n", len(backups))
	default:
		fmt.Fprintf(out, "\n%d secret(s) stored, plus %d encrypted file backup(s) kept for `jit migrate undo` (list with --all).\n", len(secrets), len(backups))
	}
}

var vaultCmd = &cobra.Command{
	Use:     "vault",
	GroupID: groupSecrets,
	Short:   "Manage the local encrypted secret vault",
	Long: "jit vault stores each secret as its own encrypted file under jit's data\n" +
		"directory — no monolithic database. Access is gated by a Touch ID/passcode\n" +
		"prompt enforced by jit itself (a real prompt, though not yet an OS-enforced\n" +
		"Keychain/Secure Enclave guarantee).",
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
		fmt.Fprintf(cmd.OutOrStdout(), "Vault initialized at %s.\nRun `jit vault set <path>` to add a secret, or `jit migrate local` to move existing secrets in.\n", root)
		return nil
	},
}

var vaultSetCmd = &cobra.Command{
	Use:   "set <path> [value]",
	Short: "Encrypt and store a secret",
	Long: "Stores a secret at <path> (e.g. \"stripe/dev-key\"). If [value] is omitted,\n" +
		"prompts for it with hidden input. Use --stdin for scripts. Passing the value\n" +
		"as a bare argument works but lands in shell history — prefer the prompt or --stdin.",
	Args: cobra.RangeArgs(1, 2),
	RunE: func(cmd *cobra.Command, args []string) error {
		path := args[0]

		value, err := readSecretValue(cmd, args)
		if err != nil {
			return fmt.Errorf("jit vault set: %w", err)
		}
		if len(value) == 0 {
			return fmt.Errorf("jit vault set: value must not be empty")
		}

		v, err := openVault()
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

		if err := v.Set(path, value); err != nil {
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
		"--copy to send it straight to the clipboard instead.",
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		v, err := openVault()
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

		if vaultGetCopy {
			if err := copyToClipboard(value); err != nil {
				return fmt.Errorf("jit vault get: %w", err)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Copied to clipboard.")
			return nil
		}
		fmt.Fprintln(cmd.OutOrStdout(), string(value))
		return nil
	},
}

var vaultListCmd = &cobra.Command{
	Use:   "list",
	Short: "List stored secret paths (names only, never values)",
	Long: "Lists every secret path currently stored, never a value. The encrypted\n" +
		"file backups jit migrate keeps for `jit migrate undo` are summarized in\n" +
		"the count line rather than listed; --all lists them too. --format json\n" +
		"prints {\"secrets\": [...], \"backups\": [...]} instead of one path per line.",
	Args: cobra.NoArgs,
	// See doctor.go's SilenceUsage comment — the same "don't corrupt a
	// --format json snapshot with usage text on a RunE error" reasoning
	// applies to every command in this file that gained --format json.
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateOutputFormat(vaultListFormat); err != nil {
			return fmt.Errorf("jit vault list: %w", err)
		}

		v, err := openVault()
		if err != nil {
			return fmt.Errorf("jit vault list: %w", err)
		}
		paths, err := v.List()
		if err != nil {
			return fmt.Errorf("jit vault list: %w", err)
		}
		secrets, backups := splitBackupPaths(paths)

		if vaultListFormat == "json" {
			// --all is text-display-only: JSON always carries both
			// arrays, since a script parsing the snapshot shouldn't
			// need a flag to see the whole picture.
			return writeJSON(cmd.OutOrStdout(), vaultListResult{Secrets: secrets, Backups: backups})
		}

		printVaultList(cmd.OutOrStdout(), secrets, backups, vaultListAll)
		return nil
	},
}

var vaultRmCmd = &cobra.Command{
	Use:   "rm <path>",
	Short: "Delete a secret",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if !vaultRmForce && !confirmPrompt(cmd, fmt.Sprintf("Permanently delete %s from the vault? This can't be undone. [y/N] ", args[0])) {
			fmt.Fprintln(cmd.OutOrStdout(), "Aborted.")
			return nil
		}

		v, err := openVault()
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

var vaultExportCmd = &cobra.Command{
	Use:   "export <file>",
	Short: "Export every secret to a passphrase-encrypted local backup file",
	Long: "Decrypts every secret currently in the vault and re-encrypts the whole set\n" +
		"under a passphrase you supply — NOT the vault's own per-secret encryption,\n" +
		"which is bound to this device and useless on a different machine. A\n" +
		"passphrase-derived key is what actually makes this file restorable after\n" +
		"laptop loss or a reformat — `jit vault import <file>` reverses it, on this\n" +
		"machine or any other. Remembering the passphrase is entirely on you: jit\n" +
		"never stores it anywhere. This is a local file, moved around by whatever\n" +
		"means you choose — jit never uploads it.\n\n" +
		"--stdin reads the passphrase from stdin (one line, no confirmation\n" +
		"double-entry) instead of the default hidden prompt — for scripting, e.g.\n" +
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
		"any existing secret at the same path. Confirms first unless --yes — the\n" +
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

		v, err := openVault()
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
	return confirmPrompt(cmd, fmt.Sprintf("%s already exists in the vault. Overwrite it? The current value can't be recovered afterward. [y/N] ", path))
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
		"encrypted file backups jit migrate keeps for `jit migrate undo` — after\n" +
		"this, undo has nothing left to restore from. The vault itself stays\n" +
		"initialized (its encryption key and device identity are kept), so\n" +
		"`jit vault set`/`jit migrate` keep working immediately afterward.\n" +
		"Refuses while any file is still live-mounted — unmount first, or the\n" +
		"mounted file's real content would be gone for good.\n" +
		"To destroy the vault entirely, key included, use `jit vault delete`.",
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Same refusal as `jit vault delete`, for the same reason: wiping
		// the secrets out from under a registered mount permanently strands
		// the file as decoys — and unmounting AFTER a clean is impossible
		// (unmount needs the vault to write the plaintext back), so the
		// only recoverable order is unmount first. A real incident: a
		// playground vault cleaned with 4 mounts registered left all four
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
			return fmt.Errorf("jit vault clean: %d file(s) are still live-mounted — run `jit unmount <path>` on each first, or their real content is gone for good", len(entries))
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
			fmt.Fprintln(cmd.OutOrStdout(), "The vault is already empty — nothing to clean.")
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
			warning = fmt.Sprintf(" — including %d encrypted file backup(s), so `jit migrate undo` will have nothing left to restore from", backups)
		}
		if !vaultCleanYes && !confirmPrompt(cmd, fmt.Sprintf(
			"Permanently delete ALL %d secret(s) from the vault%s? This can't be undone. [y/N] ", len(paths), warning)) {
			fmt.Fprintln(cmd.OutOrStdout(), "Aborted. Nothing was deleted.")
			return nil
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
		fmt.Fprintf(cmd.OutOrStdout(), "Deleted %d secret(s). The vault itself is still set up — `jit vault set` works immediately.\n", len(paths))
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
		"repeated migrate/undo cycles accumulate backups indefinitely — nothing\n" +
		"expires them automatically, on purpose (a recovery snapshot silently aging\n" +
		"out is worse than a big vault). This prunes the accumulation: for every\n" +
		"file, the NEWEST backup — the one `jit migrate undo` would restore — is\n" +
		"kept, and every older one is permanently deleted.\n\n" +
		"Backups taken by jit builds before the undo index existed aren't touched\n" +
		"(they're invisible to undo but may be your only copy) — see them with\n" +
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
			fmt.Fprintln(out, "Nothing to prune — each backed-up file already has only its newest backup.")
			return nil
		}

		fmt.Fprintf(out, "Pruning %d stale backup(s) — each file's newest backup is kept, so `jit migrate undo` still works:\n", len(stale))
		for _, r := range stale {
			fmt.Fprintf(out, "  • %s (%s, backed up %s ago)\n", r.VaultPath, displayPath(home, r.OriginalPath), humanAgo(time.Since(time.Unix(r.UnixTS, 0))))
		}
		if !vaultPruneYes && !confirmPrompt(cmd, fmt.Sprintf("Permanently delete %d stale backup(s)? This can't be undone. [y/N] ", len(stale))) {
			fmt.Fprintln(out, "Aborted. Nothing was deleted.")
			return nil
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
		"afterward — only a passphrase-encrypted `jit vault export` file survives\n" +
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
			return fmt.Errorf("jit vault delete: %d file(s) are still live-mounted — run `jit unmount <path>` on each first, or their real content is gone for good", len(entries))
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
				noBackup = " No vault export exists — every secret will be unrecoverable."
			}
		}
		if !vaultDeleteYes && !confirmPrompt(cmd, fmt.Sprintf(
			"Permanently destroy the ENTIRE vault — %d secret(s), the undo backups, and the encryption key in the macOS keychain?%s [y/N] ", len(paths), noBackup)) {
			fmt.Fprintln(cmd.OutOrStdout(), "Aborted. Nothing was deleted.")
			return nil
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
		fmt.Fprintln(cmd.OutOrStdout(), "The vault is gone. Run `jit vault init` to start fresh.")
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
		fmt.Fprintf(w, "warning: couldn't lock the running agent's cached session — run `jit agent lock` before using a new vault: %v\n", err)
		return ""
	}
	return "the running agent's cached session (locked)"
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

func copyToClipboard(value []byte) error {
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
func openVaultFreshAuth() (*vault.Vault, error) {
	root, err := vaultRootDir()
	if err != nil {
		return nil, err
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
	// A persisted random ID, never os.Hostname() — a Mac rename or a
	// DHCP-supplied hostname used to change the recipient key out from
	// under every stored envelope, making the whole vault error with
	// "encrypted on a different machine" on a machine that never moved.
	deviceID, err := vault.EnsureDeviceID(root)
	if err != nil {
		return nil, fmt.Errorf("determining device recipient ID: %w", err)
	}

	var kw vault.KeyWrapper = keychainwrap.New()
	if agentClient := agent.NewClient(agent.SocketPath(root)); agentClient.Reachable() {
		kw = agentClient
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
	vaultRmCmd.Flags().BoolVarP(&vaultRmForce, "force", "f", false, "delete without confirmation")
	vaultListCmd.Flags().StringVar(&vaultListFormat, "format", "text", `output format: "text" (default) or "json"`)
	vaultListCmd.Flags().BoolVar(&vaultListAll, "all", false, "also list jit migrate's encrypted file backups (_backups/...)")
	vaultExportCmd.Flags().BoolVar(&vaultExportStdin, "stdin", false, "read the passphrase from stdin instead of prompting (no confirmation double-entry)")
	vaultImportCmd.Flags().BoolVar(&vaultImportStdin, "stdin", false, "read the passphrase from stdin instead of prompting")
	vaultImportCmd.Flags().BoolVarP(&vaultImportYes, "yes", "y", false, "skip the confirmation prompt and import immediately")

	vaultCleanCmd.Flags().BoolVarP(&vaultCleanYes, "yes", "y", false, "skip the confirmation prompt")
	vaultPruneCmd.Flags().BoolVarP(&vaultPruneYes, "yes", "y", false, "skip the confirmation prompt")
	vaultDeleteCmd.Flags().BoolVarP(&vaultDeleteYes, "yes", "y", false, "skip the confirmation prompt")
	vaultCmd.AddCommand(vaultInitCmd, vaultSetCmd, vaultGetCmd, vaultListCmd, vaultRmCmd, vaultCleanCmd, vaultPruneCmd, vaultDeleteCmd, vaultExportCmd, vaultImportCmd)
	rootCmd.AddCommand(vaultCmd)
}
