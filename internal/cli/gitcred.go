// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/inject"
	"github.com/jitpass/jit/internal/migrate"
	"github.com/jitpass/jit/internal/profile"
)

var gitCredentialCmd = &cobra.Command{
	Use:     "git-credential <get|store|erase>",
	GroupID: groupPlumbing,
	// Hidden only from shell tab-completion: helpVisibleAnnotation keeps it
	// in the root help (rootUsageTemplate) and the generated docs.
	Hidden:      true,
	Annotations: map[string]string{helpVisibleAnnotation: "1"},
	Short:       "Implement git's credential-helper protocol for migrated HTTPS logins",
	Long: "Not typically run by hand: jit migrate writes a git-credential-jit\n" +
		"helper script (on PATH via ~/.jit/shims) and sets credential.helper to it\n" +
		"in your git config, so `git push` over HTTPS (and submodule fetches, LFS,\n" +
		"and anything else that shells out to git) fetches the credential from the\n" +
		"vault instead of ~/.git-credentials.\n\n" +
		"The three verbs are git's own protocol, each reading a set of key=value\n" +
		"attributes from stdin (protocol, host, path, username, password),\n" +
		"terminated by a blank line: `get` reads the host and prints the matching\n" +
		"`username=`/`password=` pair, or nothing when jit holds no credential for\n" +
		"that host, so git falls through to its next helper or prompts; `store`\n" +
		"reads a credential and saves it to the vault, so a push that authenticated\n" +
		"with a typed-in password lands in the vault instead of back in plaintext;\n" +
		"`erase` removes it. jit keys on host alone, matching git's default\n" +
		"(credential.useHttpPath=false).\n\n" +
		"`get` for a host jit holds nothing for, and `erase`, never cost a Touch ID\n" +
		"prompt. A successful `get` resolves the vault the same way jit run/export\n" +
		"do: either a reachable jit background service with an already-unlocked session, or an\n" +
		"interactive context able to show a Touch ID/passcode prompt.",
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		switch verb := args[0]; verb {
		case "get":
			in, err := migrate.ParseGitCredentialInput(cmd.InOrStdin())
			if err != nil {
				return fmt.Errorf("jit git-credential get: reading request from stdin: %w", err)
			}
			// A host jit holds nothing for must be silent success, not an
			// error or a prompt: git queries the helper for every HTTPS
			// remote it talks to, and the protocol reads empty output as "no
			// credential" and moves on. Checked against the global manifest
			// directly (git profiles are always global-store), BEFORE
			// openVault() so an unknown host never costs a Touch ID prompt.
			profileName := migrate.GitProfileName(in.Host)
			if profileName == "" {
				return nil
			}
			globalRoot, err := profile.GlobalRoot()
			if err != nil {
				return fmt.Errorf("jit git-credential: %w", err)
			}
			manifestPath, err := profile.Path(globalRoot, profileName)
			if err != nil {
				return fmt.Errorf("jit git-credential: %w", err)
			}
			p, err := profile.LoadFile(manifestPath)
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			if err != nil {
				return fmt.Errorf("jit git-credential: %w", err)
			}

			v, err := openVault()
			if err != nil {
				return fmt.Errorf("jit git-credential: %w", err)
			}
			values, err := inject.Resolve(v, p)
			if err != nil {
				return fmt.Errorf("jit git-credential: %w", err)
			}
			out, ok := buildGitCredentialOutput(values)
			if !ok {
				// Profile exists but resolved to no password: treat as no
				// credential rather than emit a malformed pair.
				return nil
			}
			fmt.Fprint(cmd.OutOrStdout(), out)
			return nil

		case "store":
			in, err := migrate.ParseGitCredentialInput(cmd.InOrStdin())
			if err != nil {
				return fmt.Errorf("jit git-credential store: reading credential from stdin: %w", err)
			}
			if in.Host == "" {
				return fmt.Errorf("jit git-credential store: no host in stdin request")
			}
			if in.Password == "" {
				return fmt.Errorf("jit git-credential store: no password in stdin request")
			}
			v, err := openVault()
			if err != nil {
				return fmt.Errorf("jit git-credential: %w", err)
			}
			if err := migrate.StoreGitCredential(v, in); err != nil {
				return fmt.Errorf("jit git-credential store: %w", err)
			}
			return nil

		case "erase":
			in, err := migrate.ParseGitCredentialInput(cmd.InOrStdin())
			if err != nil {
				return fmt.Errorf("jit git-credential erase: reading request from stdin: %w", err)
			}
			// Removing a secret never decrypts anything (Vault.Remove doesn't
			// touch KeyWrapper), so an erase must never cost a Touch ID
			// prompt, read-only construction like docker-credential erase.
			v, err := openVaultReadOnly()
			if err != nil {
				return fmt.Errorf("jit git-credential: %w", err)
			}
			if err := migrate.EraseGitCredential(v, in.Host); err != nil {
				return fmt.Errorf("jit git-credential erase: %w", err)
			}
			return nil

		default:
			return fmt.Errorf("jit git-credential: unknown verb %q (want get, store, or erase)", verb)
		}
	},
}

// buildGitCredentialOutput turns a resolved profile's values into the helper
// protocol's `get` response (username=/password= lines, each newline
// terminated). Split out of RunE so the protocol shape is testable without a
// real vault/Touch ID challenge (same split as dockercred.go's
// buildDockerCredentialOutput). Returns ok=false when there's no password,
// the one field git actually needs.
func buildGitCredentialOutput(values map[string]string) (string, bool) {
	// git's helper protocol is newline-delimited key=value, so a value
	// containing a newline would inject further attributes into the response —
	// a stored password of "x\nquit=1" makes git abandon the credential search,
	// and "x\nurl=..." rewrites the context it thinks it is authenticating to.
	// The value is the user's own secret rather than an attacker's, so this is
	// hygiene rather than a live hole, but a protocol writer should never be
	// able to emit a frame it did not intend.
	password := singleLine(values["PASSWORD"])
	if password == "" {
		return "", false
	}
	var b strings.Builder
	if username := singleLine(values["USERNAME"]); username != "" {
		fmt.Fprintf(&b, "username=%s\n", username)
	}
	fmt.Fprintf(&b, "password=%s\n", password)
	return b.String(), true
}

// singleLine truncates at the first CR or LF: git's protocol has no escaping,
// so the only safe rendering of a multi-line value is to stop where the frame
// would have ended anyway.
func singleLine(s string) string {
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		return s[:i]
	}
	return s
}

func init() {
	rootCmd.AddCommand(gitCredentialCmd)
}
