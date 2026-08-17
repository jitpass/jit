// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/onepassword"
	"github.com/jitpass/jit/internal/vault"
)

// jit vault link — store a 1Password secret reference instead of a value
// (design/1password-adapter.md, issue #60). The vault entry holds the
// op:// URI, encrypted and consent-gated like any secret; every delivery
// surface (run, credential helpers, mounts, export) resolves it through
// the 1Password CLI at the moment of use, so 1Password stays the system
// of record and jit never keeps a drifting copy of the value.

var (
	vaultLinkYes      bool
	vaultLinkNoVerify bool
)

var vaultLinkCmd = &cobra.Command{
	Use:   "link <path> <op://vault/item/field>",
	Short: "Store a 1Password reference instead of a value",
	Long: "Links <path> to a secret that stays in 1Password: the vault stores the\n" +
		"op:// reference (encrypted, like any secret), and every use (jit run,\n" +
		"credential helpers, mounts) resolves it through the 1Password CLI at\n" +
		"that moment. Rotate and share the value in 1Password; jit never keeps\n" +
		"a copy that can drift.\n\n" +
		"Copy the reference from the 1Password app (field menu > Copy Secret\n" +
		"Reference). Item and vault IDs also work in place of names and survive\n" +
		"renames.\n\n" +
		"The link is test-resolved through `op` first, so a typo or a signed-out\n" +
		"CLI fails here, not at first use; --no-verify skips that (offline setup).\n" +
		"Requires the 1Password CLI (`brew install 1password-cli`) with the\n" +
		"desktop app integration on.\n\n" +
		"Requires a fresh Touch ID/passcode on every run, never the cached service\n" +
		"session, same as `jit vault set`.\n\n" +
		"Overwriting an existing secret asks first; -y/--yes skips that question,\n" +
		"as it does on every other jit command.",
	Example: "  jit vault link stripe/live \"op://Private/Stripe/credential\"\n" +
		"  jit vault link deploy/token \"op://dev/GitHub/credentials/token\" --no-verify",
	Args:              requireArgs(2, 2, "a secret path and an op:// secret reference"),
	ValidArgsFunction: completeVaultPaths,
	SilenceUsage:      true,
	RunE: func(cmd *cobra.Command, args []string) error {
		path, ref := args[0], args[1]

		// Shape first: a typo'd reference must cost nothing — no op exec,
		// no Touch ID.
		if err := onepassword.ValidateRef(ref); err != nil {
			return fmt.Errorf("jit vault link: %w", err)
		}

		// Trial resolve BEFORE any Touch ID: this is where 1Password's own
		// authorization prompt fires, at setup time where the user expects
		// it, and where "op is not installed / not signed in / item gone"
		// surfaces without costing a fingerprint on a doomed link.
		if !vaultLinkNoVerify {
			if _, err := onepassword.New().ResolveRef(ref); err != nil {
				return fmt.Errorf("jit vault link: %w (use --no-verify to link anyway)", err)
			}
		}

		// Fresh auth on every sensitive vault command, never the cached
		// agent session — writing a pointer is writing a secret: whoever
		// controls the reference controls what every consumer of this path
		// receives.
		v, err := openVaultFreshAuth()
		if err != nil {
			return fmt.Errorf("jit vault link: %w", err)
		}

		if !vaultLinkYes {
			exists, err := v.Exists(path)
			if err != nil {
				return fmt.Errorf("jit vault link: %w", err)
			}
			if exists && !confirmOverwrite(cmd, path) {
				fmt.Fprintln(cmd.OutOrStdout(), "Aborted.")
				return nil
			}
		}

		// Born as a link: its only source IS 1Password (ClassOnePassword).
		// A rotation of an existing path keeps its birth class, same as
		// every Set.
		if err := v.SetReference(path, ref, vault.Meta{Class: vault.ClassOnePassword}); err != nil {
			return fmt.Errorf("jit vault link: %w", err)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Linked %s\n", path)
		return nil
	},
}

func init() {
	vaultLinkCmd.Flags().BoolVarP(&vaultLinkYes, "yes", "y", false, "overwrite an existing secret without confirmation")
	vaultLinkCmd.Flags().BoolVar(&vaultLinkNoVerify, "no-verify", false, "skip the trial resolve through `op` (offline setup)")
	vaultCmd.AddCommand(vaultLinkCmd)
}
