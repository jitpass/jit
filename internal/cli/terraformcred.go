// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

//go:build darwin

package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/inject"
	"github.com/jitpass/jit/internal/migrate"
	"github.com/jitpass/jit/internal/profile"
)

// terraformCredentialOutput is the credentials-helper protocol's "get"
// response: a single JSON object with the token. Terraform's protocol
// expects an empty JSON object when no credentials are available for the
// hostname — that case is handled in RunE directly (before any vault
// access), not here.
type terraformCredentialOutput struct {
	Token string `json:"token"`
}

var terraformCredentialsCmd = &cobra.Command{
	Use:     "terraform-credentials <get|store|forget> <hostname>",
	GroupID: groupPlumbing,
	// Hidden only from shell tab-completion: helpVisibleAnnotation keeps
	// it in the root help (rootUsageTemplate) and the generated docs.
	Hidden:      true,
	Annotations: map[string]string{helpVisibleAnnotation: "1"},
	Short:       "Implement Terraform's credentials-helper protocol for a migrated token",
	Long: "Not typically run by hand: jit migrate writes a terraform-credentials-jit\n" +
		"helper script that invokes this command, and a credentials_helper block in\n" +
		"~/.terraformrc, so terraform fetches its API token from the vault with no\n" +
		"file on disk at all.\n\n" +
		"The three verbs are Terraform's own protocol: `get <host>` prints the\n" +
		"token as JSON (an empty object when jit holds nothing for that host, so\n" +
		"terraform falls through to anonymous access exactly as if no credentials\n" +
		"file entry existed); `store <host>` (what `terraform login` calls) reads\n" +
		"the token JSON from stdin and saves it to the vault, so a re-login lands\n" +
		"in the vault instead of back in a plaintext file; `forget <host>`\n" +
		"(`terraform logout`) removes it.\n\n" +
		"Requires local auth to resolve the vault the same way jit run/export do:\n" +
		"either a reachable jit agent with an already-unlocked session, or an\n" +
		"interactive context able to show a Touch ID/passcode prompt.",
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		verb, host := args[0], args[1]
		profileName := "terraform-" + host

		switch verb {
		case "get":
			// A host jit holds nothing for must NOT be an error or a
			// prompt: terraform queries the helper for any host it talks
			// to, and the protocol's "no credentials" answer is an empty
			// JSON object. Checked against the global manifest directly
			// (terraform profiles are always global-store), BEFORE
			// openVault() — an unknown host must never cost a Touch ID
			// prompt.
			globalRoot, err := profile.GlobalRoot()
			if err != nil {
				return fmt.Errorf("jit terraform-credentials: %w", err)
			}
			manifestPath, err := profile.Path(globalRoot, profileName)
			if err != nil {
				return fmt.Errorf("jit terraform-credentials: %w", err)
			}
			p, err := profile.LoadFile(manifestPath)
			if errors.Is(err, os.ErrNotExist) {
				fmt.Fprintln(cmd.OutOrStdout(), "{}")
				return nil
			}
			if err != nil {
				return fmt.Errorf("jit terraform-credentials: %w", err)
			}

			v, err := openVault()
			if err != nil {
				return fmt.Errorf("jit terraform-credentials: %w", err)
			}
			values, err := inject.Resolve(v, p)
			if err != nil {
				return fmt.Errorf("jit terraform-credentials: %w", err)
			}
			out, err := buildTerraformCredentialOutput(values)
			if err != nil {
				return fmt.Errorf("jit terraform-credentials: profile %q: %w", profileName, err)
			}
			data, err := json.Marshal(out)
			if err != nil {
				return fmt.Errorf("jit terraform-credentials: %w", err)
			}
			fmt.Fprintln(cmd.OutOrStdout(), string(data))
			return nil

		case "store":
			var in terraformCredentialOutput
			if err := json.NewDecoder(cmd.InOrStdin()).Decode(&in); err != nil {
				return fmt.Errorf("jit terraform-credentials store: reading token from stdin: %w", err)
			}
			if in.Token == "" {
				return fmt.Errorf("jit terraform-credentials store: no token in stdin JSON")
			}
			v, err := openVault()
			if err != nil {
				return fmt.Errorf("jit terraform-credentials: %w", err)
			}
			if err := migrate.StoreTerraformToken(v, host, in.Token); err != nil {
				return fmt.Errorf("jit terraform-credentials store: %w", err)
			}
			return nil

		case "forget":
			// Removing a secret never decrypts anything (Vault.Remove
			// doesn't touch KeyWrapper), so `terraform logout` must never
			// cost a Touch ID prompt — read-only construction, like doctor.
			v, err := openVaultReadOnly()
			if err != nil {
				return fmt.Errorf("jit terraform-credentials: %w", err)
			}
			if err := migrate.ForgetTerraformToken(v, host); err != nil {
				return fmt.Errorf("jit terraform-credentials forget: %w", err)
			}
			return nil

		default:
			return fmt.Errorf("jit terraform-credentials: unknown verb %q (want get, store, or forget)", verb)
		}
	},
}

// buildTerraformCredentialOutput validates a resolved profile's values
// and builds the helper protocol's "get" JSON — split out of RunE so the
// protocol shape is testable without a real vault/Touch ID challenge
// (same split as awscred.go/k8scred.go).
func buildTerraformCredentialOutput(values map[string]string) (terraformCredentialOutput, error) {
	if values["TOKEN"] == "" {
		return terraformCredentialOutput{}, fmt.Errorf("missing TOKEN")
	}
	return terraformCredentialOutput{Token: values["TOKEN"]}, nil
}

func init() {
	rootCmd.AddCommand(terraformCredentialsCmd)
}
