// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

//go:build darwin

package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/inject"
	"github.com/jitpass/jit/internal/profile"
)

var sopsAgeKeyProfile string

var sopsAgeKeyCmd = &cobra.Command{
	Use:     "sops-age-key",
	GroupID: groupPlumbing,
	// Hidden only from shell tab-completion: helpVisibleAnnotation keeps
	// it in the root help (rootUsageTemplate) and the generated docs.
	Hidden:      true,
	Annotations: map[string]string{helpVisibleAnnotation: "1"},
	Short:       "Print the SOPS age private key from a migrated profile",
	Long: "Not typically run by hand: sops (v3.10+) runs it via SOPS_AGE_KEY_CMD, its\n" +
		"native hook for fetching the age key from an external command, so decryption\n" +
		"works with no plaintext keys.txt on disk at all:\n\n" +
		"  export SOPS_AGE_KEY_CMD=\"jit sops-age-key\"\n\n" +
		"Tools whose embedded sops predates SOPS_AGE_KEY_CMD keep working through the\n" +
		"migrated keys.txt live mount instead (jit run opens the reveal window), so\n" +
		"this hook is the fast path, not the only path.\n\n" +
		"Requires local auth to resolve the vault the same way jit run/export do:\n" +
		"either a reachable jit agent with an already-unlocked session, or an\n" +
		"interactive context able to show a Touch ID/passcode prompt. Invoked from\n" +
		"a fully headless context (a cron job, a CI runner) with neither will hang\n" +
		"or fail, the same tradeoff jit run/export already accept.",
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("jit sops-age-key: %w", err)
		}
		p, err := profile.Load(home, sopsAgeKeyProfile)
		if err != nil {
			return fmt.Errorf("jit sops-age-key: %w", err)
		}

		v, err := openVault()
		if err != nil {
			return fmt.Errorf("jit sops-age-key: %w", err)
		}
		values, err := inject.Resolve(v, p)
		if err != nil {
			return fmt.Errorf("jit sops-age-key: %w", err)
		}

		key, err := buildSOPSAgeKeyOutput(values)
		if err != nil {
			return fmt.Errorf("jit sops-age-key: profile %q: %w", sopsAgeKeyProfile, err)
		}
		fmt.Fprintln(cmd.OutOrStdout(), key)
		return nil
	},
}

// buildSOPSAgeKeyOutput validates values (a resolved profile's variable ->
// plaintext map) and returns the bare key string, split out from RunE so
// the output contract is testable without a real vault/Touch ID challenge
// (the buildK8sExecCredentialOutput pattern).
//
// The contract matters because sops parses SOPS_AGE_KEY_CMD's stdout as
// age key material: exactly the key token, no banners, no logging — any
// extra output breaks every decrypt on the machine.
func buildSOPSAgeKeyOutput(values map[string]string) (string, error) {
	key := strings.TrimSpace(values["SOPS_AGE_KEY"])
	if key == "" {
		return "", fmt.Errorf("has no SOPS_AGE_KEY entry")
	}
	if !strings.HasPrefix(key, "AGE-SECRET-KEY-1") {
		return "", fmt.Errorf("SOPS_AGE_KEY entry is not an age secret key")
	}
	return key, nil
}

func init() {
	sopsAgeKeyCmd.Flags().StringVar(&sopsAgeKeyProfile, "profile", "sops-age",
		"vault profile to resolve (defaults to the one jit migrate creates)")
	_ = sopsAgeKeyCmd.RegisterFlagCompletionFunc("profile", completeProfileNames)
	rootCmd.AddCommand(sopsAgeKeyCmd)
}
