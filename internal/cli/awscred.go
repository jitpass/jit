// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

//go:build darwin

package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/inject"
	"github.com/jitpass/jit/internal/profile"
)

var awsCredProfile string

// awsCredentialProcessOutput matches AWS's credential_process protocol
// exactly (documented under "Sourcing credentials with an external
// process" in the AWS CLI config file docs): Version must be 1;
// SessionToken/Expiration are omitted entirely for a static long-term
// credential pair rather than sent as empty/null, which the AWS CLI reads
// as "never expires."
type awsCredentialProcessOutput struct {
	Version         int    `json:"Version"`
	AccessKeyId     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	SessionToken    string `json:"SessionToken,omitempty"`
}

var awsCredentialProcessCmd = &cobra.Command{
	Use:     "aws-credential-process --profile <name>",
	GroupID: groupPlumbing,
	// Hidden only from shell tab-completion: helpVisibleAnnotation keeps
	// it in the root help (rootUsageTemplate) and the generated docs.
	Hidden:      true,
	Annotations: map[string]string{helpVisibleAnnotation: "1"},
	Short:       "Print AWS credential_process JSON for a migrated profile",
	Long: "Not typically run by hand: jit migrate rewrites the matching ~/.aws/config\n" +
		"profile to invoke this command directly\n" +
		"(`credential_process = jit aws-credential-process --profile aws-<name>`),\n" +
		"so the AWS CLI/SDK gets credentials with no file on disk at all.\n\n" +
		"Requires local auth to resolve the vault the same way jit run/export do:\n" +
		"either a reachable jit background service with an already-unlocked session, or an\n" +
		"interactive context able to show a Touch ID/passcode prompt. Invoked from\n" +
		"a fully headless context (a cron job, a CI runner) with neither will hang\n" +
		"or fail, the same tradeoff jit run/export already accept.",
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if awsCredProfile == "" {
			return fmt.Errorf("jit aws-credential-process: --profile is required")
		}

		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("jit aws-credential-process: %w", err)
		}
		p, err := profile.Load(home, awsCredProfile)
		if err != nil {
			return fmt.Errorf("jit aws-credential-process: %w", err)
		}

		v, err := openVault()
		if err != nil {
			return fmt.Errorf("jit aws-credential-process: %w", err)
		}
		values, err := inject.Resolve(v, p)
		if err != nil {
			return fmt.Errorf("jit aws-credential-process: %w", err)
		}

		out, err := buildAWSCredentialProcessOutput(values)
		if err != nil {
			return fmt.Errorf("jit aws-credential-process: profile %q: %w", awsCredProfile, err)
		}
		data, err := json.Marshal(out) // #nosec G117 -- AWS's credential_process protocol requires emitting SessionToken as a JSON field; this is the documented output shape, not an accidental secret leak
		if err != nil {
			return fmt.Errorf("jit aws-credential-process: %w", err)
		}
		fmt.Fprintln(cmd.OutOrStdout(), string(data))
		return nil
	},
}

// buildAWSCredentialProcessOutput validates values (a resolved profile's
// variable -> plaintext map) and builds the credential_process JSON
// shape, split out from RunE specifically so the protocol shape is
// testable without a real vault/Touch ID challenge (same reason
// run.go/export.go split resolveRunPlan out of their own RunE).
func buildAWSCredentialProcessOutput(values map[string]string) (awsCredentialProcessOutput, error) {
	if values["ACCESS_KEY_ID"] == "" || values["SECRET_ACCESS_KEY"] == "" {
		return awsCredentialProcessOutput{}, fmt.Errorf("missing ACCESS_KEY_ID/SECRET_ACCESS_KEY")
	}
	return awsCredentialProcessOutput{
		Version:         1,
		AccessKeyId:     values["ACCESS_KEY_ID"],
		SecretAccessKey: values["SECRET_ACCESS_KEY"],
		SessionToken:    values["SESSION_TOKEN"],
	}, nil
}

func init() {
	awsCredentialProcessCmd.Flags().StringVar(&awsCredProfile, "profile", "", "vault profile to resolve (required, e.g. aws-default)")
	_ = awsCredentialProcessCmd.RegisterFlagCompletionFunc("profile", completeProfileNames)
	rootCmd.AddCommand(awsCredentialProcessCmd)
}
