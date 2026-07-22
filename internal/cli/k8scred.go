// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

//go:build darwin

package cli

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/inject"
	"github.com/jitpass/jit/internal/profile"
)

var k8sCredProfile string

const k8sExecCredentialAPIVersion = "client.authentication.k8s.io/v1"

// k8sExecCredentialStatus matches client-go's exec plugin protocol
// (ExecCredential): a bearer token OR a client-certificate/client-key
// pair, never both populated at once in practice, so both are tagged
// omitempty and only whichever this profile actually holds gets printed.
type k8sExecCredentialStatus struct {
	Token                 string `json:"token,omitempty"`
	ClientCertificateData string `json:"clientCertificateData,omitempty"`
	ClientKeyData         string `json:"clientKeyData,omitempty"`
}

type k8sExecCredentialOutput struct {
	APIVersion string                  `json:"apiVersion"`
	Kind       string                  `json:"kind"`
	Status     k8sExecCredentialStatus `json:"status"`
}

var k8sExecCredentialCmd = &cobra.Command{
	Use:     "k8s-exec-credential --profile <name>",
	GroupID: groupPlumbing,
	// Hidden only from shell tab-completion: helpVisibleAnnotation keeps
	// it in the root help (rootUsageTemplate) and the generated docs.
	Hidden:      true,
	Annotations: map[string]string{helpVisibleAnnotation: "1"},
	Short:       "Print a Kubernetes ExecCredential JSON for a migrated profile",
	Long: "Not typically run by hand: jit migrate rewrites the matching kubeconfig\n" +
		"user's `exec` block to invoke this command directly, so kubectl/client-go\n" +
		"get credentials with no plaintext token or key on disk at all.\n\n" +
		"Requires local auth to resolve the vault the same way jit run/export do:\n" +
		"either a reachable jit background service with an already-unlocked session, or an\n" +
		"interactive context able to show a Touch ID/passcode prompt. Invoked from\n" +
		"a fully headless context (a cron job, a CI runner) with neither will hang\n" +
		"or fail, the same tradeoff jit run/export already accept.",
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if k8sCredProfile == "" {
			return fmt.Errorf("jit k8s-exec-credential: --profile is required")
		}

		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("jit k8s-exec-credential: %w", err)
		}
		p, err := profile.Load(home, k8sCredProfile)
		if err != nil {
			return fmt.Errorf("jit k8s-exec-credential: %w", err)
		}

		v, err := openVault()
		if err != nil {
			return fmt.Errorf("jit k8s-exec-credential: %w", err)
		}
		values, err := inject.Resolve(v, p)
		if err != nil {
			return fmt.Errorf("jit k8s-exec-credential: %w", err)
		}

		out, err := buildK8sExecCredentialOutput(values)
		if err != nil {
			return fmt.Errorf("jit k8s-exec-credential: profile %q: %w", k8sCredProfile, err)
		}
		data, err := json.Marshal(out)
		if err != nil {
			return fmt.Errorf("jit k8s-exec-credential: %w", err)
		}
		fmt.Fprintln(cmd.OutOrStdout(), string(data))
		return nil
	},
}

// buildK8sExecCredentialOutput validates values (a resolved profile's
// variable -> plaintext map) and builds the ExecCredential JSON shape,
// split out from RunE specifically so the protocol shape is testable
// without a real vault/Touch ID challenge (same reason
// run.go/export.go split resolveRunPlan out of their own RunE).
func buildK8sExecCredentialOutput(values map[string]string) (k8sExecCredentialOutput, error) {
	status := k8sExecCredentialStatus{
		Token:                 values["TOKEN"],
		ClientCertificateData: pemFromKubeconfigData(values["CLIENT_CERTIFICATE_DATA"]),
		ClientKeyData:         pemFromKubeconfigData(values["CLIENT_KEY_DATA"]),
	}
	if status.Token == "" && (status.ClientCertificateData == "" || status.ClientKeyData == "") {
		return k8sExecCredentialOutput{}, fmt.Errorf("has neither TOKEN nor a complete CLIENT_CERTIFICATE_DATA/CLIENT_KEY_DATA pair")
	}
	return k8sExecCredentialOutput{
		APIVersion: k8sExecCredentialAPIVersion,
		Kind:       "ExecCredential",
		Status:     status,
	}, nil
}

// pemFromKubeconfigData converts a kubeconfig-style client-certificate-data/
// client-key-data value into what an ExecCredential's clientCertificateData/
// clientKeyData actually requires. The two formats disagree: kubeconfig's
// *-data fields hold base64-encoded PEM, but client-go's ExecCredential
// protocol wants the PEM directly ("PEM-encoded client TLS certificate/key"),
// NOT base64 — feeding it the base64 makes kubectl fail with "tls: failed to
// find any PEM data in certificate input", which is exactly what happened to
// every cert-based kubeconfig (docker-desktop/minikube/kind/kubeadm) after
// migration until this decode was added. jit migrate stores the raw
// kubeconfig value verbatim in the vault, so the base64->PEM step has to
// happen here at emit time.
//
// Best-effort by design: a value that isn't valid standard base64 is assumed
// to already be PEM and passed through unchanged (PEM begins with "-----BEGIN",
// whose '-' isn't in the base64 alphabet, so DecodeString reliably rejects it)
// — that covers a hand-set vault entry as well as the base64 kubeconfig case,
// and never turns a usable value into an unusable one.
func pemFromKubeconfigData(v string) string {
	if v == "" {
		return ""
	}
	decoded, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return v
	}
	return string(decoded)
}

func init() {
	k8sExecCredentialCmd.Flags().StringVar(&k8sCredProfile, "profile", "", "vault profile to resolve (required, e.g. k8s-myuser)")
	_ = k8sExecCredentialCmd.RegisterFlagCompletionFunc("profile", completeProfileNames)
	rootCmd.AddCommand(k8sExecCredentialCmd)
}
