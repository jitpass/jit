// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/migrate"
)

// The Azure CLI's run command (design/azure-sealed-store.md): the shim
// `jit wrap az` installs execs this, and runStoreRun does the work.

var azRunReal string

var azRunCmd = &cobra.Command{
	Use:     "az-run --real <path> -- [args]",
	GroupID: groupPlumbing,
	// Hidden from tab-completion only, like gcloud-run: the shim is its one
	// caller, but the root help and generated docs still list it.
	Hidden:      true,
	Annotations: map[string]string{helpVisibleAnnotation: "1"},
	Short:       "Run the Azure CLI with its login unsealed for that one run",
	Long: "Not typically run by hand: the shim `jit wrap az` installs execs this around\n" +
		"every az invocation. The Azure CLI's login (its token cache and service\n" +
		"principal secrets) lives in the vault; this unpacks it into a private\n" +
		"folder for the one run, points az at it with AZURE_CONFIG_DIR, and seals it\n" +
		"again afterwards if the run changed it (a refresh, a login, a logout),\n" +
		"merged with any change another az run sealed meanwhile. Your settings stay\n" +
		"in ~/.azure. The tool's exit status is passed through unchanged.",
	Args: cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runStoreRunCommand(cmd, migrate.AzureStore, azRunReal, args)
	},
}

func init() {
	azRunCmd.Flags().StringVar(&azRunReal, "real", "", "absolute path to the real tool (supplied by the shim)")
	rootCmd.AddCommand(azRunCmd)
}
