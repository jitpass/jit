// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"os"
	"path/filepath"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/migrate"
)

// The gcloud family's run command (design/gcloud-sealed-store.md): the five
// gcloud-family shims exec this, and runStoreRun does the work.

var gcloudRunReal string

var gcloudRunCmd = &cobra.Command{
	Use:     "gcloud-run --real <path> -- [args]",
	GroupID: groupPlumbing,
	// Hidden from tab-completion only, like clisso-capture: the shim is its
	// one caller, but the root help and generated docs still list it.
	Hidden:      true,
	Annotations: map[string]string{helpVisibleAnnotation: "1"},
	Short:       "Run a Google Cloud CLI with its login unsealed for that one run",
	Long: "Not typically run by hand: the shims `jit wrap gcloud` installs (gcloud, bq,\n" +
		"gsutil, docker-credential-gcloud, git-credential-gcloud) exec this around\n" +
		"every invocation. gcloud's login store lives in the vault; this unpacks it\n" +
		"into a private folder for the one run, points the tool at it with\n" +
		"CLOUDSDK_CONFIG, and seals it again afterwards if the run changed it (a\n" +
		"login, an activate, a revoke). Your settings stay in ~/.config/gcloud.\n" +
		"The tool's exit status is passed through unchanged.",
	Args: cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runStoreRunCommand(cmd, migrate.GcloudStore, gcloudRunReal, args)
	},
}

func init() {
	gcloudRunCmd.Flags().StringVar(&gcloudRunReal, "real", "", "absolute path to the real tool (supplied by the shim)")
	rootCmd.AddCommand(gcloudRunCmd)
}

// isADCCommand reports whether a gcloud command line is `auth
// application-default …`, wherever global flags put it.
func isADCCommand(args []string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "--" {
			return false
		}
		if args[i] == "auth" && args[i+1] == "application-default" {
			return true
		}
	}
	return false
}

// execADCGrant runs an ADC command the way the grant-wrap did: inside
// `jit run --with gcp` when the ADC file is migrated, plain otherwise.
func execADCGrant(real string, args []string, tool string) error {
	if _, err := withMountPaths([]string{"gcp"}); err != nil {
		return execRealTool(migrate.GcloudStore, real, args, tool)
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	self, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return err
	}
	argv := append([]string{"jit", "run", "--with", "gcp", "--", real}, args...)
	return syscall.Exec(self, argv, storeChildEnv(migrate.GcloudStore, os.Environ(), tool, os.Getenv("CLOUDSDK_CONFIG"))) // #nosec G204 -- self is this binary; real and args as above
}
