// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"path/filepath"

	"github.com/jitpass/jit/internal/sealstore"
	"github.com/jitpass/jit/internal/vault"
)

// GcloudStorePath is where the gcloud CLI's own login store lives in the
// vault: one canonical tar of credentials.db and legacy_credentials/
// (sealstore.Gcloud), class gcp, so one unseal is one consent prompt naming
// the credential the user knows from ADC (design/gcloud-sealed-store.md D2).
const GcloudStorePath = "gcloud-cli/store"

// GcloudStore is gcloud's login store. Its refresh token does not rotate,
// so the store changes only at a login, an activate or a revoke: a run's
// store replaces the vault's, with a fresh backup each time (D10).
var GcloudStore = ToolStore{
	Name:       "gcloud",
	Tool:       "gcloud",
	Label:      "gcloud's login",
	VaultPath:  GcloudStorePath,
	Class:      vault.ClassGCP,
	Layout:     sealstore.Gcloud,
	ConfigDir:  GcloudConfigDir,
	ConfigEnv:  "CLOUDSDK_CONFIG",
	Provenance: "credentials.db",
	DirMode:    0o755, // gcloud's own mode for its config dir; the store files inside are 0600
	// gcloud logs every command, output included, under the settings dir
	// the run links to: `gcloud auth print-access-token` left its token in
	// ~/.config/gcloud/logs for 30 days (release QA). File logging is off
	// for a wrapped run; --verbosity still prints to the terminal.
	RunEnv: []string{"CLOUDSDK_CORE_DISABLE_FILE_LOGGING=true"},
}

// GcloudConfigDir is the gcloud config dir jit seals: the default one.
// A CLOUDSDK_CONFIG pointing elsewhere is the user's own arrangement and is
// left alone (D7).
func GcloudConfigDir(home string) string {
	return filepath.Join(home, ".config", "gcloud")
}
