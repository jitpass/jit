// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jitpass/jit/internal/sealstore"
	"github.com/jitpass/jit/internal/vault"
)

// GcloudStorePath is where the gcloud CLI's own login store lives in the
// vault: one canonical tar of credentials.db and legacy_credentials/
// (sealstore.Gcloud), class gcp, so one unseal is one consent prompt naming
// the credential the user knows from ADC (design/gcloud-sealed-store.md D2).
const GcloudStorePath = "gcloud-cli/store"

// StoreVaultPath maps a store-wrap's store name (wrap.Entry.Store) to the
// vault path its sealed store lives at. One table, so everything that asks
// "what does this wrap use" agrees.
func StoreVaultPath(store string) (string, bool) {
	switch store {
	case "gcloud":
		return GcloudStorePath, true
	case "aws-sso":
		return AWSSSOStorePath, true
	}
	return "", false
}

// GcloudConfigDir is the gcloud config dir jit seals: the default one.
// A CLOUDSDK_CONFIG pointing elsewhere is the user's own arrangement and is
// left alone (D7).
func GcloudConfigDir(home string) string {
	return filepath.Join(home, ".config", "gcloud")
}

// GcloudSealResult says what SealGcloudStore did.
type GcloudSealResult struct {
	// Files are the plaintext files moved into the vault (backed up first).
	Files []string
	// LoggedOut is true when the dir held no login: the vault holds an
	// empty store, so the next `gcloud auth login` through the wrap is
	// captured straight into it (D5).
	LoggedOut bool
	// AlreadySealed is true when there was nothing in plaintext to move and
	// the vault already held a store.
	AlreadySealed bool
}

// SealGcloudStore moves gcloud's login store out of its config dir into the
// vault. Order matters: every plaintext file is backed up (linked, so undo
// brings them back together), then the store is vaulted, and only then are
// the files removed — a failure before the removal leaves the user exactly
// where they were. The access-token cache is deleted, never vaulted (D3).
//
// Plaintext on disk wins over an existing vaulted store: if gcloud logged in
// without the wrap, that newer login is what the user is using.
func SealGcloudStore(v *vault.Vault, home string) (GcloudSealResult, error) {
	dir := GcloudConfigDir(home)
	var res GcloudSealResult
	files, err := gcloudStoreFiles(dir)
	if err != nil {
		return res, err
	}
	sealed, err := v.Exists(GcloudStorePath)
	if err != nil {
		return res, err
	}
	if len(files) == 0 && sealed {
		res.AlreadySealed = true
		return res, sealstore.Gcloud.Remove(dir)
	}
	blob, err := sealstore.Gcloud.Pack(dir)
	if err != nil {
		return res, fmt.Errorf("reading gcloud's login store: %w", err)
	}
	for _, f := range files {
		data, err := os.ReadFile(f) // #nosec G304 -- f is under the gcloud config dir, from gcloudStoreFiles
		if err != nil {
			return res, err
		}
		if _, err := storeSecretBackup(v, f, data, backupFlags{restoreWith: restorePartners(files, f)}); err != nil {
			return res, err
		}
	}
	if err := storeGcloudBlob(v, home, blob); err != nil {
		return res, err
	}
	if err := sealstore.Gcloud.Remove(dir); err != nil {
		return res, fmt.Errorf("removing the plaintext store from %s (it is vaulted and backed up; delete it by hand): %w", dir, err)
	}
	res.Files = files
	res.LoggedOut = sealstore.Empty(blob)
	return res, nil
}

// ResealGcloudStore vaults the store a run changed (a login, an activate, a
// revoke: D4), and records fresh backups of it under the original paths, so
// `jit migrate undo` and `jit uninstall --restore` put back the latest login
// rather than the one from the day of the wrap (D10). runDir is the run's
// private dir, which still holds the new files.
func ResealGcloudStore(v *vault.Vault, home, runDir string, blob []byte) error {
	if err := storeGcloudBlob(v, home, blob); err != nil {
		return err
	}
	files, err := gcloudStoreFiles(runDir)
	if err != nil || len(files) == 0 {
		return err
	}
	dir := GcloudConfigDir(home)
	var originals []string
	for _, f := range files {
		rel, err := filepath.Rel(runDir, f)
		if err != nil {
			return err
		}
		originals = append(originals, filepath.Join(dir, rel))
	}
	for i, f := range files {
		data, err := os.ReadFile(f) // #nosec G304 -- f is under the run's own private dir
		if err != nil {
			return err
		}
		if _, err := storeSecretBackup(v, originals[i], data, backupFlags{restoreWith: restorePartners(originals, originals[i])}); err != nil {
			return err
		}
	}
	return nil
}

// UnsealGcloudStore writes the vaulted store back into gcloud's config dir
// in plaintext — `jit wrap undo gcloud`. The caller has already taken a
// fresh Touch ID, as for every plaintext-restoring action. It refuses to
// write over a plaintext store already there, and keeps the vault copy.
func UnsealGcloudStore(v *vault.Vault, home string) ([]string, error) {
	dir := GcloudConfigDir(home)
	blob, err := v.Get(GcloudStorePath)
	if err != nil {
		return nil, err
	}
	if present, err := gcloudStoreFiles(dir); err != nil {
		return nil, err
	} else if len(present) > 0 {
		return nil, fmt.Errorf("%s already holds a plaintext login store; not writing over it", dir)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil { // #nosec G301 -- gcloud's own mode for its config dir; the store files inside are 0600
		return nil, err
	}
	if err := sealstore.Gcloud.Unpack(blob, dir); err != nil {
		return nil, err
	}
	return gcloudStoreFiles(dir)
}

// IsGcloudStoreFile reports whether path is one of the files sealing moves
// into the vault: credentials.db, or anything under legacy_credentials/.
func IsGcloudStoreFile(home, path string) bool {
	dir := GcloudConfigDir(home)
	return path == filepath.Join(dir, "credentials.db") ||
		strings.HasPrefix(path, filepath.Join(dir, "legacy_credentials")+string(filepath.Separator))
}

// GcloudStoreSealed reports whether the vault holds gcloud's login store.
func GcloudStoreSealed(v *vault.Vault) (bool, error) {
	return v.Exists(GcloudStorePath)
}

func storeGcloudBlob(v *vault.Vault, home string, blob []byte) error {
	meta, err := newProvenance(vault.ClassGCP, filepath.Join(GcloudConfigDir(home), "credentials.db"))
	if err != nil {
		return err
	}
	if err := v.SetWithMeta(GcloudStorePath, blob, meta); err != nil {
		return fmt.Errorf("storing gcloud's login in the vault: %w", err)
	}
	return nil
}

// gcloudStoreFiles lists the regular files of dir's secret set, sorted.
func gcloudStoreFiles(dir string) ([]string, error) {
	var files []string
	for _, name := range sealstore.Gcloud.Secrets {
		root := filepath.Join(dir, name)
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.Type().IsRegular() {
				files = append(files, p)
			}
			return nil
		})
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
	}
	sort.Strings(files)
	return files, nil
}

// restorePartners is list without self: a file's RestoreWith partners.
func restorePartners(list []string, self string) []string {
	var out []string
	for _, x := range list {
		if x != self {
			out = append(out, x)
		}
	}
	return out
}
