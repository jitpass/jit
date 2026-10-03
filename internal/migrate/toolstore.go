// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/jitpass/jit/internal/atomicfile"
	"github.com/jitpass/jit/internal/sealstore"
	"github.com/jitpass/jit/internal/vault"
)

// ToolStore is a CLI's own login store that a store-wrap seals whole
// (wrap.KindStore): the files in its config dir that hold the login, packed
// into one vault value and unpacked into a private dir for each run of the
// tool (design/gcloud-sealed-store.md, design/azure-sealed-store.md). One
// entry per store; whatever seals, unseals, counts or sweeps a store reads
// it from ToolStores.
type ToolStore struct {
	// Name is the store's name in the wrap catalog (wrap.CatalogEntry.Store):
	// its shims run `jit <Name>-run`, and `jit wrap <Name>` seals it.
	Name string
	// Tool names the CLI in messages ("gcloud", "Azure CLI"), and Label its
	// login ("gcloud's login").
	Tool      string
	Label     string
	VaultPath string
	Class     string
	Layout    sealstore.Layout
	// ConfigDir is the config dir jit seals, the tool's default. ConfigEnv
	// is the variable that moves it: a run points it at the run dir, and a
	// user's own setting elsewhere is left alone.
	ConfigDir func(home string) string
	ConfigEnv string
	// Provenance is the file the vault records as the login's origin,
	// relative to ConfigDir.
	Provenance string
	// DirMode is the config dir's mode when unsealing has to create it.
	DirMode fs.FileMode
	// Rotates says the store changes in routine use, not only at a login:
	// its refresh token rotates on every refresh. A reseal of it is then
	// silent unless a login comes or goes, and records no backup (they
	// would pile up hourly). A store that changes only at a login (gcloud's)
	// gets a fresh backup at every reseal instead.
	Rotates bool
	// Merge folds the changes a run made since base into current, the
	// vault's copy when another run sealed in between. nil means the run's
	// store replaces it.
	Merge func(base, current, after []byte) ([]byte, error)
	// Accounts names the accounts a store is signed in to, sorted, so a
	// reseal can tell a routine refresh from a login or a sign-out.
	Accounts func(blob []byte) []string
}

// ToolStores lists every sealed tool store.
func ToolStores() []ToolStore { return []ToolStore{GcloudStore, AzureStore} }

// ToolStoreNamed returns the store a catalog entry names.
func ToolStoreNamed(name string) (ToolStore, bool) {
	for _, s := range ToolStores() {
		if s.Name == name {
			return s, true
		}
	}
	return ToolStore{}, false
}

// StoreVaultPath maps a store's name (wrap.Entry.Store, or "aws-sso") to
// the vault path its sealed store lives at. One table, so everything that
// asks "what does this wrap use" agrees.
func StoreVaultPath(store string) (string, bool) {
	if s, ok := ToolStoreNamed(store); ok {
		return s.VaultPath, true
	}
	if store == "aws-sso" {
		return AWSSSOStorePath, true
	}
	return "", false
}

// SealedStoreName is StoreVaultPath's inverse: the store a vault path holds
// ("gcloud", "az", "aws-sso"), the same name a store's vault users carry.
func SealedStoreName(path string) (string, bool) {
	for _, s := range ToolStores() {
		if s.VaultPath == path {
			return s.Name, true
		}
	}
	if path == AWSSSOStorePath {
		return "aws-sso", true
	}
	return "", false
}

// SealedStoreOwner names the command that takes a sealed store out of the
// vault, for a refusal to say what to run instead.
func SealedStoreOwner(name string) string {
	if name == "aws-sso" {
		return "`jit aws-sso logout` signs out; `jit migrate undo ~/.aws/config` puts the login back"
	}
	return "`jit wrap undo " + name + "` puts the login back"
}

// StoreSealResult says what Seal did.
type StoreSealResult struct {
	// Files are the plaintext files moved into the vault (backed up first).
	Files []string
	// LoggedOut is true when the dir held no login: the vault holds an
	// empty store, so the next login through the wrap is captured straight
	// into it (D5).
	LoggedOut bool
	// AlreadySealed is true when there was nothing in plaintext to move and
	// the vault already held a store.
	AlreadySealed bool
}

// Seal moves the store out of its config dir into the vault. Order
// matters: every plaintext file is backed up (linked, so undo brings them
// back together), then the store is vaulted, and only then are the files
// removed — a failure before the removal leaves the user exactly where
// they were. Ephemeral entries are deleted, never vaulted (gcloud D3).
//
// Plaintext on disk wins over an existing vaulted store: if the tool logged
// in without the wrap, that newer login is what the user is using.
func (s ToolStore) Seal(v *vault.Vault, home string) (StoreSealResult, error) {
	dir := s.ConfigDir(home)
	var res StoreSealResult
	files, err := s.files(dir)
	if err != nil {
		return res, err
	}
	sealed, err := v.Exists(s.VaultPath)
	if err != nil {
		return res, err
	}
	if len(files) == 0 && sealed {
		res.AlreadySealed = true
		return res, s.Layout.Remove(dir)
	}
	blob, err := s.Layout.Pack(dir)
	if err != nil {
		return res, fmt.Errorf("reading %s store: %w", s.Label, err)
	}
	if sealed && s.Merge != nil {
		// A login made without the shim, beside accounts only the vault
		// holds: keep both, the plaintext's entries winning.
		current, err := v.Get(s.VaultPath)
		if err != nil {
			return res, err
		}
		if blob, err = s.Merge(nil, current, blob); err != nil {
			return res, err
		}
	}
	for _, f := range files {
		data, err := os.ReadFile(f) // #nosec G304 -- f is under the tool's config dir, from s.files
		if err != nil {
			return res, err
		}
		if _, err := storeSecretBackup(v, f, data, backupFlags{restoreWith: restorePartners(files, f)}); err != nil {
			return res, err
		}
	}
	if err := s.store(v, home, blob); err != nil {
		return res, err
	}
	if err := s.Layout.Remove(dir); err != nil {
		return res, fmt.Errorf("removing the plaintext store from %s (it is vaulted and backed up; delete it by hand): %w", dir, err)
	}
	res.Files = files
	res.LoggedOut = sealstore.Empty(blob)
	return res, nil
}

// ReadSealed returns the sealed store, empty when nothing is sealed yet,
// and the wrapped data key it was read under: Reseal compares it to tell
// whether another run sealed in between, without decrypting anything.
func (s ToolStore) ReadSealed(v *vault.Vault) (blob, dek []byte, err error) {
	sealed, err := v.Exists(s.VaultPath)
	if err != nil || !sealed {
		return nil, nil, err
	}
	// The key first: a write landing between the two reads then makes the
	// reseal merge needlessly, never miss a change.
	if dek, _, err = v.WrappedDEK(s.VaultPath); err != nil {
		return nil, nil, err
	}
	if blob, err = v.Get(s.VaultPath); err != nil {
		return nil, nil, err
	}
	return blob, dek, nil
}

// Reseal vaults the store a run changed (a login, a refresh, a sign-out:
// D4). base is the store as the run started from it, read under dek
// (ReadSealed); after is what the run left. When another run sealed in
// between and the store can merge, the run's own changes are laid over
// that newer copy rather than replacing it, so a long run's refresh cannot
// drop a login made meanwhile. Under a lock, so two reseals do not
// interleave. Returns what was sealed.
//
// Unless the store Rotates, fresh backups of it are recorded under the
// original paths, so a restore of the backups puts back the latest login
// rather than the one from the day of the wrap (D10). runDir is the run's
// private dir, which still holds the new files.
func (s ToolStore) Reseal(v *vault.Vault, home, runDir string, base, dek, after []byte) ([]byte, error) {
	unlock, err := s.lock(v.Root)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if s.Merge != nil {
		if now, _, err := v.WrappedDEK(s.VaultPath); err == nil && !bytes.Equal(now, dek) {
			current, err := v.Get(s.VaultPath)
			if err != nil {
				return nil, err
			}
			if after, err = s.Merge(base, current, after); err != nil {
				return nil, err
			}
		}
	}
	if err := s.store(v, home, after); err != nil {
		return nil, err
	}
	if s.Rotates {
		return after, nil
	}
	if err := s.backupRun(v, home, runDir); err != nil {
		return after, fmt.Errorf("%w: %v", ErrResealBackup, err)
	}
	return after, nil
}

// ErrResealBackup says a reseal stored the login but could not record its
// backup: the login is sealed, only undo would hand back an older copy.
var ErrResealBackup = errors.New("sealed, but its backup was not recorded")

// backupRun records fresh backups of the store a run left, under the
// original paths.
func (s ToolStore) backupRun(v *vault.Vault, home, runDir string) error {
	files, err := s.files(runDir)
	if err != nil || len(files) == 0 {
		return err
	}
	dir := s.ConfigDir(home)
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

// lock takes the store's reseal lock, blocking until it is free: a hidden
// file beside the run dirs (the vault's own .<name>.lock convention), so
// the run base holds nothing but runs.
func (s ToolStore) lock(root string) (func(), error) {
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(root, "."+s.Name+"-run.lock"), os.O_CREATE|os.O_RDWR, 0o600) // #nosec G304 -- jit's own lock file under its root
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil { // #nosec G115 -- a file descriptor fits in int
		_ = f.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) // #nosec G115 -- as above
		_ = f.Close()
	}, nil
}

// Unseal writes the vaulted store back into the config dir in plaintext:
// `jit wrap undo` and `jit uninstall --restore`. The caller has already
// taken a fresh Touch ID, as for every plaintext-restoring action. It
// refuses to write over a plaintext store already there, and keeps the
// vault copy.
func (s ToolStore) Unseal(v *vault.Vault, home string) ([]string, error) {
	dir := s.ConfigDir(home)
	blob, err := v.Get(s.VaultPath)
	if err != nil {
		return nil, err
	}
	if present, err := s.files(dir); err != nil {
		return nil, err
	} else if len(present) > 0 {
		return nil, fmt.Errorf("%s already holds a plaintext login store; not writing over it", dir)
	}
	if err := os.MkdirAll(dir, s.DirMode); err != nil {
		return nil, err
	}
	if err := s.Layout.Unpack(blob, dir); err != nil {
		return nil, err
	}
	return s.files(dir)
}

// RestoreCurrent writes the vault's current store over the config dir's
// secret files: after `jit migrate undo` put back the seal-day copies, for
// a store that Rotates (its seal-day refresh token was long since rotated
// away; AWS SSO D10's reasoning). Returns the files written.
func (s ToolStore) RestoreCurrent(v *vault.Vault, home string) ([]string, error) {
	blob, err := v.Get(s.VaultPath)
	if err != nil {
		return nil, err
	}
	files, err := sealstore.Files(blob)
	if err != nil {
		return nil, err
	}
	dir := s.ConfigDir(home)
	if err := os.MkdirAll(dir, s.DirMode); err != nil {
		return nil, err
	}
	var written []string
	for name, data := range files {
		if !s.Layout.IsSecretFile(name) {
			continue
		}
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := atomicfile.WriteFileMode(p, data, 0o600); err != nil {
			return written, err
		}
		written = append(written, p)
	}
	sort.Strings(written)
	return written, nil
}

// IsStoreFile reports whether path is one of the files sealing moves into
// the vault: a secret entry of the config dir, or a file under one.
func (s ToolStore) IsStoreFile(home, path string) bool {
	dir := s.ConfigDir(home)
	for _, name := range s.Layout.Secrets {
		root := filepath.Join(dir, name)
		if path == root || strings.HasPrefix(path, root+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// ToolStoreForFile returns the store path is a file of.
func ToolStoreForFile(home, path string) (ToolStore, bool) {
	for _, s := range ToolStores() {
		if s.IsStoreFile(home, path) {
			return s, true
		}
	}
	return ToolStore{}, false
}

// Sealed reports whether the vault holds the store.
func (s ToolStore) Sealed(v *vault.Vault) (bool, error) {
	return v.Exists(s.VaultPath)
}

func (s ToolStore) store(v *vault.Vault, home string, blob []byte) error {
	meta, err := newProvenance(s.Class, filepath.Join(s.ConfigDir(home), s.Provenance))
	if err != nil {
		return err
	}
	if err := v.SetWithMeta(s.VaultPath, blob, meta); err != nil {
		return fmt.Errorf("storing %s in the vault: %w", s.Label, err)
	}
	// A login's previous versions are logins the tool has since refreshed
	// away or signed out of: kept, a `jit vault restore` would hand a
	// signed-out refresh token back. Undo works from backups and the
	// current copy, never from history.
	if err := v.ForgetHistory(s.VaultPath); err != nil {
		return err
	}
	if sealstore.Empty(blob) {
		// Signed out: the seal-day backups hold the login too, and an undo
		// would write it back to disk (release QA: a signed-out `aws login`
		// came back live). They go with the sign-out.
		return dropLoginBackups(v, func(p string) bool { return s.IsStoreFile(home, p) })
	}
	return nil
}

// dropLoginBackups deletes every recorded backup of a file a sealed login is
// made of, from the vault and the undo index: what a sign-out must take
// with it so no undo can resurrect the login.
func dropLoginBackups(v *vault.Vault, isLoginFile func(string) bool) error {
	recs, err := LoadBackupRecords(v.Root)
	if err != nil {
		return err
	}
	var drop []BackupRecord
	for _, r := range recs {
		if r.VaultPath != "" && isLoginFile(r.OriginalPath) {
			drop = append(drop, r)
		}
	}
	for _, r := range drop {
		if err := v.Remove(r.VaultPath); err != nil && !errors.Is(err, vault.ErrNotFound) {
			return err
		}
	}
	return DropBackupRecords(v.Root, drop)
}

// files lists the regular files of dir's secret set, sorted.
func (s ToolStore) files(dir string) ([]string, error) {
	var files []string
	for _, name := range s.Layout.Secrets {
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
