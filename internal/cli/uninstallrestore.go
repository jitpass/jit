// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jitpass/jit/internal/agent"
	"github.com/jitpass/jit/internal/audit"
	"github.com/jitpass/jit/internal/migrate"
	"github.com/jitpass/jit/internal/mount"
	"github.com/jitpass/jit/internal/profile"
	"github.com/jitpass/jit/internal/vault"
)

// `jit uninstall --restore`: put every file jit ever rewrote back, across
// the whole machine, before the purge deletes the only thing that can.
//
// `jit migrate undo` and `jit migrate remove` both need a path, and each is
// the wrong tool for half the job. Undo writes the whole file back as it was
// on migration day, which for a shell config or a kubeconfig silently drops
// everything added since. Remove is scoped to one project, asks for a
// fingerprint per project, and stops at the first error with the project
// half gone. This walks the mount registry and the backup index instead, and
// picks, per file, the reversal that loses nothing:
//
//	mount, pointer, MCP   current vault values (the existing write-backs)
//	shell config          jit's two lines become export lines again, in place
//	anything else         its pre-migration bytes; when the file changed
//	                      since, today's version is first kept beside it
//	history, AI caches    left cleaned: restoring migration day's history
//	                      deletes every command typed since, to put a
//	                      leaked token back
//
// Every restore runs, failures are collected, and a single failure means
// the caller deletes nothing.

type restoreKind string

const (
	restoreMount   restoreKind = "mount"
	restorePointer restoreKind = "pointer"
	restoreMCP     restoreKind = "mcp"
	restoreShell   restoreKind = "shell"
	restoreBackup  restoreKind = "backup"
	restoreCreated restoreKind = "created"
)

// driftGrace is how long after its backup a file's mtime still counts as
// migration's own write. The backup is taken immediately before the rewrite.
const driftGrace = time.Minute

// keptBesideSuffix names the copy of today's version left next to a file
// that changed since migration. That version holds none of the secrets jit
// moved (jit stripped them), so a sibling on disk exposes nothing new.
const keptBesideSuffix = ".before-jitpass-removal"

type restoreItem struct {
	Path string      `json:"path"`
	Kind restoreKind `json:"kind"`
	// Drifted: a backup restore over a file modified after migration.
	Drifted bool `json:"drifted,omitempty"`

	rec   migrate.BackupRecord
	entry mount.Entry
	mcp   map[string]string
}

type vaultOnlySecret struct {
	Path  string `json:"path"`
	Class string `json:"class,omitempty"`
}

type uninstallRestorePlan struct {
	Restore []restoreItem `json:"restore"`
	// KeptClean: shell history and AI-agent cache files, not un-cleaned.
	KeptClean []string `json:"kept_clean"`
	// Unwired: shell configs the user already took jit's line out of.
	Unwired []string `json:"unwired"`
	// Gone: migrated files that no longer exist (a deleted project, a config
	// the user removed). Not recreated: jit's footprint there is already
	// gone, and resurrecting a deleted file full of secrets is not "back".
	Gone []string `json:"gone"`
	// VaultOnly: secrets no restored file will hold. The purge loses them.
	VaultOnly []vaultOnlySecret `json:"vault_only"`
	// ProjectStores: every project .jit directory, deleted after the restore.
	ProjectStores []string `json:"project_stores"`
}

// mountBornClasses are the provenance classes whose migration turns the file
// into a live mount or a pointer file. A recorded file of one of these that
// is neither any more was already put back (`jit unmount`), by hand or by an
// earlier run, and must not be overwritten with migration day's bytes.
var mountBornClasses = map[string]bool{
	vault.ClassDotenv: true, vault.ClassNpmrc: true, vault.ClassPypirc: true,
	vault.ClassNetrc: true, vault.ClassGCP: true, vault.ClassSOPS: true,
	vault.ClassStreamlit: true, vault.ClassLooseFile: true, vault.ClassK8sSecret: true,
}

// buildUninstallRestorePlan reads the registry, the index and secret
// metadata only. rv needs no key: planning never costs a prompt.
func buildUninstallRestorePlan(root, home string, rv *vault.Vault) (uninstallRestorePlan, error) {
	plan := uninstallRestorePlan{
		Restore: []restoreItem{}, KeptClean: []string{}, Unwired: []string{},
		Gone: []string{}, VaultOnly: []vaultOnlySecret{}, ProjectStores: []string{},
	}

	entries, err := mount.LoadRegistry(mount.RegistryPath(root))
	if err != nil {
		return plan, fmt.Errorf("reading the mount registry: %w", err)
	}
	recs, err := migrate.LoadBackupRecords(root)
	if err != nil {
		return plan, err
	}

	// Birth-time provenance: which file each secret came from, and as what.
	originClass := map[string]string{}
	type secretMeta struct{ path, class, origin string }
	var secrets []secretMeta
	if rv != nil {
		paths, err := rv.List()
		if err != nil {
			return plan, fmt.Errorf("listing the vault: %w", err)
		}
		for _, p := range paths {
			if vault.IsBackupPath(p) {
				continue
			}
			info, err := rv.Info(p)
			if err != nil {
				return plan, fmt.Errorf("reading secret metadata for %s: %w", p, err)
			}
			origin := ""
			if info.Origin != "" {
				origin = expandTilde(info.Origin, home)
				originClass[origin] = info.Class
			}
			secrets = append(secrets, secretMeta{p, info.Class, origin})
		}
	}

	stores := map[string]bool{}
	noteStore := func(path string) {
		if projectRoot, ok := findProjectRoot(filepath.Dir(path)); ok && projectRoot != home {
			stores[filepath.Join(projectRoot, ".jit")] = true
		}
	}

	mounted := map[string]bool{}
	for _, e := range entries {
		mounted[e.MountPath] = true
		plan.Restore = append(plan.Restore, restoreItem{Path: e.MountPath, Kind: restoreMount, entry: e})
		noteStore(e.MountPath)
		noteStore(e.ProfilePath)
	}

	shellConfigs := map[string]bool{}
	for _, p := range migrate.ShellConfigPaths(home) {
		shellConfigs[p] = true
	}

	for _, rec := range migrate.LatestBackups(recs) {
		path := rec.OriginalPath
		noteStore(path)
		switch {
		case mounted[path]:
			// the registry entry above covers it
		case rec.RemoveOnRestore:
			if _, err := os.Lstat(path); err == nil {
				plan.Restore = append(plan.Restore, restoreItem{Path: path, Kind: restoreCreated, rec: rec})
			}
		case isGone(path):
			plan.Gone = append(plan.Gone, path)
		case audit.IsShellHistoryPath(path),
			audit.AgentLabelForPath(home, path) != "" && originClass[path] == "":
			// An agent's own credential file (~/.codex/auth.json, which
			// `jit wrap` scrubs) sits under the same roots as its caches;
			// a secret born from the path is what tells them apart.
			plan.KeptClean = append(plan.KeptClean, path)
		case shellConfigs[path]:
			if migrate.ShellConfigWired(path) {
				plan.Restore = append(plan.Restore, restoreItem{Path: path, Kind: restoreShell, rec: rec})
			} else {
				plan.Unwired = append(plan.Unwired, path)
			}
		case len(migrate.WrappedMCPProfiles(path)) > 0:
			owned := map[string]string{}
			for name := range migrate.WrappedMCPProfiles(path) {
				if pp, err := profile.Path(home, name); err == nil {
					if _, statErr := os.Stat(pp); statErr == nil {
						owned[name] = pp
					}
				}
			}
			plan.Restore = append(plan.Restore, restoreItem{Path: path, Kind: restoreMCP, rec: rec, mcp: owned})
		case migrate.IsPointerFile(path):
			// A project's pointer file regenerates as dotenv from current
			// values. A loose one (a bare token.txt) is not dotenv-shaped,
			// so it gets its own bytes back.
			kind := restoreBackup
			if projectRoot, ok := findProjectRoot(filepath.Dir(path)); ok && projectRoot != home {
				kind = restorePointer
			}
			plan.Restore = append(plan.Restore, restoreItem{Path: path, Kind: kind, rec: rec})
		case mountBornClasses[originClass[path]], migrate.IsEnvFileName(filepath.Base(path)):
			// already a plain file again
		default:
			item := restoreItem{Path: path, Kind: restoreBackup, rec: rec}
			if info, err := os.Stat(path); err == nil {
				item.Drifted = info.ModTime().After(time.Unix(rec.UnixTS, 0).Add(driftGrace))
			}
			plan.Restore = append(plan.Restore, item)
		}
	}

	// A secret comes back if a restored file is where it was born, or if a
	// profile a restore reads from names it. The second matters for every
	// secret older than birth-time provenance, which carries no origin.
	returned := map[string]bool{}
	referenced := map[string]bool{}
	noteProfile := func(profilePath string) {
		if refs, err := profile.LoadFile(profilePath); err == nil {
			for _, vaultPath := range refs {
				referenced[vaultPath] = true
			}
		}
	}
	for _, item := range plan.Restore {
		returned[item.Path] = true
		// Some migrators record the folder as the origin (tfvars, one
		// profile for a directory's files), not the file.
		returned[filepath.Dir(item.Path)] = true
		switch item.Kind {
		case restoreMount:
			noteProfile(item.entry.ProfilePath)
		case restoreMCP:
			for _, pp := range item.mcp {
				noteProfile(pp)
			}
		case restoreShell:
			if pp, err := profile.Path(home, migrate.ShellProfileName(item.Path)); err == nil {
				noteProfile(pp)
			}
		case restorePointer:
			if projectRoot, ok := findProjectRoot(filepath.Dir(item.Path)); ok {
				if names, err := profile.ListNames(projectRoot); err == nil {
					for _, name := range names {
						if pp, err := profile.Path(projectRoot, name); err == nil {
							noteProfile(pp)
						}
					}
				}
			}
		}
	}
	for _, s := range secrets {
		// A 1Password link holds a reference; the value lives there.
		if s.class == vault.ClassOnePassword || referenced[s.path] || (s.origin != "" && returned[s.origin]) {
			continue
		}
		plan.VaultOnly = append(plan.VaultOnly, vaultOnlySecret{Path: s.path, Class: s.class})
	}

	for dir := range stores {
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			plan.ProjectStores = append(plan.ProjectStores, dir)
		}
	}
	sort.Strings(plan.ProjectStores)
	sort.Strings(plan.KeptClean)
	sort.Strings(plan.Unwired)
	sort.Slice(plan.Restore, func(i, j int) bool { return plan.Restore[i].Path < plan.Restore[j].Path })
	return plan, nil
}

// restoreFailure is one file that could not be put back.
type restoreFailure struct {
	Path string `json:"path"`
	Err  string `json:"error"`
}

// restoreResult is what runUninstallRestore did.
type restoreResult struct {
	Restored   []string
	KeptBeside []string
	Failures   []restoreFailure
}

// runUninstallRestore applies plan.Restore with an authenticated vault. It
// never stops early: the caller needs the complete list of what failed, and
// a file already restored is simply a plain file, which is what it was.
// onFile hears each outcome as it happens (err nil = put back).
func runUninstallRestore(v *vault.Vault, root, home string, plan uninstallRestorePlan, onFile func(item restoreItem, err error)) restoreResult {
	var res restoreResult
	registryPath := mount.RegistryPath(root)
	agentClient := agent.NewClient(agent.SocketPath(root))
	agentUp := agentClient.Reachable()

	for _, item := range plan.Restore {
		keptBeside, err := restoreOneItem(v, home, item, registryPath, agentClient, agentUp)
		if keptBeside != "" {
			res.KeptBeside = append(res.KeptBeside, keptBeside)
		}
		if err != nil {
			res.Failures = append(res.Failures, restoreFailure{Path: item.Path, Err: err.Error()})
		} else {
			res.Restored = append(res.Restored, item.Path)
		}
		if onFile != nil {
			onFile(item, err)
		}
	}
	return res
}

func restoreOneItem(v *vault.Vault, home string, item restoreItem, registryPath string, agentClient *agent.Client, agentUp bool) (keptBeside string, err error) {
	switch item.Kind {
	case restoreMount:
		e := item.entry
		// The agent's Serve goroutine must have stopped before anything
		// replaces the FIFO (the ordering `jit unmount` keeps).
		if agentUp {
			if err := agentClient.StopMount(e.MountPath); err != nil {
				return "", fmt.Errorf("stopping the running service's mount: %w", err)
			}
		}
		if _, err := migrate.UnmountFile(v, e.ProfilePath, e.MountPath, e.TemplatePath); err != nil {
			return "", err
		}
		if _, err := mount.RemoveMount(registryPath, e.MountPath); err != nil {
			return "", err
		}
		removeIfPresent(migrate.PointerFilePath(e.MountPath))
		return "", nil

	case restorePointer:
		_, err := migrate.RestorePointerFile(v, item.Path)
		removeIfPresent(migrate.PointerFilePath(item.Path))
		return "", err

	case restoreMCP:
		_, err := migrate.UnwrapMCPConfig(v, item.Path, item.mcp)
		return "", err

	case restoreShell:
		_, err := migrate.RestoreShellConfig(v, item.Path)
		return "", err

	case restoreCreated:
		return "", migrate.RestoreFromBackup(v, item.rec)

	default:
		if err := checkRestoreDestination(item.Path); err != nil {
			return "", err
		}
		same, err := backupMatchesDisk(v, item.rec)
		if err != nil {
			return "", fmt.Errorf("reading its backup: %w", err)
		}
		if same {
			return "", nil
		}
		if item.Drifted {
			keptBeside = item.Path + keptBesideSuffix
			if err := copyFileKeepingMode(item.Path, keptBeside); err != nil {
				return "", fmt.Errorf("keeping today's version beside it: %w", err)
			}
		}
		if err := migrate.RestoreFromBackup(v, item.rec); err != nil {
			return keptBeside, err
		}
		removeIfPresent(migrate.PointerFilePath(item.Path))
		return keptBeside, nil
	}
}

// checkRestoreDestination refuses the two destinations a whole-file restore
// must never write to. RestoreFromBackup unlinks whatever sits at the path,
// so a symlink there (a dotfiles link) would be replaced by a regular file
// and its target's content captured nowhere. And it MkdirAll's a missing
// parent, which under an unmounted volume's mountpoint writes the secret
// onto the boot disk, to be shadowed when the volume returns.
// isGone reports a recorded file that no longer exists, other than one on a
// volume that is merely not connected: that file may well still be there, as
// a pointer or a dead mount, so it stays in the plan and fails loudly.
func isGone(path string) bool {
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		return false
	}
	return !onUnmountedVolume(path)
}

func onUnmountedVolume(path string) bool {
	rest, ok := strings.CutPrefix(path, "/Volumes/")
	if !ok {
		return false
	}
	name, _, _ := strings.Cut(rest, "/")
	_, err := os.Stat(filepath.Join("/Volumes", name))
	return os.IsNotExist(err)
}

func checkRestoreDestination(path string) error {
	if onUnmountedVolume(path) {
		return errors.New("its volume is not connected")
	}
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return errors.New("a symlink sits at this path now; jit will not replace it")
	}
	if _, err := os.Stat(filepath.Dir(path)); err != nil {
		return fmt.Errorf("its folder is not there (an unmounted volume?): %w", err)
	}
	return nil
}

func copyFileKeepingMode(src, dst string) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	in, err := os.Open(src) // #nosec G304 -- src is a path from jit's own backup index
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, info.Mode().Perm()) // #nosec G304 G302 -- src's sibling, at src's own mode
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

func removeIfPresent(path string) {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return // cosmetic: a stale companion never fails a restore
	}
}

// removeProjectStores deletes each project's .jit directory. Only ever after
// every file is back: the profiles and templates in them are what the
// write-backs read.
func removeProjectStores(dirs []string) (removed []string, err error) {
	var errs []error
	for _, dir := range dirs {
		if filepath.Base(dir) != ".jit" {
			continue
		}
		if rmErr := os.RemoveAll(dir); rmErr != nil {
			errs = append(errs, rmErr)
			continue
		}
		removed = append(removed, dir)
	}
	return removed, errors.Join(errs...)
}

// restoreKindPhrase is how the text plan describes each kind.
func restoreKindPhrase(k restoreKind) string {
	switch k {
	case restoreMount:
		return "live mount, current values"
	case restorePointer:
		return "pointer file, current values"
	case restoreMCP:
		return "MCP config, current values"
	case restoreShell:
		return "shell config, jit's line becomes exports again"
	case restoreCreated:
		return "created by jit, deleted"
	default:
		return "its content from before jit"
	}
}

func classCounts(secrets []vaultOnlySecret) string {
	counts := map[string]int{}
	for _, s := range secrets {
		c := s.Class
		if c == "" {
			c = "unlabelled"
		}
		counts[c]++
	}
	parts := make([]string, 0, len(counts))
	for c, n := range counts {
		parts = append(parts, fmt.Sprintf("%d %s", n, c))
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}
