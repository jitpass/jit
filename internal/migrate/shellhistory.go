// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/jitpass/jit/internal/audit"
	"github.com/jitpass/jit/internal/profile"
	"github.com/jitpass/jit/internal/vault"
)

// Shell history redaction: the fix half of audit's shell-history scanner
// (internal/audit/shellhistory.go — read the two together). A history file is
// unlike every other migrate target in that nothing READS it back for a
// credential: there is no mount to serve, no helper protocol to interpose, and
// the file must keep working as the shell's own record. So the fix is not
// relocation but surgery — each credential span is vaulted, then spliced out
// of the file in place, replaced by an inert "<jit:redacted:VAR>" marker that
// names the vault variable holding the original value.
//
// Splice, never re-serialize. zsh metafies bytes >= 0x83, fish wraps commands
// in YAML-ish escaping, bash interleaves "#<epoch>" stanzas — and a rewrite
// that parsed and re-emitted any of those formats would have to prove it
// round-trips every one of them byte-for-byte. Replacing only the matched
// spans (which are plain ASCII by construction — every vendor pattern matches
// [A-Za-z0-9_.+/=-] classes only) and copying every other byte untouched makes
// the fidelity question not arise. audit.HistoryLineTokens does the format
// parsing and hands back spans addressed into the raw line.
//
// What this deliberately does NOT fix, and the CLI says so out loud: the
// credential was typed at a prompt and recorded on disk, so rotation at the
// provider is the durable fix — redaction clears the recorded copy so it stops
// being findable, greppable, and backupable from here on. And a running shell
// holds its history in MEMORY and (in zsh's default setup) rewrites the file
// on exit, so a redacted line can come back until open shells reload
// (`fc -R`) or close. That resurrection risk is why the redaction marker
// carries the vault variable name: a re-run after the shells settle re-redacts
// the resurrected copies into the SAME variables, idempotently.
type ShellHistoryMigration struct {
	Path        string
	ProfileName string
	ProfilePath string
	// Variables holds one vault variable per DISTINCT credential value, in
	// first-appearance order. Occurrences counts every span redacted — the
	// same token pasted five times is five occurrences, one variable.
	Variables   []string
	Occurrences int
	BackupPath  string
}

// maxHistoryRedactSize mirrors audit's maxHistoryScanSize: a sanity bound far
// above any plausible history, so a pathological file cannot pin the run —
// and crossing it is an error the caller reports, never a silent skip.
const maxHistoryRedactSize = 256 << 20

// historyRedactedPrefix/Suffix frame the marker left where a credential was.
// The variable name sits between them, so the marker itself documents the
// recovery path (`jit vault get <profile>/<VAR>`). The shape must never
// re-detect as a credential — audit's tests hold a marker sample against
// every vendor pattern.
const (
	historyRedactedPrefix = "<jit:redacted:"
	historyRedactedSuffix = ">"
)

// historyOccurrence is one credential span addressed into the file's bytes.
type historyOccurrence struct {
	start, end int
	value      string
}

// collectHistoryTokens walks data line by line and returns every credential
// span in file order plus the distinct values (first-seen order, with their
// vendor labels). Spans never overlap: audit's matcher resolves overlaps
// within a line first-claim-wins, and lines are disjoint.
func collectHistoryTokens(data []byte) (occ []historyOccurrence, distinct []audit.FileToken) {
	seen := map[string]bool{}
	lineStart := 0
	for lineStart <= len(data) {
		lineEnd := lineStart + len(data[lineStart:])
		if i := bytes.IndexByte(data[lineStart:], '\n'); i >= 0 {
			lineEnd = lineStart + i
		}
		line := string(data[lineStart:lineEnd])
		for _, tk := range audit.HistoryLineTokens(line) {
			occ = append(occ, historyOccurrence{start: lineStart + tk.Start, end: lineStart + tk.End, value: tk.Value})
			if !seen[tk.Value] {
				seen[tk.Value] = true
				distinct = append(distinct, tk)
			}
		}
		if lineEnd == len(data) {
			break
		}
		lineStart = lineEnd + 1
	}
	return occ, distinct
}

// readShellHistory reads path with the checks every history caller needs: a
// regular file (a symlinked history is refused — see ApplyShellHistory's doc)
// within the sanity bound.
func readShellHistory(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s is a symlink; jit migrate rewrites files only at their real path — name the link's target instead", path)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if info.Size() > maxHistoryRedactSize {
		return nil, fmt.Errorf("%s is %d bytes, above the %d-byte bound; not touched", path, info.Size(), int64(maxHistoryRedactSize))
	}
	return os.ReadFile(path) // #nosec G304 -- explicitly-named migrate target, same trust boundary as every Apply* path
}

// PreviewShellHistory reports how many distinct credential values and total
// occurrences path holds — the plan/discovery number, from the same collect
// call ApplyShellHistory acts on, so preview and reality cannot disagree.
// ok=false means the file is missing or unreadable, not "clean".
func PreviewShellHistory(path string) (secrets, occurrences int, ok bool) {
	data, err := readShellHistory(path)
	if err != nil {
		return 0, 0, false
	}
	occ, distinct := collectHistoryTokens(data)
	return len(distinct), len(occ), true
}

// historyProfileName names the profile after the history file itself
// (".zsh_history" -> "zsh_history"), same convention as shellProfileName —
// two shells' histories can hold different tokens under the same vendor, and
// a shared profile would let one run shadow the other's naming.
func historyProfileName(path string) string {
	name := filepath.Base(path)
	name = looseSecretNameRe.ReplaceAllString(name, "_")
	name = strings.Trim(name, "_")
	if name == "" {
		return "shell_history"
	}
	return strings.ToLower(name)
}

// claimHistoryVarName finds the variable name a distinct credential value
// lands under: the vendor-derived base, suffixed _2, _3, … past any name an
// EARLIER value claimed this run or a PREVIOUS run claimed for a different
// value. A previous run's entry holding this same value is reused — that is
// what makes a re-run after shell-exit resurrection idempotent instead of
// minting GITHUB_PERSONAL_ACCESS_TOKEN_2 for the token it already vaulted.
// An entry whose secret was since deleted from the vault is a free slot.
func claimHistoryVarName(v *vault.Vault, entries profile.Profile, used map[string]bool, base, value string) string {
	for i := 1; ; i++ {
		name := base
		if i > 1 {
			name = fmt.Sprintf("%s_%d", base, i)
		}
		if used[name] {
			continue
		}
		secretPath, exists := entries[name]
		if !exists {
			used[name] = true
			return name
		}
		cur, err := v.Get(secretPath)
		if err != nil || string(cur) == value {
			used[name] = true
			return name
		}
		// Taken by a different live value: never clobber it, try the next.
	}
}

// lockShellHistory takes the same advisory fcntl write-lock zsh takes under
// HIST_FCNTL_LOCK, best-effort, so the rewrite and a locked zsh's append
// serialize instead of racing. Released when f closes. Best-effort on
// purpose: most shells never lock (then this always succeeds instantly and
// guards nothing), and a held lock clears in the milliseconds an append
// takes — after ~100ms this proceeds anyway rather than hanging a migrate
// run on a stuck process. The real resurrection risk is a shell's IN-MEMORY
// history rewriting the file on exit, which no file lock can prevent; the
// CLI's post-apply guidance (`fc -R`, re-scan) is the honest cover for that.
func lockShellHistory(f *os.File) {
	lk := syscall.Flock_t{Type: syscall.F_WRLCK, Whence: io.SeekStart}
	for i := 0; i < 20; i++ {
		if err := syscall.FcntlFlock(f.Fd(), syscall.F_SETLK, &lk); err == nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// ApplyShellHistory vaults every vendor-format credential in one history file
// and redacts each occurrence in place. Order matches every other Apply*:
// vault writes, the profile manifest, and the encrypted backup all land
// before the file itself is touched, so a failure partway never leaves the
// history altered with nothing recoverable. The rewrite is atomic (temp file
// + rename in the same directory) and preserves the file's permission bits.
//
// A symlinked history file is refused rather than followed: renaming over the
// link would silently replace it with a regular file and leave the link's
// target — typically a dotfiles working copy — still holding every credential
// while the scan reads clean. The caller names the target instead (and its
// git history is its own exposure; checkGitHistory warns there).
func ApplyShellHistory(v *vault.Vault, path string) (ShellHistoryMigration, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return ShellHistoryMigration{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return ShellHistoryMigration{}, fmt.Errorf("%s is a symlink; jit migrate rewrites files only at their real path — name the link's target instead", path)
	}
	if !info.Mode().IsRegular() {
		return ShellHistoryMigration{}, fmt.Errorf("%s is not a regular file", path)
	}
	if info.Size() > maxHistoryRedactSize {
		return ShellHistoryMigration{}, fmt.Errorf("%s is %d bytes, above the %d-byte bound; not touched", path, info.Size(), int64(maxHistoryRedactSize))
	}

	// O_RDWR, not O_RDONLY: a write-mode fd is what an fcntl write-lock needs.
	f, err := os.OpenFile(path, os.O_RDWR, 0) // #nosec G304 -- explicitly-named migrate target, same trust boundary as every Apply* path
	if err != nil {
		return ShellHistoryMigration{}, err
	}
	defer f.Close() // also releases the advisory lock
	lockShellHistory(f)

	data, err := io.ReadAll(f)
	if err != nil {
		return ShellHistoryMigration{}, fmt.Errorf("reading %s: %w", path, err)
	}
	occ, distinct := collectHistoryTokens(data)
	if len(occ) == 0 {
		return ShellHistoryMigration{}, fmt.Errorf("%s holds no vendor-format credential to redact", path)
	}

	profileName := historyProfileName(path)
	root, err := profile.GlobalRoot()
	if err != nil {
		return ShellHistoryMigration{}, fmt.Errorf("resolving global profile root: %w", err)
	}
	profilePath, err := profile.Path(root, profileName)
	if err != nil {
		return ShellHistoryMigration{}, err
	}
	entries := profile.Profile{}
	switch existing, lerr := profile.LoadFile(profilePath); {
	case lerr == nil:
		for k, v2 := range existing {
			entries[k] = v2
		}
	case errors.Is(lerr, os.ErrNotExist):
		// no existing profile yet — start fresh
	default:
		return ShellHistoryMigration{}, fmt.Errorf("loading existing profile %s: %w", profilePath, lerr)
	}

	// Name and vault each distinct value; remember which marker replaces
	// which occurrence.
	nameOf := make(map[string]string, len(distinct))
	varNames := make([]string, 0, len(distinct))
	used := map[string]bool{}
	meta, err := newProvenance(vault.ClassShellHistory, path)
	if err != nil {
		return ShellHistoryMigration{}, err
	}
	for _, tk := range distinct {
		name := claimHistoryVarName(v, entries, used, looseSecretName(tk.Vendor), tk.Value)
		secretPath := profileName + "/" + name
		if err := v.SetWithMeta(secretPath, []byte(tk.Value), meta); err != nil {
			return ShellHistoryMigration{}, fmt.Errorf("storing %s in vault: %w", name, err)
		}
		entries[name] = secretPath
		nameOf[tk.Value] = name
		varNames = append(varNames, name)
	}

	if err := writeProfileManifest(profilePath, entries, nil); err != nil {
		return ShellHistoryMigration{}, fmt.Errorf("writing profile %s: %w", profilePath, err)
	}

	backupPath, err := backupSecretFile(v, path)
	if err != nil {
		return ShellHistoryMigration{}, fmt.Errorf("backing up %s: %w", path, err)
	}

	// Splice: copy every byte outside the credential spans untouched.
	var out bytes.Buffer
	out.Grow(len(data))
	prev := 0
	for _, o := range occ {
		out.Write(data[prev:o.start])
		out.WriteString(historyRedactedPrefix + nameOf[o.value] + historyRedactedSuffix)
		prev = o.end
	}
	out.Write(data[prev:])

	if err := replaceShellHistory(path, out.Bytes(), info.Mode().Perm()); err != nil {
		return ShellHistoryMigration{}, err
	}

	return ShellHistoryMigration{
		Path:        path,
		ProfileName: profileName,
		ProfilePath: profilePath,
		Variables:   varNames,
		Occurrences: len(occ),
		BackupPath:  backupPath,
	}, nil
}

// replaceShellHistory writes content atomically over path — temp file in the
// same directory, then rename — preserving the original permission bits. An
// in-place truncate-and-write would hand a concurrently-reading shell a
// half-written file; rename never does.
func replaceShellHistory(path string, content []byte, perm os.FileMode) error {
	dir, base := filepath.Split(path)
	tmp, err := os.CreateTemp(dir, base+".jit-redact-*")
	if err != nil {
		return fmt.Errorf("creating temp file for %s: %w", path, err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = tmp.Close(); _ = os.Remove(tmpName) }
	if _, err := tmp.Write(content); err != nil {
		cleanup()
		return fmt.Errorf("writing %s: %w", tmpName, err)
	}
	// CreateTemp opens 0600; widen only if the original was wider, through
	// the fd so the mode lands on this exact file.
	if perm != 0o600 {
		if err := tmp.Chmod(perm); err != nil {
			cleanup()
			return fmt.Errorf("setting permissions on %s: %w", tmpName, err)
		}
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("closing %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("replacing %s: %w", path, err)
	}
	return nil
}
