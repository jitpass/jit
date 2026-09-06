// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/jitpass/jit/internal/selfpath"
	"github.com/jitpass/jit/internal/vault"
)

// A RecordedJitPath is one artifact `jit migrate` rewrote to call back into
// jit by absolute path — a kubeconfig exec, an AWS credential_process line,
// the docker/git/terraform helper scripts — and the path it currently
// carries (design/jit-path-refresh.md). The path was right when written;
// nothing revalidates it afterwards, and on a Homebrew install a copy
// written before internal/selfpath names the version-numbered Caskroom
// file the next `brew upgrade` deletes. jit doctor reports these; jit
// migrate refreshes them, because migrate wrote them and owns their backup
// and undo. Both go through this one enumeration so they cannot disagree
// about what an artifact is.
type RecordedJitPath struct {
	// Label names the artifact the way the user thinks of it — the helper
	// scripts under ~/.jit/shims are an implementation detail nobody chose.
	Label string
	Path  string
	// Category is the --only token whose migration wrote the artifact:
	// `--only aws` refreshes ~/.aws/config the way it migrates
	// ~/.aws/credentials. A refresh is maintenance of a category's
	// artifact, not a category of its own.
	Category string
	// Key is the token whose line carries the recorded path. Anchoring to
	// it is what keeps an unrelated /usr/bin/jit mentioned in a comment
	// from being reported as a broken artifact.
	Key string
	// Recorded is the jit path the artifact carries.
	Recorded string
}

// jitPathArtifacts is the table: every non-MCP artifact that records jit's
// absolute path. MCP configs are deliberately absent — doctor's mcpFindings
// checks theirs and can say which SERVER broke, the more useful sentence,
// and each server's re-migration is its own path.
func jitPathArtifacts(home string) []RecordedJitPath {
	return []RecordedJitPath{
		{Label: "~/.kube/config", Path: KubeconfigPath(home), Category: "kube", Key: "command:"},
		{Label: "~/.aws/config", Path: AWSConfigPath(home), Category: "aws", Key: "credential_process"},
		{Label: "the docker credential helper", Path: DockerHelperPath(home), Category: "docker", Key: "exec "},
		{Label: "the git credential helper", Path: GitHelperPath(home), Category: "git", Key: "exec "},
		{Label: "the terraform credentials helper", Path: TerraformHelperPath(home), Category: "terraform", Key: "exec "},
		{Label: "the cargo credential provider", Path: CargoHelperPath(home), Category: "cargo", Key: "exec "},
	}
}

// recordedJitPath matches an absolute path ending in the jit binary, with
// the surrounding quoting the writers apply (shell single quotes, YAML/JSON
// double quotes) left outside the capture.
var recordedJitPath = regexp.MustCompile(`(/[^\s"']*/jit)\b`)

// DiscoverRecordedJitPaths reads every artifact and returns one entry per
// distinct jit path each records. Best-effort and read-only: an absent or
// unreadable artifact yields nothing, and a file jit never wrote has no
// matching line and is silently uninteresting — which is what makes it
// safe to probe all five unconditionally.
func DiscoverRecordedJitPaths(home string) []RecordedJitPath {
	var out []RecordedJitPath
	for _, a := range jitPathArtifacts(home) {
		data, err := os.ReadFile(a.Path) // #nosec G304 -- fixed, jit-owned artifact locations
		if err != nil {
			continue
		}
		seen := map[string]bool{}
		for _, line := range strings.Split(string(data), "\n") {
			if !strings.Contains(line, a.Key) {
				continue
			}
			m := recordedJitPath.FindStringSubmatch(line)
			if m == nil || seen[m[1]] {
				continue
			}
			seen[m[1]] = true
			r := a
			r.Recorded = m[1]
			out = append(out, r)
		}
	}
	return out
}

// The two ways a recorded path is stale, in the order they are tested: a
// path that is gone is broken now; a version-numbered Homebrew path works
// today and stops existing at the next upgrade.
const (
	StaleMissing   = "isn't there"
	StaleVersioned = "version-pinned"
)

// Stale reports why the recorded path needs refreshing, "" when it does
// not. Every durable path — the common healthy install — answers "".
func (r RecordedJitPath) Stale() string {
	switch {
	case !executableFile(r.Recorded):
		return StaleMissing
	case selfpath.VersionedBrew(r.Recorded):
		return StaleVersioned
	}
	return ""
}

// executableFile reports whether path is a regular file with an execute
// bit. Both halves matter: a directory at the path and a non-executable
// file both fail exec with errors the host renders as one opaque failure.
func executableFile(path string) bool {
	if path == "" {
		return false
	}
	info, err := os.Stat(path) // #nosec G703 -- stat-only probe; no content is read
	return err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0
}

// ResolveDurableJitPath is the path a refresh records — resolveJitExecutable
// (selfpath.Durable) for callers outside the package — or the refusal
// naming why this jit has none (a build directory, ~/Downloads, an
// unmatched Caskroom copy). Prompt-free and cheap, so a plan can ask
// before anything is confirmed and turn a refusal into a note rather than
// a failure after [y/N] (design/jit-path-refresh.md D4).
func ResolveDurableJitPath() (string, error) {
	return resolveJitExecutable()
}

// JitPathRefresh is one refreshed artifact, for the mutation log.
type JitPathRefresh struct {
	Path   string
	From   string
	To     string
	Backup string // the vault path holding the pristine bytes; `jit migrate undo` restores it
}

// RefreshRecordedJitPath rewrites the jit path r records to `to`, the
// durable path the plan resolved and showed the user — passed in rather
// than re-resolved here so the line the user confirmed is the line that
// gets written. Line-anchored: only lines carrying r.Key, only the regex
// match equal to r.Recorded; every other byte, quoting included, is
// preserved, and the file keeps its own mode (the helpers are 0755
// scripts). Backed up first through the run's tracker, so undo restores
// the pristine artifact even when a category migration rewrites the same
// file later in the run.
func RefreshRecordedJitPath(v *vault.Vault, r RecordedJitPath, to string, tracker *BackupTracker) (JitPathRefresh, error) {
	// The writers quote per artifact (single quotes in a shell helper,
	// nothing in INI/YAML); a substitution inside their quoting is right
	// only for a path that needs none. Homebrew and /usr/local never do.
	if strings.ContainsAny(to, " \t'\"") {
		return JitPathRefresh{}, fmt.Errorf("refusing to record %q: a jit path with whitespace or quotes cannot be substituted into every artifact's own quoting", to)
	}
	data, err := os.ReadFile(r.Path) // #nosec G304 -- fixed, jit-owned artifact location
	if err != nil {
		return JitPathRefresh{}, fmt.Errorf("reading %s: %w", r.Path, err)
	}
	info, err := os.Stat(r.Path)
	if err != nil {
		return JitPathRefresh{}, err
	}
	rewritten, changed := refreshRecordedLines(string(data), r.Key, r.Recorded, to)
	if !changed {
		return JitPathRefresh{}, fmt.Errorf("%s no longer carries %s; nothing to refresh", r.Path, r.Recorded)
	}
	backup, err := tracker.backupOnce(v, r.Path)
	if err != nil {
		return JitPathRefresh{}, fmt.Errorf("backing up %s: %w", r.Path, err)
	}
	if err := vault.AtomicWriteFile(r.Path, []byte(rewritten)); err != nil {
		return JitPathRefresh{}, fmt.Errorf("writing %s: %w", r.Path, err)
	}
	// AtomicWriteFile lands at the vault's own 0600; a helper script has
	// to stay executable or the tool it serves fails on its next call.
	if err := os.Chmod(r.Path, info.Mode().Perm()); err != nil {
		return JitPathRefresh{}, fmt.Errorf("restoring mode of %s: %w", r.Path, err)
	}
	return JitPathRefresh{Path: r.Path, From: r.Recorded, To: to, Backup: backup}, nil
}

// refreshRecordedLines is the pure substitution: on every line containing
// key, each recorded-path match equal to from becomes to. Splitting and
// joining on "\n" keeps a trailing newline (or its absence) exactly as
// the file had it.
func refreshRecordedLines(content, key, from, to string) (string, bool) {
	lines := strings.Split(content, "\n")
	changed := false
	for i, line := range lines {
		if !strings.Contains(line, key) {
			continue
		}
		lines[i] = recordedJitPath.ReplaceAllStringFunc(line, func(m string) string {
			if m != from {
				return m
			}
			changed = true
			return to
		})
	}
	return strings.Join(lines, "\n"), changed
}
