// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"os"
	"regexp"
	"strings"

	"github.com/jitpass/jit/internal/selfpath"
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
