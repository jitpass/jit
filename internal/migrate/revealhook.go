// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: Apache-2.0

package migrate

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
)

// RevealHookKind identifies which project-level pre-run hook (if any)
// InstallRevealHook wired an automatic "jit agent reveal" call into.
type RevealHookKind string

const (
	RevealHookNone   RevealHookKind = ""
	RevealHookDirenv RevealHookKind = "direnv (.envrc)"
	RevealHookNpm    RevealHookKind = "npm pre-script (package.json)"
)

// InstallRevealHook is migrate's answer to the decoy-by-default mount's
// remaining ergonomic gap (GAPS.md #2): internal/cli/agent.go's
// mountManager already reveals every mount automatically for a short window
// on unlock/refresh, but a dev server started well after that window
// closed (or one that never triggers a fresh unlock at all — the agent
// might already be unlocked from something unrelated) would otherwise see
// decoy values with no obvious reason why. Rather than leave "remember to
// run `jit agent reveal` first" as a purely manual step, migrate tries to
// wire the trust signal into whatever already runs right before the
// consumer reads the mount.
//
// Best-effort and narrowly scoped on purpose: tries known integration
// points in order and installs at most one, doing nothing (RevealHookNone,
// nil error) if none apply. The manual `jit agent reveal <path>` command and
// the automatic post-unlock window remain the fallback either way — this
// is a convenience layer on top of the real gate (RevealState), never a
// replacement for it, and it automates a step a human could always type
// themselves: the injected command still goes through the same
// ensureUnlocked/Touch-ID-or-cached-session path `jit agent reveal` always
// has, so this doesn't lower the bar RFC.md's threat model already
// accepts (GAPS.md #1/#4 — anyone with existing code execution as you can
// already reach an unlocked agent's session directly).
//
// Deliberately does NOT cover docker-compose, Makefiles, or IDE run
// configurations: none of them has a generic "about to run" hook point
// jit can safely, mechanically target without guessing which of several
// possible entry points the user actually invokes — silently guessing
// wrong (rewriting the wrong Makefile target, say) is worse than doing
// nothing and leaving the human the manual/automatic fallbacks. See
// GAPS.md #2.
// Variadic on purpose: a directory with several mounts (.env + .env.local +
// .npmrc is the common playground/monorepo shape) must wire all of them in
// ONE edit of the hook file — a per-mount call re-edited (and re-backed-up)
// package.json once per mount, leaving N nearly-identical
// package.json.jit-bak-<ts> siblings from a single migrate run, a real,
// observed mess. internal/cli's migrateSummary batches per directory and
// calls this once with every mount for that dir.
func InstallRevealHook(dir string, mountPaths ...string) (RevealHookKind, error) {
	if len(mountPaths) == 0 {
		return RevealHookNone, nil
	}
	jitPath, err := resolveJitExecutable()
	if err != nil {
		return RevealHookNone, fmt.Errorf("resolving jit's own executable path: %w", err)
	}

	kind, err := installDirenvRevealHook(dir, jitPath, mountPaths)
	if err != nil {
		return RevealHookNone, err
	}
	if kind != RevealHookNone {
		return kind, nil
	}

	return installNpmRevealHook(dir, jitPath, mountPaths)
}

// revealHookMarker uniquely identifies a jit-injected reveal command for
// mountPath inside a hook file, INDEPENDENT of which jit binary path was used
// at install time — jit may have been reinstalled to a different path (or the
// undo run may be a different build) between migrate and undo, so matching the
// full revealHookCommand (which embeds the absolute jitPath) would miss it.
// The injected command is always
//
//	'<jitPath>' agent reveal '<mountPath>' --quiet 2>/dev/null || true
//
// so "agent reveal '<mountPath>' --quiet" is present iff this is jit's own
// reveal line for that mount.
func revealHookMarker(mountPath string) string {
	return "agent reveal " + shellQuote(mountPath) + " --quiet"
}

// jitBakSiblingRe matches the "<file>.jit-bak-<unix-ts>" backups backupFile
// leaves next to an edited hook file, so UninstallRevealHook can clean them up
// once a hook file has no jit reveal command left — anchored to digits only so
// it can never match an unrelated user file.
var jitBakSiblingRe = regexp.MustCompile(`\.jit-bak-\d+$`)

// UninstallRevealHook is the surgical inverse of InstallRevealHook: it removes
// jit's reveal command(s) for exactly the given mountPaths from dir's .envrc
// and package.json, leaving every other line and every user-authored script
// untouched (it matches and drops only jit's own marked commands, never
// rewrites the whole file from a backup — so a script the user edited since
// migration is never clobbered, the exact concern that used to make undo leave
// these hooks in place). Once a hook file has no jit reveal command left at
// all, its "<file>.jit-bak-<ts>" siblings are removed too. Best-effort and
// idempotent: a missing file, an unparsable package.json, or a path with no
// jit hook is a no-op (nil). This is what lets `jit migrate undo` actually
// reverse the reveal-hook wiring instead of leaving dead hooks — with
// machine-absolute paths baked in — and a stray .jit-bak behind.
func UninstallRevealHook(dir string, mountPaths ...string) error {
	if len(mountPaths) == 0 {
		return nil
	}
	if err := uninstallDirenvRevealHook(dir, mountPaths); err != nil {
		return err
	}
	return uninstallNpmRevealHook(dir, mountPaths)
}

// jsonSemanticallyEqual reports whether a and b decode to the same JSON
// value — indifferent to key order, whitespace, and a trailing newline.
// This is the "did removing jit's hooks give back exactly what was there
// before install?" test writeNpmHookFile uses.
func jsonSemanticallyEqual(a, b []byte) bool {
	var av, bv any
	if err := json.Unmarshal(a, &av); err != nil {
		return false
	}
	if err := json.Unmarshal(b, &bv); err != nil {
		return false
	}
	return reflect.DeepEqual(av, bv)
}

// writeNpmHookFile writes pkgPath's surgically-cleaned content and returns
// the bytes actually written. The JSON round-trip the surgical edit rides
// on (map[string]json.RawMessage in, MarshalIndent out) alphabetizes
// top-level keys and drops any trailing newline — semantically identical,
// but git-dirty after an undo that promises byte-for-byte (a real E2E
// finding: a full migrate-then-undo left package.json reordered, with git
// flagging "\ No newline at end of file"). So when the cleaned content is
// semantically identical to a ".jit-bak" sibling — the exact pre-install
// bytes backupFile kept — those original bytes are restored verbatim
// instead. A file the user edited since install never matches any backup
// and falls through to the surgical rewrite, which then at least preserves
// the original file's trailing-newline convention.
func writeNpmHookFile(pkgPath string, cleaned, original []byte) ([]byte, error) {
	matches, err := filepath.Glob(pkgPath + ".jit-bak-*")
	if err == nil {
		sort.Strings(matches) // deterministic pick when several backups match
		for _, m := range matches {
			if !jitBakSiblingRe.MatchString(m) {
				continue
			}
			bak, rerr := os.ReadFile(m) // #nosec G304 -- a fixed-suffix sibling of jit's own hook file
			if rerr != nil {
				continue
			}
			if jsonSemanticallyEqual(cleaned, bak) {
				if werr := os.WriteFile(pkgPath, bak, 0o600); werr != nil { // #nosec G703 -- pkgPath is the mount's own directory joined with a fixed literal filename, never external input

					return nil, werr
				}
				return bak, nil
			}
		}
	}
	if len(original) > 0 && original[len(original)-1] == '\n' {
		cleaned = append(cleaned, '\n')
	}
	if err := os.WriteFile(pkgPath, cleaned, 0o600); err != nil {
		return nil, err
	}
	return cleaned, nil
}

func lineHasAnyMarker(s string, markers []string) bool {
	for _, m := range markers {
		if strings.Contains(s, m) {
			return true
		}
	}
	return false
}

// hookFileStillHasJitReveal reports whether content still contains any jit
// reveal command (for a mount other than the one(s) just removed) — the gate
// for whether the .jit-bak siblings are safe to clean up. Checks both halves
// of the injected shape so it can't be fooled by a user command that merely
// mentions "agent reveal".
func hookFileStillHasJitReveal(content string) bool {
	return strings.Contains(content, "agent reveal ") &&
		strings.Contains(content, "--quiet 2>/dev/null || true")
}

// cleanupHookBackupsIfClean removes hookPath's "<hookPath>.jit-bak-<ts>"
// siblings, but only when newContent has no jit reveal command left — a
// partial undo (one of several mounts in the directory) keeps the backup,
// since jit still has wiring in that file. Best-effort: a failed remove is
// returned so the caller can warn, never fatal.
func cleanupHookBackupsIfClean(hookPath, newContent string) error {
	if hookFileStillHasJitReveal(newContent) {
		return nil
	}
	matches, err := filepath.Glob(hookPath + ".jit-bak-*")
	if err != nil {
		return err
	}
	for _, m := range matches {
		if !jitBakSiblingRe.MatchString(m) {
			continue // defense-in-depth: only exact "<file>.jit-bak-<digits>"
		}
		if err := os.Remove(m); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("removing stale backup %s: %w", m, err)
		}
	}
	return nil
}

func uninstallDirenvRevealHook(dir string, mountPaths []string) error {
	envrcPath := filepath.Join(dir, ".envrc")
	info, err := os.Stat(envrcPath)
	if err != nil || info.IsDir() {
		return nil
	}
	lines, err := readLines(envrcPath)
	if err != nil {
		return fmt.Errorf("reading %s: %w", envrcPath, err)
	}

	markers := make([]string, len(mountPaths))
	for i, mp := range mountPaths {
		markers[i] = revealHookMarker(mp)
	}

	kept := make([]string, 0, len(lines))
	removed := false
	for _, l := range lines {
		if lineHasAnyMarker(l, markers) {
			removed = true
			continue
		}
		kept = append(kept, l)
	}
	if !removed {
		return nil
	}

	newContent := strings.Join(kept, "\n")
	if err := os.WriteFile(envrcPath, []byte(newContent), 0o600); err != nil {
		return fmt.Errorf("writing %s: %w", envrcPath, err)
	}
	return cleanupHookBackupsIfClean(envrcPath, newContent)
}

func uninstallNpmRevealHook(dir string, mountPaths []string) error {
	pkgPath := filepath.Join(dir, "package.json")
	data, err := os.ReadFile(pkgPath) // #nosec G304 -- dir is jit's own restored mount directory joined with a fixed filename
	if err != nil {
		return nil // no package.json — nothing to undo
	}
	var pkg map[string]json.RawMessage
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil
	}
	scriptsRaw, ok := pkg["scripts"]
	if !ok {
		return nil
	}
	var scripts map[string]string
	if err := json.Unmarshal(scriptsRaw, &scripts); err != nil {
		return nil
	}

	markers := make([]string, len(mountPaths))
	for i, mp := range mountPaths {
		markers[i] = revealHookMarker(mp)
	}

	changed := false
	for _, target := range npmRevealHookScripts {
		preKey := "pre" + target
		existing, ok := scripts[preKey]
		if !ok {
			continue
		}
		// The pre-script is jit's reveal command(s) joined with " && " and,
		// if the user already had a pre-script, their command appended after
		// another " && " (see installNpmRevealHook). Split on the same
		// separator, drop only jit's marked segments, and rejoin — a user
		// segment that itself contains " && " is over-split then rejoined
		// identically, since none of its pieces carry a jit marker.
		segments := strings.Split(existing, " && ")
		kept := make([]string, 0, len(segments))
		for _, seg := range segments {
			if lineHasAnyMarker(seg, markers) {
				continue
			}
			kept = append(kept, seg)
		}
		newVal := strings.Join(kept, " && ")
		if newVal == existing {
			continue
		}
		changed = true
		if strings.TrimSpace(newVal) == "" {
			delete(scripts, preKey) // it was entirely jit's — remove the key
		} else {
			scripts[preKey] = newVal
		}
	}
	if !changed {
		return nil
	}

	scriptsJSON, err := marshalJSONNoEscape(scripts, "")
	if err != nil {
		return err
	}
	pkg["scripts"] = scriptsJSON

	out, err := marshalJSONNoEscape(pkg, "  ")
	if err != nil {
		return err
	}
	written, err := writeNpmHookFile(pkgPath, out, data)
	if err != nil {
		return fmt.Errorf("writing %s: %w", pkgPath, err)
	}
	return cleanupHookBackupsIfClean(pkgPath, string(written))
}

// revealHookCommand is the actual line injected into a hook: `|| true` so a
// locked-out agent (not installed, not reachable) never fails the
// consumer's real command — revealing is a convenience, not a precondition
// the wrapped tool should be held hostage to. Stderr is silenced for the
// same reason; a genuine problem is still visible via `jit agent status`
// or the agent's own log, not by breaking someone's `npm run dev`.
func revealHookCommand(jitPath, mountPath string) string {
	return fmt.Sprintf("%s agent reveal %s --quiet 2>/dev/null || true", shellQuote(jitPath), shellQuote(mountPath))
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// installDirenvRevealHook prepends revealHookCommand to an EXISTING .envrc,
// never creates one — a project that hasn't opted into direnv shouldn't
// have jit introduce it. Prepending (not appending) matters: direnv's own
// `dotenv`/`source_env` calls that actually read the mount must run AFTER
// revealing, and a line at the very top always runs first regardless of what
// else the file does. Idempotent: a second migrate run recognizes its own
// previously-injected line (by exact command match) and does nothing.
func installDirenvRevealHook(dir, jitPath string, mountPaths []string) (RevealHookKind, error) {
	envrcPath := filepath.Join(dir, ".envrc")
	info, err := os.Stat(envrcPath)
	if err != nil || info.IsDir() {
		return RevealHookNone, nil
	}

	lines, err := readLines(envrcPath)
	if err != nil {
		return RevealHookNone, fmt.Errorf("reading %s: %w", envrcPath, err)
	}

	// Per-path idempotency: only lines not already present get prepended,
	// so a re-run (or a later migrate adding one new mount to a dir with
	// hooks already wired) edits the file at most once, for the genuinely
	// new paths.
	var missing []string
	for _, mountPath := range mountPaths {
		revealLine := revealHookCommand(jitPath, mountPath)
		present := false
		for _, l := range lines {
			if strings.Contains(l, revealLine) {
				present = true
				break
			}
		}
		if !present {
			missing = append(missing, revealLine)
		}
	}
	if len(missing) == 0 {
		return RevealHookDirenv, nil
	}

	if _, err := backupFile(envrcPath); err != nil {
		return RevealHookNone, fmt.Errorf("backing up %s: %w", envrcPath, err)
	}

	newContent := strings.Join(missing, "\n") + "\n" + strings.Join(lines, "\n")
	if err := os.WriteFile(envrcPath, []byte(newContent), 0o600); err != nil {
		return RevealHookNone, fmt.Errorf("writing %s: %w", envrcPath, err)
	}
	return RevealHookDirenv, nil
}

// npmRevealHookScripts is the deliberately small set of npm lifecycle script
// names InstallRevealHook will wire a "pre<name>" hook for — the two
// conventional Node dev-server entry points, not every script in the
// file. Blanket-injecting a hook ahead of every script (pretest, prebuild,
// ...) would be presumptuous about which ones actually read the mount;
// "dev"/"start" are the ones that plausibly do.
var npmRevealHookScripts = []string{"dev", "start"}

// installNpmRevealHook adds (or extends) a "pre<name>" script for each of
// npmRevealHookScripts that exists in package.json's "scripts" block, using
// npm's own pre-script convention (npm runs "predev" automatically before
// "npm run dev") rather than anything jit has to enforce itself. Never
// overwrites an existing pre-script the user already authored — the reveal
// command is prepended with "&&" so theirs still runs after it. Skips
// (RevealHookNone, nil) entirely if package.json doesn't exist, has no
// scripts block, or matches neither target — never fails the whole
// migrate run over a malformed/unusual package.json.
func installNpmRevealHook(dir, jitPath string, mountPaths []string) (RevealHookKind, error) {
	pkgPath := filepath.Join(dir, "package.json")
	data, err := os.ReadFile(pkgPath) // #nosec G304 -- path is dir (the mount's own directory, from jit's own migrate walk) joined with a fixed literal filename
	if err != nil {
		return RevealHookNone, nil
	}

	var pkg map[string]json.RawMessage
	if err := json.Unmarshal(data, &pkg); err != nil {
		return RevealHookNone, nil // malformed package.json — not this function's problem to fix
	}
	scriptsRaw, ok := pkg["scripts"]
	if !ok {
		return RevealHookNone, nil
	}
	var scripts map[string]string
	if err := json.Unmarshal(scriptsRaw, &scripts); err != nil {
		return RevealHookNone, nil
	}

	changed := false
	for _, target := range npmRevealHookScripts {
		if _, exists := scripts[target]; !exists {
			continue
		}
		preKey := "pre" + target
		existing := scripts[preKey]
		// Per-path idempotency, same as the direnv installer: only
		// commands not already present get prepended, joined into ONE
		// combined prefix so all of a directory's mounts land in a single
		// edit of this pre-script.
		var missing []string
		for _, mountPath := range mountPaths {
			if revealCmd := revealHookCommand(jitPath, mountPath); !strings.Contains(existing, revealCmd) {
				missing = append(missing, revealCmd)
			}
		}
		if len(missing) == 0 {
			continue // already installed by an earlier migrate run
		}
		combined := strings.Join(missing, " && ")
		if existing == "" {
			scripts[preKey] = combined
		} else {
			scripts[preKey] = combined + " && " + existing
		}
		changed = true
	}
	if !changed {
		return RevealHookNone, nil
	}

	if _, err := backupFile(pkgPath); err != nil {
		return RevealHookNone, fmt.Errorf("backing up %s: %w", pkgPath, err)
	}

	scriptsJSON, err := marshalJSONNoEscape(scripts, "")
	if err != nil {
		return RevealHookNone, err
	}
	pkg["scripts"] = scriptsJSON

	// Re-marshaling a map[string]json.RawMessage sorts top-level keys
	// alphabetically (encoding/json doesn't preserve original map key
	// order) — the same tradeoff ApplyMCPConfig already accepts for
	// mcp.json/claude_desktop_config.json, not a new one introduced here.
	out, err := marshalJSONNoEscape(pkg, "  ")
	if err != nil {
		return RevealHookNone, err
	}
	if err := os.WriteFile(pkgPath, out, 0o600); err != nil {
		return RevealHookNone, fmt.Errorf("writing %s: %w", pkgPath, err)
	}
	return RevealHookNpm, nil
}
