// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jitpass/jit/internal/mount"
	"github.com/jitpass/jit/internal/profile"
	"github.com/jitpass/jit/internal/vault"
)

// checkKind classifies one doctor finding so a --format json consumer can
// filter on the failure type (missing vs. corrupt vs. an unloadable manifest)
// without string-matching an English sentence — the thing the old flat
// []string Problems shape made impossible. It is also what separates hard
// problems (which fail the run) from advisory warnings (which don't); see
// checkKind.warning.
type checkKind string

const (
	// kindParse: the profile manifest itself won't load (bad YAML, empty,
	// an entry with no path). No secret was ever reached.
	kindParse checkKind = "parse"
	// kindNotFound: the named profile resolved to no manifest in any scope.
	// Split out of kindParse because the two are different problems with
	// different fixes — a typo'd --profile versus broken YAML — and a
	// consumer filtering on "parse" could not tell them apart.
	kindNotFound checkKind = "not_found"
	// kindMissing: a referenced secret path isn't in the vault at all.
	kindMissing checkKind = "missing"
	// kindCorrupt: the secret file exists but its envelope won't parse or is
	// a version this jit can't read — it passes a bare existence check yet
	// fails the moment an app needs the value. Caught auth-free via
	// vault.Verify, only when integrity checking is requested.
	kindCorrupt checkKind = "corrupt"
	// kindVaultError: an unexpected error while checking the vault (a
	// permissions problem on the store, say) — neither cleanly present nor
	// cleanly absent.
	kindVaultError checkKind = "vault_error"
	// kindBadPath: the profile names something that isn't a legal secret path
	// at all (an absolute path, a ".." segment, stray whitespace). A manifest
	// bug, fixed by editing the YAML — nothing to do with the vault's health,
	// which is where it used to be filed. profile.LoadFile validates variable
	// NAMES strictly and never validated path SHAPE, so these only ever
	// surfaced when Exists() rejected them, wearing the wrong kind.
	kindBadPath checkKind = "bad_path"
	// kindOrphan: a vault secret that no profile references. Advisory only
	// (see warning): dead weight and audit surface worth surfacing, never a
	// reason to fail the run.
	kindOrphan checkKind = "orphan"
	// kindShadowed: a profile name exists in BOTH project and global scope.
	// Load resolves to the project one, so the global profile of the same
	// name is silently ignored — the exact "why is my global profile not
	// taking effect" confusion. Advisory: nothing is broken, but the user
	// should know one file is dead weight in this directory.
	kindShadowed checkKind = "shadowed"
	// kindService/kindBackup are absorbed system-health sections, both
	// advisory: a stopped agent and an unrecorded export each break something
	// worth surfacing, but neither makes a secret unresolvable.
	kindService checkKind = "service"
	kindBackup  checkKind = "backup"
	// kindWrap is a wrapped-tool installation that is actually damaged — a
	// missing shim dir, a symlink pointing at nothing, a vanished profile, an
	// rc file that lost its PATH line. A hard problem: the tool it wraps runs
	// unwrapped or not at all, and that is breakage, not a nudge. This is the
	// verdict `jit wrap doctor` always gave; `jit doctor` used to disagree
	// with it, and now doesn't.
	kindWrap checkKind = "wrap"
	// kindWrapEnv is a wrap check that failed for a reason true of THIS
	// process rather than of the installation: the shim dir absent from the
	// PATH this run was handed, or the real tool missing from it. A new login
	// shell may well disagree, and a CI job that legitimately doesn't put the
	// shim dir on PATH must not fail for it — which is exactly the reasoning
	// that used to justify `jit wrap doctor` and `jit doctor` disagreeing on
	// every wrap failure. The distinction belongs on the check, not on which
	// command rendered it.
	kindWrapEnv checkKind = "wrap_env"
	// kindMount: a registered mount's profile manifest won't load, so jit is
	// serving (or failing to serve) a file whose variable list it can't read.
	// Advisory: the mount is broken, but nothing about the profiles the user
	// asked about is, and the registry can outlive a project directory
	// legitimately (see reconcileSecrets, which tolerates the same state).
	kindMount checkKind = "mount"
	// kindVaultKey: the vault holds secrets but this Mac's master key is gone
	// from the keychain. Every envelope still passes Verify — structure and
	// recipient are intact — and not one of them can be decrypted. A hard
	// problem, and the one doctor was most conspicuously blind to: the
	// keychain item is the single thing standing between a healthy-looking
	// vault and a total loss.
	kindVaultKey checkKind = "vault_key"
	// kindRekey: a master-key rotation is in progress or was interrupted.
	// While the marker exists every vault WRITE is refused (see
	// errRekeyInProgress), so a doctor that reported a clean bill of health
	// left the user to discover the state from the next command that failed.
	kindRekey checkKind = "rekey"
	// kindAudit: the audit trail has stopped recording. Advisory — no secret
	// is at risk and no command is blocked — but for a tool whose job is
	// custody of secrets, losing the record of what touched them silently is
	// worth one line.
	kindAudit checkKind = "audit"
	// kindMCP: an MCP server entry jit itself rewrote can no longer launch —
	// the jit binary it names is gone, or the profile it names is. A hard
	// problem for the same reason kindWrap is: the server it wraps doesn't
	// run, and an MCP host reports that as nothing more than "server failed."
	//
	// This is the one check whose subject is jit's own past output. The
	// rewrite pins an absolute path (see WrappedMCPEntry.JitPath) and then
	// nobody looks at it again, so the breakage arrives with no command run
	// and no error printed — from `jit upgrade` relocating the binary, a
	// Homebrew-to-manual switch, or a workspace copied between machines.
	kindMCP checkKind = "mcp"
	// kindInstall: more than one distinct jit binary is reachable on PATH —
	// the state every pre-Homebrew user lands in by running `brew install`
	// over a tarball install at /usr/local/bin. Nothing shared breaks (vault,
	// keychain and profiles are per-user, not per-binary), which is exactly
	// why nobody notices: PATH order silently picks which copy runs, and the
	// two upgrade on separate tracks — `brew upgrade` refreshing a binary
	// shells never execute is the observed field shape. Advisory: no secret
	// is unreadable, but the user should know which jit they are actually on.
	kindInstall checkKind = "install"
	// kindCompletion: this shell has no jit tab-completion loaded, so the
	// arguments only jit knows — a vault path, a live grant id, a profile
	// name, the kinds `jit audit --kind` takes — cannot be completed at all.
	//
	// Advisory, and easy to dismiss as cosmetic, except for how a user
	// arrives here: a Homebrew CASK installs the binary and nothing else, so
	// every cask install before completions shipped in the archive had this,
	// and a tarball install still does. The remedy is one line in a shell rc
	// that the README calls optional, which means the people who never read
	// it are exactly the people who never learn the flags exist.
	kindCompletion checkKind = "completion"
	// kindJitPath: an artifact `jit migrate` rewrote records an absolute jit
	// path that will not keep working — the binary is already gone, or it is
	// a version-numbered Homebrew copy the next upgrade deletes.
	//
	// Sibling of kindMCP, split off because MCP was the only recorded path
	// anyone checked. `jit migrate` pins jit's path into a kubeconfig exec, an
	// AWS credential_process, and the docker/git/terraform helper scripts by
	// exactly the same mechanism, and none of them was ever revalidated: the
	// failure surfaces as kubectl or terraform reporting a missing binary,
	// with nothing naming jit as the cause.
	//
	// A hard problem: the artifact is broken now, exactly like kindMCP.
	kindJitPath checkKind = "jit_path"
	// kindJitPathUpgrade: the same recorded path, still working, but pinned
	// to a version-numbered Homebrew directory the next `brew upgrade`
	// deletes. Reported before it breaks, which is the only useful time —
	// afterwards the user is mid-task on a tool that just stopped working,
	// with nothing pointing at jit.
	//
	// A separate kind from kindJitPath, not a flag on the finding, because
	// advisory-ness is a property of the kind here (see warning) and the two
	// states want different words on the group header. Same split, same
	// reason, as kindWrap and kindWrapEnv.
	kindJitPathUpgrade checkKind = "jit_path_upgrade"
)

// allCheckKinds enumerates every kind above, for the completeness tests that
// walk it. It exists because a kind is declared in one file and rendered in
// another: kindMCP shipped with no case in findingLabel, so its group header
// rendered as a bare count with no name, and every unit test passed because
// each asserted on the finding it built rather than on how it displayed.
// A switch with a "" default cannot fail loudly, so the enumeration has to.
//
// Add new kinds here.
var allCheckKinds = []checkKind{
	kindParse, kindNotFound, kindMissing, kindCorrupt, kindVaultError,
	kindBadPath, kindOrphan, kindShadowed, kindService, kindBackup,
	kindWrap, kindWrapEnv, kindMount, kindVaultKey, kindRekey, kindAudit,
	kindMCP, kindInstall, kindJitPath, kindJitPathUpgrade, kindCompletion,
}

// warning reports whether a finding of this kind is advisory (does not fail
// the run or flip ok=false) rather than a hard problem. A hard problem means
// a secret this setup depends on cannot be read: missing, corrupt,
// unparseable, or — the two kinds added with the vault-integrity checks —
// unreadable because the master key is gone or a rekey never finished.
// Everything else (an extra secret, a shadowed profile, a stopped agent, a
// stale backup, a mount whose manifest vanished) is advisory.
//
// Note kindWrap is NOT advisory and kindWrapEnv is: a damaged shim
// installation is real breakage, while "not on PATH in THIS shell" is true of
// one process and must never fail a CI run.
func (k checkKind) warning() bool {
	switch k {
	case kindOrphan, kindShadowed, kindService, kindBackup, kindMount, kindWrapEnv, kindAudit, kindInstall, kindJitPathUpgrade, kindCompletion:
		return true
	default:
		return false
	}
}

// checkFinding is one structured problem or warning. Its zero-omitting JSON
// tags mean an orphan finding (which has only a path) doesn't carry empty
// profile/variable fields, and a parse finding (no single variable) doesn't
// carry an empty path.
type checkFinding struct {
	Kind     checkKind `json:"kind"`
	Profile  string    `json:"profile,omitempty"`
	Scope    string    `json:"scope,omitempty"`
	Variable string    `json:"variable,omitempty"`
	Path     string    `json:"path,omitempty"`
	Detail   string    `json:"detail"`
	// Action is what to DO about the finding — one runnable step, with its
	// commands `backtick`-delimited for hlCmds, and nothing else on it
	// (design/output-style.md, "The action line"). Empty when the finding
	// names no single next step.
	//
	// It is authored here rather than derived. The renderer used to recover
	// this clause from Detail with a regexp — reverse-engineering prose the
	// same package had just generated — and the seams showed: the split left
	// dangling subordinate clauses ("→ jit vault export <file> so losing it
	// isn't losing every secret"), and a JSON consumer got an English
	// sentence with markup in it instead of a field.
	Action string `json:"action,omitempty"`
}

// checkedRef is one variable→path reference that resolved cleanly, retained
// so --verbose can show exactly what a passing run examined (a bare count
// can't answer "is doctor even seeing my profile?").
type checkedRef struct {
	Profile  string
	Scope    string
	Variable string
	Path     string
}

// checkOptions tunes runProfileCheck. The zero value is the cheapest, safest
// pass: every visible profile, existence checks only, no orphan sweep.
type checkOptions struct {
	// Root is jit's config directory, needed only to read the mount
	// registry. Empty skips the mount sweep entirely, which is what a
	// caller that genuinely only wants cwd-visible profiles should pass.
	Root string
	// Profile limits the run to a single named profile; "" checks every
	// profile visible from cwd (project-local and global), the same set
	// jit status --secrets reconciles.
	Profile string
	// Integrity additionally runs vault.Verify on each existing secret,
	// turning "the file is there" into "this build of jit can actually read
	// its envelope" — still without decrypting, so still no auth prompt.
	Integrity bool
	// Orphans additionally reports vault secrets no profile references. It
	// needs the whole profile picture to be meaningful, so it is ignored
	// when Profile is set (a single profile can't tell you what's unused).
	Orphans bool
}

// checkOutcome is the structured result both jit doctor and jit status build
// their reports from — the one place the profile→vault check lives, so the
// glance (status) and the detail (doctor) can never drift on what "a
// problem" means.
type checkOutcome struct {
	ProfilesChecked int
	SecretsChecked  int
	OKRefs          []checkedRef
	// OKChecks are the non-reference checks that PASSED, as rendered lines —
	// today the wrap shims. Surfaced only under --verbose, and the reason the
	// standalone `jit wrap doctor` is no longer needed: confirming a shim
	// installation is healthy was the one thing it could say that the rollup,
	// which only ever reported failures, could not.
	OKChecks []string
	Findings []checkFinding
	// Cwd is where the profile sweep looked, retained so a zero-profile run
	// can say something more useful than "nothing here".
	Cwd string
	// WrapOnly marks a run that never swept profiles at all (`jit doctor
	// --wrap`). Without it the report closed on "No profiles found under
	// .jit/profiles/ or the global store" — a true statement about a search
	// that never happened, and exactly the kind of line that sends someone
	// looking for a second problem they don't have.
	WrapOnly bool
}

// Problems returns the hard findings — everything a warning() kind is not —
// in the order they were recorded. Their count is what flips ok=false and
// drives the non-zero exit.
func (o checkOutcome) Problems() []checkFinding {
	var out []checkFinding
	for _, f := range o.Findings {
		if !f.Kind.warning() {
			out = append(out, f)
		}
	}
	return out
}

// Warnings returns the advisory findings (orphans today) — surfaced to the
// user but never a reason to fail.
func (o checkOutcome) Warnings() []checkFinding {
	var out []checkFinding
	for _, f := range o.Findings {
		if f.Kind.warning() {
			out = append(out, f)
		}
	}
	return out
}

// runProfileCheck resolves the target profiles, checks every secret each
// references against the vault, and (per opts) verifies envelope integrity
// and sweeps for orphans — returning a structured outcome rather than
// pre-formatted text so each caller owns its own rendering. It never touches
// the vault's KeyWrapper (Exists/Verify/List are all auth-free), so it is
// safe to run as often as jit status does.
func runProfileCheck(cwd string, v *vault.Vault, opts checkOptions) (checkOutcome, error) {
	out := checkOutcome{Cwd: cwd}

	// scope is a plain string, not profile.Scope: a mount's manifest is
	// reached through the registry rather than through a scope lookup, so
	// scopeMount is a fourth value the profile package has no reason to know
	// about.
	type entry struct {
		name  string
		scope string
		prof  profile.Profile
	}
	var entries []entry
	// parseFailed records that at least one manifest wouldn't load. It gates
	// the orphan sweep: a profile we couldn't read contributes none of its
	// references to `referenced`, so calling its secrets "orphaned" would be
	// a lie — better to skip the sweep than emit false orphan warnings.
	parseFailed := false

	if opts.Profile != "" {
		p, scope, _, err := profile.LoadWithScope(cwd, opts.Profile)
		out.ProfilesChecked = 1
		if err != nil {
			// A named profile that won't load is a finding, not a fatal
			// error: doctor's job is to report, and a script asked to check
			// one profile still wants the verdict. Not-found and won't-parse
			// are separated so the reader is sent after the right fix.
			kind := kindParse
			if errors.Is(err, profile.ErrNotFound) {
				kind = kindNotFound
			}
			out.Findings = append(out.Findings, checkFinding{Kind: kind, Profile: opts.Profile, Detail: err.Error()})
			return out, nil
		}
		entries = append(entries, entry{name: opts.Profile, scope: string(scope), prof: p})
	} else {
		infos, err := profile.ListAll(cwd)
		if err != nil {
			return checkOutcome{}, err
		}
		out.ProfilesChecked = len(infos)

		// A name present in BOTH scopes is shadowed: Load resolves to the
		// project copy, so the global one is dead weight here. Collect the
		// project names first so the global pass can flag the overlap.
		projectNames := map[string]bool{}
		for _, info := range infos {
			if info.Scope == profile.ScopeProject {
				projectNames[info.Name] = true
			}
		}

		// seen keys the manifests already accounted for by PATH, so the mount
		// sweep below can add the ones nothing else reaches without
		// double-counting the (very common) mount that points straight at a
		// global profile ListAll already returned.
		seen := map[string]bool{}

		for _, info := range infos {
			if info.Scope == profile.ScopeGlobal && projectNames[info.Name] {
				out.Findings = append(out.Findings, checkFinding{
					Kind:    kindShadowed,
					Profile: info.Name,
					Scope:   string(profile.ScopeGlobal),
					Detail:  "also defined as a project profile, which wins; this global copy is ignored here",
					// No action line: nothing is broken, and the right fix
					// (delete one, rename one, or leave it) depends on which
					// copy the user actually meant. Inventing a command here
					// would be advice, not a next step.
				})
			}
			seen[filepath.Clean(info.Path)] = true
			p, err := profile.LoadFile(info.Path)
			if err != nil {
				parseFailed = true
				out.Findings = append(out.Findings, checkFinding{Kind: kindParse, Profile: info.Name, Scope: string(info.Scope), Detail: err.Error()})
				continue
			}
			entries = append(entries, entry{name: info.Name, scope: string(info.Scope), prof: p})
		}

		// A registered mount's profile is a first-class check target, not a
		// bystander. Its manifest can live in a project tree cwd will never
		// walk into, yet the agent is actively serving from it, so leaving it
		// out was wrong twice over: a secret only that profile referenced got
		// reported as an orphan (while `jit vault orphans` and `jit status`,
		// which both DO read the registry, correctly called it in use), and a
		// mount whose secret had gone missing was invisible — doctor printed
		// "all resolve cleanly" over a mount that could serve nothing.
		mountEntries, mountFindings, mountParseFailed := mountCheckTargets(opts.Root, seen)
		out.Findings = append(out.Findings, mountFindings...)
		if mountParseFailed {
			parseFailed = true
		}
		for _, me := range mountEntries {
			out.ProfilesChecked++
			entries = append(entries, entry{name: me.name, scope: scopeMount, prof: me.prof})
		}
	}

	// referenced collects every vault path any target profile points at, for
	// the orphan sweep below. cache dedupes the actual vault work: the same
	// path referenced by five profiles (or five variables) is one stat, not
	// five — a real saving on a shared credential without changing any count.
	referenced := map[string]bool{}
	cache := map[string]secretStatus{}

	for _, e := range entries {
		vars := make([]string, 0, len(e.prof))
		for varName := range e.prof {
			vars = append(vars, varName)
		}
		sort.Strings(vars)

		for _, varName := range vars {
			secretPath := e.prof[varName]
			out.SecretsChecked++
			referenced[secretPath] = true

			status := checkSecret(v, secretPath, opts.Integrity, cache)
			switch status.kind {
			case kindCorrupt, kindMissing, kindVaultError, kindBadPath:
				out.Findings = append(out.Findings, checkFinding{
					Kind:     status.kind,
					Profile:  e.name,
					Scope:    e.scope,
					Variable: varName,
					Path:     secretPath,
					Detail:   status.detail,
					Action:   secretAction(status.kind, secretPath),
				})
			default:
				out.OKRefs = append(out.OKRefs, checkedRef{
					Profile:  e.name,
					Scope:    e.scope,
					Variable: varName,
					Path:     secretPath,
				})
			}
		}
	}

	// Orphan detection needs the WHOLE profile picture to be truthful, so it
	// runs only across all profiles (not --profile), only when at least one
	// profile actually loaded (a zero-profile directory would otherwise call
	// the entire vault orphaned), and only when every manifest parsed (an
	// unreadable one leaves `referenced` incomplete — see parseFailed).
	if opts.Orphans && opts.Profile == "" && len(entries) > 0 && !parseFailed {
		paths, err := v.List()
		if err != nil {
			// The orphan sweep is a bonus; a vault it can't list is still a
			// reportable problem, not a reason to lose the checks above.
			out.Findings = append(out.Findings, checkFinding{Kind: kindVaultError, Detail: fmt.Sprintf("listing the vault for orphan detection: %v", err)})
			return out, nil
		}
		secrets, _ := splitBackupPaths(paths)
		for _, p := range secrets {
			if !referenced[p] {
				out.Findings = append(out.Findings, checkFinding{
					Kind:   kindOrphan,
					Path:   p,
					Detail: "in the vault but referenced by no profile",
					// Identical for every orphan, which is exactly why the
					// renderer states a group's shared action once rather
					// than repeating it under each of twenty lines.
					Action: "`jit vault orphans --prune` to delete, or `jit vault list` to inspect first",
				})
			}
		}
	}

	return out, nil
}

// secretAction is the one runnable step for a broken secret reference.
// Missing and corrupt want different fixes: one is "put a value there", the
// other is "the value there is unreadable, restore or replace it".
// kindVaultError names a malformed path or an unreadable store — neither has
// a single command behind it, so it gets no action line rather than a guess.
func secretAction(kind checkKind, secretPath string) string {
	switch kind {
	case kindMissing:
		return fmt.Sprintf("`jit vault set %s`, or `jit migrate <path>` to convert the file it came from", secretPath)
	case kindCorrupt:
		return fmt.Sprintf("`jit vault history %s` to see earlier versions, or `jit vault set %s` to replace it", secretPath, secretPath)
	default:
		return ""
	}
}

// scopeMount labels a finding whose profile was reached through the mount
// registry rather than through cwd's project/global scopes — so a report can
// say WHERE a broken reference came from, which for a manifest sitting in
// some other project's tree is the whole difference between an actionable
// finding and a mystery.
const scopeMount = "mount"

// mountTarget is one registered mount's loaded profile.
type mountTarget struct {
	name string
	prof profile.Profile
}

// mountCheckTargets loads the profile behind every registered mount that
// `seen` doesn't already cover, keyed by cleaned manifest path.
//
// Both failure modes are reported rather than swallowed. A machine that has
// never mounted anything has no registry FILE, and mount.LoadRegistry returns
// no error for that (see loadRegistry) — so an error here always means the
// file is there and unreadable or malformed, which leaves the agent unable to
// tell what it is meant to serve. A registry entry whose manifest won't load
// is the same shape of problem one level down: the state `reconcileSecrets`
// deliberately tolerates because `jit status` must never fail, which is
// precisely why reporting it falls to doctor.
//
// parseFailed comes back separately so the caller can suppress the orphan
// sweep: a mount profile we couldn't read contributes none of its references,
// and calling its secrets orphaned would be the same lie an unreadable
// project manifest would tell.
func mountCheckTargets(root string, seen map[string]bool) (targets []mountTarget, findings []checkFinding, parseFailed bool) {
	if root == "" {
		return nil, nil, false
	}
	entries, err := mount.LoadRegistry(mount.RegistryPath(root))
	if err != nil {
		return nil, []checkFinding{{
			Kind:   kindMount,
			Scope:  scopeMount,
			Detail: fmt.Sprintf("the mount registry won't load, so jit can't tell which files it is meant to serve: %v", err),
			Action: "`jit unmount --all` and re-run `jit migrate` to rebuild it",
		}}, true
	}
	for _, e := range entries {
		clean := filepath.Clean(e.ProfilePath)
		if seen[clean] {
			continue
		}
		seen[clean] = true
		p, err := profile.LoadFile(e.ProfilePath)
		if err != nil {
			parseFailed = true
			// The error already names the manifest path in full, so the
			// detail says only which MOUNT is affected — repeating the same
			// long path twice in one finding was the single worst line in
			// the report (rule 5: state a shared fact once).
			findings = append(findings, checkFinding{
				Kind:   kindMount,
				Scope:  scopeMount,
				Path:   e.MountPath,
				Detail: fmt.Sprintf("the mount at %s can't be served: %s", shortPath(e.MountPath), shortHome(err.Error())),
				// shortPath in the ACTION too, not just the detail: "~" is
				// what a shell expands, so the command stays runnable
				// verbatim while fitting the window (rule 6). An unshortened
				// path here pushed the one runnable thing on screen onto
				// three wrapped lines.
				Action: "fix the manifest, or `jit unmount " + shortPath(e.MountPath) + "` to stop tracking it",
			})
			continue
		}
		// The manifest's own filename is the only name a registry entry
		// carries — there is no separate profile name in the registry.
		name := strings.TrimSuffix(filepath.Base(clean), filepath.Ext(clean))
		targets = append(targets, mountTarget{name: name, prof: p})
	}
	return targets, findings, parseFailed
}

// secretStatus is one path's verdict, cached across profiles that share it.
type secretStatus struct {
	kind   checkKind // kindMissing/kindCorrupt/kindVaultError/kindBadPath, or "" for OK
	detail string
}

// checkSecret resolves one secret path to a status, memoizing through cache.
// Existence first (a bare stat, always); Verify (envelope parse + version,
// still no decrypt) only when integrity is requested and the file is there.
func checkSecret(v *vault.Vault, secretPath string, integrity bool, cache map[string]secretStatus) secretStatus {
	if s, ok := cache[secretPath]; ok {
		return s
	}
	var s secretStatus
	exists, err := v.Exists(secretPath)
	switch {
	case errors.Is(err, vault.ErrInvalidPath):
		s = secretStatus{kind: kindBadPath, detail: err.Error()}
	case err != nil:
		s = secretStatus{kind: kindVaultError, detail: err.Error()}
	case !exists:
		s = secretStatus{kind: kindMissing}
	case integrity:
		if verr := v.Verify(secretPath); verr != nil {
			s = secretStatus{kind: kindCorrupt, detail: verr.Error()}
		}
	}
	cache[secretPath] = s
	return s
}
