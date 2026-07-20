// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package cli

import (
	"fmt"
	"sort"

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
	// kindAgent/kindBackup/kindWrap are the absorbed system-health sections
	// (mega-doctor). All three are advisory: a stopped agent, an unrecorded
	// or stale export, and a broken/misplaced wrap shim each break something
	// worth surfacing, but none of them makes a profile's secret unresolvable
	// — doctor's non-zero exit stays reserved for that. (The dedicated `jit
	// wrap doctor` still exits non-zero on a shim failure; here it is one ⚠
	// line among the rollup, and folding an environmental "shim dir not on
	// PATH in THIS shell" check into doctor's exit code would fail CI runs
	// that legitimately don't put it there.)
	kindAgent  checkKind = "agent"
	kindBackup checkKind = "backup"
	kindWrap   checkKind = "wrap"
)

// warning reports whether a finding of this kind is advisory (does not fail
// the run or flip ok=false) rather than a hard problem. Only a profile's own
// secret being missing, corrupt, or unparseable is a hard problem; everything
// else — an extra secret, a shadowed profile, a stopped agent, a stale
// backup, a broken wrap shim — is advisory.
func (k checkKind) warning() bool {
	switch k {
	case kindOrphan, kindShadowed, kindAgent, kindBackup, kindWrap:
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
	// Profile limits the run to a single named profile; "" checks every
	// profile visible from cwd (project-local and global), the same set
	// jit profile list shows.
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
	Findings        []checkFinding
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
	var out checkOutcome

	type entry struct {
		name  string
		scope profile.Scope
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
			// A named profile that won't load (not found, bad YAML) is a
			// parse finding, not a fatal error: doctor's job is to report,
			// and a script asked to check one profile still wants the verdict.
			out.Findings = append(out.Findings, checkFinding{Kind: kindParse, Profile: opts.Profile, Detail: err.Error()})
			return out, nil
		}
		entries = append(entries, entry{name: opts.Profile, scope: scope, prof: p})
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

		for _, info := range infos {
			if info.Scope == profile.ScopeGlobal && projectNames[info.Name] {
				out.Findings = append(out.Findings, checkFinding{
					Kind:    kindShadowed,
					Profile: info.Name,
					Scope:   string(profile.ScopeGlobal),
					Detail:  "also defined as a project profile, which wins; this global copy is ignored here",
				})
			}
			p, err := profile.LoadFile(info.Path)
			if err != nil {
				parseFailed = true
				out.Findings = append(out.Findings, checkFinding{Kind: kindParse, Profile: info.Name, Scope: string(info.Scope), Detail: err.Error()})
				continue
			}
			entries = append(entries, entry{name: info.Name, scope: info.Scope, prof: p})
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
			case kindCorrupt, kindMissing, kindVaultError:
				out.Findings = append(out.Findings, checkFinding{
					Kind:     status.kind,
					Profile:  e.name,
					Scope:    string(e.scope),
					Variable: varName,
					Path:     secretPath,
					Detail:   status.detail,
				})
			default:
				out.OKRefs = append(out.OKRefs, checkedRef{
					Profile:  e.name,
					Scope:    string(e.scope),
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
				})
			}
		}
	}

	return out, nil
}

// secretStatus is one path's verdict, cached across profiles that share it.
type secretStatus struct {
	kind   checkKind // kindMissing, kindCorrupt, kindVaultError, or "" for OK
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
