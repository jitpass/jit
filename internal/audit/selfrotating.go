// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"path/filepath"
	"strings"
)

// selfRotatingCache is a credential file a TOOL maintains for itself: the
// tool mints the value, writes it, and rewrites it on its own schedule when
// the value refreshes. jit can report one, and can say how to revoke it —
// but it must never offer to protect one in place.
//
// The test for membership is mechanical: does the owning tool rewrite this
// path without being asked? If it does, a mount loses. `jit migrate --mount`
// replaces the file with a FIFO serving vault content, so the tool's next
// refresh either writes over the pipe (protection silently gone) or fails
// against it, and every read in between serves a token the provider already
// rotated away. The honest remedy for the whole class is the provider's own:
// revoke, then let the tool re-authenticate.
//
// This began as a single inline check for ~/.mcp-auth, in two places that
// had to agree (the remedy switch and the report's action line). It is a
// table because it was never one path. ~/.gemini/oauth_creds.json is the
// same mechanism — an OAuth access/refresh pair the Gemini CLI rewrites
// whenever the access token expires — and a real scan told it to mount
// itself (2026-07-29), which is the exact advice the .mcp-auth carve-out
// exists to prevent. The AWS CLI's own caches are this class one step
// further out: never findings at all, reported as advisories by
// ScanDerivedCredentials.
type selfRotatingCache struct {
	// match is a path fragment: for a dir entry, a component that must
	// appear in the path; for a file entry, the exact trailing path.
	// Deliberately home-independent — these tools use the same layout under
	// any HOME, and a scan of a copied-out home directory should recognize
	// them just the same.
	match string
	dir   bool
	// title is what the file IS, in the report's voice.
	title string
	// action is the one honest instruction for it.
	action string
	// toolMinted marks the entries whose VALUE the tool minted for itself —
	// an OAuth pair the CLI writes on login and rewrites on refresh. These
	// stay findings (a refresh token is a durable credential, worth naming
	// and worth revoking if exposed — the issue #93 decision), but they are
	// excluded from the coverage ledger: the only "fix" jit can offer
	// (sign out and back in) reproduces the same plaintext file, so counting
	// them under "only you can fix, → 100%" promised a 100% the user could
	// never reach while the tool stayed installed. The triage view renders
	// them in their own uncounted block instead.
	//
	// False for a tool-REWRITTEN file holding a USER-stored value
	// (.clisso.yaml's OneLogin client-secret): that credential is the user's,
	// `jit wrap clisso` genuinely protects it, and it counts.
	toolMinted bool
}

var selfRotatingCaches = []selfRotatingCache{
	{
		match:      mcpAuthDir,
		dir:        true,
		title:      "A remote-MCP OAuth token (rotates itself)",
		action:     "revoke at the provider if exposed; reset with rm -rf ~/.mcp-auth",
		toolMinted: true,
	},
	{
		match:      filepath.Join(".gemini", "oauth_creds.json"),
		title:      "A Gemini CLI OAuth token (rotates itself)",
		action:     "revoke at the provider if exposed; sign out and back in to reset",
		toolMinted: true,
	},
	// The gcloud CLI's own login store (issue #93). gcloud rewrites
	// credentials.db on login, reauth and refresh-token rotation, and the
	// legacy_credentials tree on every login — and both are doubly out of
	// mount's reach: a SQLite file needs seeks and byte-range locks no FIFO
	// can serve, and the tool writes back. scanGcloudCLICredentials reports
	// what is inside; these entries keep the remedy manual so scan never
	// promises a `jit migrate` that migrate would refuse.
	// One shared action string for both gcloud entries: the triage group
	// prints a single arrow for the class, so two entries that will always
	// appear together must agree on it or the group shows one of them
	// picked arbitrarily.
	{
		match:      filepath.Join(".config", "gcloud", "credentials.db"),
		title:      "The gcloud CLI's own login (gcloud rewrites this store itself)",
		action:     "revoke with `gcloud auth revoke` if exposed, then log in again when needed",
		toolMinted: true,
	},
	{
		// Anchored under .config/gcloud, not a bare component match: a
		// project's own legacy_credentials/ directory holding, say, a
		// Stripe key must keep its migrate offer and must not be told to
		// run `gcloud auth revoke` (code review, 2026-09-10).
		match:      filepath.Join(".config", "gcloud", "legacy_credentials"),
		dir:        true,
		title:      "A gcloud legacy credential copy (rewritten on every login)",
		action:     "revoke with `gcloud auth revoke` if exposed, then log in again when needed",
		toolMinted: true,
	},
	// A variant of the class: the value (a OneLogin API client-secret)
	// never rotates, but the file is still tool-rewritten — clisso creates
	// it on any run and rewrites it wholesale from `clisso apps create`,
	// `providers passwd`, and `cp`. The mount-loses logic is identical: a
	// FIFO here would break those commands against a pipe, so the mount
	// offer must never be made. The protection that DOES exist is
	// `jit wrap clisso` — the capture shim serves the real config per run
	// and reconciles the file after clisso's own writes, which a static
	// mount could never do. scanClissoConfig points the client-secret
	// finding there itself; this entry keeps the mount offer suppressed
	// for any OTHER secret the sweep finds in this file.
	{
		match:  ".clisso.yaml",
		title:  "A secret in clisso's config (clisso rewrites this file itself)",
		action: "`jit wrap clisso` vaults the client-secret; anything else here, move out and rotate — jit never mounts a file clisso rewrites",
	},
}

// selfRotatingCacheFor returns the class entry describing path, if any.
func selfRotatingCacheFor(path string) (selfRotatingCache, bool) {
	sep := string(filepath.Separator)
	for _, c := range selfRotatingCaches {
		if c.dir {
			if strings.Contains(path, sep+c.match+sep) {
				return c, true
			}
			continue
		}
		if strings.HasSuffix(path, sep+c.match) {
			return c, true
		}
	}
	return selfRotatingCache{}, false
}

// isSelfRotatingCache reports whether path belongs to the class.
func isSelfRotatingCache(path string) bool {
	_, ok := selfRotatingCacheFor(path)
	return ok
}

// toolMintedLoginFor returns the tool-minted class entry for path, if any —
// the subset of selfRotatingCaches the coverage ledger excludes (see
// selfRotatingCache.toolMinted).
func toolMintedLoginFor(path string) (selfRotatingCache, bool) {
	c, ok := selfRotatingCacheFor(path)
	if !ok || !c.toolMinted {
		return selfRotatingCache{}, false
	}
	return c, true
}

// toolMintedLogin reports whether f is a finding the triage view renders in
// its uncounted "rotates itself" block: a Critical/High/Medium match inside a
// tool-minted login store. The severity and fixture gates mirror
// CountedAsSecret's, so this names exactly the findings that WOULD have
// counted but for the class — the footer's low-confidence tally keeps the
// rest, unchanged.
func toolMintedLogin(f Finding) bool {
	if f.TestFixture || f.SourceExample {
		return false
	}
	switch f.Severity {
	case SeverityCritical, SeverityHigh, SeverityMedium:
		_, ok := toolMintedLoginFor(f.FilePath)
		return ok
	default:
		return false
	}
}

// mountableExts are the file kinds where replacing the file with a jit FIFO
// is a working substitute: a program opens the path at runtime, reads it
// once, and closes it.
//
// An allowlist, because the two failure directions are not symmetric.
// Offering --mount for a file nothing reads at runtime is advice that cannot
// help. Offering it for a file OTHER tooling reads is advice that breaks the
// machine: a compiler, a linter, an editor and git all re-read source on
// their own schedule, none of them are under a `jit run` grant, and so each
// would be served decoy content. That is how a real scan came to print
// `jit migrate internal/audit/tokenpatterns_test.go --mount` (2026-07-29) —
// a command that would have replaced this repository's own scanner fixtures
// with a pipe and broken its build.
var mountableExts = map[string]bool{
	".env": true, ".json": true, ".yaml": true, ".yml": true,
	".toml": true, ".ini": true, ".conf": true, ".cfg": true,
	".config": true, ".properties": true, ".netrc": true, ".npmrc": true,
	".pypirc": true, ".tfvars": true,
	// Scripts read their own secrets at run time, and a mount serves them
	// under a grant exactly like a .env — this is the case the --mount offer
	// was written for.
	".sh": true, ".bash": true, ".zsh": true,
}

// mountable reports whether offering `jit migrate <path> --mount` for path
// could actually help. See mountableExts for why the answer defaults to no.
func mountable(path string) bool {
	name := strings.ToLower(filepath.Base(path))
	// .env.local, .env.production: the family Ext() cannot see, because the
	// meaningful part is a prefix.
	if strings.HasPrefix(name, ".env") {
		return true
	}
	ext := filepath.Ext(name)
	if ext == "" {
		// No extension at all is the shape of a hand-placed config or
		// credential store (~/.aws/credentials, ~/.docker/config), never the
		// shape of source a compiler re-reads.
		return true
	}
	return mountableExts[ext]
}

// isTerraformState reports whether path is a Terraform state file.
//
// State is where Terraform records every attribute it wrote, including the
// ones that were secret: HashiCorp's own documentation says so plainly, and
// local state is plaintext by design. jit cannot protect it — Terraform
// writes the file itself, with no seam to interpose on the way credential_
// process gives jit one for the AWS CLI — so this exists to make the scan
// stop walking past it, not to make `jit migrate` claim it.
//
// The name gate matters because nothing else admits these files: a state
// file is called terraform.tfstate, so the content sweep's credential-word
// filename hints never fire on it, and it would otherwise be read by nobody.
func isTerraformState(path string) bool {
	name := strings.ToLower(filepath.Base(path))
	return strings.HasSuffix(name, ".tfstate") || strings.HasSuffix(name, ".tfstate.backup")
}
