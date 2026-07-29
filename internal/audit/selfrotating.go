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
}

var selfRotatingCaches = []selfRotatingCache{
	{
		match:  mcpAuthDir,
		dir:    true,
		title:  "A remote-MCP OAuth token (rotates itself)",
		action: "revoke at the provider if exposed; reset with rm -rf ~/.mcp-auth",
	},
	{
		match:  filepath.Join(".gemini", "oauth_creds.json"),
		title:  "A Gemini CLI OAuth token (rotates itself)",
		action: "revoke at the provider if exposed; sign out and back in to reset — the CLI rewrites this file on every refresh",
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
