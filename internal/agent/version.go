// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package agent

import (
	"regexp"
	"runtime/debug"
)

// version is set at build time via -ldflags
// "-X github.com/jitpass/jit/internal/agent.version=vX.Y.Z" (see
// .goreleaser.yml). It lives here rather than internal/cli for the same
// reason BuildID does: both sides of the socket report it — the CLI as
// `jit --version` and `jit status`'s own version, the agent on every
// OpStatus — and internal/agent is the one deliberately portable package
// they share.
var version = "dev"

// Version identifies which release of jit this process is running:
// the goreleaser-stamped version for release binaries, or the module
// version Go embedded for builds that never get the ldflags stamp —
// `go install github.com/jitpass/jit/cmd/jit@vX.Y.Z` and, on Go 1.24+,
// in-tree `go build`s too (the toolchain stamps the nearest VCS tag,
// e.g. "v0.8.2+dirty"). "dev" only when nothing better is embedded
// (e.g. a `go test` binary). Complements BuildID(), which answers the
// finer-grained "which exact revision" — a released version and a VCS
// revision identify a build at different zoom levels, and status
// reports carry both.
func Version() string {
	if version != "dev" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		if v := bi.Main.Version; v != "" && v != "(devel)" && !isPseudoVersion(v) {
			return v
		}
	}
	return version
}

// pseudoVersion matches Go's synthesized "no tag here" version:
// vX.Y.Z-<pre.>0.<14-digit UTC stamp>-<12 hex of the commit>, with the
// "+dirty" build metadata an in-tree build adds.
var pseudoVersion = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?-?[0-9]{14}-[0-9a-f]{12}(\+[0-9A-Za-z.-]+)?$`)

// isPseudoVersion reports whether v is synthesized rather than a tag.
//
// It must be rejected, not reported, because it is a confident wrong
// answer. This module's path carries no /vN suffix while the repo is
// tagged v2.x, so the toolchain ignores every v2 tag and derives the
// pseudo-version from the highest v1 one: an in-tree `go build` of a v2.1
// tree reports "v1.9.1-0.<stamp>-<sha>", and shortVersion renders that as
// "v1.9.1" — a real release, and not this binary. doctor puts that string
// in its footer precisely so a pasted report can be tied to a build, so
// naming the wrong release is worse there than admitting to none.
//
// A genuine tag (`go install …@v1.9.0`) is not a pseudo-version and is
// still reported. Falling back to "dev" loses nothing: BuildID() carries
// the exact revision, and status and doctor print both.
func isPseudoVersion(v string) bool { return pseudoVersion.MatchString(v) }
