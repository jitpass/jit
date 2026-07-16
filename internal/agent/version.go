// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package agent

import "runtime/debug"

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
		if v := bi.Main.Version; v != "" && v != "(devel)" {
			return v
		}
	}
	return version
}
