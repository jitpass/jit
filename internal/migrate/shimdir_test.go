// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"path/filepath"
	"testing"

	"github.com/jitpass/jit/internal/wrap"
)

// TestHelperPathsLiveInWrapsShimDir pins the ".jit/shims" copies in
// DockerHelperPath and GitHelperPath to the directory internal/wrap actually
// owns and keeps on PATH.
//
// Both functions carry the path as "a small independent copy … rather than an
// import of internal/wrap", and that stays as it is on purpose: migrate does
// not import wrap in production, reversing that is the maintainer's call, and
// the 2026-08-06 review declined to make it. What was missing is any check at
// all — if wrap ever moves its shim directory, both helper scripts land in a
// directory that is no longer on anyone's PATH, and docker/git report the
// helper missing with nothing pointing at why. wrap is already in migrate's
// transitive dependencies, and a TEST import adds no production edge — the
// same shape the AEAD interop test uses between keychainwrap and agent.
func TestHelperPathsLiveInWrapsShimDir(t *testing.T) {
	const home = "/Users/fixture"
	shimDir := wrap.ShimDir(home)
	for name, path := range map[string]string{
		"DockerHelperPath": DockerHelperPath(home),
		"GitHelperPath":    GitHelperPath(home),
	} {
		if got := filepath.Dir(path); got != shimDir {
			t.Errorf("%s puts its helper in %q, but wrap's shim directory is %q; "+
				"docker/git would look the helper up on PATH and not find it", name, got, shimDir)
		}
	}
}
