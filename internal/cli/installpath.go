// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"path/filepath"
	"strings"
)

// stableBinaryPath resolves exePath to the path a DURABLE reference should
// record: the binary the launchd plist re-execs at every login, the target a
// wrap shim symlinks to. For almost everyone that is plain EvalSymlinks —
// resolve the install symlink or shim to the real file, so the reference
// survives the name in front of it being rearranged.
//
// The exception is a Homebrew-managed jit, where full resolution lands in a
// VERSIONED directory (/opt/homebrew/Caskroom/jitpass/0.80.1/jit) that the
// very next `brew upgrade` deletes. Recording that path is how an upgrade
// used to orphan the service plist and dangle every wrap shim at once. The
// durable name in a brew install is the one brew relinks on every upgrade:
// the prefix's bin symlink (/opt/homebrew/bin/jit). So when resolution ends
// inside a Caskroom or Cellar, this recovers that bin path from the layout —
// prefix/bin/<name>, the prefix being whatever sits above Caskroom — and
// returns it only after proving it currently resolves back to the very same
// file. Recovering from the layout rather than walking the symlinks in hand
// means a DIRECT invocation of the Caskroom copy (launchd re-running an old
// plist, a shim that resolved all the way through) heals onto the stable
// name too, instead of re-recording the versioned one.
//
// Anything unexpected — no bin symlink, or one pointing at a different build
// — falls back to the fully resolved path, which is at worst the old
// behaviour.
func stableBinaryPath(exePath string) (string, error) {
	resolved, err := filepath.EvalSymlinks(exePath)
	if err != nil {
		return "", err
	}
	sep := string(filepath.Separator)
	segs := strings.Split(resolved, sep)
	brewIdx := -1
	for i, seg := range segs {
		if seg == "Caskroom" || seg == "Cellar" {
			brewIdx = i
			break
		}
	}
	if brewIdx <= 0 {
		return resolved, nil
	}
	prefix := strings.Join(segs[:brewIdx], sep)
	candidate := filepath.Join(prefix, "bin", filepath.Base(resolved))
	if r, cerr := filepath.EvalSymlinks(candidate); cerr == nil && r == resolved {
		return candidate, nil
	}
	return resolved, nil
}
