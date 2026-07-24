// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package wrap

import (
	"fmt"
	"os"
	"strings"
)

// An extractor pulls one string value out of a config file's bytes given a
// format-specific selector. found=false means "file parsed fine, value not
// there" — a normal state (tool not logged in), never an error.
type extractor func(data []byte, selector string) (value string, found bool)

// extractors registers one extractor per TokenSource.Format. Formats and
// their files stay decoupled: extractors contain zero tool names, catalog
// data contains zero parsing (docs/internal/WRAP-PLAN.md §4).
var extractors = map[string]extractor{
	"yaml": extractYAML,
	"toml": extractTOML, // also covers INI files, same line shape
	"json": extractJSON,
	"raw":  extractRaw, // the whole file is the credential; selector unused
}

// ExtractToken reads src's file under home and applies its extractor.
// A missing file is (found=false, nil): the tool simply isn't configured
// there. Used by both the wrap flow and audit's wrappable-cli-token signal,
// which is what keeps detection and migration from ever disagreeing.
//
// A source path that is currently a live jit mount (a FIFO — GAPS.md #2,
// decoy-by-default) is refused with an error, never read: a
// plain os.ReadFile against a FIFO with jit's own Serve goroutine behind it
// doesn't fail or block, it rendezvouses with whatever cycle is being
// served right now — decoy content by default. Reading it here would
// silently vault decoy bytes (`jit-hidden-...`) as if they were the real
// credential, and a later ScrubToken write against the same path would
// push bytes into the pipe instead of editing a file. No catalog entry's
// Source could collide with a mount until gemini/codex: their Source IS a
// `.env`/JSON file jit migrate's own home-wide `.env` discovery
// (migrate.DiscoverEnvFiles, matched by filename pattern anywhere under
// $HOME) can independently turn into a mount before `jit wrap` ever runs.
func ExtractToken(home string, src TokenSource) (value string, found bool, err error) {
	ext, ok := extractors[src.Format]
	if !ok {
		return "", false, fmt.Errorf("no extractor for format %q", src.Format)
	}
	path := ExpandHome(home, src.Path)
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", false, nil
		}
		return "", false, err
	}
	if info.Mode()&os.ModeNamedPipe != 0 {
		return "", false, fmt.Errorf("%s is a live jit mount, not a plaintext file — its value is already in the vault under whatever profile `jit migrate` created for it, not readable here; run `jit vault get`/`jit export` to see the value, or check `jit status` for the profile it belongs to", path)
	}
	data, err := os.ReadFile(path) // #nosec G304 -- a fixed catalog path under the user's home dir
	if err != nil {
		if os.IsNotExist(err) {
			return "", false, nil
		}
		return "", false, err
	}
	value, found = ext(data, src.Selector)
	return value, found, nil
}

// selectorParts splits a "/"-separated selector. "/" rather than "." so
// keys like "github.com" survive as single segments.
func selectorParts(selector string) []string {
	return strings.Split(selector, "/")
}
