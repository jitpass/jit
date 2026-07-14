// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

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
// data contains zero parsing (docs/WRAP-PLAN.md §4).
var extractors = map[string]extractor{
	"yaml": extractYAML,
	"toml": extractTOML,
}

// ExtractToken reads src's file under home and applies its extractor.
// A missing file is (found=false, nil): the tool simply isn't configured
// there. Used by both the wrap flow and audit's wrappable-cli-token signal,
// which is what keeps detection and migration from ever disagreeing.
func ExtractToken(home string, src TokenSource) (value string, found bool, err error) {
	ext, ok := extractors[src.Format]
	if !ok {
		return "", false, fmt.Errorf("no extractor for format %q", src.Format)
	}
	data, err := os.ReadFile(ExpandHome(home, src.Path)) // #nosec G304 -- a fixed catalog path under the user's home dir
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
