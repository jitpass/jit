// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"os"
	"regexp"
	"testing"
)

// findingTypeDecl matches a finding type as declared in finding.go's const
// block, e.g. `FindingTypeExposedSecret = "exposed_secret"` — trailing #nosec
// comments and gofmt's alignment padding included.
var findingTypeDecl = regexp.MustCompile(`(?m)^\s*FindingType[A-Za-z0-9]+\s*=\s*"([a-z_0-9]+)"`)

// TestAllFindingTypesListsEveryDeclaredType closes the hole in every test that
// walks AllFindingTypes (scan_test, markdown, ndjson, the report): each proves
// "every type SOMEONE REMEMBERED TO REGISTER is handled", never "every type
// exists". The slice is hand-maintained, so a new const that never gets a line
// added is invisible to all of them at once.
//
// That is not hypothetical — it is the failure AllFindingTypes' own comment
// records, and the same shape as kindMCP in internal/cli: a finding absent
// from this slice is silently dropped from scan_summary's
// findings_by_category, from the markdown report, and from the NDJSON stream,
// while every existing test stays green.
//
// Both directions, because a stale entry is the mirror failure: a slice naming
// a const that was renamed or removed emits a category key for a finding type
// nothing can ever produce.
func TestAllFindingTypesListsEveryDeclaredType(t *testing.T) {
	const src = "finding.go"
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("reading %s: %v", src, err)
	}

	matches := findingTypeDecl.FindAllStringSubmatch(string(data), -1)
	// Without this the guard passes vacuously the day the constants are
	// renamed or moved to another file.
	if len(matches) < 10 {
		t.Fatalf("found only %d FindingType constants in %s — the guard would pass vacuously; fix findingTypeDecl", len(matches), src)
	}

	listed := make(map[string]bool, len(AllFindingTypes))
	for _, ft := range AllFindingTypes {
		listed[ft] = true
	}
	declared := make(map[string]bool, len(matches))
	for _, m := range matches {
		declared[m[1]] = true
		if !listed[m[1]] {
			t.Errorf("finding type %q is declared in %s but missing from AllFindingTypes; "+
				"it would be dropped from findings_by_category, the markdown report and the "+
				"NDJSON stream, with every existing test still green", m[1], src)
		}
	}
	for _, ft := range AllFindingTypes {
		if !declared[ft] {
			t.Errorf("AllFindingTypes lists %q, which no FindingType constant in %s declares; "+
				"scan_summary carries a category key nothing can ever produce", ft, src)
		}
	}
}
