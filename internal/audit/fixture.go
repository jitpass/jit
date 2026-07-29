// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"path/filepath"
	"strings"
)

// fixtureDirNames are path components whose contents are, by overwhelming
// convention, inputs written FOR a test rather than credentials belonging to
// the user. Kept narrow on purpose: "test"/"tests"/"spec" as bare directory
// names are common enough in ordinary source trees that treating them as
// fixture markers would start hiding real files.
var fixtureDirNames = map[string]bool{
	"testdata": true, "fixtures": true, "__fixtures__": true,
	"__tests__": true, "__mocks__": true,
}

// fixtureFileSuffixes are the per-language spellings of "this file IS a
// test", matched against the lowercased base name.
var fixtureFileSuffixes = []string{
	"_test.go",
	"_test.py", "_test.rb", "_test.js", "_test.ts",
	"_spec.rb",
	".test.js", ".test.ts", ".test.jsx", ".test.tsx",
	".spec.js", ".spec.ts", ".spec.jsx", ".spec.tsx",
}

// LooksTestFixture reports whether path is test scaffolding: a file under a
// testdata/fixtures directory, or a test source file itself.
//
// Why this earns a flag of its own rather than a severity downgrade: a
// vendor-format value in a fixture is a real value of a real shape, which is
// the entire point of it — scanner tests need inputs that look exactly like
// the thing being detected. What is false is not the match but the OWNERSHIP.
// The user did not store that credential; a test author wrote it to exercise
// a parser, and there is nothing to rotate, revoke or vault.
//
// So a fixture finding stays fully visible in `jit scan --full` and in
// NDJSON, flagged, and simply stops being charged to the coverage ledger
// (see CountedAsSecret). jit's rule throughout is that what it does not
// stand behind, it does not spend the user's attention on; counting fixtures
// broke that twice over, by demanding work to reach 100% and — on jit's own
// repository — by recommending a mount that would have broken the build.
//
// The cost of being wrong is bounded and one-directional: a genuine key
// someone parked in testdata/ is still reported, still in --full, still in
// the machine stream. It is quieter, never invisible.
func LooksTestFixture(path string) bool {
	parts := strings.Split(filepath.ToSlash(path), "/")
	for i, part := range parts {
		if i == len(parts)-1 {
			break // the base name is judged by suffix below, not as a dir
		}
		if fixtureDirNames[strings.ToLower(part)] {
			return true
		}
	}

	name := strings.ToLower(filepath.Base(path))
	for _, suffix := range fixtureFileSuffixes {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	// Python's other convention puts the marker in front: test_parser.py.
	return strings.HasPrefix(name, "test_") && filepath.Ext(name) == ".py"
}
