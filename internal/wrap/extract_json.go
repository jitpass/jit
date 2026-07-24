// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package wrap

import "encoding/json"

// extractJSON walks a JSON object tree along the selector's segments and
// returns the string at the end. Objects only, same stance as extractYAML:
// no cataloged file selects into an array, and guessing at index semantics
// would let a wrong selector match the wrong value silently.
func extractJSON(data []byte, selector string) (string, bool) {
	var root any
	if err := json.Unmarshal(data, &root); err != nil {
		return "", false
	}
	node := root
	for _, part := range selectorParts(selector) {
		obj, ok := node.(map[string]any)
		if !ok {
			return "", false
		}
		node, ok = obj[part]
		if !ok {
			return "", false
		}
	}
	s, ok := node.(string)
	if !ok || s == "" {
		return "", false
	}
	return s, true
}
