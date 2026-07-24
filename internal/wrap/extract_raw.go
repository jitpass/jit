// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package wrap

import "strings"

// extractRaw treats the whole file as the credential: trim surrounding
// whitespace and return what's left. The selector is unused — catalog
// entries leave it empty. Anything with internal whitespace after trimming
// is refused, same stance as the structured extractors: a raw credential
// file holds exactly one token, so a multi-token or prose file means the
// path isn't what the catalog thinks it is, and vaulting it blind would
// scrub the wrong thing.
func extractRaw(data []byte, _ string) (string, bool) {
	value := strings.TrimSpace(string(data))
	if value == "" || strings.ContainsAny(value, " \t\r\n") {
		return "", false
	}
	return value, true
}
