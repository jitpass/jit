// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import "fmt"

// assignUniqueVarNames resolves sanitization collisions between placeholder
// variable names. identities[i] is what makes match i distinct in the source
// format (a .pypirc section name, an npmrc key); base[i] is the sanitized
// name derived from it. Matches sharing an identity share a name (repeats of
// one section/key — last value wins, as the formats' own parsers read them),
// but two DISTINCT identities never share one: the later claimant gets a
// "_2"/"_3" suffix.
//
// Without this, [my-index] and [my_index] both sanitized to
// MY_INDEX_PASSWORD: one section's password silently overwrote the other's
// in the vault, the template stamped the surviving value into BOTH sections,
// and the mount then served repo B's password for repo A — uploads to A fail
// against a correct-looking file, while A's real password survives only in
// the encrypted backup. Found in review, 2026-07-28. The suffix scheme
// mirrors nameLooseTokens', so the disambiguated names stay deterministic
// across re-runs of an unchanged file.
func assignUniqueVarNames(identities, base []string) []string {
	taken := map[string]bool{}      // names handed out so far
	assigned := map[string]string{} // identity -> its name
	names := make([]string, len(base))
	for i := range base {
		if name, ok := assigned[identities[i]]; ok {
			names[i] = name
			continue
		}
		name := base[i]
		for suffix := 2; taken[name]; suffix++ {
			name = fmt.Sprintf("%s_%d", base[i], suffix)
		}
		taken[name] = true
		assigned[identities[i]] = name
		names[i] = name
	}
	return names
}
