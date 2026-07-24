// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package mount

import "regexp"

// placeholderPattern matches `${VAR_NAME}` — the same shell-familiar
// syntax as `jit export`'s own `eval "$(jit export ...)"` output, chosen
// so a template file reads naturally to anyone who's seen a `.env.example`
// or a shell script before it.
var placeholderPattern = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// FormatTemplate renders template with every `${VAR_NAME}` placeholder
// replaced by values[VAR_NAME], leaving everything else — including a
// placeholder whose name isn't in values — untouched. Used for a mount
// whose source file mixes secret and non-secret content (npmrc's Tier 4
// case, GAPS.md #8): unlike FormatDotenv, which generates a mount's whole
// content from a profile's resolved values, a template mount's content is
// mostly the original file, with only the secret-shaped lines replaced.
func FormatTemplate(template []byte, values map[string]string) []byte {
	return placeholderPattern.ReplaceAllFunc(template, func(match []byte) []byte {
		name := placeholderPattern.FindSubmatch(match)[1]
		if v, ok := values[string(name)]; ok {
			return []byte(v)
		}
		return match
	})
}
