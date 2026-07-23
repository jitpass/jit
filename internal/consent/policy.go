// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package consent

// credentialClasses are the provenance Class values (vault.Class* string
// values) that represent a real machine/tool credential a process should not
// obtain silently: the classes consent gates. They mirror vault's Class
// constants by string value on purpose — consent stays a pure package and does
// not import internal/vault, and these string values are stable.
//
// Deliberately EXCLUDED (project- or run-scoped, not gated here): dotenv,
// shell, mcp, tfvars, manual, loose_file (a project's own secrets, delivered
// through a jit run the user launched), and wrap (a per-tool token the shim
// path makes explicit). Adjusting this set is the one knob that decides what
// prompts.
var credentialClasses = map[string]bool{
	"aws":       true,
	"terraform": true,
	"docker":    true,
	"git":       true,
	"kube":      true,
	"gcp":       true,
	"sops":      true,
	"npmrc":     true,
	"netrc":     true,
}

// RequiresConsent reports whether a secret of the given provenance class is
// one consent gates. An empty class (a legacy v1/v2 secret with no provenance)
// is never gated.
func RequiresConsent(class string) bool {
	return credentialClasses[class]
}
