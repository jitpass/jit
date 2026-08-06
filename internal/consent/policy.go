// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

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
//
// shell_history is gated. It is a credential jit found RECORDED in a shell
// history file, which says nothing about its scope — the reason it was flagged
// is that it is a real machine credential sitting somewhere it should not, and
// the vault doc calls rotation its durable fix. It reached this list by being
// in neither half of it: the class was added to vault and nobody revisited the
// partition, so it defaulted to ungated with no record that anyone had decided.
// k8s_secret joins it for the same reason and on the same footing as kube.
//
// TestEveryVaultClassIsClassified is what makes that impossible to repeat: it
// enumerates vault's Class* constants and fails unless each appears in exactly
// one of the two sets. The lists mirror vault's string values rather than
// importing it (consent stays a pure package); the TEST imports vault, which
// is where the coupling belongs.
var credentialClasses = map[string]bool{
	"aws":           true,
	"terraform":     true,
	"docker":        true,
	"git":           true,
	"kube":          true,
	"gcp":           true,
	"sops":          true,
	"npmrc":         true,
	"netrc":         true,
	"pypirc":        true,
	"k8s_secret":    true,
	"shell_history": true,
}

// ungatedClasses is the other half of the partition, listed rather than implied
// so a new vault class cannot pass TestEveryVaultClassIsClassified by accident.
// Membership here is a decision that the credential is project- or run-scoped;
// see the exclusion note above for the reasoning per class.
var ungatedClasses = map[string]bool{
	"dotenv":     true,
	"shell":      true,
	"mcp":        true,
	"tfvars":     true,
	"manual":     true,
	"loose_file": true,
	"wrap":       true,
}

// RequiresConsent reports whether a secret of the given provenance class is
// one consent gates. An empty class (a legacy v1/v2 secret with no provenance)
// is never gated.
func RequiresConsent(class string) bool {
	return credentialClasses[class]
}
