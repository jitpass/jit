// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package consent

import "testing"

func TestRequiresConsent(t *testing.T) {
	// pypirc belongs with npmrc/netrc, not with the ungated project classes:
	// it is a machine-global publish credential served through a mount, and
	// `jit run --with pypi` grants it explicitly. It was missed when the
	// category was added, so twine could read the real password with no
	// prompt while npm and curl were gated — and docs/migrate/pypi.md
	// promised the prompt. Found reviewing the branch's second-order effects.
	gated := []string{"aws", "terraform", "docker", "git", "kube", "gcp", "sops", "npmrc", "netrc", "pypirc"}
	for _, c := range gated {
		if !RequiresConsent(c) {
			t.Errorf("class %q should be gated", c)
		}
	}
	ungated := []string{"dotenv", "shell", "mcp", "tfvars", "manual", "loose_file", "wrap", "", "unknown"}
	for _, c := range ungated {
		if RequiresConsent(c) {
			t.Errorf("class %q should NOT be gated", c)
		}
	}
}
