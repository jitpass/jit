// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package consent

import "testing"

func TestRequiresConsent(t *testing.T) {
	gated := []string{"aws", "terraform", "docker", "git", "kube", "gcp", "sops", "npmrc", "netrc"}
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
