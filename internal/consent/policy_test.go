// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package consent

import (
	"os"
	"regexp"
	"testing"
)

func TestRequiresConsent(t *testing.T) {
	// pypirc belongs with npmrc/netrc, not with the ungated project classes:
	// it is a machine-global publish credential served through a mount, and
	// `jit run --with pypi` grants it explicitly. It was missed when the
	// category was added, so twine could read the real password with no
	// prompt while npm and curl were gated — and docs/migrate/pypi.md
	// promised the prompt. Found reviewing the branch's second-order effects.
	gated := []string{"aws", "terraform", "docker", "git", "kube", "gcp", "sops", "npmrc", "netrc", "pypirc", "k8s_secret", "shell_history"}
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

// vaultClassDecl matches a provenance class as declared in vault's const block,
// which is the source of truth this package mirrors by string value.
var vaultClassDecl = regexp.MustCompile(`(?m)^\s*Class[A-Za-z0-9]+\s*(?:Class\s*)?=\s*"([a-z_0-9]+)"`)

// Every vault provenance class must be classified as gated or ungated —
// exactly one, explicitly. This is the guard whose absence let two classes
// (k8s_secret, shell_history) sit in NEITHER list: the string values are
// mirrored here rather than imported, so a class added to vault reached
// consent as "not gated" with nothing recording that anyone had decided, and
// shell_history is a live machine credential.
//
// It scans vault's source rather than importing the package, matching how
// TestNoFaintText and TestPaletteIsCentralised enforce their rules — and it
// keeps consent a pure package, which is the reason the values are mirrored in
// the first place.
func TestEveryVaultClassIsClassified(t *testing.T) {
	const src = "../vault/envelope.go"
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("reading %s: %v", src, err)
	}
	matches := vaultClassDecl.FindAllStringSubmatch(string(data), -1)
	// Without this the whole test passes vacuously the day someone renames the
	// constants or moves them to another file.
	if len(matches) < 15 {
		t.Fatalf("found only %d Class constants in %s — the guard would pass vacuously; fix vaultClassDecl", len(matches), src)
	}
	for _, m := range matches {
		class := m[1]
		gated, ungated := credentialClasses[class], ungatedClasses[class]
		switch {
		case gated && ungated:
			t.Errorf("class %q is in BOTH lists", class)
		case !gated && !ungated:
			t.Errorf("class %q is in NEITHER list — decide whether reading it should prompt, and say so in policy.go", class)
		}
	}
}
