// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/vault"
)

// The -l per-row tag is the storage marker's, with two suppressions that
// keep it honest without stuttering: a born-as-link row's class already
// says 1password, and a 1password-class secret whose link was overwritten
// by a literal is exactly when the reader must be told it ISN'T linked.
func TestSecretMetaSuffixLinkTag(t *testing.T) {
	cases := []struct {
		name    string
		info    vault.SecretInfo
		want    string
		wantNot string
	}{
		{"migrate-linked keeps class, gains tag",
			vault.SecretInfo{Class: vault.ClassDotenv, Storage: vault.StorageOpRef},
			"linked to 1Password", "local copy"},
		{"plain literal untouched",
			vault.SecretInfo{Class: vault.ClassDotenv},
			"dotenv", "1Password"},
		{"born-as-link does not stutter",
			vault.SecretInfo{Class: vault.ClassOnePassword, Storage: vault.StorageOpRef},
			"1password", "linked to 1Password"},
		{"overwritten link says local copy",
			vault.SecretInfo{Class: vault.ClassOnePassword},
			"local copy", "linked to"},
	}
	for _, c := range cases {
		got := secretMetaSuffix(c.info)
		if !strings.Contains(got, c.want) {
			t.Errorf("%s: suffix %q missing %q", c.name, got, c.want)
		}
		if c.wantNot != "" && strings.Contains(got, c.wantNot) {
			t.Errorf("%s: suffix %q must not contain %q", c.name, got, c.wantNot)
		}
	}
}

func TestVaultListFooterCountsLinks(t *testing.T) {
	secrets := []string{"myapp/A", "myapp/B", "myapp/C"}
	meta := map[string]vault.SecretInfo{
		"myapp/A": {Class: vault.ClassDotenv, Storage: vault.StorageOpRef},
		"myapp/B": {Class: vault.ClassDotenv, Storage: vault.StorageOpRef},
		"myapp/C": {Class: vault.ClassDotenv},
	}
	var buf bytes.Buffer
	printVaultList(&buf, secrets, nil, false, false, false, meta, "path")
	if !strings.Contains(buf.String(), "3 secrets stored, 2 linked to 1Password.") {
		t.Errorf("footer missing the linked count, got:\n%s", buf.String())
	}

	// And silence when nothing is linked — the clause must not become
	// boilerplate on every vault.
	buf.Reset()
	printVaultList(&buf, secrets, nil, false, false, false, map[string]vault.SecretInfo{}, "path")
	if strings.Contains(buf.String(), "1Password") {
		t.Errorf("no links, no clause, got:\n%s", buf.String())
	}
}
