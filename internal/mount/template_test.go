// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: Apache-2.0

package mount

import (
	"bytes"
	"testing"
)

func TestFormatTemplateSubstitutesKnownPlaceholders(t *testing.T) {
	template := []byte("//registry.npmjs.org/:_authToken=${NPM_AUTH_TOKEN}\nregistry=https://registry.npmjs.org\nsave-exact=true\n")
	values := map[string]string{"NPM_AUTH_TOKEN": "sk_test_secret"}

	got := FormatTemplate(template, values)
	want := []byte("//registry.npmjs.org/:_authToken=sk_test_secret\nregistry=https://registry.npmjs.org\nsave-exact=true\n")
	if !bytes.Equal(got, want) {
		t.Errorf("FormatTemplate = %q, want %q", got, want)
	}
}

func TestFormatTemplateLeavesUnknownPlaceholderUntouched(t *testing.T) {
	template := []byte("_authToken=${UNKNOWN_VAR}\n")
	got := FormatTemplate(template, map[string]string{"OTHER": "x"})
	if !bytes.Equal(got, template) {
		t.Errorf("FormatTemplate = %q, want the template unchanged since UNKNOWN_VAR isn't in values", got)
	}
}

func TestFormatTemplateNoPlaceholders(t *testing.T) {
	template := []byte("registry=https://registry.npmjs.org\n")
	got := FormatTemplate(template, map[string]string{"NPM_AUTH_TOKEN": "x"})
	if !bytes.Equal(got, template) {
		t.Errorf("FormatTemplate = %q, want the template unchanged", got)
	}
}

func TestFormatTemplateMultiplePlaceholders(t *testing.T) {
	template := []byte("a=${A}\nb=${B}\n")
	got := FormatTemplate(template, map[string]string{"A": "1", "B": "2"})
	want := []byte("a=1\nb=2\n")
	if !bytes.Equal(got, want) {
		t.Errorf("FormatTemplate = %q, want %q", got, want)
	}
}

func TestFormatTemplateValueContainingDollarSign(t *testing.T) {
	template := []byte("token=${TOKEN}\n")
	got := FormatTemplate(template, map[string]string{"TOKEN": "has$literal${braces}"})
	want := []byte("token=has$literal${braces}\n")
	if !bytes.Equal(got, want) {
		t.Errorf("FormatTemplate = %q, want %q (no re-scanning the substituted value)", got, want)
	}
}
