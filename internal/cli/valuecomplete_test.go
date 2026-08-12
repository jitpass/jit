// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"sort"
	"strings"
	"testing"
)

// completionValues strips the descriptions and the active-help lines, leaving
// the values a shell would insert.
func completionValues(comps []string) []string {
	out := make([]string, 0, len(comps))
	for _, c := range comps {
		if strings.HasPrefix(c, "_activeHelp_") {
			continue
		}
		if i := strings.IndexByte(c, '\t'); i >= 0 {
			c = c[:i]
		}
		out = append(out, c)
	}
	return out
}

// A value tab offers must be a value the command accepts. These pairs are the
// drift this file exists to prevent: the vocabulary is written down twice, in
// the validator and in the completion, and a format accepted but never
// offered (or offered but rejected) is invisible until a user hits it.
func TestOfferedFormatsAreAccepted(t *testing.T) {
	comps, _ := completeOutputFormat(nil, nil, "")
	values := completionValues(comps)
	if len(values) != len(outputFormats) {
		t.Errorf("completion offers %v, validator accepts %v", values, outputFormats)
	}
	for _, v := range values {
		if err := validateOutputFormat(v); err != nil {
			t.Errorf("completion offers --format %q, which the validator rejects: %v", v, err)
		}
	}
	if validateOutputFormat("yaml") == nil {
		t.Error("validateOutputFormat accepts yaml, so the completion list is not the whole vocabulary")
	}
}

func TestOfferedScanFormatsAreAccepted(t *testing.T) {
	fn, ok := scanCmd.GetFlagCompletionFunc("format")
	if !ok {
		t.Fatal("scan --format has no completion registered, so tab offers filenames")
	}
	comps, _ := fn(scanCmd, nil, "")
	for _, v := range completionValues(comps) {
		if err := validateScanFormat(v); err != nil {
			t.Errorf("completion offers --format %q, which validateScanFormat rejects: %v", v, err)
		}
	}
}

// The kinds tab offers must be exactly the canonical tokens --kind maps to.
// The forgiving spellings (command, start, read, mount, ...) are accepted but
// deliberately not offered: eight aliases in the list read as eight more
// kinds. If a kind is added to the alias map, this fails until it is
// described here too.
func TestAuditKindCompletionCoversEveryKind(t *testing.T) {
	canonical := map[string]bool{}
	for _, v := range auditKindAliases {
		canonical[v] = true
	}
	offered := map[string]bool{}
	for _, k := range auditCanonicalKinds() {
		offered[k] = true
	}
	var missing, extra []string
	for k := range canonical {
		if !offered[k] {
			missing = append(missing, k)
		}
	}
	for k := range offered {
		if !canonical[k] {
			extra = append(extra, k)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	if len(missing) > 0 {
		t.Errorf("--kind accepts %v but tab never offers them", missing)
	}
	if len(extra) > 0 {
		t.Errorf("--kind completion offers %v, which compileAuditFilter would reject", extra)
	}
}

// Every offered --status must survive compileAuditFilter, the function that
// rejects the rest.
func TestAuditStatusCompletionMatchesTheFilter(t *testing.T) {
	comps, _ := completeAuditStatuses(nil, nil, "")
	values := completionValues(comps)
	if len(values) != len(auditStatuses) {
		t.Errorf("completion offers %v, the filter accepts %v", values, auditStatuses)
	}
	for _, v := range values {
		auditStatus = v
		if _, err := compileAuditFilter(); err != nil {
			t.Errorf("completion offers --status %q, which compileAuditFilter rejects: %v", v, err)
		}
	}
	auditStatus = "nonsense"
	if _, err := compileAuditFilter(); err == nil {
		t.Error("compileAuditFilter accepted an unknown --status, so the offered list is not the vocabulary")
	}
	auditStatus = ""
}

// A list of common picks must not read as the only accepted values: --since
// also takes absolute dates, --ttl any duration under the ceiling. That was a
// real report against --for on a grant (completeGrantFor).
func TestOpenEndedValueCompletionsSayTheyAreOpenEnded(t *testing.T) {
	cases := map[string][]string{
		"since": func() []string { c, _ := completeAuditTimes(nil, nil, ""); return c }(),
		"ttl":   func() []string { c, _ := completeDurations("8h", "1m", "8h")(nil, nil, ""); return c }(),
		"mode":  func() []string { c, _ := completeEnvModes(nil, nil, ""); return c }(),
	}
	for name, comps := range cases {
		joined := strings.Join(comps, "\n")
		if !strings.Contains(joined, "_activeHelp_") {
			t.Errorf("--%s completion is a bare list with no hint that the grammar is open:\n%s", name, joined)
		}
	}
}

// filterValues matches on the VALUE, never on the description, or typing "h"
// would offer every entry whose help text happens to contain an h.
func TestFilterValuesMatchesValuesNotDescriptions(t *testing.T) {
	values := []string{"text\thuman-readable", "json\tmachine-readable"}
	got := filterValues(values, "h")
	if len(got) != 0 {
		t.Errorf("filterValues(%q) = %v, want nothing: no value starts with h", "h", got)
	}
	if got := filterValues(values, "j"); len(got) != 1 || !strings.HasPrefix(got[0], "json") {
		t.Errorf(`filterValues("j") = %v, want the json entry`, got)
	}
}
