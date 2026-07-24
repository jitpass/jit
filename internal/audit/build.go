// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import "fmt"

// ValueFindingParams describes a discovered key/value pair a category
// scanner wants turned into a Finding. BaseSeverity/Evidence apply only when
// no cross-cutting signal fires — a production-indicator or public-IP match
// always overrides both, per RFC.md §4: "Either one alone escalates a
// finding to Critical, regardless of total count."
type ValueFindingParams struct {
	FindingType  string
	FilePath     string
	Line         *int
	KeyName      string
	RawValue     string
	BaseSeverity string
	Confidence   string
	Evidence     string
}

// ValueFinding builds a Finding for a discovered key/value pair, centralizing
// the redaction and cross-cutting escalation rules from RFC.md §4 so every
// category scanner gets them identically instead of reimplementing them:
//
//   - An already-masked value (RedactValue) is passed through as-is and
//     never evaluated for production/IP signals — RFC.md §4: "skipping
//     already-masked values for both detections."
//   - Otherwise the value is masked (MaskValue) and checked for a
//     production-indicator or public-IP match, which escalates severity to
//     Critical unconditionally.
func (c Config) ValueFinding(p ValueFindingParams) Finding {
	f := c.baseFinding()
	f.FindingType = p.FindingType
	f.FilePath = p.FilePath
	f.Line = p.Line
	key := p.KeyName
	f.KeyName = &key
	f.Confidence = p.Confidence

	if IsAlreadyMasked(p.RawValue) {
		preview := p.RawValue
		f.ValuePreview = &preview
		f.AlreadyMasked = true
		f.Severity = SeverityLow
		f.Evidence = "value already masked at source; not evaluated for production/IP signals"
		f.RecordID = RecordID(f.FindingType, f.FilePath, f.KeyName)
		return f
	}

	preview := MaskValue(p.RawValue)
	f.ValuePreview = &preview

	keyProd := IsProductionIndicator(p.KeyName)
	valueProd := IsProductionIndicator(p.RawValue)
	f.ProductionIndicatorMatch = keyProd || valueProd

	ip, ipOK := MatchPublicIP(p.RawValue)
	if ipOK {
		f.PublicIPMatch = &ip
	}

	vendor, verified, tokenOK := MatchKnownTokenPattern(p.RawValue)

	switch {
	case keyProd:
		f.Severity = SeverityCritical
		f.Evidence = "key name matches production-indicator pattern"
	case valueProd:
		f.Severity = SeverityCritical
		f.Evidence = "value matches production-indicator pattern"
	case ipOK:
		f.Severity = SeverityCritical
		f.Evidence = "public IP address found in value"
	case tokenOK:
		// A positive vendor-format match is stronger evidence than
		// whatever the caller passed in — including a category's own
		// downgrade, like the MCP scanner's bare-URL discount — so this
		// takes priority over BaseSeverity/Confidence/Evidence entirely.
		f.Severity = SeverityHigh
		if verified {
			f.Confidence = ConfidenceHigh
			f.Evidence = fmt.Sprintf("value matches %s's known token format", vendor)
		} else {
			f.Confidence = ConfidenceMedium
			f.Evidence = fmt.Sprintf("value looks like it may be a %s (pattern not independently verified)", vendor)
		}
	default:
		f.Severity = p.BaseSeverity
		f.Evidence = p.Evidence
	}

	f.RecordID = RecordID(f.FindingType, f.FilePath, f.KeyName)
	return f
}
