// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"encoding/json"
	"io"
)

// WriteNDJSON writes findings then a single closing summary as
// newline-delimited JSON records, matching RFC.md §4's envelope shape for
// bumblebee co-ingestion. json.Encoder.Encode appends a newline after each
// value, which is exactly NDJSON's format.
func WriteNDJSON(w io.Writer, findings []Finding, summary ScanSummary) error {
	enc := json.NewEncoder(w)
	for _, f := range findings {
		if err := enc.Encode(f); err != nil {
			return err
		}
	}
	return enc.Encode(summary)
}
