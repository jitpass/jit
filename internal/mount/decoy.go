// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package mount

import "fmt"

// decoyValuePrefix marks a decoy value as recognizably fake — never a
// plausible-looking working credential. This is deliberately NOT RFC.md
// §5.1's "honey-secret" deception engineering (a decoy crafted to look
// real enough that using it against a live external service is a
// high-confidence compromise signal): that's separate, not-yet-built scope.
// This decoy's only job is "never hand the real value to an hidden
// reader" — see RevealState and GAPS.md #2.
const decoyValuePrefix = "jit-hidden-"

// DecoyValues returns a map with the same keys as real but every value
// replaced by a fixed, recognizably-fake placeholder — what an hidden
// mount serves instead of the real profile values (RevealState.IsRevealed ==
// false). Keeping the same key set matters: an app that just checks a
// variable is present and non-empty shouldn't break in a confusing way
// before it ever gets to actually using the (decoy) value.
func DecoyValues(real map[string]string) map[string]string {
	decoy := make(map[string]string, len(real))
	for name := range real {
		decoy[name] = decoyValuePrefix + name
	}
	return decoy
}

// DecoyNotice is prepended to a mount's decoy content so the file
// explains itself the moment someone opens it: without this, a dev
// server failing on `jit-hidden-API_KEY` values sends its owner
// through app logs and service dashboards before anyone thinks to `cat`
// the .env — and the values alone say what they are but not what to DO
// about it. A `#` line comment is safe in two of the content formats a
// mount serves (dotenv loaders and npm's ini parser both treat `#` as a
// comment); in the third — JSON (the GCP ADC template mount) — it is a
// syntax error, and that is deliberate, not an oversight: an unrevealed
// ADC read then fails locally and immediately at the parse, instead of a
// valid-JSON decoy shipping a fake refresh token to Google's live token
// endpoint to fail remotely with a far more confusing invalid_grant.
// A human who `cat`s the file still sees this line either way. Making
// this notice "format-aware" someday must not silently flip JSON decoys
// to valid — that would invert the local-vs-remote failure mode
// docs/migrate/gcp.md documents. Deliberately absent from real (revealed)
// content — its presence IS the "you're looking at decoys" signal.
func DecoyNotice(mountPath string) []byte {
	return fmt.Appendf(nil, "# jit: fake placeholder values — this mount is not revealed. Run: jit agent reveal %s\n", mountPath)
}
