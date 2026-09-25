// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"encoding/json"
	"testing"

	"github.com/jitpass/jit/internal/keystore"
)

// TestStatusVaultInitialized pins the one thing a zero secret count cannot
// say: whether this Mac was ever set up. A GUI hangs its first-run offer on
// "no" and only "no", so an unanswerable keychain must read "unknown" rather
// than collapse into it, and the field must be present in the JSON in every
// state, the empty vault included.
func TestStatusVaultInitialized(t *testing.T) {
	for _, tc := range []struct {
		presence keystore.Presence
		want     string
	}{
		{keystore.Present, "yes"},
		{keystore.Absent, "no"},
		{keystore.Indeterminate, "unknown"},
	} {
		t.Run(tc.want, func(t *testing.T) {
			home := withFixtureHome(t)
			stubKeychain(t, tc.presence)

			got, err := gatherVaultStatus(fixtureVault(home), fixtureRoot(home))
			if err != nil {
				t.Fatal(err)
			}
			if got.Initialized != tc.want {
				t.Errorf("Initialized = %q, want %q", got.Initialized, tc.want)
			}
			raw, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			var decoded map[string]any
			if err := json.Unmarshal(raw, &decoded); err != nil {
				t.Fatal(err)
			}
			if decoded["initialized"] != tc.want {
				t.Errorf("JSON initialized = %v, want %q", decoded["initialized"], tc.want)
			}
		})
	}
}
