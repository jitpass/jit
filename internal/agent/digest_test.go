// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package agent

import (
	"testing"

	"github.com/jitpass/jit/internal/rekeymap"
)

// A job's and a standing grant's pin is wrappedDigest; a key rotation's
// digest map is keyed by rekeymap.Digest. If the two ever differ, no pin
// reaches its rewrapped envelope and every job stops after a rotation.
func TestWrappedDigestIsTheRekeyMapsDigest(t *testing.T) {
	for _, wrapped := range [][]byte{nil, []byte("abc"), make([]byte, 60)} {
		if got, want := wrappedDigest(wrapped), rekeymap.Digest(wrapped); got != want {
			t.Errorf("wrappedDigest(%x) = %s, rekeymap.Digest = %s", wrapped, got, want)
		}
	}
	const abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got := wrappedDigest([]byte("abc")); got != abc {
		t.Errorf("wrappedDigest(abc) = %s, want SHA-256 hex %s", got, abc)
	}
}
