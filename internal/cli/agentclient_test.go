// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"bytes"
	"strings"
	"testing"
)

// The wait notice explains ONE hang per process: a migrate's several slow
// RPCs after its single unlock must not print it three or four times.
func TestTouchIDNoticePrintsOncePerProcess(t *testing.T) {
	touchIDNotice.mu.Lock()
	prevOut, prevShown := touchIDNotice.out, touchIDNotice.shown
	var buf bytes.Buffer
	touchIDNotice.out, touchIDNotice.shown = &buf, false
	touchIDNotice.mu.Unlock()
	t.Cleanup(func() {
		touchIDNotice.mu.Lock()
		touchIDNotice.out, touchIDNotice.shown = prevOut, prevShown
		touchIDNotice.mu.Unlock()
	})
	for i := 0; i < 4; i++ {
		announceTouchIDWait()
	}
	if n := strings.Count(buf.String(), "Touch ID required"); n != 1 {
		t.Errorf("notice printed %d times across 4 slow RPCs, want 1:\n%s", n, buf.String())
	}
}
