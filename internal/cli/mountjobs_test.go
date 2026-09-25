// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"bytes"
	"testing"
)

// jobMountManager: the service is pid 50; pid 200 is its child (a job's
// python), pid 300 is a stranger. The mount under test is a project .env.
func jobMountManager(holders []int32, known bool) *mountManager {
	return &mountManager{
		stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}, grantKq: -1,
		servicePID:     50,
		grantHoldersFn: func(string) ([]int32, bool) { return holders, known },
		grantAncestryFn: func(pid, root int32) bool {
			return root == 50 && pid == 200
		},
		pointerFn: func(string) ([]byte, bool) { return []byte("# jit pointer\n"), true },
	}
}

const jobEnvPath = "/Users/x/custom_scripts/notion/.env"

func TestJobReaderGetsThePointerAndNoRecord(t *testing.T) {
	sm := newTestServedMount()
	sm.decoy = []byte("decoy")
	m := jobMountManager([]int32{200}, true)
	end := m.beginJobRun("/Users/x/custom_scripts/notion")
	if got := m.serveContent(jobEnvPath, sm); string(got) != "# jit pointer\n" {
		t.Fatalf("a job's own read got %q, want the pointer", got)
	}
	sm.mu.Lock()
	pending := sm.pendingServe
	sm.mu.Unlock()
	if pending != nil {
		t.Fatal("a job's pointer read was recorded as a serve, which is what raised the decoy alert")
	}
	end()
	if got := m.serveContent(jobEnvPath, sm); string(got) != "decoy" {
		t.Fatalf("after the job ended the same reader got %q, want the decoy", got)
	}
}

// Every other read keeps the decoy and its alert.
func TestNonJobReadsStillGetTheDecoy(t *testing.T) {
	cases := map[string]struct {
		holders []int32
		known   bool
		jobDir  string
	}{
		"no job running":             {[]int32{200}, true, ""},
		"another project's mount":    {[]int32{200}, true, "/Users/x/custom_scripts/jamf"},
		"a stranger reads it":        {[]int32{300}, true, "/Users/x/custom_scripts/notion"},
		"a stranger reads alongside": {[]int32{200, 300}, true, "/Users/x/custom_scripts/notion"},
		"holders unknown":            {nil, false, "/Users/x/custom_scripts/notion"},
		"the service itself":         {[]int32{50}, true, "/Users/x/custom_scripts/notion"},
		"a sibling folder by prefix": {[]int32{200}, true, "/Users/x/custom_scripts/noti"},
	}
	for name, tc := range cases {
		sm := newTestServedMount()
		sm.decoy = []byte("decoy")
		m := jobMountManager(tc.holders, tc.known)
		if tc.jobDir != "" {
			defer m.beginJobRun(tc.jobDir)()
		}
		if got := m.serveContent(jobEnvPath, sm); string(got) != "decoy" {
			t.Errorf("%s: got %q, want the decoy", name, got)
		}
		sm.mu.Lock()
		if sm.pendingServe == nil || !sm.pendingServe.rec.decoy {
			t.Errorf("%s: the decoy serve was not recorded", name)
		}
		sm.mu.Unlock()
	}
}
