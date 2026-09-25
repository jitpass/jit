// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"bytes"
	"testing"
)

// The job is pid 200 in /Users/x/custom_scripts/notion; pid 201 is its
// child (the python it runs); pid 300 is a stranger; pid 400 is another
// job's process. The mount under test is the notion folder's .env.
func jobMountManager(holders []int32, known bool) *mountManager {
	return &mountManager{
		stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}, grantKq: -1,
		grantHoldersFn: func(string) ([]int32, bool) { return holders, known },
		grantAncestryFn: func(pid, root int32) bool {
			return root == 200 && pid == 201
		},
		pointerFn: func(string) ([]byte, bool) { return []byte("# jit pointer\n"), true },
	}
}

const (
	jobDir     = "/Users/x/custom_scripts/notion"
	jobEnvPath = jobDir + "/.env"
)

func TestJobReaderGetsThePointerAndNoRecord(t *testing.T) {
	for _, holders := range [][]int32{{200}, {201}, {200, 201}} {
		sm := newTestServedMount()
		sm.decoy = []byte("decoy")
		m := jobMountManager(holders, true)
		end := m.beginJobRun(jobDir, 200)
		if got := m.serveContent(jobEnvPath, sm); string(got) != "# jit pointer\n" {
			t.Fatalf("holders %v: a job's own read got %q, want the pointer", holders, got)
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
}

// Every other read keeps the decoy and its alert.
func TestNonJobReadsStillGetTheDecoy(t *testing.T) {
	type run struct {
		dir string
		pid int32
	}
	cases := map[string]struct {
		holders []int32
		known   bool
		runs    []run
	}{
		"no job running":                    {[]int32{201}, true, nil},
		"a job in another folder":           {[]int32{201}, true, []run{{"/Users/x/custom_scripts/jamf", 200}}},
		"a job in a parent folder (nested)": {[]int32{201}, true, []run{{"/Users/x/custom_scripts", 200}}},
		"another job reads this job's .env": {[]int32{400}, true, []run{{jobDir, 200}, {"/Users/x/other", 400}}},
		"a stranger reads it":               {[]int32{300}, true, []run{{jobDir, 200}}},
		"a stranger reads alongside":        {[]int32{201, 300}, true, []run{{jobDir, 200}}},
		"holders unknown":                   {nil, false, []run{{jobDir, 200}}},
		"a sibling folder by prefix":        {[]int32{201}, true, []run{{"/Users/x/custom_scripts/noti", 200}}},
	}
	for name, tc := range cases {
		sm := newTestServedMount()
		sm.decoy = []byte("decoy")
		m := jobMountManager(tc.holders, tc.known)
		for _, r := range tc.runs {
			defer m.beginJobRun(r.dir, r.pid)()
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
