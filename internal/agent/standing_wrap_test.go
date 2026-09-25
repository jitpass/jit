// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// A ledger written by a newer jit holds entries in a wrap this build cannot
// open (grant keys in the Secure Enclave, plan C). This build must serve
// what it can, and write every entry back exactly as it found it: before
// this, it dropped the unknown entry on load and its next save erased it,
// so a downgrade and an upgrade again lost the grant's secrets.
func TestLedgerKeepsEntriesItCannotOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "grants.json")
	unknown := ledgerSecret{Path: "aws/secret", Class: "aws", DeviceDigest: "d2", GrantWrapped: "c0ffee", Wrap: "se-p256-v1"}
	known := ledgerSecret{Path: "stripe/key", Class: "env", DeviceDigest: "d1", GrantWrapped: "00ff", Wrap: standingWrapAEAD}
	g := ledgerGrant{ID: "g-01", CreatedUnix: 1, Profiles: []GrantProfile{}, Secrets: []ledgerSecret{known, unknown}}
	g.Anchor.ExecPath, g.Anchor.Name = "/Applications/Claude.app", "Claude"
	g.Program.Name = "node"
	data, err := json.Marshal(ledgerFile{Version: ledgerVersion, Grants: []ledgerGrant{g}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	s := &Server{}
	if n, err := s.SetGrantLedger(path); err != nil || n != 1 {
		t.Fatalf("SetGrantLedger = %d, %v", n, err)
	}
	if got := len(s.standing["g-01"].secrets); got != 1 {
		t.Fatalf("serving %d secrets, want only the one this build can open", got)
	}
	if err := s.saveLedger(); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var f ledgerFile
	if err := json.Unmarshal(raw, &f); err != nil || len(f.Grants) != 1 {
		t.Fatalf("saved ledger unreadable: %v\n%s", err, raw)
	}
	byPath := map[string]ledgerSecret{}
	for _, sec := range f.Grants[0].Secrets {
		byPath[sec.Path] = sec
	}
	if got, ok := byPath["aws/secret"]; !ok || got != unknown {
		t.Errorf("the entry this build cannot open came back as %+v (present %v), want it verbatim", got, ok)
	}
	if got := byPath["stripe/key"]; got != known {
		t.Errorf("the known entry came back as %+v, want %+v", got, known)
	}
}
