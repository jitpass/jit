// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package agent

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/jitpass/jit/internal/secureenclave"
)

// Plan C2: a grant made with a Secure Enclave key is recorded as such, and
// serves after a restart with no prompt, as a keychain-keyed one does.
func TestStandingGrantWithAnEnclaveKey(t *testing.T) {
	var calls int32
	store := &memGrantKeys{enclave: true}
	ledger := filepath.Join(t.TempDir(), "grants.json")
	s, socketPath, cleanup := standingTestServer(t, &calls, store, ledger)

	dek := bytes.Repeat([]byte{0x09}, 32)
	sec := sealGrantSecret(t, "jamf/api-pass", "mcp", dek)
	wireGrantResolver(s, sec)
	name, parent := ownNameAndParent(t)
	standingCreate(t, NewClient(socketPath), name, parent)

	raw, err := os.ReadFile(ledger)
	if err != nil {
		t.Fatal(err)
	}
	var f ledgerFile
	if err := json.Unmarshal(raw, &f); err != nil || len(f.Grants) != 1 || len(f.Grants[0].Secrets) != 1 {
		t.Fatalf("ledger: %s (%v)", raw, err)
	}
	if w := f.Grants[0].Secrets[0].Wrap; w != standingWrapEnclave {
		t.Fatalf("ledger wrap = %q, want %q", w, standingWrapEnclave)
	}

	cleanup()
	s2, socketPath2, cleanup2 := standingTestServer(t, &calls, store, ledger)
	defer cleanup2()
	_ = s2
	before := atomic.LoadInt32(&calls)
	got, err := NewClient(socketPath2).UnwrapKeyLabeled(sec.Wrapped, "jamf/api-pass", "mcp")
	if err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("serve after restart: %v", err)
	}
	if atomic.LoadInt32(&calls) != before {
		t.Error("an enclave-keyed standing grant prompted to serve")
	}
}

// An entry sealed for one kind of key is never tried with the other: after a
// store switch, the grant does not serve (the caller falls through to the
// ordinary path, which asks), rather than feeding one wrap to the wrong key.
func TestStandingGrantNeverOpensAnEntryWithTheWrongKindOfKey(t *testing.T) {
	var calls int32
	store := &memGrantKeys{enclave: true}
	ledger := filepath.Join(t.TempDir(), "grants.json")
	s, socketPath, cleanup := standingTestServer(t, &calls, store, ledger)
	dek := bytes.Repeat([]byte{0x0a}, 32)
	sec := sealGrantSecret(t, "jamf/api-pass", "mcp", dek)
	wireGrantResolver(s, sec)
	name, parent := ownNameAndParent(t)
	standingCreate(t, NewClient(socketPath), name, parent)
	cleanup()

	store.enclave = false // the same key bytes, now presented as a keychain key
	s2, socketPath2, cleanup2 := standingTestServer(t, &calls, store, ledger)
	defer cleanup2()
	_ = s2
	before := atomic.LoadInt32(&calls)
	_, _ = NewClient(socketPath2).UnwrapKeyLabeled(sec.Wrapped, "jamf/api-pass", "mcp")
	if atomic.LoadInt32(&calls) == before {
		t.Fatal("the standing grant served an enclave-sealed entry through a keychain-kind key")
	}
}

// The agent spells the enclave wrap itself (it never imports a CGo backend);
// this holds the spelling to the one the enclave's GrantKey reports.
func TestEnclaveWrapMatchesSecureEnclave(t *testing.T) {
	if standingWrapEnclave != secureenclave.GrantWrap {
		t.Fatalf("agent says %q, secureenclave says %q", standingWrapEnclave, secureenclave.GrantWrap)
	}
}
