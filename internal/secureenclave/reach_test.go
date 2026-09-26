// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package secureenclave

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// What the REAL enclave answers a plain `go test` binary, which is exactly
// a jit outside JitPass.app (no entitlement, no provisioning profile): the
// lookup behind keystore's Presence (jit doctor, jit status) says
// Unavailable. It only looks a TEST-ONLY tag up: no key is made, nothing
// prompts. The refusals in internal/cli decide from Entitled instead, a
// property of the binary no lock or keychain state can change.
func TestUnsignedBinaryCannotReachTheEnclave(t *testing.T) {
	if os.Getenv("JIT_SE_TEST") == "1" {
		t.Skip("this binary is signed; the refusal is tested unsigned")
	}
	root := t.TempDir()
	w := NewTesting(root, hardwareTag(t))
	if err := os.WriteFile(filepath.Join(root, SealedFile), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A developer's Mac answers errSecMissingEntitlement. A CI runner is a
	// VM that may have no enclave at all and answer differently; only the
	// Mac's answer is pinned.
	if p := w.Presence(); os.Getenv("CI") == "" && p != Unavailable {
		t.Fatalf("Presence() = %v, want Unavailable", p)
	}
}

// Only a key the enclave was reached for and does not hold is "gone"
// (ErrNoGrantKey): an enclave this jit can't reach, or a lookup that failed,
// says nothing about the key.
func TestGrantKeyLoadSaysGoneOnlyWhenItIs(t *testing.T) {
	g, keys := fakeGrantKeys(t)
	_, err := g.Load("g-missing")
	if !errors.Is(err, ErrNoGrantKey) {
		t.Fatalf("Load of a key the enclave doesn't hold = %v, want ErrNoGrantKey", err)
	}
	if err.Error() != "no Secure Enclave key for grant g-missing (was it revoked?)" {
		t.Errorf("the sentence changed: %q", err)
	}
	for _, cause := range []error{ErrUnavailable, ErrLocked, errors.New("a lookup that failed")} {
		keys["com.jitpass.grant.TEST-ONLY.g-x"] = &fakeEnclave{presErr: cause}
		_, err := g.Load("g-x")
		if err == nil || errors.Is(err, ErrNoGrantKey) {
			t.Errorf("Load with the enclave answering %v = %v: must fail, and not as gone", cause, err)
		}
		if !errors.Is(err, cause) {
			t.Errorf("Load lost its cause %v: %v", cause, err)
		}
	}
}
