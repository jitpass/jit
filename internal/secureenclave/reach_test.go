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

// Reachable only looks the key up: it answers for the access group whether
// or not a key is there, passes ErrUnavailable through for a jit that can't
// reach it, and never opens or makes a key.
func TestReachable(t *testing.T) {
	for _, tc := range []struct {
		name   string
		exists bool
		err    error
	}{
		{"reachable, no key", false, nil},
		{"reachable, key there", true, nil},
		{"unreachable", false, ErrUnavailable},
		{"couldn't tell", false, errors.New("a lookup that failed")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(t)
			f.exists, f.presErr = tc.exists, tc.err
			w := newWrapper(t.TempDir(), testTag, f)
			if err := w.Reachable(); !errors.Is(err, tc.err) {
				t.Fatalf("Reachable() = %v, want %v", err, tc.err)
			}
			if len(f.opens) != 0 || f.exists != tc.exists {
				t.Fatalf("Reachable used or changed the key: opens %q, exists %v", f.opens, f.exists)
			}
		})
	}
}

// The measurement behind the refusals in internal/cli (the service, and
// `jit vault rekey --wrapper`): what the REAL enclave answers a plain `go
// test` binary, which is exactly a jit outside JitPass.app (no entitlement,
// no provisioning profile). Both probes only look a TEST-ONLY tag up: no key
// is made, nothing prompts.
func TestUnsignedBinaryCannotReachTheEnclave(t *testing.T) {
	if os.Getenv("JIT_SE_TEST") == "1" {
		t.Skip("this binary is signed; the refusal is tested unsigned")
	}
	root := t.TempDir()
	w := NewTesting(root, hardwareTag(t))
	err := w.Reachable()
	if err == nil {
		t.Fatal("an unsigned test binary reached the enclave's access group")
	}
	// A developer's Mac answers errSecMissingEntitlement. A CI runner is a
	// VM that may have no enclave at all and answer differently; both are
	// "not reachable", and only the Mac's answer is pinned.
	if os.Getenv("CI") == "" && !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Reachable() = %v, want ErrUnavailable", err)
	}
	// With a sealed file, what keystore (and so the service check) sees.
	if err := os.WriteFile(filepath.Join(root, SealedFile), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
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
