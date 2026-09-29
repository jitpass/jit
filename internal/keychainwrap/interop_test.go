// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package keychainwrap

import (
	"bytes"
	"path/filepath"
	"testing"
	"time"

	"github.com/jitpass/jit/internal/agent"
	"github.com/jitpass/jit/internal/vault"
)

// fixedMEK is an agent.MEKFetcher that hands out the SAME master key this
// package's Wrapper is holding, so both wrappers are operating on one vault —
// which is the only configuration in which the interop property below is even
// a question. A fresh copy per call, because every consumer of a fetched MEK
// in both packages does `defer wipe(mek)` on what it gets back.
type fixedMEK []byte

func (f fixedMEK) FetchMEK(string) ([]byte, error) {
	out := make([]byte, len(f))
	copy(out, f)
	return out, nil
}

// interopPair builds a keychainwrap.Wrapper and an agent.Server sharing one
// MEK. The Server is never Listen()ed: WrapKeyLabeled/UnwrapKeyLabeled are the
// agent unlocking ITSELF in-process (server.go), so there is no socket, no
// peer and no consent gate on this path — exactly the code a DEK crossing
// between the two wrappers actually travels through.
func interopPair(t *testing.T) (*Wrapper, *agent.Server) {
	t.Helper()

	w := testWrapper(noChallenge)
	cleanupTestMEK(t, w)
	if err := w.EnsureMEK(); err != nil {
		t.Fatalf("EnsureMEK: %v", err)
	}
	mek, err := w.fetchMEK("interop test")
	if err != nil {
		t.Fatalf("fetchMEK: %v", err)
	}
	t.Cleanup(w.Close)

	srv := agent.NewServer(
		filepath.Join(t.TempDir(), "agent.sock"),
		func() agent.MEKFetcher { return fixedMEK(mek) },
		time.Minute,
	)
	return w, srv
}

// interopClasses spans the shapes the AAD derivation has to get right: the
// legacy empty class (v1/v2 secrets, written before provenance existed and
// byte-compatible with the pre-AAD wraps), an ordinary class, and one
// carrying an underscore.
var interopClasses = []string{"", vault.ClassManual, vault.ClassAWS, vault.ClassShellHistory}

// TestDEKWrapsInteropAcrossAgentAndKeychain is the check vault.LabeledKeyWrapper
// demands in prose and nothing enforced: "Both wrappers (agent and
// keychainwrap) MUST bind it identically: a DEK wrapped by one and unwrapped
// by the other has to agree on the AAD."
//
// That is not a hypothetical crossing. Whether a given secret's DEK was
// wrapped through the agent or through keychainwrap directly depends only on
// whether the service happened to be running when it was written, so a single
// vault routinely holds both — and any process may later read either one
// through whichever wrapper is available to it.
//
// Both packages carry their own full copy of seal/open, each citing the other,
// and both report a mismatch with the identical message "unwrap failed (wrong
// MEK, wrong class, or corrupted data)". So a divergence does not read as a
// code change; it reads to the user as vault corruption, on some secrets and
// not others. The natural hardening move on an AAD — a domain separator or a
// version prefix, `"v3|" + class` — made in one package and not the other is
// enough to do it.
//
// Deliberately driven through the exported wrappers rather than seal/open,
// which are unexported in both packages: the property covers nonce placement,
// nonce size and cipher choice too, not just the one line deriving the AAD.
func TestDEKWrapsInteropAcrossAgentAndKeychain(t *testing.T) {
	w, srv := interopPair(t)
	dek := bytes.Repeat([]byte{0x5A}, 32)

	for _, class := range interopClasses {
		name := class
		if name == "" {
			name = "legacy-empty"
		}
		t.Run(name, func(t *testing.T) {
			t.Run("agent wraps, keychain unwraps", func(t *testing.T) {
				wrapped, err := srv.WrapKeyLabeled(dek, "interop/secret", class)
				if err != nil {
					t.Fatalf("agent WrapKeyLabeled: %v", err)
				}
				got, err := w.UnwrapKeyLabeled(wrapped, "interop/secret", class)
				if err != nil {
					t.Fatalf("keychainwrap could not unwrap a DEK the agent wrapped: %v; "+
						"the two wrappers have diverged and secrets written while the "+
						"service was running are now undecryptable without it", err)
				}
				if !bytes.Equal(got, dek) {
					t.Errorf("round trip returned a different DEK: got %x, want %x", got, dek)
				}
			})

			t.Run("keychain wraps, agent unwraps", func(t *testing.T) {
				wrapped, err := w.WrapKeyLabeled(dek, "interop/secret", class)
				if err != nil {
					t.Fatalf("keychainwrap WrapKeyLabeled: %v", err)
				}
				got, err := srv.UnwrapKeyLabeled(wrapped, "interop/secret", class)
				if err != nil {
					t.Fatalf("the agent could not unwrap a DEK keychainwrap wrapped: %v; "+
						"the two wrappers have diverged and secrets written with the "+
						"service down are now undecryptable through it", err)
				}
				if !bytes.Equal(got, dek) {
					t.Errorf("round trip returned a different DEK: got %x, want %x", got, dek)
				}
			})
		})
	}
}

// TestClassBindingIsAuthoritativeAcrossWrappers pins the other half of the
// contract: the class is AAD, so presenting a different one has to fail the
// auth tag no matter which wrapper sealed the DEK.
//
// Without this, the interop test above still passes against a pair of
// wrappers that BOTH ignore class entirely — identical, interoperable, and
// with the consent gate's authoritative input reduced to a caller-supplied
// string it can lie about freely.
func TestClassBindingIsAuthoritativeAcrossWrappers(t *testing.T) {
	w, srv := interopPair(t)
	dek := bytes.Repeat([]byte{0x5A}, 32)

	agentWrapped, err := srv.WrapKeyLabeled(dek, "interop/secret", vault.ClassAWS)
	if err != nil {
		t.Fatalf("agent WrapKeyLabeled: %v", err)
	}
	keychainWrapped, err := w.WrapKeyLabeled(dek, "interop/secret", vault.ClassAWS)
	if err != nil {
		t.Fatalf("keychainwrap WrapKeyLabeled: %v", err)
	}

	if _, err := w.UnwrapKeyLabeled(agentWrapped, "interop/secret", vault.ClassDocker); err == nil {
		t.Error("keychainwrap unwrapped an agent-wrapped DEK under the wrong class; " +
			"class is not bound as AAD and the consent gate can be lied to")
	}
	if _, err := srv.UnwrapKeyLabeled(keychainWrapped, "interop/secret", vault.ClassDocker); err == nil {
		t.Error("the agent unwrapped a keychainwrap-wrapped DEK under the wrong class; " +
			"class is not bound as AAD and the consent gate can be lied to")
	}
}

// TestLabelIsNotBoundAcrossWrappers is the negative of the pair: label is
// caller-reported audit data and MUST NOT reach the AAD, in either package.
//
// It is the mistake the two are shaped to invite — WrapKeyLabeled takes label
// and class adjacently, and binding "both identifiers, for safety" looks like
// hardening. It would instead make every unwrap depend on a string the writer
// chose and the reader has to guess: vault falls back to the unlabeled methods
// whenever the wrapper doesn't implement LabeledKeyWrapper, so the same DEK is
// legitimately unwrapped under "" and under its path.
func TestLabelIsNotBoundAcrossWrappers(t *testing.T) {
	w, srv := interopPair(t)
	dek := bytes.Repeat([]byte{0x5A}, 32)

	agentWrapped, err := srv.WrapKeyLabeled(dek, "stripe/live-key", vault.ClassManual)
	if err != nil {
		t.Fatalf("agent WrapKeyLabeled: %v", err)
	}
	if _, err := w.UnwrapKeyLabeled(agentWrapped, "a totally different label", vault.ClassManual); err != nil {
		t.Errorf("keychainwrap rejected a differently-labeled unwrap: %v; "+
			"label has been bound into the AAD, which makes audit metadata "+
			"load-bearing for decryption", err)
	}

	keychainWrapped, err := w.WrapKeyLabeled(dek, "stripe/live-key", vault.ClassManual)
	if err != nil {
		t.Fatalf("keychainwrap WrapKeyLabeled: %v", err)
	}
	if _, err := srv.UnwrapKeyLabeled(keychainWrapped, "", vault.ClassManual); err != nil {
		t.Errorf("the agent rejected an unlabeled unwrap of a labeled wrap: %v; "+
			"label has been bound into the AAD, which breaks vault's own "+
			"fallback to the unlabeled KeyWrapper methods", err)
	}
}
