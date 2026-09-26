// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package secureenclave

import (
	"errors"
	"os"
	"testing"
)

// Entitled decides from the signature alone: the vault's access group AND
// an application identifier of the team, or no. A signature it can't read
// is an error, never a quiet yes or no.
func TestEntitled(t *testing.T) {
	unreadable := errors.New("the signature couldn't be read")
	for _, tc := range []struct {
		name string
		e    entitlements
		err  error
		want bool
	}{
		{"the app's helper", entitlements{hasGroup: true, appID: TeamID + ".com.jitpass.agent"}, nil, true},
		{"another bundle of the team", entitlements{hasGroup: true, appID: TeamID + ".com.jitpass.other"}, nil, true},
		{"a jit outside the app", entitlements{}, nil, false},
		{"the group without an app id", entitlements{hasGroup: true}, nil, false},
		{"the group under another team's app id", entitlements{hasGroup: true, appID: "ZZZZZZZZZZ.com.jitpass.agent"}, nil, false},
		{"the team's prefix, not a team", entitlements{hasGroup: true, appID: TeamID + "X.com.jitpass.agent"}, nil, false},
		{"an app id without the group", entitlements{appID: TeamID + ".com.jitpass.agent"}, nil, false},
		{"unreadable", entitlements{hasGroup: true, appID: TeamID + ".com.jitpass.agent"}, unreadable, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			orig := readEntitlements
			readEntitlements = func() (entitlements, error) { return tc.e, tc.err }
			t.Cleanup(func() { readEntitlements = orig })
			got, err := Entitled()
			if got != tc.want || !errors.Is(err, tc.err) {
				t.Fatalf("Entitled() = %v, %v; want %v, %v", got, err, tc.want, tc.err)
			}
		})
	}
}

// The measurement, on the real signature: a plain `go test` binary is a
// jit outside JitPass.app and is not entitled; the same tests signed by
// scripts/se-test.sh (IDENTIFIER=jit signs as the shipped helper is) are.
// Both halves are asserted, the signed one gated on JIT_SE_TEST (only
// se-test.sh sets it): a plain run alone would pass an se_entitlements that
// always answered no. Reading a signature is no keychain query: no key is
// looked up or made.
func TestThisBinarysEntitlement(t *testing.T) {
	signed := os.Getenv("JIT_SE_TEST") == "1"
	got, err := Entitled()
	if err != nil {
		t.Fatalf("reading this binary's own signature failed: %v", err)
	}
	e, err := hardwareEntitlements()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("keychain-access-groups names %s: %v; application identifier %q", AccessGroup, e.hasGroup, e.appID)
	if signed {
		// se-test.sh's entitlements: the vault's group and the agent's
		// application identifier, exactly.
		if !got || !e.hasGroup || e.appID != TeamID+".com.jitpass.agent" {
			t.Fatalf("signed by se-test.sh: Entitled() = %v, group %v, app id %q; want true, true, %q", got, e.hasGroup, e.appID, TeamID+".com.jitpass.agent")
		}
		return
	}
	if got || e.hasGroup || e.appID != "" {
		t.Fatalf("a plain test binary: Entitled() = %v, group %v, app id %q; want false, false, none", got, e.hasGroup, e.appID)
	}
}
