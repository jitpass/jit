// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"bytes"
	"strings"
	"testing"
)

// An unknown registry must be the protocol's not-found answer — never an
// error and never a Touch ID prompt (the manifest check runs before
// openVault()) — so cargo falls back to `cargo:token` exactly as if jit
// weren't installed (spike/cargo-credential-provider finding 6).
func TestCargoCredGetUnknownRegistryAnswersNotFound(t *testing.T) {
	withFixtureHome(t)

	var buf bytes.Buffer
	handleCargoCredRequest(&buf, cargoCredRequest{
		V:    1,
		Kind: "get",
		Registry: struct {
			IndexURL string `json:"index-url"`
			Name     string `json:"name"`
		}{IndexURL: "sparse+https://never.example/index/", Name: "never-migrated"},
	})
	if got := strings.TrimSpace(buf.String()); got != `{"Err":{"kind":"not-found"}}` {
		t.Errorf("output = %q, want the protocol's not-found answer", got)
	}
}

// A nameless invocation (source-replacement setups pass only the index
// URL) can't match a cargo-<name> profile, so it must fall through, not
// guess.
func TestCargoCredGetNamelessRegistryAnswersNotFound(t *testing.T) {
	withFixtureHome(t)

	var buf bytes.Buffer
	handleCargoCredRequest(&buf, cargoCredRequest{V: 1, Kind: "get"})
	if got := strings.TrimSpace(buf.String()); got != `{"Err":{"kind":"not-found"}}` {
		t.Errorf("output = %q, want not-found for a nameless registry", got)
	}
}

func TestCargoCredUnknownKindAnswersOperationNotSupported(t *testing.T) {
	withFixtureHome(t)

	var buf bytes.Buffer
	req := cargoCredRequest{V: 1, Kind: "read"}
	req.Registry.Name = "crates-io"
	handleCargoCredRequest(&buf, req)
	if got := strings.TrimSpace(buf.String()); got != `{"Err":{"kind":"operation-not-supported"}}` {
		t.Errorf("output = %q, want operation-not-supported", got)
	}
}

// The full command conversation: greeting first ({"v":[1]}), then one
// answer per request line — the handshake cargo 1.98 was verified to
// accept in the spike.
func TestCargoCredCommandConversation(t *testing.T) {
	withFixtureHome(t)
	withFixtureCwd(t)

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetIn(strings.NewReader(`{"v":1,"registry":{"index-url":"sparse+https://x.example/","name":"never-migrated"},"kind":"get","operation":"read"}` + "\n"))
	rootCmd.SetArgs([]string{"cargo-credential", "--cargo-plugin"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("cargo-credential: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines %q, want greeting + one answer", len(lines), lines)
	}
	if lines[0] != `{"v":[1]}` {
		t.Errorf("greeting = %q, want {\"v\":[1]}", lines[0])
	}
	if lines[1] != `{"Err":{"kind":"not-found"}}` {
		t.Errorf("answer = %q, want not-found", lines[1])
	}
}
