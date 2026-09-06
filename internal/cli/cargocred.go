// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/inject"
	"github.com/jitpass/jit/internal/migrate"
	"github.com/jitpass/jit/internal/profile"
)

// Cargo's credential-provider protocol (JSON lines over stdin/stdout,
// cargo 1.74+): cargo spawns the provider with `--cargo-plugin` per
// operation, the provider greets with {"v":[1]}, then answers one request
// per line. Every shape here was verified empirically against cargo 1.98
// — see spike/cargo-credential-provider/FINDINGS.md, including that
// {"Err":{"kind":"not-found"}} falls back to `cargo:token` for a registry
// jit holds nothing for, and that an "other" error's message surfaces in
// cargo's own error chain.

// cargoCredRequest is one request line from cargo.
type cargoCredRequest struct {
	V         int    `json:"v"`
	Kind      string `json:"kind"`
	Operation string `json:"operation,omitempty"`
	Registry  struct {
		IndexURL string `json:"index-url"`
		Name     string `json:"name"`
	} `json:"registry"`
	Token string `json:"token,omitempty"`
}

type cargoCredGetOK struct {
	Kind                 string `json:"kind"`
	Token                string `json:"token"`
	Cache                string `json:"cache"`
	OperationIndependent bool   `json:"operation_independent"`
}

func cargoRespond(w io.Writer, v any) {
	data, err := json.Marshal(v)
	if err != nil {
		// Marshalling a map/struct of strings can't fail in practice; a
		// broken write is cargo's to report when the pipe closes.
		return
	}
	fmt.Fprintln(w, string(data))
}

func cargoOK(w io.Writer, payload any) { cargoRespond(w, map[string]any{"Ok": payload}) }
func cargoErr(w io.Writer, kind string) {
	cargoRespond(w, map[string]any{"Err": map[string]any{"kind": kind}})
}
func cargoErrOther(w io.Writer, msg string) {
	cargoRespond(w, map[string]any{"Err": map[string]any{"kind": "other", "message": msg}})
}

var cargoCredentialCmd = &cobra.Command{
	// The [--cargo-plugin] placeholder is real: cargo invokes the provider
	// with that marker argument, and flag parsing is disabled below, so it
	// arrives as an ordinary arg.
	Use:     "cargo-credential [--cargo-plugin]",
	GroupID: groupPlumbing,
	// Hidden only from shell tab-completion: helpVisibleAnnotation keeps
	// it in the root help (rootUsageTemplate) and the generated docs.
	Hidden:      true,
	Annotations: map[string]string{helpVisibleAnnotation: "1"},
	Short:       "Implement cargo's credential-provider protocol for a migrated registry token",
	Long: "Not typically run by hand: jit migrate writes a cargo-credential-jit\n" +
		"wrapper that invokes this command and registers it (last, so it takes\n" +
		"precedence) in ~/.cargo/config.toml's global-credential-providers, so\n" +
		"cargo fetches its registry token from the vault with no plaintext file\n" +
		"on disk.\n\n" +
		"The protocol's three kinds map to the vault: `get` serves the token from\n" +
		"the registry's cargo-<name> profile (answering not-found for a registry\n" +
		"jit holds nothing for, so cargo falls back to credentials.toml exactly\n" +
		"as if jit weren't installed); `login` (what `cargo login` calls) saves\n" +
		"the new token to the vault, so a re-login lands in the vault instead of\n" +
		"back in a plaintext file; `logout` removes it.\n\n" +
		"Requires local auth to resolve the vault the same way jit run/export do:\n" +
		"either a reachable jit background service with an already-unlocked session, or an\n" +
		"interactive context able to show a Touch ID/passcode prompt.",
	// cargo passes --cargo-plugin; parse nothing and accept anything.
	DisableFlagParsing: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		for _, a := range args {
			if a == "--help" || a == "-h" {
				return cmd.Help()
			}
		}
		out := cmd.OutOrStdout()
		cargoRespond(out, map[string]any{"v": []int{1}})

		scanner := bufio.NewScanner(cmd.InOrStdin())
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for scanner.Scan() {
			line := scanner.Bytes()
			if len(line) == 0 {
				continue
			}
			var req cargoCredRequest
			if err := json.Unmarshal(line, &req); err != nil {
				cargoErrOther(out, fmt.Sprintf("jit cargo-credential: malformed request: %v", err))
				continue
			}
			handleCargoCredRequest(out, req)
		}
		return scanner.Err()
	},
}

// handleCargoCredRequest answers one protocol request. Every answer is a
// protocol response, never a process error: cargo owns the conversation,
// and a provider that dies mid-stream reports worse than one that says
// what went wrong (spike finding 7).
func handleCargoCredRequest(out io.Writer, req cargoCredRequest) {
	registry := req.Registry.Name
	if registry == "" {
		// jit keys profiles by registry NAME (the [registries.<name>] the
		// migration read; crates.io is cargo's own reserved "crates-io").
		// A nameless invocation (source-replacement setups) can't match
		// one, so fall through to the next provider rather than guess.
		cargoErr(out, "not-found")
		return
	}
	profileName := "cargo-" + registry

	switch req.Kind {
	case "get":
		// A registry jit holds nothing for must NOT be an error or a
		// prompt: checked against the global manifest directly (cargo
		// profiles are always global-store), BEFORE openVault() — an
		// unknown registry must never cost a Touch ID prompt, and
		// not-found lets cargo fall back to credentials.toml (spike
		// finding 6).
		globalRoot, err := profile.GlobalRoot()
		if err != nil {
			cargoErrOther(out, fmt.Sprintf("jit cargo-credential: %v", err))
			return
		}
		manifestPath, err := profile.Path(globalRoot, profileName)
		if err != nil {
			cargoErrOther(out, fmt.Sprintf("jit cargo-credential: %v", err))
			return
		}
		p, err := profile.LoadFile(manifestPath)
		if errors.Is(err, os.ErrNotExist) {
			cargoErr(out, "not-found")
			return
		}
		if err != nil {
			cargoErrOther(out, fmt.Sprintf("jit cargo-credential: %v", err))
			return
		}
		v, err := openVault()
		if err != nil {
			cargoErrOther(out, fmt.Sprintf("jit cargo-credential: %v", err))
			return
		}
		values, err := inject.Resolve(v, p)
		if err != nil {
			cargoErrOther(out, fmt.Sprintf("jit cargo-credential: %v", err))
			return
		}
		if values["TOKEN"] == "" {
			cargoErr(out, "not-found")
			return
		}
		// cache "session" spans one cargo invocation; the next cargo
		// process asks again — exactly the just-in-time model.
		cargoOK(out, cargoCredGetOK{Kind: "get", Token: values["TOKEN"], Cache: "session", OperationIndependent: true})

	case "login":
		if req.Token == "" {
			cargoErrOther(out, "jit cargo-credential: login carried no token")
			return
		}
		v, err := openVault()
		if err != nil {
			cargoErrOther(out, fmt.Sprintf("jit cargo-credential: %v", err))
			return
		}
		if err := migrate.StoreCargoToken(v, registry, req.Token); err != nil {
			cargoErrOther(out, fmt.Sprintf("jit cargo-credential: %v", err))
			return
		}
		cargoOK(out, map[string]any{"kind": "login"})

	case "logout":
		// Removing a secret never decrypts anything, so `cargo logout`
		// must never cost a Touch ID prompt — read-only construction,
		// same as terraform-credentials forget.
		v, err := openVaultReadOnly()
		if err != nil {
			cargoErrOther(out, fmt.Sprintf("jit cargo-credential: %v", err))
			return
		}
		if err := migrate.ForgetCargoToken(v, registry); err != nil {
			cargoErrOther(out, fmt.Sprintf("jit cargo-credential: %v", err))
			return
		}
		cargoOK(out, map[string]any{"kind": "logout"})

	default:
		cargoErr(out, "operation-not-supported")
	}
}

func init() {
	rootCmd.AddCommand(cargoCredentialCmd)
}
