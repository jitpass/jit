// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

//go:build darwin

package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/inject"
	"github.com/jitpass/jit/internal/migrate"
	"github.com/jitpass/jit/internal/profile"
)

// dockerCredentialPayload is Docker's credential-helper protocol JSON —
// the same shape for get's stdout and store's stdin. Field names are the
// protocol's own (docs.docker.com/reference/cli/docker/login, "Credential
// helper protocol"), which Go's default marshaling matches exactly.
type dockerCredentialPayload struct {
	ServerURL string
	Username  string
	Secret    string
}

// dockerCredentialsNotFoundMsg is the exact sentinel docker's client
// matches (string comparison against trimmed stdout) to distinguish "no
// credentials stored, fall through to anonymous access" from a genuine
// helper failure. Every official docker-credential-* helper prints this
// same line; the wording is part of the protocol, not jit's.
const dockerCredentialsNotFoundMsg = "credentials not found in native keychain"

var dockerCredentialCmd = &cobra.Command{
	Use:     "docker-credential <get|store|erase|list>",
	GroupID: groupPlumbing,
	// Hidden only from shell tab-completion: helpVisibleAnnotation keeps
	// it in the root help (rootUsageTemplate) and the generated docs.
	Hidden:      true,
	Annotations: map[string]string{helpVisibleAnnotation: "1"},
	Short:       "Implement Docker's credential-helper protocol for migrated registry logins",
	Long: "Not typically run by hand: jit migrate writes a docker-credential-jit\n" +
		"helper script (on PATH via ~/.jit/shims) and routes registries to it in\n" +
		"~/.docker/config.json (credHelpers per migrated registry, plus credsStore\n" +
		"when the config had no store at all), so docker fetches registry\n" +
		"credentials from the vault with nothing on disk but docker's own empty\n" +
		"\"auths\" markers.\n\n" +
		"The four verbs are Docker's own protocol, each reading its payload from\n" +
		"stdin: `get` reads a registry address and prints the credential as JSON,\n" +
		"or the protocol's exact \"" + dockerCredentialsNotFoundMsg + "\"\n" +
		"sentinel when jit holds nothing for that registry, so docker falls\n" +
		"through to anonymous access; `store` (what `docker login` calls) reads\n" +
		"a JSON credential and saves it to the vault, so a re-login lands in the\n" +
		"vault instead of back in base64; `erase` (`docker logout`) removes it;\n" +
		"`list` prints an empty JSON object, deliberately: a truthful listing\n" +
		"would need a vault unlock inside headless docker calls, and docker still\n" +
		"resolves every registry's real credential per-registry via `get`.\n\n" +
		"`get` for a registry jit holds nothing for, and `erase`, never cost a\n" +
		"Touch ID prompt. A successful `get` resolves the vault the same way\n" +
		"jit run/export do: either a reachable jit agent with an already-unlocked\n" +
		"session, or an interactive context able to show a Touch ID/passcode\n" +
		"prompt.",
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		switch verb := args[0]; verb {
		case "get":
			serverURL, err := readDockerStdinPayload(cmd.InOrStdin())
			if err != nil {
				return fmt.Errorf("jit docker-credential get: reading registry address from stdin: %w", err)
			}
			// A registry jit holds nothing for must NOT be a bare error or
			// a prompt: docker queries the helper for any registry it talks
			// to (public pulls included), and the protocol's "no
			// credentials" answer is the sentinel on stdout plus a non-zero
			// exit. Checked against the global manifest directly (docker
			// profiles are always global-store), BEFORE openVault() — an
			// unknown registry must never cost a Touch ID prompt.
			profileName := migrate.DockerProfileName(serverURL)
			if profileName == "" {
				fmt.Fprintln(cmd.OutOrStdout(), dockerCredentialsNotFoundMsg)
				return fmt.Errorf("jit docker-credential get: no credentials stored for %q", serverURL)
			}
			globalRoot, err := profile.GlobalRoot()
			if err != nil {
				return fmt.Errorf("jit docker-credential: %w", err)
			}
			manifestPath, err := profile.Path(globalRoot, profileName)
			if err != nil {
				return fmt.Errorf("jit docker-credential: %w", err)
			}
			p, err := profile.LoadFile(manifestPath)
			if errors.Is(err, os.ErrNotExist) {
				fmt.Fprintln(cmd.OutOrStdout(), dockerCredentialsNotFoundMsg)
				return fmt.Errorf("jit docker-credential get: no credentials stored for %q", serverURL)
			}
			if err != nil {
				return fmt.Errorf("jit docker-credential: %w", err)
			}

			v, err := openVault()
			if err != nil {
				return fmt.Errorf("jit docker-credential: %w", err)
			}
			values, err := inject.Resolve(v, p)
			if err != nil {
				return fmt.Errorf("jit docker-credential: %w", err)
			}
			out, err := buildDockerCredentialOutput(serverURL, values)
			if err != nil {
				return fmt.Errorf("jit docker-credential: profile %q: %w", profileName, err)
			}
			data, err := json.Marshal(out) // #nosec G117 -- the get verb's whole contract is printing the credential to docker on stdout
			if err != nil {
				return fmt.Errorf("jit docker-credential: %w", err)
			}
			fmt.Fprintln(cmd.OutOrStdout(), string(data))
			return nil

		case "store":
			var in dockerCredentialPayload
			if err := json.NewDecoder(cmd.InOrStdin()).Decode(&in); err != nil {
				return fmt.Errorf("jit docker-credential store: reading credential from stdin: %w", err)
			}
			if in.ServerURL == "" {
				return fmt.Errorf("jit docker-credential store: no ServerURL in stdin JSON")
			}
			if in.Secret == "" {
				return fmt.Errorf("jit docker-credential store: no Secret in stdin JSON")
			}
			v, err := openVault()
			if err != nil {
				return fmt.Errorf("jit docker-credential: %w", err)
			}
			if err := migrate.StoreDockerCredential(v, in.ServerURL, in.Username, in.Secret); err != nil {
				return fmt.Errorf("jit docker-credential store: %w", err)
			}
			return nil

		case "erase":
			serverURL, err := readDockerStdinPayload(cmd.InOrStdin())
			if err != nil {
				return fmt.Errorf("jit docker-credential erase: reading registry address from stdin: %w", err)
			}
			// Removing a secret never decrypts anything (Vault.Remove
			// doesn't touch KeyWrapper), so `docker logout` must never
			// cost a Touch ID prompt — read-only construction, like
			// terraform-credentials forget.
			v, err := openVaultReadOnly()
			if err != nil {
				return fmt.Errorf("jit docker-credential: %w", err)
			}
			if err := migrate.EraseDockerCredential(v, serverURL); err != nil {
				return fmt.Errorf("jit docker-credential erase: %w", err)
			}
			return nil

		case "list":
			// Deliberately empty (see Long above): docker's per-registry
			// resolution goes through `get`, and a truthful list would
			// either need a lossy profile-name→URL reverse mapping or a
			// vault unlock inside headless docker invocations.
			fmt.Fprintln(cmd.OutOrStdout(), "{}")
			return nil

		default:
			return fmt.Errorf("jit docker-credential: unknown verb %q (want get, store, erase, or list)", verb)
		}
	},
}

// readDockerStdinPayload reads the single-line string payload get/erase
// receive on stdin (the registry server address), trimmed of the
// trailing newline docker sends.
func readDockerStdinPayload(r io.Reader) (string, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// buildDockerCredentialOutput validates a resolved profile's values and
// builds the helper protocol's "get" JSON — split out of RunE so the
// protocol shape is testable without a real vault/Touch ID challenge
// (same split as awscred.go/k8scred.go/terraformcred.go).
func buildDockerCredentialOutput(serverURL string, values map[string]string) (dockerCredentialPayload, error) {
	if values["SECRET"] == "" {
		return dockerCredentialPayload{}, fmt.Errorf("missing SECRET")
	}
	username := values["USERNAME"]
	if username == "" {
		// An identity-token credential's username is the protocol's own
		// "<token>" placeholder — never leave it empty, docker treats the
		// pair as malformed.
		username = migrate.DockerTokenUsername
	}
	return dockerCredentialPayload{ServerURL: serverURL, Username: username, Secret: values["SECRET"]}, nil
}

func init() {
	rootCmd.AddCommand(dockerCredentialCmd)
}
