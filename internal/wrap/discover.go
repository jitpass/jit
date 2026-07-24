// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package wrap

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// Discovery is where a catalog entry's token was actually found on this
// machine. Source is non-nil when it came from a plaintext file (the scrub
// target); nil when it came from the tool's TokenCommand (keyring-backed —
// nothing on disk to scrub).
type Discovery struct {
	Value  string
	Source *TokenSource
}

// DiscoverToken finds a catalog entry's live token: each Source in order,
// then TokenCommand as the fallback. (found=false, nil error) means the
// tool simply isn't logged in anywhere we know to look — the caller decides
// whether that's an error (wrap flow: instruct `jit vault set` first).
func DiscoverToken(home string, e CatalogEntry) (Discovery, bool, error) {
	for i, src := range e.Sources {
		value, found, err := ExtractToken(home, src)
		if err != nil {
			return Discovery{}, false, err
		}
		if found {
			return Discovery{Value: value, Source: &e.Sources[i]}, true, nil
		}
	}
	if len(e.TokenCommand) > 0 {
		value, err := runTokenCommand(e.TokenCommand)
		if err == nil && value != "" {
			return Discovery{Value: value}, true, nil
		}
	}
	return Discovery{}, false, nil
}

// runTokenCommand runs a catalog entry's own token-export command (e.g.
// `gh auth token`). Errors are soft — an entry that can't export (not
// logged in, old version) just means "not found here".
func runTokenCommand(argv []string) (string, error) {
	cmd := exec.Command(argv[0], argv[1:]...) // #nosec G204 -- argv is compiled-in catalog data, never user input
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s: %w", strings.Join(argv, " "), err)
	}
	return strings.TrimSpace(out.String()), nil
}
