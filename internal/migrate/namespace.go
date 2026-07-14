// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package migrate

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/jitpass/jit/internal/profile"
	"github.com/jitpass/jit/internal/vault"
)

// sanitizeNamePart turns an arbitrary path component (a project directory
// name, a relative path already joined with "-") into something
// profile.Path's name pattern accepts, or "" when nothing survives (an
// all-symbols name, a bare "." or ".." from a degenerate path).
func sanitizeNamePart(part string) string {
	s := strings.Trim(sanitizeProfileName(part), "-")
	if strings.Trim(s, ".") == "" {
		return ""
	}
	return s
}

// maxNamespaceCandidates bounds claimNamespace's "-2"/"-3"/... search. Two
// same-named projects is real; a hundred is a corrupted vault or a bug —
// fail loud instead of scanning forever.
const maxNamespaceCandidates = 100

// claimNamespace picks the profile name a migration may safely write its
// vault secrets under: base itself, or the first free base-2/base-3/...
// when base's vault namespace already holds some OTHER migration's value
// for one of varNames.
//
// The vault is machine-global while profile manifests are per-store — that
// asymmetry is exactly what made silent cross-project overwrites possible
// (GAPS.md #55): two projects whose files derived the same profile name
// (every project migrated from its own root derived the literal "root"
// before deriveProfileName was fixed; two directories genuinely named
// "api" still can) wrote to the same <name>/<VAR> vault paths, the later
// run silently replacing the earlier one's live secret while both mounts
// kept serving from it. A vault path counts as this migration's own — safe
// to overwrite, so a re-run refreshes its earlier values rather than
// forking a new namespace — only when the candidate's manifest at
// profilesRoot already maps that variable to that exact path.
//
// Returns the claimed name, its manifest path, the manifest's existing
// entries (empty for a fresh namespace), and — when the name had to move —
// base itself as movedFrom, so callers can say so out loud rather than
// leave a surprising name unexplained.
func claimNamespace(v *vault.Vault, profilesRoot, base string, varNames []string) (name, profilePath string, entries profile.Profile, movedFrom string, err error) {
	for i := 1; i <= maxNamespaceCandidates; i++ {
		name = base
		if i > 1 {
			name = fmt.Sprintf("%s-%d", base, i)
		}
		profilePath, err = profile.Path(profilesRoot, name)
		if err != nil {
			return "", "", nil, "", err
		}

		entries = profile.Profile{}
		switch existing, lerr := profile.LoadFile(profilePath); {
		case lerr == nil:
			for k, p := range existing {
				entries[k] = p
			}
		case errors.Is(lerr, os.ErrNotExist):
			// no manifest yet — a fresh namespace, unless the vault
			// disagrees below
		default:
			return "", "", nil, "", fmt.Errorf("loading existing profile %s: %w", profilePath, lerr)
		}

		conflict := false
		for _, varName := range varNames {
			secretPath := name + "/" + varName
			exists, eerr := v.Exists(secretPath)
			if eerr != nil {
				return "", "", nil, "", fmt.Errorf("checking vault path %s: %w", secretPath, eerr)
			}
			if exists && entries[varName] != secretPath {
				conflict = true
				break
			}
		}
		if !conflict {
			if i > 1 {
				movedFrom = base
			}
			return name, profilePath, entries, movedFrom, nil
		}
	}
	return "", "", nil, "", fmt.Errorf("no free vault namespace for %q after %d candidates — every candidate path already holds another migration's secret", base, maxNamespaceCandidates)
}
