// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"time"

	"github.com/jitpass/jit/internal/vault"
)

// A vault path can be written by more than one flow, and when two flows
// disagree about where a secret came from, the second one silently
// replaces the first. Two real cases:
//
//   - aws-<name>/*: `jit migrate` stores a long-lived key read from
//     ~/.aws/credentials; `jit wrap clisso` stores a session minted by an
//     IdP. A machine with a static profile and an SSO app that share a
//     name (both called "prod" is not a stretch) has the capture replace
//     the stored key.
//   - wrap-<tool>/VAR: the wrap docs tell users to `jit vault set` the
//     token by hand for tools with nothing discoverable on disk (openai,
//     pulumi, jira, …). A later `jit wrap <tool>` that DOES find
//     something — a short-lived OAuth token where the user vaulted a
//     long-lived key — replaces it.
//
// Neither is data loss (SetWithMeta archives the previous version, so
// `jit vault history` still has it) and neither is necessarily wrong —
// the user may well mean it. What's wrong is doing it without saying so.
// This file is the detection half; callers do the telling, in their own
// voice, before the write.

// OriginConflict describes an existing secret whose recorded provenance
// says it came from somewhere other than what is about to overwrite it.
type OriginConflict struct {
	Path    string
	Class   string    // the stored secret's provenance class
	Origin  string    // where the stored secret came from ("" if unrecorded)
	Updated time.Time // when the stored value was last written
}

// InspectOriginConflict reports whether writing to path with the given
// provenance would replace a secret born somewhere else. It returns nil
// when there is no conflict: no such secret yet, a straight rotation of
// the same source, or a legacy secret whose provenance predates the
// field (nothing to compare, so nothing to claim).
//
// Cheap and prompt-free by construction — Info reads the envelope's
// metadata and never touches the KeyWrapper, so a guard on a hot path
// like every clisso login costs no Touch ID and no decryption.
func InspectOriginConflict(v *vault.Vault, path, incomingClass, incomingOrigin string) *OriginConflict {
	info, err := v.Info(path)
	if err != nil {
		return nil // not stored yet (or unreadable) — nothing to replace
	}
	incomingOrigin = normalizeOrigin(incomingOrigin)

	classDiffers := info.Class != "" && incomingClass != "" && info.Class != incomingClass
	originDiffers := info.Origin != "" && incomingOrigin != "" && info.Origin != incomingOrigin
	if !classDiffers && !originDiffers {
		return nil
	}
	return &OriginConflict{
		Path:    path,
		Class:   info.Class,
		Origin:  info.Origin,
		Updated: time.Unix(info.UpdatedUnix, 0),
	}
}

// Describe renders the conflict as one human clause naming where the
// stored value came from — "the key jit migrate read from
// ~/.aws/credentials", "a secret you stored by hand" — for a caller to
// drop into its own warning.
func (c OriginConflict) Describe() string {
	switch {
	case c.Origin != "":
		return "a secret from " + c.Origin
	case c.Class == vault.ClassManual:
		return "a secret you stored by hand"
	case c.Class != "":
		return "a secret from jit's " + c.Class + " migration"
	default:
		return "an existing secret"
	}
}
