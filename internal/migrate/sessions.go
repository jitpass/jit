// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"fmt"
	"sort"
	"time"

	"github.com/jitpass/jit/internal/profile"
	"github.com/jitpass/jit/internal/vault"
)

// A Session is a vaulted credential with a known end: the temporary AWS
// credentials an SSO CLI mints (clisso's capture, or a ~/.aws/credentials
// migration that found an aws_expiration stamp) — anything stored under a
// profile that carries an EXPIRATION variable. The variable is the
// contract, not the tool: a future capture wrap that writes EXPIRATION is
// a session with no change here.
//
// This is the answer to "is the morning's login still good" that clisso's
// own `status` can no longer give once the wrap empties
// ~/.aws/credentials (docs/wrap/clisso.md), and the row jit status shows
// beside grants. Both surfaces render this one query.
type Session struct {
	// Profile is the manifest's name — for a capture, "aws-<app>", which
	// is also the AWS profile a caller names in --profile.
	Profile string
	Scope   profile.Scope
	// Origin is the source the session's secrets were born from, as the
	// vault recorded it ("~/.clisso.yaml", "~/.aws/credentials"): which
	// tool minted it. Empty for secrets stored before provenance existed.
	Origin string
	// ExpiresUnix is when the session ends. Zero means the stamp is
	// unknown — the secrets predate the expiry field in the vault, and
	// the next login will stamp them — never "expired": that reading
	// would send every script into a needless re-login.
	ExpiresUnix int64
}

// Live reports whether the session is still usable at now. A session with
// no known expiry is reported live: the credential_process serve is what
// refuses a dead token (it reads the authenticated EXPIRATION value), and
// a listing that guessed "dead" from a missing stamp would be wrong for
// every capture that predates the stamp.
func (s Session) Live(now time.Time) bool {
	return s.ExpiresUnix == 0 || time.Unix(s.ExpiresUnix, 0).After(now)
}

// Remaining is the time left at now, zero once expired or when the expiry
// is unknown.
func (s Session) Remaining(now time.Time) time.Duration {
	if s.ExpiresUnix == 0 {
		return 0
	}
	d := time.Unix(s.ExpiresUnix, 0).Sub(now)
	if d < 0 {
		return 0
	}
	return d
}

// ListSessions returns every session visible from root (project manifests
// first, then the global store — profile.ListAll's order), sorted by
// profile name. It reads envelope METADATA only (vault.Info), never a
// value, so it never prompts: jit status is prompt-free by design, and
// this is what lets a session row live on it.
//
// The expiry is taken from the EXPIRATION secret's own stamp. A manifest
// whose EXPIRATION secret is missing from the vault is skipped rather than
// reported — doctor's [missing] finding already owns that story, and a
// half-present session is not a session.
func ListSessions(v *vault.Vault, root string, now time.Time) ([]Session, error) {
	infos, err := profile.ListAll(root)
	if err != nil {
		return nil, err
	}
	var sessions []Session
	for _, info := range infos {
		p, err := profile.LoadFile(info.Path)
		if err != nil {
			return nil, fmt.Errorf("reading profile %s: %w", info.Path, err)
		}
		secretPath, ok := p["EXPIRATION"]
		if !ok || secretPath == "" {
			continue
		}
		si, err := v.Info(secretPath)
		if err != nil {
			continue
		}
		sessions = append(sessions, Session{
			Profile:     info.Name,
			Scope:       info.Scope,
			Origin:      si.Origin,
			ExpiresUnix: si.ExpiresUnix,
		})
	}
	sort.Slice(sessions, func(i, j int) bool { return sessions[i].Profile < sessions[j].Profile })
	_ = now // reserved: callers filter with Session.Live(now); listing every session is the honest default
	return sessions, nil
}

// expiryStamp turns the RFC3339 expiry a minting tool printed into the
// vault's metadata stamp, or 0 when it does not parse. A malformed stamp
// deliberately stamps nothing: the EXPIRATION value itself is still
// stored and served verbatim, so the SDK's own complaint about it wins
// over jit guessing — the same rule buildAWSCredentialProcessOutput
// applies on the way out.
func expiryStamp(rfc3339 string) int64 {
	if rfc3339 == "" {
		return 0
	}
	t, err := time.Parse(time.RFC3339, rfc3339)
	if err != nil {
		return 0
	}
	return t.Unix()
}
