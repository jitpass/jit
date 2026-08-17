// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package vault

import "errors"

// ErrRefUnresolvable is returned (wrapped, with the secret's path and
// reference kind) when Get opens a reference-kind envelope on a Vault with
// no RefResolver. It exists so surfaces that must never block on an
// external tool's GUI prompt can opt out by construction — they simply
// build their Vault without a resolver — and still fail with a typed,
// explainable error instead of a mystery.
var ErrRefUnresolvable = errors.New("secret is a reference but this vault has no resolver")

// RefResolver resolves a reference-kind payload (see envelope.Storage) to
// the secret bytes it names. It mirrors the KeyWrapper seam: this package
// has no opinion about WHERE references resolve — internal/onepassword is
// the shipped implementation, exec-ing the `op` CLI — and dispatches on
// nothing but the stored, AAD-bound storage marker. Reference schemes are
// the resolver's business: a resolver must reject a reference it does not
// recognize rather than guess.
//
// A resolver may block on user interaction (1Password's own unlock
// prompt), so callers on interaction-free paths must leave the Vault's
// RefResolver nil rather than wrap a resolver in a timeout of their own.
type RefResolver interface {
	ResolveRef(ref string) ([]byte, error)
}
