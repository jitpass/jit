// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package agent

// This file is the MEK-fetcher seam: how the server obtains the master key
// when a challenge is needed, and the contract for disposing of a fetcher's
// own copy afterwards. Split out of server.go so the one place key material
// ENTERS the process is readable on its own.

// MEKFetcher provides the raw MEK bytes, challenging (Touch ID/passcode)
// if necessary. internal/keychainwrap's *Wrapper satisfies this.
//
// Server calls newFetcher() to build a FRESH one on every unlock, never
// reusing a single instance across unlocks — a Wrapper caches its MEK
// forever within its own lifetime (see its own doc comment), so reusing
// one across multiple Server-level unlocks would silently skip the
// challenge after the very first, defeating Server's own TTL-based
// re-locking entirely.
//
// reason is what the human reads on the resulting prompt (macOS renders it
// as "jit is trying to <reason>."), built per-unlock by challengeReason from
// who actually asked. It is a parameter rather than a constant inside the
// fetcher because only Server knows that — and a prompt that can't say why
// it appeared is the entire problem this plumbing exists to fix.
// A fetcher MAY also implement Close() to release whatever it cached; see
// closeFetcher. Whether it does or not, FetchMEK's return value must be a
// COPY the caller owns — never a view onto state Close would destroy — since
// Server keeps that copy as the session key long after closing the fetcher
// that produced it.
type MEKFetcher interface {
	FetchMEK(reason string) ([]byte, error)
}

// closeFetcher ends a fetcher's own MEK cache once we've taken the copy we
// need. A fetcher is built fresh per challenge and dropped immediately, but
// "dropped" is not "gone": keychainwrap's Wrapper pins its cached MEK with
// mlock and, before it grew a Close, never wiped it — so every unlock and
// every disclosed prompt left a plaintext master key in this long-lived
// process that survived the session's lock, the screen-lock wipe and the
// sleep wipe alike, and went away only when the GC reused the page.
//
// Optional by design: MEKFetcher stays a one-method interface so test
// fetchers (which hold no OS resources) don't have to implement anything,
// and a fetcher with nothing to release simply isn't asked to.
//
// Optional also means silent, which is the risk: a fetcher whose Close grew a
// return value would stop matching this assertion, the leak would come back,
// and nothing would fail. ClosableFetcher exists so the production fetcher's
// conformance is asserted at compile time where it is wired up.
func closeFetcher(f MEKFetcher) {
	if c, ok := f.(ClosableFetcher); ok {
		c.Close()
	}
}

// ClosableFetcher is a MEKFetcher that holds resources worth releasing as soon
// as its MEK has been copied out — keychainwrap's *Wrapper, whose cache is
// mlocked and must be wiped rather than left for the GC.
//
// Assert against it wherever a real fetcher is constructed
// (var _ agent.ClosableFetcher = (*keychainwrap.Wrapper)(nil)): closeFetcher's
// check is a runtime type assertion, so without a compile-time counterpart a
// signature change would turn it into a silent no-op.
type ClosableFetcher interface {
	MEKFetcher
	Close()
}
