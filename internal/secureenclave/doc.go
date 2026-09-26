// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

// Package secureenclave keeps the vault's master encryption key (MEK) sealed
// to a key in the Mac's Secure Enclave, instead of in the login keychain in
// the clear (internal/keychainwrap). Design: design/secure-enclave.md; the
// order of work: design/secure-enclave-plan.md (this package is step B1);
// evidence: spike/secure-enclave-mek/FINDINGS.md.
//
// # What it is
//
// An enclave P-256 key, created with kSecAccessControlUserPresence, seals
// the same 32-byte MEK keychainwrap holds (ECIES). The sealed bytes live in
// <vault root>/vault-key.sealed. Opening them is the enclave's decision, and
// shows the Touch ID or password dialog; the MEK that comes out is used
// exactly as keychainwrap's is (crypto.go is byte-compatible), so envelopes,
// the agent's session, standing grants and AI Jobs do not change.
//
// Wrapper satisfies vault.KeyWrapper, vault.LabeledKeyWrapper,
// agent.MEKFetcher and agent.ClosableFetcher, and has keychainwrap's
// RequireUserPresence. internal/keystore chooses it for a vault whose root
// holds the sealed key file (step B3), which `jit vault rekey --wrapper
// secure-enclave` writes (step B4, internal/cli/vaultmove.go).
//
// # What it guarantees, and what it does not
//
// At rest, the MEK cannot be read by another program running as the user,
// even with the keychain unlocked: only a process signed with the vault's
// access group entitlement can use the enclave key, and only after the
// dialog. keychainwrap's own comment names the gap this closes (its prompt
// is "not cryptographically enforced").
//
// During a session the MEK is in the agent's memory, as it is with
// keychainwrap. A sealed file copied to another Mac opens nowhere, which is
// also why a recovery file (`jit vault export`) must exist before a vault
// moves here (decision D3).
//
// # Who can use it
//
// Only a jit that is the main executable of a bundle carrying an
// embedded.provisionprofile that authorizes AccessGroup: JitPass.app's
// helper bundle. Every other jit gets ErrUnavailable; a second executable in
// a signed bundle is killed at launch (spike S3a). Test binaries reach the
// real enclave only through scripts/se-test.sh, which wraps and signs them;
// a plain `go test` exercises everything else against a fake enclave.
//
// Whether THIS process is such a jit is Entitled: its own signature's
// keychain-access-groups and application identifier, read with no keychain
// query, so the answer never depends on a locked screen or a lookup that
// failed. A command that refuses a jit outside the app decides from it.
//
// # The CGo seam
//
// enclave.m is this package's whole C surface: find, create and delete one
// key by tag in the data-protection keychain, seal to its public half (never
// prompts, spike S1b), open with it, and read this process's own
// entitlements (SecTaskCreateFromSelf). Tests never touch prodTag.
package secureenclave
