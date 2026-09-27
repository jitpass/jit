// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import "github.com/jitpass/jit/internal/auditlog"

// EnvVarClass is what one .env variable is, for deciding where `jit migrate`
// keeps it: in the vault, or as a plain setting beside the profile
// (design/secrets-only-vault.md).
type EnvVarClass string

const (
	// EnvVarSecret is a value the scan counts as a credential.
	EnvVarSecret EnvVarClass = "secret"
	// EnvVarCheck is a name that looks like a secret holding a value that
	// does not: EXPORT_SECRETS_FILE=exports/secrets.csv. The scan cannot
	// tell, so it goes to the vault unless the user says otherwise — a
	// setting kept in the vault costs a Touch ID, a secret kept in plain
	// text is a leak.
	EnvVarCheck EnvVarClass = "check"
	// EnvVarSetting is everything the scan does not flag.
	EnvVarSetting EnvVarClass = "setting"
)

// InVault reports whether a class goes to the vault by default.
func (c EnvVarClass) InVault() bool { return c != EnvVarSetting }

// ClassifyEnvVar sorts one active .env variable by the rules
// buildEnvFileFinding applies to each line, judged on its own. Per line, not
// per file, is the difference that matters: the file scanner stops claiming
// after the first random-looking value, because one is enough to raise a
// finding, and a split built on its claims would leave the second one in
// plain text.
//
// The caller passes the value its own parser produced (migrate's, already
// unquoted), so the classifier and the file it rewrites can never disagree
// about what a value is. The default gates only: --unfiltered is a reading
// mode for the report, never a reason to move a value.
func ClassifyEnvVar(key, value string) EnvVarClass {
	if value == "" || IsAlreadyMasked(value) {
		return EnvVarSetting
	}
	// A 1Password reference holds no secret at rest, but migrate links it as
	// an op:// reference in the vault (migrate1password.go), which is where
	// it has always gone. Keeping it there keeps that path unchanged.
	if IsOpSecretReference(value) {
		return EnvVarSecret
	}
	if LooksLikeUnresolvedReference(value) {
		return EnvVarSetting
	}
	if vendor, _, ok := MatchKnownTokenPattern(value); ok {
		// A JWT under a documented-public name (SUPABASE_ANON_KEY) is public
		// by design; every other format is issuer-specific and counts.
		if !IsAmbiguousTokenFormat(vendor) || NonSecretNameReason(key) == "" {
			return EnvVarSecret
		}
	}
	if LooksLikeSecretKey(key) && NonSecretNameReason(key) == "" && NonSecretValueReason(value) == "" {
		if auditlog.LooksHighEntropy(value) {
			return EnvVarSecret
		}
		return EnvVarCheck
	}
	if LooksLikeHighEntropySecret(key, value) {
		return EnvVarSecret
	}
	return EnvVarSetting
}
