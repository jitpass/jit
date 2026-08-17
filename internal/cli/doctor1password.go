// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"fmt"
	"io"

	"github.com/jitpass/jit/internal/onepassword"
	"github.com/jitpass/jit/internal/vault"
)

// This file is doctor's 1Password surface (design/1password-adapter.md),
// in two deliberately different halves. The AUTOMATIC half runs on every
// full doctor sweep and is prompt-free by construction: counting linked
// secrets reads envelope metadata (no decrypt), and vetting the op binary
// runs codesign over it without ever executing op. The EXPLICIT half —
// the --1password resolve sweep — costs a Touch ID (the stored op://
// references are sealed like values) and can pop 1Password's own
// authorization prompt per session, so it runs only when asked, the same
// line the CLI draws between `vault list` and `vault get`.

// doctorOpVerified/doctorOpVersion are seams so tests can pin the op
// probe: without them every doctor test's output would depend on whether
// the machine running it has op installed.
var (
	doctorOpVerified = onepassword.InstalledVerified
	doctorOpVersion  = onepassword.Version
)

// linkedSecretPaths returns the vault paths whose envelopes carry the
// op-ref storage marker — auth-free (List + Info read metadata only).
func linkedSecretPaths(v *vault.Vault) ([]string, error) {
	paths, err := v.List()
	if err != nil {
		return nil, err
	}
	var linked []string
	for _, p := range paths {
		info, err := v.Info(p)
		if err != nil {
			continue // integrity findings already cover unreadable envelopes
		}
		if info.Storage == vault.StorageOpRef {
			linked = append(linked, p)
		}
	}
	return linked, nil
}

// onePasswordFindings is the automatic section: findings when linked
// secrets exist but cannot possibly resolve (no op, or an op that fails
// the signature gate), and a --verbose OK line when they can. A vault
// with no linked secrets reports nothing — there is no 1Password health
// to have.
func onePasswordFindings(v *vault.Vault) ([]checkFinding, []string) {
	linked, err := linkedSecretPaths(v)
	if err != nil || len(linked) == 0 {
		return nil, nil
	}
	return onePasswordFindingsFor(len(linked))
}

// onePasswordFindingsFor is the probe half, split from the vault listing
// so tests can drive it by count with the doctorOp* seams pinned.
func onePasswordFindingsFor(linkedCount int) ([]checkFinding, []string) {
	n := countWord(linkedCount, "secret is", "secrets are")

	path, verr := doctorOpVerified()
	if verr != nil {
		if path == "" && !onepassword.Installed() {
			return []checkFinding{{
				Kind:   kind1Password,
				Detail: fmt.Sprintf("%s linked to 1Password but the op CLI is not installed; they cannot resolve until it is", n),
				Action: "`brew install 1password-cli`",
			}}, nil
		}
		return []checkFinding{{
			Kind:   kind1Password,
			Detail: fmt.Sprintf("%s linked to 1Password but the op on PATH is not a signature-verified 1Password CLI; jit refuses to resolve through it", n),
			Action: "`brew reinstall 1password-cli`",
		}}, nil
	}

	ok := fmt.Sprintf("%s linked to 1Password", countWord(linkedCount, "secret", "secrets"))
	if ver := doctorOpVersion(path); ver != "" {
		ok += " · op " + ver + " signature-verified"
	} else {
		ok += " · op signature-verified"
	}
	ok += " (`jit doctor --1password` test-resolves each link)"
	return nil, []string{ok}
}

// sweepOpLinks is the explicit sweep's core, factored over its two
// dependencies so tests can drive it without a keychain or an op binary:
// getStored unwraps one sealed reference (the Touch ID lives behind it),
// resolve test-resolves it. Returns per-dead-link findings and the tally.
func sweepOpLinks(paths []string,
	getStored func(path string) ([]byte, string, error),
	resolve func(ref string) ([]byte, error)) (findings []checkFinding, checked, ok int) {
	for _, p := range paths {
		ref, storage, err := getStored(p)
		if err != nil {
			findings = append(findings, checkFinding{
				Kind:   kind1PasswordLink,
				Path:   p,
				Detail: fmt.Sprintf("%s: could not read the stored reference: %v", p, err),
			})
			checked++
			continue
		}
		if storage != vault.StorageOpRef {
			continue // rotated to a literal since the listing; nothing linked to check
		}
		checked++
		value, rerr := resolve(string(ref))
		for i := range value {
			value[i] = 0 // the sweep proves resolvability; it must not keep what it proved
		}
		for i := range ref {
			ref[i] = 0
		}
		if rerr != nil {
			findings = append(findings, checkFinding{
				Kind:   kind1PasswordLink,
				Path:   p,
				Detail: fmt.Sprintf("%s does not resolve: %v", p, rerr),
				Action: fmt.Sprintf("fix the item in 1Password, or `jit vault link %s <op://...>` to relink", p),
			})
			continue
		}
		ok++
	}
	return findings, checked, ok
}

// onePasswordSweep runs the explicit --1password resolve sweep: list the
// linked paths (auth-free, from the read-only vault doctor already
// holds), then open the vault with a fresh Touch ID and test-resolve each
// reference through the real, signature-verified op.
func onePasswordSweep(errOut io.Writer, ro *vault.Vault) ([]checkFinding, int, int, error) {
	linked, err := linkedSecretPaths(ro)
	if err != nil {
		return nil, 0, 0, err
	}
	if len(linked) == 0 {
		return nil, 0, 0, nil
	}
	fmt.Fprintf(errOut, "test-resolving %s with 1Password (its prompt may appear)...\n",
		countWord(len(linked), "linked secret", "linked secrets"))
	av, err := openVaultFreshAuth()
	if err != nil {
		return nil, 0, 0, err
	}
	r := onepassword.New()
	findings, checked, ok := sweepOpLinks(linked, av.GetStored, r.ResolveRef)
	return findings, checked, ok, nil
}
