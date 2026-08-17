// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package onepassword

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// signatureRequirement is the codesign requirement one `op` binary must
// satisfy before this package will exec it: Apple-anchored, carrying the
// Developer ID marker OIDs (so an Apple DEVELOPMENT cert from the same
// team does not pass), leaf OU = AgileBits' team. Same shape, same OIDs,
// and same rationale as internal/cli/upgrade.go's signatureRequirement —
// the OIDs are Apple-defined constants, duplicated here rather than
// exported across the cli boundary (cli sits above every other package
// and cannot be imported from one). The leading "=" marks an INLINE
// requirement; without it codesign treats the argument as a file path
// and rejects everything, including genuine binaries — fail closed, but
// wrong.
func signatureRequirement() string {
	return fmt.Sprintf("=anchor apple generic"+
		" and certificate 1[field.1.2.840.113635.100.6.2.6] exists"+
		" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists"+
		" and certificate leaf[subject.OU] = %q", opTeamID)
}

// verifySignature refuses to exec an `op` that is not a genuine, intact,
// Developer-ID-signed 1Password CLI. Fails closed on an unsigned binary,
// a missing codesign, or an unreadable result — and there is deliberately
// no override: a switch that turns off signature checking on the binary a
// security tool pipes references through is the thing an attacker asks
// the user to pass.
func verifySignature(path string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/codesign", "--verify", "--strict", "-R", signatureRequirement(), path) // #nosec G204 -- fixed system binary; path is exec.LookPath's result for op
	output, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}
	detail := strings.TrimSpace(string(output))
	if detail == "" {
		detail = err.Error()
	}
	return fmt.Errorf("%s is not a signature-verified 1Password CLI (%s); refusing to run it", path, detail)
}
