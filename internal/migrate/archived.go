// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package migrate

import (
	"github.com/jitpass/jit/internal/audit"
)

// LooksArchived reports whether path lives under a directory that looks
// archived/backed-up rather than actively worked on. `jit migrate home`'s
// whole-machine sweep skips anything matching it by default
// (--include-archived overrides) — GAPS.md #26. The name list itself is
// audit.LooksArchived's (this package already imports audit, not the
// other way around), so the audit report's [archived] tag and this
// sweep's skip can never disagree about which findings are archived.
//
// Why this matters specifically for the walked categories (.env, tfvars,
// MCP, npmrc) and not the fixed-path ones: converting a forgotten
// project's .env into a live-mounted pipe (internal/mount) can turn it
// from "insecure but readable" into "permanently unreadable" — nothing
// will ever serve that pipe's content unless something later runs `jit
// agent` from that exact project again, which is exactly what won't
// happen for a project nobody revisits. Shell-config/AWS/kubeconfig live
// at fixed home paths that never look archived, so they're never
// filtered by this.
func LooksArchived(path string) bool {
	return audit.LooksArchived(path)
}

// FilterArchived splits paths into kept (doesn't look archived) and
// skipped (does), preserving order in both. Callers report skipped so a
// whole-machine run never silently drops a finding without saying so
// ("fail safe and loud").
func FilterArchived(paths []string) (kept, skipped []string) {
	for _, p := range paths {
		if LooksArchived(p) {
			skipped = append(skipped, p)
		} else {
			kept = append(kept, p)
		}
	}
	return kept, skipped
}

// FilterPlayground splits paths into kept and skipped-as-synthetic: a path
// inside a jitpass-playground checkout under home is planted bait `jit
// audit` excludes from its score (audit.InSyntheticPlayground), and a
// whole-machine sweep must not convert it — vaulting fake secrets and
// live-mounting the tour repo's .env files would wreck the checkout for
// its actual purpose. Unlike FilterArchived there is no flag to override
// this: practicing a migration inside the playground is what `jit migrate
// local` run from the checkout is for (audit's own home-in-playground
// escape hatch keeps that path working). Callers report skipped so the
// sweep never silently drops a finding without saying so.
func FilterPlayground(home string, paths []string) (kept, skipped []string) {
	for _, p := range paths {
		if audit.InSyntheticPlayground(home, p) {
			skipped = append(skipped, p)
		} else {
			kept = append(kept, p)
		}
	}
	return kept, skipped
}
