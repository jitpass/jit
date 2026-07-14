// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: Apache-2.0

package migrate

import (
	"fmt"
	"os"
	"sort"

	"github.com/jitpass/jit/internal/inject"
	"github.com/jitpass/jit/internal/mount"
	"github.com/jitpass/jit/internal/profile"
	"github.com/jitpass/jit/internal/vault"
)

// UnmountFile reverses ApplyEnvFile/ApplyNpmrc: decrypts every secret the
// mount's profile references and writes them back out as a plain file at
// mountPath, replacing the FIFO. templatePath is "" for a plain
// dotenv-style mount (.env, shell-config — content is generated entirely
// from the profile's resolved values via FormatDotenv); non-empty for a
// template-based mount (npmrc's Tier 4 case, GAPS.md #8), where only the
// template's ${VAR_NAME} placeholders are substituted and everything else
// in the original file's structure is preserved via FormatTemplate.
// Returns the resolved variable names, sorted, for a caller's confirmation
// message.
//
// Deliberately does NOT delete the vault secrets or the profile manifest —
// only the physical mount is reversed. Both stay available afterward
// (e.g. for jit export or a future re-migration) unless removed
// separately; this is "put the plaintext file back," not "forget this
// secret ever existed."
//
// Callers are responsible for making sure nothing is actively serving
// mountPath (e.g. a running jit agent) before calling this — replacing a
// FIFO an agent is mid-Serve() on with a regular file can race in ways
// that redo the agent's next write into the caller's fresh plaintext.
func UnmountFile(v *vault.Vault, profilePath, mountPath, templatePath string) ([]string, error) {
	p, order, err := profile.LoadFileOrdered(profilePath)
	if err != nil {
		return nil, fmt.Errorf("loading profile %s: %w", profilePath, err)
	}
	values, err := inject.Resolve(v, p)
	if err != nil {
		return nil, fmt.Errorf("resolving secrets: %w", err)
	}

	var content []byte
	if templatePath != "" {
		tmpl, err := os.ReadFile(templatePath) // #nosec G304 -- path comes from jit's own mount registry, not external input
		if err != nil {
			return nil, fmt.Errorf("reading template %s: %w", templatePath, err)
		}
		content = mount.FormatTemplate(tmpl, values)
	} else {
		content = mount.FormatDotenv(values, order)
	}

	// RetireFIFO instead of a bare remove: a reader blocked in open(2) on
	// the pipe at this instant (a file watcher mid-poll — GAPS.md #57's
	// real incident) would otherwise wait forever on the unlinked pipe's
	// vnode; release hands it the same content just written at the path.
	release, err := mount.RetireFIFO(mountPath)
	if err != nil {
		return nil, fmt.Errorf("removing mount at %s: %w", mountPath, err)
	}
	if err := os.WriteFile(mountPath, content, 0o600); err != nil { // #nosec G703 -- mountPath comes from jit's own mount registry, not external input
		return nil, fmt.Errorf("writing %s: %w", mountPath, err)
	}
	if err := release(content); err != nil {
		return nil, fmt.Errorf("releasing readers of the old mount at %s (the file itself was restored): %w", mountPath, err)
	}

	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}
